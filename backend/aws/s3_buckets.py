"""Reading, creating, updating, and deleting S3 buckets.

Handles all boto3 AWS interactions for the storage half of the tool.

Two things about S3 that differ from EC2 and shape this file:

1. There is no DryRun. Every call here is real. Testing means creating a bucket
   and deleting it, which is free as long as the bucket is empty.
2. "Not configured" is an error, not an empty response. Asking an unencrypted
   bucket about its encryption raises ServerSideEncryptionConfigurationNotFoundError
   rather than returning nothing. Each getter below swallows its specific
   not-found code and reports the absence as a value.
"""

import json
from aws.common import client as _client, ClientError

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

# Codes that mean "this was never configured" rather than "something broke".
_NOT_CONFIGURED = {
    "ServerSideEncryptionConfigurationNotFoundError",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchBucketPolicy",
    "NoSuchTagSet",
    "NoSuchLifecycleConfiguration",
    "NoSuchWebsiteConfiguration",
}

# Codes that mean "this login is not allowed to look".
_DENIED = {"AccessDenied", "AllAccessDisabled", "Forbidden"}


class PermissionDenied(Exception):
    """Raised when the current login cannot read or write a bucket setting.

    Distinct from a setting being absent. "Encryption is off" is a finding to
    report; "I am not allowed to ask about encryption" is a gap in the audit.
    Conflating the two would let the tool announce a bucket is unencrypted when
    it has no idea either way, which is worse than saying nothing.
    """

    def __init__(self, permission, message=""):
        self.permission = permission
        self.message = message
        super().__init__(f"{permission}: {message}")


def _denied(e, permission):
    """Converts an AccessDenied ClientError into PermissionDenied, else re-raises."""
    if e.response["Error"]["Code"] in _DENIED:
        raise PermissionDenied(permission, e.response["Error"]["Message"]) from e
    raise

ALL_BLOCKS_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

# The same four switches, off. This is not the absence of a configuration and
# not the default: since April 2023 AWS writes ALL_BLOCKS_ON onto every new
# bucket itself, so producing an open one takes a write. See
# unblock_public_access.
ALL_BLOCKS_OFF = {key: False for key in ALL_BLOCKS_ON}


def get_client(region="us-east-1"):
    """Initializes and returns an S3 client."""
    return _client("s3", region)


# ---------------------------------------------------------------- CRUD Operations


def bucket_exists(s3, bucket_name):
    """Returns whether the bucket is already there.

    Needed because us-east-1 makes CreateBucket idempotent: recreating a bucket
    you already own returns success rather than BucketAlreadyOwnedByYou, which
    is what every other region raises. Relying on that exception means the tool
    silently reports "created" for a bucket it merely found, and in us-east-1
    only. Asking first behaves the same everywhere.

    A 403 means the name exists but belongs to someone else, which counts as
    existing for this purpose; the create call that follows reports it properly.
    """
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        return e.response["Error"]["Code"] not in ("404", "NoSuchBucket")


def create_bucket(s3, bucket_name, region="us-east-1", secure_by_default=True,
                  website=False):
    """Creates a tagged bucket, optionally hardened on creation.

    Returns (ok, name_or_error, problems). The third element is the part that
    matters: a bucket can be created successfully and still fail to be tagged
    or hardened, because those are separate permissions. Reporting only ok/name
    would print "Created, secure by default" over a bucket that is neither
    tagged nor secure.

    us-east-1 rejects a CreateBucketConfiguration block; every other region
    requires one. That asymmetry is a genuine AWS quirk, not a bug here.

    With secure_by_default left on, the bucket comes up blocked, encrypted and
    versioned. Pass False for a deliberately weak bucket, which takes a write
    of its own rather than the absence of one - see unblock_public_access.

    Encryption is not part of that bargain in either direction. AWS has applied
    SSE-S3 to every new bucket since January 2023 and will not let it be turned
    off; delete_bucket_encryption returns success and leaves AES256 in place. A
    bucket created here is encrypted whatever this flag says.

    `website` turns on static hosting, last of all, and is orthogonal to
    `secure_by_default`: hosting is a thing the bucket does, not a posture, and
    the two combine in a way worth being told about rather than prevented. A
    secure bucket that hosts serves nobody, because the endpoint is http-only
    and the CIS 2.1.1 policy applied above denies exactly that. enable_website
    says so in its message, which lands in `problems`.
    """
    existed = bucket_exists(s3, bucket_name)

    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "BucketAlreadyOwnedByYou":
            existed = True
        elif code == "BucketAlreadyExists":
            return False, (
                f"The name '{bucket_name}' is already taken by another AWS "
                "account. Bucket names are global, not per-account. Pick another."
            ), []
        else:
            return False, e.response["Error"]["Message"], []

    problems = []
    if existed:
        problems.append(
            "A bucket with this name already existed in your account, so nothing "
            "new was created. The settings below are that bucket's."
        )

    # Tag it so cleanup can find it later even if this run crashes.
    try:
        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={"TagSet": [
                {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                {"Key": "Environment", "Value": "test"},
            ]},
        )
    except ClientError as e:
        problems.append(
            "could not tag it, so the cleanup command will not find it "
            f"(needs s3:PutBucketTagging): {e.response['Error']['Message']}"
        )

    if secure_by_default:
        for harden in (block_public_access, enable_encryption,
                       enable_versioning, enforce_https):
            ok, msg = harden(s3, bucket_name)
            if not ok:
                problems.append(msg)
    elif existed:
        # Hardening a bucket that was already there is safe in the direction
        # this tool usually travels. Weakening one is not. The name was in use,
        # so whatever is inside belongs to somebody, and stripping the
        # protection off it is not what asking for a new weak bucket meant.
        problems.append(
            "Its public access blocks were left exactly as they were. Asking "
            "for a weak bucket does not weaken a bucket that already existed."
        )
    else:
        ok, msg = unblock_public_access(s3, bucket_name)
        if not ok:
            problems.append(msg)

    # Last, so the obstacles it reports describe the bucket as it ends up
    # rather than as it was halfway through being hardened.
    #
    # The message is appended whether or not the call succeeded, which is the
    # one place here a success lands in `problems`. It earns the space: "on,
    # and serving nobody, because the policy this same request installed
    # denies the only protocol the endpoint speaks" is precisely what somebody
    # who ticked both boxes needs to read, and saying nothing would let the
    # form imply a working site.
    if website:
        ok, msg = enable_website(s3, bucket_name)
        problems.append(msg)

    return True, bucket_name, problems


def list_buckets(s3, only_ours=False):
    """Returns buckets, optionally filtered to ones this tool created.

    S3 has no server-side tag filter, so the tag check is one extra call per
    bucket. Fine at capstone scale; worth caching if the account ever grows.

    Raises PermissionDenied rather than returning an empty list when the login
    cannot list or read tags. An empty list reads as "nothing to clean up",
    which is the most dangerous possible way to be wrong about test resources.
    """
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        _denied(e, "s3:ListAllMyBuckets")

    if not only_ours:
        return buckets

    ours = []
    for b in buckets:
        tags = get_bucket_tags(s3, b["Name"])
        if tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE:
            ours.append(b)
    return ours


def get_bucket_tags(s3, bucket_name):
    """Returns bucket tags as a flat dict, empty if untagged.

    A bucket in someone else's region or account will deny the tag read; that is
    expected while scanning a shared account and is not worth failing over, so
    denial here returns empty rather than raising.
    """
    try:
        resp = s3.get_bucket_tagging(Bucket=bucket_name)
        return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    except ClientError:
        return {}


def delete_bucket(s3, bucket_name, force=False):
    """Deletes a bucket. AWS refuses unless it is completely empty.

    With force, every object and every object version is removed first. That is
    genuinely destructive and has no undo, so the CLI asks before passing it.
    """
    if force:
        ok, msg = empty_bucket(s3, bucket_name)
        if not ok:
            return False, msg

    try:
        s3.delete_bucket(Bucket=bucket_name)
        return True, f"Deleted {bucket_name}"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "BucketNotEmpty":
            return False, (
                f"{bucket_name} still has files in it. Empty it first, or use "
                "the force option if you are certain."
            )
        return False, e.response["Error"]["Message"]


def empty_bucket(s3, bucket_name):
    """Removes all objects and all versions from a bucket.

    Versioned buckets keep delete markers and old versions that a plain object
    delete leaves behind, which is why this pages list_object_versions rather
    than list_objects_v2.
    """
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            targets = []
            for key in ("Versions", "DeleteMarkers"):
                for obj in page.get(key, []):
                    targets.append({"Key": obj["Key"], "VersionId": obj["VersionId"]})
            if targets:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": targets})
        return True, f"Emptied {bucket_name}"
    except ClientError as e:
        return False, e.response["Error"]["Message"]


def cleanup_all_managed_buckets(s3, force=False):
    """Purges every bucket this tool created."""
    results = []
    for b in list_buckets(s3, only_ours=True):
        ok, msg = delete_bucket(s3, b["Name"], force=force)
        results.append((b["Name"], ok, msg))
    return results


# ------------------------------------------------------------------ Settings Reads


def get_public_access_block(s3, bucket_name):
    """Returns the four public access switches, or None if never configured."""
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_CONFIGURED:
            return None
        _denied(e, "s3:GetBucketPublicAccessBlock")


def get_encryption(s3, bucket_name):
    """Returns {enabled, algorithm} for the bucket's default encryption."""
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
        if not rules:
            return {"enabled": False, "algorithm": None}
        default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
        return {
            "enabled": True,
            "algorithm": default.get("SSEAlgorithm"),
            "kms_key": default.get("KMSMasterKeyID"),
        }
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_CONFIGURED:
            return {"enabled": False, "algorithm": None}
        _denied(e, "s3:GetEncryptionConfiguration")


def get_versioning(s3, bucket_name):
    """Returns {enabled, mfa_delete}. An unversioned bucket returns no Status."""
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        return {
            "enabled": resp.get("Status") == "Enabled",
            "suspended": resp.get("Status") == "Suspended",
            "mfa_delete": resp.get("MFADelete") == "Enabled",
        }
    except ClientError as e:
        _denied(e, "s3:GetBucketVersioning")


def get_public_acl_grants(s3, bucket_name):
    """Returns any ACL grants handed to the public or to all AWS users."""
    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
    except ClientError as e:
        _denied(e, "s3:GetBucketAcl")

    grants = []
    for g in acl.get("Grants", []):
        uri = g.get("Grantee", {}).get("URI")
        if uri in public_uris:
            grants.append({"uri": uri, "permission": g.get("Permission", "access")})
    return grants


def policy_is_public(s3, bucket_name):
    """Returns whether the attached bucket policy grants public access.

    Prefers AWS's own get_bucket_policy_status. Falls back to reading the policy
    document directly, since moto does not implement the status call.
    """
    try:
        resp = s3.get_bucket_policy_status(Bucket=bucket_name)
        return resp["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in _NOT_CONFIGURED:
            return False
        if code in _DENIED:
            # Fall through to reading the policy directly. A login often has
            # GetBucketPolicy without GetBucketPolicyStatus.
            pass
    except Exception:
        pass

    try:
        doc = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_CONFIGURED:
            return False
        _denied(e, "s3:GetBucketPolicy")
    except (ValueError, KeyError):
        return False

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and "*" in str(principal.get("AWS", ""))
        ):
            return True
    return False


def get_bucket_policy_document(s3, bucket_name):
    """Returns the parsed bucket policy, or None if there is not one."""
    try:
        raw = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_CONFIGURED:
            return None
        _denied(e, "s3:GetBucketPolicy")
    except KeyError:
        return None

    try:
        return json.loads(raw)
    except ValueError:
        return None


def _denies_insecure_transport(statement):
    """Whether one policy statement refuses unencrypted connections.

    The shape CIS 2.1.1 asks for is a Deny conditioned on aws:SecureTransport
    being false. AWS accepts the condition value as either the string "false" or
    a JSON boolean, and condition keys are matched case-insensitively, so both
    are handled here rather than assuming the canonical form.
    """
    if statement.get("Effect") != "Deny":
        return False

    for operator, conditions in (statement.get("Condition") or {}).items():
        if operator.lower() not in ("bool", "boolifexists"):
            continue
        for key, value in (conditions or {}).items():
            if key.lower() != "aws:securetransport":
                continue
            values = value if isinstance(value, list) else [value]
            if any(str(v).lower() == "false" for v in values):
                return True

    return False


def policy_denies_http(s3, bucket_name):
    """Returns whether the bucket refuses plain HTTP. CIS 2.1.1."""
    document = get_bucket_policy_document(s3, bucket_name)
    if not document:
        return False

    return any(_denies_insecure_transport(s)
               for s in document.get("Statement", []))


def logging_enabled(s3, bucket_name):
    """Returns whether server access logging is turned on."""
    try:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" in resp
    except ClientError as e:
        _denied(e, "s3:GetBucketLogging")


def get_website(s3, bucket_name):
    """Returns {enabled, index, error} for static website hosting.

    Absent hosting is reported as a value rather than an exception, the same
    bargain every other reader in this section makes: AWS raises
    NoSuchWebsiteConfiguration for a bucket that simply never had a website,
    and "off" is an answer, not a failure.
    """
    try:
        resp = s3.get_bucket_website(Bucket=bucket_name)
        return {
            "enabled": True,
            "index": (resp.get("IndexDocument") or {}).get("Suffix"),
            "error": (resp.get("ErrorDocument") or {}).get("Key"),
        }
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_CONFIGURED:
            return {"enabled": False, "index": None, "error": None}
        _denied(e, "s3:GetBucketWebsite")


# Each setting the scanner expects, paired with the reader that fetches it.
# How many keys to ask for. One page, and the count is reported as "at least"
# past it: the question a finding needs answered is "is there anything in
# here, and roughly how much", and nobody's judgement changes between nine
# hundred objects and nine thousand. Paging a bucket to the end would make a
# scan take as long as the bucket is large.
OBJECT_SAMPLE = 1000

# How many keys travel back for a person to look at. A name is often the whole
# story - "payroll-2026.xlsx" in a world-readable bucket needs no further
# investigation - but a list of a thousand of them is not a finding, it is a
# file browser, and this tool is not one.
OBJECT_NAMES = 10


def list_objects(s3, bucket_name):
    """What is in the bucket: how many, how big, and the first few names.

    The scanner has never been able to see inside a bucket, which left every
    exposure finding unable to say how much was exposed. A world-readable
    empty bucket is a misconfiguration; a world-readable bucket with two
    hundred objects in it is an incident, and the two were reported in
    identical words.

    Deliberately a read. This module can create a bucket, empty one and delete
    one, and it cannot put an object into one - `s3:PutObject` is not in this
    tool's IAM policy at all. Combining "make this readable by the world" and
    "put a file in it" in one interface is the one thing scripts/make_vulnerable
    is careful never to do.
    """
    # Through _denied like every other reader here, and this was the one
    # that was not. A bucket whose name exists but belongs to another account
    # passes bucket_exists - a 403 counts as existing, deliberately, and that
    # is documented there - and then answers AccessDenied to each read. The
    # other eight raise PermissionDenied, which read_bucket_for_scanning
    # catches per setting and files under `unreadable`. This one let botocore's
    # ClientError out, past that `except PermissionDenied`, out of the route,
    # and into the browser as a 500. scanner/s3_rules already had the branch
    # for `unreadable["objects"]` and it could never be reached.
    try:
        found = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=OBJECT_SAMPLE)
    except ClientError as e:
        _denied(e, "s3:ListBucket")

    contents = found.get("Contents", [])

    return {
        "count": len(contents),
        # Whether the count is the whole story. IsTruncated says another page
        # exists, so the number above becomes a floor rather than a total.
        "at_least": bool(found.get("IsTruncated")),
        "bytes": sum(o.get("Size", 0) for o in contents),
        "names": [o["Key"] for o in contents[:OBJECT_NAMES]],
    }


def reachable_by_anyone(s3, bucket_name):
    """Whether this bucket is readable by people outside the account.

    Any of three things makes it so, and they fail independently: a policy
    that grants the world, an ACL that does, or the four public access blocks
    being off so that either could be added without resistance.

    A read that cannot be made counts as public. This is the one place in this
    module where an unanswered question is resolved *against* proceeding,
    because the caller is `put_objects` and the cost of being wrong is one
    direction only: a file nobody meant to publish, published.
    """
    reasons = []
    try:
        if policy_is_public(s3, bucket_name):
            reasons.append("its permissions policy grants the public")
    except PermissionDenied:
        reasons.append("its permissions policy could not be read")

    try:
        if get_public_acl_grants(s3, bucket_name):
            reasons.append("its access list grants a public group")
    except PermissionDenied:
        reasons.append("its access list could not be read")

    try:
        blocks = get_public_access_block(s3, bucket_name)
        # None means never configured, which is the *unprotected* state - and
        # `all({})` is True, so folding None into an empty dict read an
        # unconfigured bucket as fully blocked. Exactly backwards, and it
        # silently let an upload into the buckets least protected from one.
        if blocks is None:
            reasons.append("it has no public access block configuration at all")
        elif not all(blocks.values()):
            reasons.append("the four public access blocks are not all on")
    except PermissionDenied:
        reasons.append("its public access blocks could not be read")

    return reasons


def put_objects(s3, bucket_name, files, accept_risk=False):
    """Uploads objects. Refuses a bucket open to the world unless told plainly.

    `files` is [(key, bytes)].

    **The refusal is the default, and the default is the point.** Everything
    else in this tool is careful never to put data behind an exposure by
    accident: make_vulnerable weakens a bucket and deliberately stops, and
    publishes a snapshot only after proving the volume it came from was never
    written to. An upload button in the same interface that can turn Block
    Public Access off puts both halves one click apart, and the half that goes
    wrong is silent - a file lands somewhere it can be read and nothing says so.

    The bucket is therefore checked at the moment of writing, not at the moment
    the form was drawn. A bucket created secure ten minutes ago may not be
    secure now, and the only reading that matters is the one taken against the
    state the object would actually land in.

    `accept_risk` is what the person on the other end already said. It is the
    same flag the create route takes, set by the same button, and it is only
    ever true because somebody read a critical finding and chose to proceed.
    Refusing them a second time would not be a safety property; it would be the
    tool disbelieving an answer it asked for. What survives the bypass is the
    honesty: an upload into an open bucket reports that the files are readable
    by anyone, in the response, every time.

    The recommended order has not changed and the docs still give it. Upload
    first, open the bucket afterwards, and the scan then reports a public
    bucket with something in it - a sharper demonstration than an empty one,
    and the order that never leaves data somewhere by accident.
    """
    open_to = reachable_by_anyone(s3, bucket_name)
    if open_to and not accept_risk:
        return False, (
            f"Refused: {bucket_name} can be read by people outside this "
            f"account, because {', and '.join(open_to)}. This tool will not "
            "put a file into a bucket that is already open - close it first, "
            "or upload to it before opening it."
        ), []

    written = []
    for key, body in files:
        try:
            s3.put_object(Bucket=bucket_name, Key=key, Body=body)
            written.append(key)
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDenied":
                return False, (
                    "This login lacks s3:PutObject. See docs/iam-policy.json."
                ), written
            return False, e.response["Error"]["Message"], written

    # Uploaded anyway, and said so. The write succeeded, so this is not a
    # warning about what might happen - it is a description of where the files
    # now are, which is the one thing somebody who clicked past the refusal
    # still needs to be able to read back.
    if open_to:
        return True, (
            f"Uploaded {len(written)} to {bucket_name}. That bucket can be "
            f"read by people outside this account, because "
            f"{', and '.join(open_to)} - so "
            f"{'the file is' if len(written) == 1 else 'those files are'} now "
            "readable by anyone who finds the address."
        ), written

    return True, f"Uploaded {len(written)} to {bucket_name}.", written


def _principal_accounts(principal):
    """Every AWS account id named by one statement's Principal.

    A Principal arrives in four shapes - "*", {"AWS": "*"}, {"AWS": "<one>"}
    and {"AWS": [...]} - and each entry is either a bare twelve-digit account
    id or an ARN carrying the account in its fifth colon-separated field.

    Service principals ({"Service": "cloudtrail.amazonaws.com"}) name no
    account and are skipped: AWS reaching into a bucket on your own
    instruction is how logging, replication and half of everything else works,
    and reporting it would put a finding on every correctly wired account.
    """
    if isinstance(principal, str):
        entries = [principal]
    elif isinstance(principal, dict):
        aws = principal.get("AWS", [])
        entries = [aws] if isinstance(aws, str) else list(aws)
    else:
        return set()

    accounts = set()
    for entry in entries:
        if not isinstance(entry, str) or entry == "*":
            # "*" is public, which policy_is_public already reports as
            # critical. Naming it here as well would put one exposure in two
            # findings at two severities, and the public reading is the graver
            # of the two.
            continue
        if entry.startswith("arn:"):
            parts = entry.split(":")
            if len(parts) > 4 and parts[4]:
                accounts.add(parts[4])
        elif entry.isdigit():
            accounts.add(entry)

    return accounts


def _this_account(s3):
    """This account's id via STS, or None if it cannot be established."""
    try:
        sts = _client("sts", s3.meta.region_name)
        return sts.get_caller_identity()["Account"]
    except (ClientError, KeyError):
        return None


def policy_grants_other_accounts(s3, bucket_name):
    """Account ids other than this one that the bucket policy lets in.

    The other direction from every other rule here. They all ask what a bucket
    exposes to the world; this asks who has been let in deliberately. That is
    invisible in the console's public/not-public summary, survives every one of
    the four public access blocks, and is how data reaches a partner, a
    contractor, or an account somebody stopped working with two years ago.

    None means there is no policy at all, which is not the same as an empty
    list: no policy means nothing was ever granted, and an empty list means a
    policy was read and named nobody outside the account. The rule only speaks
    for the case it can actually see.
    """
    document = get_bucket_policy_document(s3, bucket_name)
    if document is None:
        return None

    mine = _this_account(s3)
    if mine is None:
        # Without knowing which account this is, every principal looks foreign
        # and the finding would fire on every correctly written policy. An
        # unanswerable question is recorded as unanswered.
        raise PermissionDenied("sts:GetCallerIdentity")

    others = set()
    for statement in document.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        others |= _principal_accounts(statement.get("Principal"))

    return sorted(others - {mine})


_READERS = {
    "public_access_block": get_public_access_block,
    "encryption": get_encryption,
    "versioning": get_versioning,
    "public_acl_grants": get_public_acl_grants,
    "policy_is_public": policy_is_public,
    "policy_denies_http": policy_denies_http,
    "logging_enabled": logging_enabled,
    "objects": list_objects,
    "other_accounts": policy_grants_other_accounts,
    "website": get_website,
}


def read_bucket_for_scanning(s3, bucket_name):
    """Retrieves bucket settings formatted for scanner processing.

    Mirrors read_group_for_scanning in the security group module: one call in,
    one flat dict out, shaped for a scanner that knows nothing about boto3.

    A setting the login cannot read is recorded in "unreadable" rather than
    guessed at or allowed to abort the scan. A partial audit that says which
    parts are missing beats no audit at all, and it beats a confident wrong
    answer by more.
    """
    # Asked once, before the seven reads below. A bucket that is not there
    # fails every one of them separately, and each failure looks like a
    # different problem; one check turns that into a plain "no such bucket".
    if not bucket_exists(s3, bucket_name):
        return None

    settings = {"bucket": bucket_name}
    unreadable = {}

    for name, reader in _READERS.items():
        try:
            settings[name] = reader(s3, bucket_name)
        except PermissionDenied as e:
            settings[name] = None
            unreadable[name] = e.permission

    settings["unreadable"] = unreadable
    return settings


# ----------------------------------------------------------------- Fix Operations


def block_public_access(s3, bucket_name):
    """Turns on all four public access blocks."""
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=ALL_BLOCKS_ON,
        )
        return True, "Public access is now blocked on all four settings."
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change bucket access settings."
        return False, e.response["Error"]["Message"]


def unblock_public_access(s3, bucket_name):
    """Turns all four public access blocks off. The inverse of block_public_access.

    A call of its own, because "not hardened" and "open" stopped meaning the
    same thing in April 2023, when AWS began applying all four blocks to every
    new bucket itself. Before that, creating a bucket and leaving it alone
    produced an open one; since then it produces a blocked one, and opening it
    is a write like any other.

    Skipping that write was the bug. Asking for a deliberately weak bucket
    returned a fully blocked one while the pre-create scan promised an exposure,
    so the warning and the resource disagreed and the warning was the wrong
    half. scripts/make_vulnerable.py had already met this and patched around it
    on its own, which left the demo path honest and the form not.

    Nothing is public when this returns. All four off means nothing stands
    between this bucket and a policy or ACL that would expose it, which is what
    CIS 2.1.4 reports and what the scan will now say about it.
    """
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=ALL_BLOCKS_OFF,
        )
        return True, ("Public access is unblocked on all four settings. Nothing "
                      "is public yet, and nothing is stopping it either.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change bucket access settings."
        return False, e.response["Error"]["Message"]


def enable_encryption(s3, bucket_name, kms_key_id=None):
    """Turns on default encryption, AES-256 unless a KMS key is given."""
    if kms_key_id:
        default = {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": kms_key_id}
        described = f"KMS key {kms_key_id}"
    else:
        default = {"SSEAlgorithm": "AES256"}
        described = "AES-256"

    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": default}]
            },
        )
        return True, f"Encryption on, using {described}. New files are encrypted."
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change encryption settings."
        return False, e.response["Error"]["Message"]


def enable_versioning(s3, bucket_name):
    """Turns on versioning so overwritten and deleted files stay recoverable."""
    try:
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        return True, "Versioning on. Overwritten and deleted files stay recoverable."
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change versioning settings."
        return False, e.response["Error"]["Message"]


DENY_HTTP_SID = "DenyInsecureTransport"


def enforce_https(s3, bucket_name):
    """Adds a policy statement refusing unencrypted connections. CIS 2.1.1.

    Reads the existing policy and appends to it. Writing a fresh policy would
    silently discard whatever access the bucket already grants, which could take
    an application offline; a security fix that causes an outage will be turned
    off and never turned back on.
    """
    try:
        document = get_bucket_policy_document(s3, bucket_name)
    except PermissionDenied as e:
        return False, (
            f"Could not read the current policy first ({e.permission}), and "
            "overwriting it blind could remove access this bucket depends on."
        )

    document = document or {"Version": "2012-10-17", "Statement": []}
    statements = document.setdefault("Statement", [])

    if any(_denies_insecure_transport(s) for s in statements):
        return True, "Unencrypted connections were already refused."

    statements[:] = [s for s in statements if s.get("Sid") != DENY_HTTP_SID]
    statements.append({
        "Sid": DENY_HTTP_SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*",
        ],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    })

    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(document))
        return True, ("Unencrypted connections are now refused. Access over "
                      "HTTPS is unaffected.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change bucket policies."
        return False, e.response["Error"]["Message"]


# ------------------------------------------------- Static website hosting


# AWS spells the website endpoint two ways, and the split is historical rather
# than systematic: the regions that existed before it standardised take a dash,
# everything opened since takes a dot. There is no rule to derive, only a list.
# Getting it wrong yields a hostname that does not resolve, which reads to
# somebody testing their site as "it is broken" rather than "that is the wrong
# address".
_WEBSITE_DASH_REGIONS = {
    "us-east-1", "us-west-1", "us-west-2", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "eu-west-1", "sa-east-1",
}


def website_endpoint(bucket_name, region="us-east-1"):
    """The URL a static site on this bucket would answer on.

    http, not https, and that is AWS's constraint rather than a shortcut taken
    here: the S3 website endpoint has no TLS form at all. Anything needing
    https in front of a bucket needs CloudFront, which is outside what this
    tool provisions.
    """
    separator = "-" if region in _WEBSITE_DASH_REGIONS else "."
    return f"http://{bucket_name}.s3-website{separator}{region}.amazonaws.com"


def website_obstacles(s3, bucket_name):
    """Reasons a configured website would not actually serve anything.

    Turning hosting on is one setting, and it is nowhere near sufficient: the
    endpoint exists immediately and returns 403 to every visitor until the
    bucket is also readable by the public. Reporting "hosting is on" without
    saying so would be the same class of mistake this module was just fixed
    for - a control that claims an outcome it did not produce.

    Each read is guarded separately. A login that cannot read one of these
    still gets a useful answer about the others, and an unreadable setting is
    left out rather than guessed at in either direction.
    """
    obstacles = []

    try:
        blocks = get_public_access_block(s3, bucket_name)
        if blocks and any(blocks.get(k) for k in
                          ("BlockPublicPolicy", "RestrictPublicBuckets")):
            obstacles.append(
                "public access is still blocked on this bucket, so the website "
                "endpoint answers every request with 403"
            )
    except PermissionDenied:
        pass

    try:
        if not policy_is_public(s3, bucket_name):
            obstacles.append(
                "no policy grants the public read access, so there is nothing "
                "the endpoint is allowed to hand out"
            )
    except PermissionDenied:
        pass

    try:
        if policy_denies_http(s3, bucket_name):
            obstacles.append(
                "this bucket's policy refuses unencrypted connections, and the "
                "S3 website endpoint is http-only - it has no https form, so "
                "that policy denies every request the website endpoint receives"
            )
    except PermissionDenied:
        pass

    return obstacles


def _joined(clauses):
    """Joins clauses that each already contain a comma.

    ", and ".join over three of those reads as a list of six things, because
    the reader cannot tell which commas separate items and which are internal.
    Semicolons carry the outer level so the clauses stay legible.
    """
    if len(clauses) == 1:
        return clauses[0]
    return "; ".join(clauses[:-1]) + "; and " + clauses[-1]


def enable_website(s3, bucket_name, index="index.html", error="error.html"):
    """Turns on static website hosting, and says what still stands in the way.

    Deliberately does not open the bucket. Hosting and exposure are two
    separate settings, AWS keeps them separate, and collapsing them into one
    button would mean a click labelled "serve a website" silently published
    every object in the bucket. The message names what is missing instead, so
    the second step stays a decision somebody makes on purpose.
    """
    try:
        s3.put_bucket_website(
            Bucket=bucket_name,
            WebsiteConfiguration={
                "IndexDocument": {"Suffix": index},
                "ErrorDocument": {"Key": error},
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change website settings."
        return False, e.response["Error"]["Message"]

    blocking = website_obstacles(s3, bucket_name)
    if blocking:
        return True, (
            f"Static website hosting is on, serving {index}. Nothing is public: "
            f"{_joined(blocking)}."
        )
    return True, (
        f"Static website hosting is on, serving {index}. This bucket is "
        "readable by the public, so the site is live to anyone with the address."
    )


def disable_website(s3, bucket_name):
    """Turns static website hosting off. Deletes nothing inside the bucket.

    AWS accepts this on a bucket that never had a website, so it needs no
    exists-check and is safe to call twice.
    """
    try:
        s3.delete_bucket_website(Bucket=bucket_name)
        return True, (
            "Static website hosting is off. The files are untouched and still "
            "reachable through the normal S3 API to anyone the policy allows."
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return False, "This login lacks permission to change website settings."
        return False, e.response["Error"]["Message"]


_FIX_ACTIONS = {
    "block_public_access": block_public_access,
    "enable_encryption": enable_encryption,
    "enable_versioning": enable_versioning,
    "enforce_https": enforce_https,
}


def apply_fix(s3, bucket_name, warning):
    """Executes remediation logic specified in warning objects.

    Same signature and same contract as aws.security_groups.apply_fix, so the
    FastAPI layer can dispatch on resource type and otherwise treat both alike.
    """
    fix = warning.get("fix")
    if not fix:
        return False, "Nothing to fix on this warning."

    handler = _FIX_ACTIONS.get(fix["action"])
    if not handler:
        return False, f"Unknown fix type: {fix['action']}"

    return handler(s3, bucket_name)
