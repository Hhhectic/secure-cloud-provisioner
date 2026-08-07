"""EC2 key pairs, imported rather than generated.

This module never calls create_key_pair, and that is the entire design.

CreateKeyPair returns the private key material in the API response body, once,
and AWS never shows it again. Any tool that calls it has to decide what to do
with a secret it now holds: write it to disk, put it in an HTTP response, or
drop it. All three are bad in different ways, and the first two put the key
somewhere it can be logged, cached, swapped to disk, or captured in a crash
dump. Getting that right is possible, but it has to keep being right forever,
in every code path anyone adds later.

ImportKeyPair takes only the public half. The private key is generated wherever
the user is — by ssh-keygen on their machine, or by the browser's WebCrypto in
the web interface — and never travels. There is no secret to protect here
because there is no secret here. That property is structural: it cannot be
broken by a careless change to this file, because nothing in this file ever
touches private key material.

The cost is that the tool cannot hand someone a key pair they did not already
have. That is a real reduction in convenience and it is worth it.
"""

import base64
import binascii
import re
import subprocess
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

# OpenSSH public key types AWS will accept on import. AWS supports RSA and
# ED25519; the ECDSA types are listed so a user offering one gets a clear
# message about what AWS supports rather than an opaque rejection.
SSH_KEY_TYPES = {
    "ssh-ed25519": "ED25519",
    "ssh-rsa": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
}

AWS_SUPPORTED_TYPES = {"ED25519", "RSA"}

_PUBLIC_KEY = re.compile(r"^(?P<type>[\w@.-]+)\s+(?P<body>[A-Za-z0-9+/=]+)(\s+.*)?$")

PRIVATE_KEY_MARKER = "PRIVATE KEY"


def get_client(region="us-east-1"):
    """Initializes and returns an EC2 client."""
    return boto3.client("ec2", region_name=region)


# ------------------------------------------------------------------ Validation


class InvalidPublicKey(ValueError):
    """The material offered is not a usable OpenSSH public key."""


def validate_public_key(material):
    """Checks that material is an OpenSSH public key, and returns its type.

    Three things are being caught, in order of how bad they are.

    A private key pasted by mistake. This is the one that matters: someone
    copies the wrong file, and without this check the secret goes into an HTTP
    request body, this process's memory, and quite possibly a log line. It is
    rejected before anything else happens and the key material is never echoed
    back in the error.

    A key type AWS cannot import, which otherwise fails deep inside boto3 with
    a message that does not explain itself.

    Malformed base64, which fails the same way.
    """
    if not material or not material.strip():
        raise InvalidPublicKey("No key was provided.")

    text = material.strip()

    if PRIVATE_KEY_MARKER in text:
        raise InvalidPublicKey(
            "That is a private key, not a public key. It has not been sent "
            "anywhere and it should not leave your machine. The public half is "
            "usually the same filename with .pub on the end. Since this key has "
            "now been on a clipboard, consider generating a fresh pair."
        )

    if "\n" in text:
        raise InvalidPublicKey(
            "A public key is a single line. This has more than one, which "
            "usually means it is a private key or the wrong file entirely."
        )

    match = _PUBLIC_KEY.match(text)
    if not match:
        raise InvalidPublicKey(
            "This does not look like an SSH public key. It should start with "
            "something like 'ssh-ed25519' or 'ssh-rsa', followed by a long "
            "block of letters and numbers."
        )

    key_type = SSH_KEY_TYPES.get(match.group("type"))
    if not key_type:
        raise InvalidPublicKey(
            f"'{match.group('type')}' is not an SSH key type. A public key "
            "starts with something like 'ssh-ed25519' or 'ssh-rsa', followed "
            "by a long block of letters and numbers."
        )

    if key_type not in AWS_SUPPORTED_TYPES:
        raise InvalidPublicKey(
            f"AWS does not accept {key_type} keys for EC2. Use ED25519, or RSA "
            "if you need compatibility with older tooling."
        )

    try:
        base64.b64decode(match.group("body"), validate=True)
    except (binascii.Error, ValueError):
        raise InvalidPublicKey(
            "The key body is not valid base64, so it has been damaged in "
            "transit or truncated when copied."
        )

    return key_type


# ---------------------------------------------------------------------- Create


def import_key_pair(ec2, key_name, public_key_material):
    """Registers a public key with AWS. Returns (ok, name_or_error, problems).

    The private half is never seen by this process, by AWS, or by anything in
    between. AWS stores the public key and a fingerprint; that is all it needs
    to let the matching private key log in.
    """
    problems = []

    try:
        key_type = validate_public_key(public_key_material)
    except InvalidPublicKey as e:
        return False, str(e), []

    if key_type == "RSA":
        problems.append(
            "This is an RSA key. ED25519 keys are shorter, faster and at least "
            "as strong; prefer one unless something in your setup needs RSA."
        )

    try:
        resp = ec2.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_material.strip().encode(),
            TagSpecifications=[{
                "ResourceType": "key-pair",
                "Tags": [
                    {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                    {"Key": "Environment", "Value": "test"},
                ],
            }],
        )
        return True, resp["KeyName"], problems
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidKeyPair.Duplicate":
            problems.append(
                "A key with this name already existed, so nothing was imported. "
                "If it is not the key you meant, delete it first: AWS will not "
                "overwrite one."
            )
            return True, key_name, problems
        if code == "UnauthorizedOperation":
            return False, "This login lacks permission to import key pairs.", []
        return False, e.response["Error"]["Message"], []


def generate_locally(key_name, directory="~/.ssh", key_type="ed25519"):
    """Runs ssh-keygen on this machine and returns the public half.

    For the command line, where there is no browser to generate a key. The
    private key is written by ssh-keygen directly to the user's own disk with
    the permissions ssh-keygen chooses; this function only ever reads back the
    .pub file. The secret does not pass through Python at any point.

    Returns (ok, public_key_or_error, private_key_path).
    """
    folder = Path(directory).expanduser()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)

    private_path = folder / key_name
    public_path = folder / f"{key_name}.pub"

    if private_path.exists():
        return False, (
            f"{private_path} already exists. Choose another name, or use the "
            "existing key's .pub file."
        ), None

    try:
        subprocess.run(
            ["ssh-keygen", "-t", key_type, "-f", str(private_path),
             "-N", "", "-C", f"{key_name} (secure-cloud-provisioner)"],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False, (
            "ssh-keygen is not installed. Generate a key another way and "
            "import the .pub file instead."
        ), None
    except subprocess.CalledProcessError as e:
        return False, f"ssh-keygen failed: {e.stderr.strip()}", None

    return True, public_path.read_text().strip(), str(private_path)


# ------------------------------------------------------------------------ Read


def list_key_pairs(ec2, only_ours=False):
    """Returns key pairs, optionally only ones this tool imported."""
    filters = []
    if only_ours:
        filters.append({"Name": f"tag:{MANAGED_TAG_KEY}",
                        "Values": [MANAGED_TAG_VALUE]})

    try:
        return ec2.describe_key_pairs(Filters=filters)["KeyPairs"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            return []
        raise


def key_pairs_in_use(ec2):
    """Returns the names of key pairs attached to an instance.

    Only instances carry a key pair, so unlike security groups there is no
    need to look at network interfaces. Terminated instances are excluded:
    they cannot be logged into, so the key is genuinely unused.
    """
    in_use = set()
    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate(Filters=[{
        "Name": "instance-state-name",
        "Values": ["pending", "running", "stopping", "stopped"],
    }]):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("KeyName"):
                    in_use.add(instance["KeyName"])

    return in_use


def read_key_pair_for_scanning(ec2, key_name):
    """Retrieves one key pair's settings formatted for scanner processing.

    Returns None when there is no such key. AWS reports that by raising rather
    than returning nothing, which turns "you asked about something that does
    not exist" into an unhandled error several layers up - a 500 where a 404
    belongs.
    """
    try:
        found = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidKeyPair.NotFound",
                                           "InvalidKeyPair.Malformed"):
            return None
        raise

    if not found:
        return None

    key = found[0]
    tags = {t["Key"]: t["Value"] for t in key.get("Tags", [])}

    return {
        "key_name": key["KeyName"],
        "key_pair_id": key.get("KeyPairId"),
        "key_type": (key.get("KeyType") or "").upper(),
        "fingerprint": key.get("KeyFingerprint"),
        "created": key.get("CreateTime"),
        "in_use": key["KeyName"] in key_pairs_in_use(ec2),
        "managed_by_us": tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE,
    }


# ---------------------------------------------------------------------- Delete


def delete_key_pair(ec2, key_name):
    """Removes a key pair from AWS.

    This deletes AWS's copy of the public key. It does not touch the private
    key on anyone's machine, and it does not lock anyone out of a running
    instance: the key was copied onto the instance at launch and stays there.
    """
    try:
        ec2.delete_key_pair(KeyName=key_name)
        return True, (
            f"Removed {key_name} from AWS. Instances already running with it "
            "are unaffected; new ones can no longer be launched with it."
        )
    except ClientError as e:
        return False, e.response["Error"]["Message"]


def cleanup_all_managed_key_pairs(ec2):
    """Removes every key pair this tool imported."""
    results = []
    for key in list_key_pairs(ec2, only_ours=True):
        ok, message = delete_key_pair(ec2, key["KeyName"])
        results.append((key["KeyName"], ok, message))
    return results


# ------------------------------------------------------------------------- Fix


def apply_fix(ec2, key_name, warning):
    """Key pair findings are not automatically fixable.

    Nothing here can be corrected in place. A key of the wrong type has to be
    replaced, which means generating a new pair, importing it, moving every
    instance that uses the old one, and only then deleting it. An unused key
    should be deleted, but only its owner knows whether it is finished with.

    Both are reported with an explanation instead. A fix button that quietly
    deleted an SSH key would be the most destructive thing in this tool.
    """
    return False, (
        "Key pair findings have to be acted on by hand. Replacing or deleting "
        "a key can lock people out of machines, so this tool will not do it "
        "for you."
    )
