"""HTTP layer over the provisioner.

Every route is generic across resource types. The path carries the type, the
registry supplies the functions, and nothing in this file knows the difference
between a firewall rule and a bucket setting. That is only possible because both
scanners return the same warning shape.

Run it with:

    uvicorn api.app:app --reload --host 127.0.0.1

and open http://127.0.0.1:8000/docs for an interactive page that will call every
endpoint below without a frontend existing yet.

Bound to localhost on purpose. This process holds credentials that can change
network access and delete storage; it has no authentication, because adding a
login screen to a tool that already trusts whoever is sitting at the machine
would be theatre. Do not put it on a public interface.
"""

import json
import queue
import re
import secrets
import threading
import time
from datetime import date
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (HTMLResponse, JSONResponse, RedirectResponse,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles

# Before api.registry imports the provider modules, and well before any route
# asks for a client. See environment.py.
import environment

environment.load()

from api import audit, models, registry
from aws.common import AwsNotConfigured
from aws import s3_buckets
from aws.s3_buckets import PermissionDenied
from az.common import AzureNotConfigured, AzureRefused
from blueprints import bastion
from scanner import acknowledged
from scanner.common import summarize, fixable, worst_level, CRITICAL

app = FastAPI(
    title="Secure Cloud Provisioner",
    description="Creates cloud resources, explains what is unsafe about them, "
                "and fixes what it can.",
    version="0.1.0",
)

# The frontend will be served from a different port during development, which
# counts as a different origin. Localhost only; never widen this to "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:3000", "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _is_local_origin(origin):
    """Whether a browser Origin header belongs to this machine."""
    return urlparse(origin).hostname in LOCAL_HOSTS


def _is_local_host_header(value):
    """Whether the Host a request asked for is this machine.

    Defends against DNS rebinding, where a page at http://evil.example is
    served by a domain whose record has been changed to 127.0.0.1. The
    browser then treats requests to that name as same-origin - no Origin
    header on a read, and an Origin the check above would have to accept for
    a write - but the Host header still says evil.example, because that is
    the name the page actually asked for.
    """
    host = (value or "").strip().lower()

    # An IPv6 literal is bracketed precisely because it is full of colons, so
    # the port cannot be split off before the brackets are dealt with.
    # Splitting first turns "[::1]:8000" into "[", which then matches nothing
    # and refuses a request from this machine.
    if host.startswith("["):
        host = host[1:host.index("]")] if "]" in host else host[1:]
    elif host.count(":") == 1:
        host = host.split(":")[0]

    return host in LOCAL_HOSTS


@app.middleware("http")
async def _refuse_cross_site_writes(request, call_next):
    """Rejects state-changing requests sent from another site's page.

    CORS does not do this. It stops a page *reading* the response, which is
    the wrong half for a tool whose endpoints are destructive: the request has
    already run by the time the answer is discarded.

    A POST with no custom header and no JSON content type is a "simple
    request" and is sent without a preflight, so any page in any tab could
    reach a server bound to localhost. POST /resources/network/cleanup needs
    no body at all and takes confirm=network in the query string, which is a
    resource type and therefore guessable - the most destructive endpoint here
    was the one most exposed.

    Requests with no Origin at all are allowed: that is curl, the CLI and the
    smoke test, none of which a hostile web page can impersonate. Browsers
    always send Origin on a write.
    """
    # Host is checked on every method, including reads. A rebound name makes
    # the browser treat this server as same-origin, so a read would be sent
    # with no Origin at all and the response handed to the attacking page.
    if not _is_local_host_header(request.headers.get("host")):
        return JSONResponse(
            status_code=403,
            content={"detail": (
                "This server answers only to localhost. The address used to "
                "reach it was something else, which is what a DNS rebinding "
                "attack looks like."
            )},
        )

    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin and not _is_local_origin(origin):
            audit.record(method=request.method, path=request.url.path,
                         outcome="refused", why="cross-site origin",
                         origin=origin)
            return JSONResponse(
                status_code=403,
                content={"detail": (
                    "This request came from a page on another site. The tool "
                    "holds credentials that can delete infrastructure and has "
                    "no login, so it only accepts changes from a page it "
                    "served itself."
                )},
            )

    response = await call_next(request)

    # Writes only. Scanning is the safe half, and recording it would bury the
    # handful of lines that matter.
    if request.method in audit.WRITE_METHODS:
        audit.record(
            method=request.method,
            path=request.url.path,
            query=str(request.url.query) or None,
            status=response.status_code,
            outcome=audit.describe(response.status_code),
        )

    return response


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


@app.exception_handler(PermissionDenied)
async def _permission_denied(request, exc):
    """Turns a missing IAM permission into a 403 that names it.

    The alternative is a 500 and a traceback in the server log, which tells the
    person using the tool nothing about what to do next.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=403,
        content={
            "detail": (
                f"The AWS login this tool uses is missing {exc.permission}. "
                "Add it to the tool's IAM policy (see docs/iam-setup.md) "
                "and try again."
            ),
            "missing_permission": exc.permission,
        },
    )


@app.exception_handler(AwsNotConfigured)
async def _aws_not_configured(request, exc):
    """The same answer as the Azure one, for the same reason.

    boto3 used to be a hard requirement of importing this module, so this state
    was unreachable: a deployment without it could not start at all. Now that
    `aws/` imports the SDK lazily, an installation with only the Azure
    dependencies serves the Azure half and answers here for the rest, which is
    what the Azure half has always done in the other direction.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=503,
        content={
            "detail": str(exc),
            "provider": "aws",
        },
    )


@app.exception_handler(AzureRefused)
async def _azure_refused(request, exc):
    """Turns "you may not look at that" into a 403 that says so.

    The mirror of the AWS handler above, and the last place the distinction
    CLAUDE.md records four times over had not been made. Azure answers "this
    resource group does not exist" and "you have no role on this resource
    group" with the same 403, so a reader that handled only 404 re-raised the
    refusal and the route turned it into a 500 with a traceback about an HTTP
    response - which tells somebody holding Contributor on two groups nothing
    about the fact that they are looking at a third.

    403 rather than 404: saying "there is nothing there" to somebody who
    simply cannot see it is the more misleading of the two answers, and the
    one that sends people to look for a resource they never lost.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=403,
        content={"detail": str(exc), "provider": "azure"},
    )


@app.exception_handler(AzureNotConfigured)
async def _azure_not_configured(request, exc):
    """Turns an absent Azure SDK or credential into a 503 that says so.

    503 rather than 500: nothing is broken. This deployment simply cannot
    reach Azure, which is an ordinary state - the two halves have separate
    dependencies and the AWS half is deliberately able to start without the
    Azure ones. A traceback about `azure.mgmt.network` would tell somebody
    running the AWS half nothing they could act on.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=503,
        content={
            "detail": str(exc),
            "provider": "azure",
        },
    )


def _resource(resource_type):
    known = registry.get(resource_type)
    if not known:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown resource type '{resource_type}'. "
                   f"Known types: {', '.join(sorted(registry.REGISTRY))}.",
        )
    return known


def _must_be_writable(known):
    """Refuses the destructive routes on a resource this tool only audits.

    405 rather than 404: the route exists, it is the resource type that does
    not accept it. Refusing here rather than letting the registry raise means
    the answer is a sentence about what this tool does, which is a better
    thing for a caller to receive than a stack trace.
    """
    if known.read_only:
        raise HTTPException(
            status_code=405,
            detail=(
                f"{known.label} is audited by this tool, not created or "
                "changed by it. Reading and scanning work; creating, deleting "
                "and cleaning up do not, because there is nothing here it "
                "would be safe for a tool to do on your behalf."
            ),
        )


def _spec_for_checking(known, spec, region):
    """The spec the pre-flight sees, carrying the region the request is for.

    A rule can only judge what it is handed. The region arrives as a query
    parameter rather than in the body, so `spec["region"]` was always None and
    `billing_wrong_region` could not fire from the page at all - a billing
    alarm built in us-west-2 pre-flighted as 0 critical and was created,
    whereupon it sat in INSUFFICIENT_DATA forever because AWS publishes
    spending figures only to us-east-1. That is the state the rule's own text
    calls "easy to read as nothing is wrong", and the guardrail against it was
    reachable only by a caller who put the region in the body by hand.

    AWS only, and deliberately. `region` on an Azure spec carries the
    *location*: `_az_vm_create` reads `spec.get("region") or
    spec.get("location")`, so injecting an AWS region here would quietly try to
    build somebody's storage account in "us-east-1".

    setdefault rather than assignment, so a caller who did state a region in
    the body still means it.
    """
    data = spec.as_dict()
    if known.provider == "aws":
        data.setdefault("region", region)
    return data


def _acknowledge(warnings, scanned=None):
    """Marks what somebody has already decided to live with.

    Applied here rather than inside the rules, so scanner/ stays a pure
    function of the settings it was given and remains testable without a file
    on disk. Nothing is removed: an acknowledged finding keeps its level and
    its place in the list, and summarize() counts it twice - once by severity
    and once as acknowledged.

    `scanned` names the resources this scan covered, so the audit only reports
    acknowledgements it is in a position to judge. Every caller here scans one
    resource; passing None would ask "does this entry match anything?" of a
    scan that looked at one thing.
    """
    entries, problem = acknowledged.load()
    acknowledged.apply(warnings, entries)
    return warnings + acknowledged.audit(warnings, entries, problem=problem,
                                         scanned=scanned)


def _scan(known, client, resource_id):
    return _acknowledge(known.check(known.read(client, resource_id)),
                        scanned={resource_id})


def _describe_and_scan(known, client, resource_id):
    """Returns (what it is, what is wrong with it) from one read.

    The settings were always being fetched and then discarded once the
    scanner had finished with them, which left the API able to say a bucket's
    versioning is off without being able to say what its versioning is. A
    caller rendering the resource needed a second round trip for data that
    had already been in memory.
    """
    settings = known.read(client, resource_id)
    return known.describe(settings), _acknowledge(known.check(settings),
                                                  scanned={resource_id})


# ------------------------------------------------------------------ Discovery


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/activity")
def recent_activity(limit: int = 20):
    """What this tool has changed, or refused to, most recently.

    Read-only, and the log holds no request bodies - method, path, outcome and
    a reason. It is exposed because the refusals are the half of this tool's
    behaviour that leaves no trace anywhere else: CloudTrail records that an
    API call happened and cannot record that somebody asked for a cascade,
    failed to type the ID back, and was stopped.
    """
    return {"activity": audit.read_recent(min(max(limit, 1), 100))}


@app.get("/resources")
def list_resource_types():
    """What this tool knows about. Lets the frontend build its own menu.

    read_only is advertised so a caller can leave out the buttons that would
    only be refused, rather than offering them and explaining afterwards.

    only_ours_label goes with it, because whether a list can be narrowed is
    not the same question as whether a resource can be changed. The page used
    to assume it was, which left the role list showing AWS's own service roles
    with no way to hide them.

    provider is here for the same reason: the page shows one cloud at a time,
    and the only other way to know which is which is to match on the "azure-"
    key prefix. That would be the frontend inferring a provider from a naming
    convention nothing enforces, and it would need editing again for a third
    cloud - the one thing adding Azure was supposed to prove unnecessary.
    """
    return {
        "resources": [
            {"key": r.key, "label": r.label, "id_label": r.id_label,
             "read_only": r.read_only,
             "only_ours_label": r.only_ours_label,
             "provider": r.provider,
             "short_label": r.short_label or r.label}
            for r in registry.REGISTRY.values()
        ],
    }


# ---------------------------------------------------------------------- Check


@app.get("/resources/{resource_type}/options")
def form_options(resource_type: str, region: str = "us-east-1"):
    """The choices a create form should offer, as {field: [{value, label}]}.

    Generic, like everything else here: the registry supplies the lists and
    this route does not know a port from a subnet. A type with nothing to
    offer answers with an empty object rather than a 404, so a caller can ask
    unconditionally and render plain text fields when the answer is empty.

    Some of these are live account lookups - which networks exist, which key
    pairs can be attached - so this costs AWS calls and is worth asking for
    once per form rather than per keystroke.
    """
    known = _resource(resource_type)
    if known.options is None:
        return {"resource_type": resource_type, "options": {}}

    client = known.get_client(region)
    return {"resource_type": resource_type,
            "options": known.options(client)}


@app.get("/resources/{resource_type}/cleanup-plan")
def cleanup_plan(resource_type: str, region: str = "us-east-1"):
    """What a cleanup would delete, and the token needed to go ahead.

    The same bargain as the deletion plan: nothing is destroyed without the
    inventory having been fetched first. Here it also carries the
    authorisation, because a caller who has read this response has proved
    something a hostile page cannot.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    found = known.list_all(client, True)

    return {
        "resource_type": resource_type,
        "items": found,
        "count": len(found),
        "confirm_with": _issue_cleanup_token(resource_type),
        "message": (
            f"{len(found)} {known.label.lower()}(s) tagged as created by this "
            "tool would be deleted, and force destroys what is inside them - "
            "for networks that terminates running machines. Repeat the "
            "cleanup with the confirm value above; it is good once and for "
            f"{_CLEANUP_TOKEN_SECONDS // 60} minutes."
        ),
    }


@app.post("/resources/{resource_type}/check", response_model=models.ScanResponse)
def check_spec(resource_type: str, spec: models.ResourceSpec,
               region: str = "us-east-1"):
    """Scans settings that have not been created yet.

    Separate from create on purpose: the form can call this on every keystroke
    and show warnings live, before anything exists in the account.

    Takes the region for the same reason create does: some findings are about
    where a thing would be built rather than how, and this route could not see
    that at all until now.
    """
    known = _resource(resource_type)
    warnings = known.check_spec(_spec_for_checking(known, spec, region))

    return models.ScanResponse(
        resource_type=resource_type,
        warnings=warnings,
        counts=summarize(warnings),
        fixable_count=len(fixable(warnings)),
    )


# --------------------------------------------------------------------- Create


@app.post("/resources/{resource_type}", response_model=models.CreateResponse,
          status_code=201)
def create(resource_type: str, spec: models.ResourceSpec, region: str = "us-east-1",
           accept_risk: bool = False):
    """Creates the resource, then reports what is actually live.

    The warnings returned are from reading the created resource back, not from
    the submitted form. Those can differ: a bucket may fail to encrypt, a group
    may fail to take its rules. Reporting the request rather than the result
    would be reporting an intention.

    The pre-flight scan runs first and a critical finding stops the create.
    /check has always been able to say a configuration is dangerous, but saying
    so and then building it anyway leaves the refusal to whoever read the
    response - which is nobody, when the caller is a script. accept_risk=true
    proceeds regardless, because there are legitimate reasons to build a thing
    this tool disapproves of and being unable to is worse than being warned.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    # One dict, used for both the pre-flight and the create.
    #
    # These were two separate calls: the check got _spec_for_checking, which
    # injects the region the request is for, and the create got a bare
    # spec.as_dict(). So the two judged different requests. `region` is sent by
    # the page only as a query parameter, never in the body, so it was absent
    # from every create: _bucket_create fell through to DEFAULT_REGION
    # "us-east-1" while the client was built for the region actually chosen,
    # and s3_buckets.create_bucket branches on that argument rather than on the
    # client - omitting CreateBucketConfiguration for us-east-1, which a
    # regional endpoint rejects. Creating a bucket anywhere but us-east-1 was
    # impossible from the page, and the refusal quoted raw AWS text naming
    # nothing anyone could act on.
    #
    # Azure is unaffected: _spec_for_checking injects only when the provider is
    # aws, because `region` on an Azure spec carries the location instead.
    data = _spec_for_checking(known, spec, region)

    blocking = [w for w in known.check_spec(data) if w["level"] == CRITICAL]
    if blocking and not accept_risk:
        raise HTTPException(
            status_code=400,
            detail={
                # Read by a person in the browser as well as by a script, so
                # it names neither the query parameter nor the HTTP status.
                # /docs advertises accept_risk; the page has a button.
                "message": (
                    f"Not created. The settings submitted have "
                    f"{len(blocking)} critical "
                    f"{'problem' if len(blocking) == 1 else 'problems'}, "
                    "listed below. Change them, or say explicitly that you "
                    "want it built this way."
                ),
                # The findings ride along for the same reason the deletion plan
                # rides along with a refused delete: a caller that is stopped
                # should learn what it nearly did without having to ask again.
                "warnings": blocking,
            },
        )

    ok, result, problems = known.create(client, data)
    if not ok:
        # problems travels with the refusal, and used to be discarded here.
        #
        # This project's stated position is that nothing rolls back and that a
        # partial failure reports exactly what exists. The adapters honour it -
        # every create returns what it built alongside the error - and this
        # line threw that half away, so a create that failed after building a
        # network, a security group and a card answered with one sentence about
        # the size and no mention of the three resources the caller now owned.
        #
        # A dict rather than a string because frontend/app.js already reads
        # detail.message when detail is not a string, so the page keeps working
        # and the list is there for anything that wants it.
        raise HTTPException(
            status_code=400,
            detail={"message": result, "problems": problems or []},
        )

    settings, warnings = _describe_and_scan(known, client, result)

    return models.CreateResponse(
        resource_type=resource_type,
        resource_id=result,
        problems=problems,
        settings=settings,
        warnings=warnings,
        counts=summarize(warnings),
    )


# ----------------------------------------------------------------------- Read


@app.get("/resources/{resource_type}", response_model=models.ListResponse)
def list_resources(resource_type: str, only_ours: bool = True,
                   region: str = "us-east-1", with_scan: bool = True):
    """Lists resources, each with a severity summary.

    with_scan costs one or more extra AWS calls per resource, which is why it
    can be turned off. A resource that cannot be read is reported with an
    unreachable note rather than dropped, because a resource you cannot audit
    is exactly the one worth knowing about.
    """
    known = _resource(resource_type)
    client = known.get_client(region)

    summaries = []
    for item in known.list_all(client, only_ours):
        summary = models.ResourceSummary(**item)
        if with_scan:
            try:
                warnings = _scan(known, client, item["id"])
                summary.counts = summarize(warnings)
                summary.worst_level = worst_level(warnings)
            except PermissionDenied as e:
                summary.unreachable = e.permission
        summaries.append(summary)

    return models.ListResponse(resource_type=resource_type, resources=summaries)


@app.get("/resources/{resource_type}/{resource_id}",
         response_model=models.ScanResponse)
def scan(resource_type: str, resource_id: str, region: str = "us-east-1"):
    """Scans one live resource, and reports what it is as well as what is wrong.

    One call rather than two, because the settings are read anyway to run the
    scanner over them. A page showing a machine needs its addresses and its
    findings together; fetching them separately would double the round trips
    and could show two different moments in time.
    """
    known = _resource(resource_type)
    client = known.get_client(region)
    settings, warnings = _describe_and_scan(known, client, resource_id)

    if settings is None:
        raise HTTPException(
            status_code=404,
            detail=f"No {known.label.lower()} called '{resource_id}' was found.",
        )

    return models.ScanResponse(
        resource_type=resource_type,
        resource_id=resource_id,
        settings=settings,
        warnings=warnings,
        counts=summarize(warnings),
        fixable_count=len(fixable(warnings)),
    )


# -------------------------------------------------------------- Bucket objects

# The most a single upload may carry. Not a technical limit - S3 takes five
# gigabytes in one PUT - but this route holds every byte in memory to hand to
# boto3, and a tool whose job is auditing configuration has no business being
# a file transfer service. Enough for the demo material somebody would put in
# a bucket to show what an exposure means.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _multipart_is_installed():
    """Whether fastapi can parse an uploaded file.

    fastapi needs python-multipart to accept one and does not depend on it, so
    declaring the route without it raises at *import* time - which would stop
    the whole application starting, both clouds and every other route, over a
    dependency belonging to one feature. That is precisely the failure
    aws/common.py and az/common.py exist to avoid for boto3 and the Azure SDK,
    and it would be a poor thing to reintroduce for a file upload.
    """
    try:
        # python_multipart, not multipart. The package renamed its import in
        # 0.0.12 and the old spelling still works while warning, so importing
        # it the old way is a deprecation notice printed on every test run.
        import python_multipart  # noqa: F401
        return True
    except ImportError:
        try:
            import multipart  # noqa: F401
            return True
        except ImportError:
            return False


if not _multipart_is_installed():
    # The feature is unavailable and says so, rather than the page failing to
    # start. Same shape as an absent SDK: one thing does not work, and the
    # message names what to install.
    @app.post("/resources/bucket/{bucket_name}/objects",
              response_model=models.ActionResponse)
    def upload_objects_unavailable(bucket_name: str):
        raise HTTPException(
            status_code=503,
            detail=("Uploading needs python-multipart, which is not installed. "
                    "pip install python-multipart, then restart. Everything "
                    "else on this page works without it."),
        )


if _multipart_is_installed():
    @app.post("/resources/bucket/{bucket_name}/objects",
              response_model=models.ActionResponse)
    async def upload_objects(bucket_name: str, files: list[UploadFile] = File(...),
                             region: str = "us-east-1", accept_risk: bool = False):
        """Puts files into a bucket, unless the bucket is open to the world.

        Its own route rather than a field on ResourceSpec, for three reasons. A
        file is multipart and the spec is JSON, so carrying one in the other means
        base64 and a third more bytes. It works on a bucket that already exists
        rather than only at creation. And it is a separate line in the audit log,
        which matters for the one action here that puts data somewhere.

        The refusal lives in `aws/s3_buckets.put_objects` and is checked against
        the bucket's state at the moment of writing - see the reasoning there.

        `accept_risk` carries the same decision the create route takes, because
        it is the same click. Attaching files to a create that was pushed
        through a critical finding used to succeed at the bucket and fail at
        the upload, which read as the tool half-working rather than as a second
        deliberate refusal. The upload still says, in its success message,
        exactly who can read what was just written.
        """
        known = _resource("bucket")
        # The region the caller is working in, like every other route here. It
        # was hardcoded to us-east-1, which was invisible only because a bucket
        # could not be created anywhere else; now that one can, uploading to it
        # would have looked for it in the wrong region and reported it missing.
        client = known.get_client(region)

        payload = []
        total = 0
        for f in files:
            body = await f.read()
            total += len(body)
            if total > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=(f"That is more than {MAX_UPLOAD_BYTES // (1024 * 1024)}MB "
                            "in one upload. This tool audits configuration; it is "
                            "not a way to move files."),
                )
            # basename only. A browser sends what the file was called and a key
            # containing "../" is a key containing "../" rather than a traversal,
            # but a bucket full of keys shaped like paths somebody did not choose
            # is its own small mess.
            payload.append((Path(f.filename or "unnamed").name, body))

        ok, message, written = s3_buckets.put_objects(
            client, bucket_name, payload, accept_risk=accept_risk)
        if not ok:
            raise HTTPException(
                status_code=400,
                detail={"message": message, "written": written},
            )

        return models.ActionResponse(ok=True, message=message)


@app.post("/resources/bucket/{bucket_name}/website",
          response_model=models.ActionResponse)
def set_website(bucket_name: str, request: models.WebsiteRequest,
                region: str = "us-east-1"):
    """Turns static website hosting on or off for one bucket.

    One route taking a direction rather than two routes, because the page
    draws one switch and a switch that posts to a different address depending
    on its current position has to know that position to act. This way the
    button sends where it wants to end up, and a double click lands there
    twice instead of toggling back.

    Not a fix action. The fix table is for findings the scanner raised, and
    hosting is neither a finding nor a remedy for one - it is a thing a bucket
    can do, that somebody may want on. Routing it through /fix would have meant
    inventing a rule that fires on every bucket without a website, which would
    be a scanner telling people off for not running a web server.

    Turning it on does not open the bucket; see aws/s3_buckets.enable_website
    for why, and read the returned message, which names whatever still stands
    between the endpoint and a visitor.
    """
    known = _resource("bucket")
    client = known.get_client(region)

    if not s3_buckets.bucket_exists(client, bucket_name):
        raise HTTPException(
            status_code=404,
            detail=f"No bucket called {bucket_name} in {region}.",
        )

    if request.enabled:
        ok, message = s3_buckets.enable_website(
            client, bucket_name,
            index=request.index_document,
            error=request.error_document,
        )
    else:
        ok, message = s3_buckets.disable_website(client, bucket_name)

    if not ok:
        raise HTTPException(status_code=400, detail=message)

    return models.ActionResponse(ok=True, message=message)


# ------------------------------------------------------------- Acknowledgement


@app.post("/acknowledgements", response_model=models.ActionResponse)
def acknowledge(request: models.AcknowledgementRequest,
                region: str = "us-east-1"):
    """Records that somebody has looked at a finding and decided to live with it.

    This endpoint did not exist until recently, and the argument against it is
    worth stating because it was a good one: the tool holds credentials and
    has no login, so a route that quietens a finding is a route an attacker
    would rather have than one that deletes something. Deletion is loud.

    Two things answer it. The middleware above refuses any write carrying
    another site's Origin, and any request whose Host is not this machine -
    which is the cross-site POST the objection described. And this API already
    exposes forced deletion of live infrastructure under exactly those guards,
    so trusting them for suppression is not a new position, it is the existing
    one applied consistently.

    What the CLI had and a browser cannot reproduce is provenance: `by` came
    from git config, so the name recorded was the one that would be on the
    commit. The guards below stand in for it. The strongest is that the
    finding must be real - the resource is re-scanned here, and a rule id the
    scan does not report is refused, so this cannot write an acknowledgement
    for something that was never found.
    """
    known = _resource(request.resource_type)
    client = known.get_client(region)

    # Re-read and re-scan rather than believing the request. Same reasoning as
    # POST /fix, which takes a rule_id and derives the action itself: what the
    # server writes down is a function of what the server can see.
    settings, warnings = _describe_and_scan(known, client, request.resource_id)
    if settings is None:
        raise HTTPException(
            status_code=404,
            detail=(f"No {known.label.lower()} called "
                    f"'{request.resource_id}' was found."),
        )

    today = date.today()
    until = request.until or date.fromordinal(
        today.toordinal() + acknowledged.DEFAULT_DAYS).isoformat()

    problem = acknowledged.check_entry(
        rule_id=request.rule_id,
        reason=request.reason,
        by=request.by,
        until=until,
        confirm=request.confirm,
        live_rule_ids={w.get("rule_id") for w in warnings if w.get("rule_id")},
        today=today,
    )
    if problem:
        audit.record(method="POST", path="/acknowledgements",
                     outcome="refused", why=problem,
                     rule_id=request.rule_id)
        raise HTTPException(status_code=400, detail=problem)

    entry = {
        "rule_id": request.rule_id,
        "reason": request.reason.strip(),
        "by": request.by.strip(),
        "on": today.isoformat(),
        "until": until,
    }
    where = acknowledged.record(entry)

    audit.record(method="POST", path="/acknowledgements", outcome="written",
                 rule_id=request.rule_id, by=entry["by"], until=until)

    return models.ActionResponse(
        ok=True,
        message=(
            f"Recorded. '{request.rule_id}' stays in every scan at the same "
            f"severity and is now marked as accepted by {entry['by']}, until "
            f"{until}. Nothing is hidden. Commit {where.name} so it applies to "
            "everybody else's scans as well."
        ),
    )


@app.delete("/acknowledgements/{rule_id:path}",
            response_model=models.ActionResponse)
def unacknowledge(rule_id: str, confirm: Optional[str] = None):
    """Takes an acknowledgement back, so the finding speaks at full volume again.

    The counterpart of the POST above, and deliberately a much smaller thing.
    Every guard on writing one is about *quietening* a finding: this service
    holds credentials and has no login, so a route that dims a warning is worth
    more to an attacker than one that deletes something, and the whole of
    `check_entry` exists to make that expensive. None of it applies in this
    direction. The worst a wrong call here can do is report something loudly
    that somebody had already decided about - which is the state the tool ships
    in, and the side it is safe to err towards.

    `confirm` is still asked for, and still has to repeat the id. Not as a
    barrier - the page fills it in from the finding the button belongs to, so
    nobody types it - but because it is the one thing that distinguishes a
    request meaning *this* acknowledgement from a request that has been
    cross-wired to the wrong one. The write path makes the same demand for the
    same reason.

    No re-scan here, unlike the POST. That check exists to stop an
    acknowledgement being written for a finding that does not exist; an
    acknowledgement that no longer matches anything is exactly the stale entry
    the audit reports and asks somebody to clear, so refusing to remove it
    because the resource is gone would trap the mess it is meant to clean up.
    """
    if confirm != rule_id:
        problem = ("To remove an acknowledgement, confirm has to repeat its "
                   f"rule id exactly. Expected '{rule_id}'.")
        audit.record(method="DELETE", path="/acknowledgements",
                     outcome="refused", why=problem, rule_id=rule_id)
        raise HTTPException(status_code=400, detail=problem)

    removed, where = acknowledged.remove(rule_id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=(f"Nothing acknowledged for '{rule_id}', so there is "
                    "nothing to take back."),
        )

    audit.record(method="DELETE", path="/acknowledgements", outcome="removed",
                 rule_id=rule_id, count=len(removed))

    # What it said, echoed back. The file no longer holds the reason, and this
    # response is the only place it still exists.
    was = removed[0]
    return models.ActionResponse(
        ok=True,
        message=(
            f"'{rule_id}' is no longer accepted and is reported normally again. "
            f"It had been accepted by {was.get('by', 'unknown')}"
            f"{' on ' + was['on'] if was.get('on') else ''}: "
            f"\"{was.get('reason', '')}\". "
            f"Commit {where.name} so it stops applying to everybody else's "
            "scans as well."
        ),
    )


# ------------------------------------------------------------------------ Fix


@app.post("/resources/{resource_type}/{resource_id}/fix",
          response_model=models.ActionResponse)
def fix(resource_type: str, resource_id: str, request: models.FixRequest,
        region: str = "us-east-1"):
    """Applies the fix this tool identified for one finding.

    The request names a rule; it does not name an action. The server re-reads
    the resource, re-runs the scanner and looks up rule_id among its own current
    findings, so the only actions it will ever perform are ones it just decided
    were warranted. Re-reading also means a rule fixed or removed since the page
    loaded is reported as gone rather than acted on twice.
    """
    known = _resource(resource_type)
    client = known.get_client(region)

    current = fixable(_scan(known, client, resource_id))
    match = next((w for w in current if w["rule_id"] == request.rule_id), None)

    if not match:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No fixable finding with id '{request.rule_id}' on "
                f"{resource_id} right now. It may already have been fixed, or "
                "removed by something else. Re-scan and try again."
            ),
        )

    options = {"new_cidr": request.new_cidr} if request.new_cidr else {}
    ok, message = known.fix(client, resource_id, match, options)
    if not ok:
        raise HTTPException(status_code=400, detail=message)

    return models.ActionResponse(ok=True, message=message)


# --------------------------------------------------------------------- Delete


def _deletion_plan(known, client, resource_type, resource_id):
    """Builds the cascade preview, or says plainly that there is not one."""
    plan = known.plan_deletion(client, resource_id) if known.plan_deletion else None

    # None covers both "this type has no preview" and "the planner could not
    # read the resource". Neither may fall through to an inventory, because an
    # empty one in front of a delete button reads as "nothing else would go".
    if plan is None:
        return models.DeletionPlanResponse(
            resource_type=resource_type,
            resource_id=resource_id,
            preview_available=False,
            items=[],
            destroys={},
            foreign_count=0,
            confirm_with=resource_id,
            message=(
                f"This tool cannot list what deleting a "
                f"{known.label.lower()} would take with it. That is not the "
                "same as saying it would take nothing: a forced delete can "
                "still destroy what is inside. Check before confirming."
            ),
        )

    # Two shapes, both meant. AWS returns a flat list of things a delete would
    # destroy and lets this function write the sentence from a count. The Azure
    # types return {"items", "destroys", "message"} instead, because for them a
    # count of destroyed things is the wrong summary and would be wrong in the
    # dangerous direction: deleting a security group destroys nothing at all
    # and un-protects everything behind it, and deleting a machine matters
    # mostly for the four resources it leaves behind, one of which keeps
    # charging. "Deleting this would destroy 2 things" is false about both.
    #
    # Before this, the dict shape reached `DeletionPlanItem(**item)` through a
    # loop that iterates a dict as its keys, so azure-nsg, azure-vnet and
    # azure-vm answered 500 on their deletion plan *and* on the delete itself.
    if isinstance(plan, dict):
        items = [
            models.DeletionPlanItem(
                kind=item.get("kind") or item.get("type") or "resource",
                id=str(item.get("id") or ""),
                label=item.get("label") or str(item.get("id") or ""),
                # Absent means unknown rather than foreign, and these lists are
                # not always inventories of things being destroyed - a group's
                # is what it protects. Claiming a stranger's subnet is ours
                # would be the safer-looking of the two wrong answers.
                created_by_this_tool=item.get("created_by_this_tool", True),
            )
            for item in plan.get("items") or []
        ]
        foreign = [item for item in items if not item.created_by_this_tool]
        said = plan.get("message") or ""
        return models.DeletionPlanResponse(
            resource_type=resource_type,
            resource_id=resource_id,
            preview_available=True,
            items=items,
            destroys=plan.get("destroys") or {},
            foreign_count=len(foreign),
            confirm_with=resource_id,
            message=(f"{said} " if said else "")
                    + f"To go ahead, repeat the delete with confirm={resource_id}.",
        )

    items = [models.DeletionPlanItem(**item) for item in plan]

    destroys = {}
    for item in items:
        destroys[item.kind] = destroys.get(item.kind, 0) + 1

    foreign = [item for item in items if not item.created_by_this_tool]
    servers = destroys.get("server", 0)

    # Assembled worst-first, the same order the CLI prints its warnings in.
    said = [f"Deleting this would destroy {len(items)} things."]
    if servers:
        said.append(
            f"{servers} running "
            f"{'machine' if servers == 1 else 'machines'} would be terminated "
            "and the disks destroyed with them. That cannot be undone."
        )
    if foreign:
        said.append(
            f"{len(foreign)} of them were not created by this tool, so "
            "something or someone else may be relying on them."
        )
    said.append(f"To go ahead, repeat the delete with confirm={resource_id}.")

    return models.DeletionPlanResponse(
        resource_type=resource_type,
        resource_id=resource_id,
        preview_available=True,
        items=items,
        destroys=destroys,
        foreign_count=len(foreign),
        confirm_with=resource_id,
        message=" ".join(said),
    )


@app.get("/resources/{resource_type}/{resource_id}/deletion-plan",
         response_model=models.DeletionPlanResponse)
def deletion_plan(resource_type: str, resource_id: str,
                  region: str = "us-east-1"):
    """Everything a forced delete would destroy, while it all still exists.

    The CLI has always printed this list and then demanded the network's ID be
    typed back. Over HTTP the same call was one query parameter and no
    inventory, which made the web path the dangerous one - and a delete button
    is a single click where typing an ID is not.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    if known.read(client, resource_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"No {known.label.lower()} with ID {resource_id}.",
        )

    return _deletion_plan(known, client, resource_type, resource_id)


def _delete_as_it_happens(known, client, resource_id, force):
    """Runs a delete on a thread and yields its progress as it arrives.

    A cascade spends four or five minutes inside one blocking boto3 sequence,
    so the progress cannot be yielded from the call itself - the callback and
    the generator want to be in charge at the same time. A queue is the seam:
    the worker pushes lines, this drains them, and the sentinel says the
    worker has finished.

    Every exception is caught and turned into a failed outcome rather than
    raised. Once a streaming response has begun the status code is already
    sent, so an exception escaping here would truncate the body and the page
    would see a stream that simply stopped - which is the failure this whole
    endpoint exists to remove.
    """
    lines = queue.Queue()
    outcome = {}

    def run():
        try:
            ok, message = known.delete(
                client, resource_id, {"force": force, "report": lines.put})
            outcome.update(ok=ok, message=message)
        except Exception as e:
            outcome.update(ok=False, message=f"{type(e).__name__}: {e}")
        finally:
            lines.put(None)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()

    while True:
        line = lines.get()
        if line is None:
            break
        yield json.dumps({"step": line}) + "\n"

    worker.join()
    yield json.dumps({"done": True, **outcome}) + "\n"


@app.delete("/resources/{resource_type}/{resource_id}",
            response_model=models.ActionResponse)
def delete(resource_type: str, resource_id: str, force: bool = False,
           confirm: Optional[str] = None, region: str = "us-east-1",
           stream: bool = False):
    """Deletes one resource. force cascades, and cascading needs confirming.

    confirm has to repeat the resource's own ID. That is the same demand the
    CLI makes, for the same reason: force=true on a network terminates every
    machine inside it, and a boolean flag is one character away from being set
    by accident, by a copied example, or by a UI that offers it as a checkbox.
    Echoing the ID cannot happen without the caller having looked at which
    resource this is.

    The refusal carries the whole deletion plan, so a caller learns what it
    was about to destroy at the moment it is stopped rather than having to go
    and ask.

    `stream=true` answers with newline-delimited JSON instead: one object per
    step as it happens, then a final one carrying the same ok and message the
    plain form returns. It is opt-in because everything already calling this -
    the CLI, the smoke test, every offline test - wants one answer, and
    because a streamed body cannot carry a status code that is decided
    partway through. The refusals above still happen before any of it, so a
    caller that forgot to confirm gets a 400 with the plan in it either way.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    if force and confirm != resource_id:
        plan = _deletion_plan(known, client, resource_type, resource_id)
        raise HTTPException(status_code=400, detail=plan.model_dump())

    if stream:
        return StreamingResponse(
            _delete_as_it_happens(known, client, resource_id, force),
            media_type="application/x-ndjson",
            # Nothing between here and the browser should hold this back
            # waiting for a complete body; the whole point is the partial one.
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    ok, message = known.delete(client, resource_id, {"force": force})
    if not ok:
        raise HTTPException(status_code=400, detail=message)

    return models.ActionResponse(ok=True, message=message)


# Tokens handed out by the cleanup preview, and spent by the cleanup itself.
#
# confirm used to be the resource type, which is the thing every caller
# already knows. That was the weakness that made the cross-site hole
# damaging: an attacker who could not read a single response could still
# guess "network". A token has to be fetched, and fetching means reading a
# response, which is precisely what a page on another site cannot do.
#
# In memory and single-process, which is the right size for a tool that binds
# to localhost. Each is good once and expires.
_CLEANUP_TOKENS = {}
_CLEANUP_TOKEN_SECONDS = 300


def _issue_cleanup_token(resource_type):
    now = time.monotonic()
    for token, (kind, expires) in list(_CLEANUP_TOKENS.items()):
        if expires < now:
            del _CLEANUP_TOKENS[token]

    token = secrets.token_urlsafe(16)
    _CLEANUP_TOKENS[token] = (resource_type, now + _CLEANUP_TOKEN_SECONDS)
    return token


def _spend_cleanup_token(resource_type, token):
    """True if this token was issued for this type and has not been used."""
    found = _CLEANUP_TOKENS.pop(token, None)
    if not found:
        return False
    kind, expires = found
    return kind == resource_type and expires >= time.monotonic()


@app.post("/resources/{resource_type}/cleanup",
          response_model=models.CleanupResponse)
def cleanup(resource_type: str, force: bool = False,
            confirm: Optional[str] = None, region: str = "us-east-1"):
    """Deletes everything this tool created, found by its tag.

    POST rather than DELETE because it is the most destructive thing here and
    should not be reachable by anything that wanders over the URL space.

    force needs confirm to repeat the resource type, for the same reason the
    single delete needs the resource's ID. This endpoint is bounded in a way
    that one is not - it only ever touches resources carrying this tool's tag,
    so it cannot reach a stranger's machine - but a forced network cleanup
    still terminates real machines, and leaving the loudest endpoint as the
    only unguarded one would be indefensible.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    if force and not _spend_cleanup_token(resource_type, confirm or ""):
        raise HTTPException(
            status_code=400,
            detail=(
                f"This would delete every {known.label.lower()} tagged as "
                "created by this tool, and force means destroying what is "
                "inside them as well - for networks, that terminates running "
                "machines. Fetch GET /resources/"
                f"{resource_type}/cleanup-plan first: it lists what would go "
                "and returns the confirm value, which is good once."
            ),
        )

    results = [
        models.CleanupResult(id=rid, ok=ok, message=msg)
        for rid, ok, msg in known.cleanup(client, {"force": force})
    ]
    return models.CleanupResponse(resource_type=resource_type, results=results)


# ------------------------------------------------------------------ Blueprints


@app.post("/blueprints/bastion", response_model=models.BastionResponse)
def build_bastion(spec: models.BastionSpec):
    """Builds a whole bastion architecture in one call.

    Not under /resources, because it is not one. Every other route here acts
    on a single thing the registry knows about; this composes six of them into
    an arrangement whose security lives in the relationships rather than in
    any one piece. Giving it a resource key would mean inventing a fake type
    with no read, no scan and no delete.

    The keys must be supplied. Called from a terminal the blueprint generates
    them with ssh-keygen, which writes the private halves to the machine
    running it - correct there, and exactly wrong here, where that machine is
    the server. Refusing rather than defaulting is the difference between an
    endpoint that is safe and one that is safe as long as nobody omits a
    field.

    This is slow. Two instances, a VPC, and the waits AWS needs between them;
    a minute or more is normal and the caller should expect to hold the
    connection open.
    """
    missing = [k for k in (bastion.BASTION_KEY, bastion.PRIVATE_KEY)
               if not spec.public_keys.get(k)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Public keys are required for: {', '.join(missing)}. Generate "
                "both pairs where the private halves should live - your own "
                "machine or your browser - and send only the public halves. "
                "This tool will not create a private key for you."
            ),
        )

    client = registry.VPC.get_client(spec.region or registry.DEFAULT_REGION)

    log = []
    try:
        ok, created, problems = bastion.build(
            client,
            spec.name,
            region=spec.region or registry.DEFAULT_REGION,
            report=log.append,
            with_instances=spec.with_instances,
            public_keys=spec.public_keys,
        )
    except bastion.BuildFailed as e:
        # Nothing rolls back. Report precisely what exists so it can be
        # removed deliberately rather than hunted for in the console.
        raise HTTPException(
            status_code=500,
            detail={"message": str(e), "created": e.created,
                    "teardown": bastion.teardown_instructions(e.created)},
        )

    details = bastion.connection_details(client, created) if ok else None

    return models.BastionResponse(
        ok=ok,
        name=spec.name,
        created=created,
        problems=problems,
        log=log,
        connection=details,
        # keys_were_downloaded is true for every caller of this route, not
        # only the page. POST /blueprints/bastion refuses to generate key
        # pairs at all - it takes public_keys and nothing else - so whoever
        # called it holds two private halves this server has never seen, and
        # over HTTP the overwhelmingly likely way they got them is the
        # browser generator this project recommends. The mv step is a no-op
        # for anybody who already filed them, and the alternative is what was
        # here before: paths that are wrong for the tool's own front door.
        instructions=bastion.connection_instructions(
            details, keys_were_downloaded=True) if ok else [],
        teardown=bastion.teardown_instructions(created),
        # The same steps as one file, because the four the instructions list
        # are the four a browser cannot perform: it cannot move a file, change
        # its mode, reach an ssh-agent or open a shell. Handing over a script
        # is the closest the tool gets to doing them, and it does it without
        # ever holding a private key - which a route that filed the keys
        # server-side could not claim.
        script=bastion.connect_script(details, name=spec.name) if ok else None,
        script_name=f"connect-{spec.name}.sh" if ok else None,
    )


# ------------------------------------------------------------------ The page


# Mounted last, because a mount at "/ui" would otherwise shadow nothing but
# still reorders route matching, and because the API is the product here - the
# page is one caller of it.
#
# Served from this process rather than a second dev server, so there is one
# thing to run and no CORS in the way. The CORS middleware above stays for
# anyone who does want to run a build tool on 5173 later.
#
# Guarded by is_dir so the backend still starts, and the tests still pass, in a
# checkout where the frontend is absent.
_PAGE = Path(__file__).resolve().parent.parent.parent / "frontend"


class _AlwaysRevalidated(StaticFiles):
    """Serves the page, and refuses to let a browser reuse it without asking.

    Without this the browser decides for itself how long a file stays fresh,
    and with no Cache-Control header it is allowed to guess. It guesses
    differently per file - so a page can load a *new* app.js against an *old*
    style.css, which is not a stale page but a broken one: markup the
    stylesheet has never heard of, rendering as unstyled fragments. That
    happened here. The counts arrived as new tally elements and the old
    stylesheet had no rule for them, so they stacked up as "2critical".

    It is the worst kind of stale, because "I refreshed and nothing changed"
    is indistinguishable from "the change did not work", and the obvious next
    move is to go looking for a bug in code that is already correct.

    `no-cache` is not `no-store`: the file is still cached, the browser simply
    has to ask whether it has changed. StaticFiles already sends an ETag and
    answers 304 when it has not, so the cost of this on a page served from
    localhost is one conditional request per file per load.

    A build step with hashed filenames is the other answer to this, and is the
    right one for something deployed. This page has no build step on purpose.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


_ASSET = re.compile(r'(href|src)="([^"?:]+\.(?:css|js))"')


def _stamped_page():
    """index.html with every local asset URL carrying its file's timestamp.

    The Cache-Control header added alongside this was necessary and was not
    sufficient, for a reason worth writing down because it wasted an evening:
    **a header only governs responses fetched after it exists.** A browser
    that had already stored style.css with no Cache-Control at all assigns it
    a heuristic freshness lifetime and then uses it *without asking* - so it
    never issues the request that would have carried the new header, and no
    number of refreshes changes that. The header fixes the next visitor and
    does nothing for the one who already has the file.

    What breaks a cache entry is a URL it is not keyed on. So each asset gets
    ?v=<mtime>, which changes exactly when the file does: edit style.css and
    every browser fetches it once, edit nothing and every browser keeps using
    what it has. No manual version to bump and forget.

    The page itself is served from here rather than by the mount so the
    rewrite has somewhere to happen, and is marked no-store because it is the
    one document that must never come from a cache - it is what carries the
    new URLs.
    """
    html = (_PAGE / "index.html").read_text()

    def stamp(match):
        attribute, name = match.group(1), match.group(2)
        beside = _PAGE / name
        version = int(beside.stat().st_mtime) if beside.is_file() else 0
        return f'{attribute}="{name}?v={version}"'

    return _ASSET.sub(stamp, html)


if _PAGE.is_dir():
    @app.get("/ui/", include_in_schema=False)
    def page():
        return HTMLResponse(
            _stamped_page(),
            headers={"Cache-Control": "no-store, must-revalidate"},
        )

    app.mount("/ui", _AlwaysRevalidated(directory=_PAGE, html=True), name="ui")
