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

import secrets
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api import audit, models, registry
from aws.s3_buckets import PermissionDenied
from az.common import AzureNotConfigured
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


def _acknowledge(warnings):
    """Marks what somebody has already decided to live with.

    Applied here rather than inside the rules, so scanner/ stays a pure
    function of the settings it was given and remains testable without a file
    on disk. Nothing is removed: an acknowledged finding keeps its level and
    its place in the list, and summarize() counts it twice - once by severity
    and once as acknowledged.
    """
    entries, problem = acknowledged.load()
    acknowledged.apply(warnings, entries)
    return warnings + acknowledged.audit(warnings, entries, problem=problem)


def _scan(known, client, resource_id):
    return _acknowledge(known.check(known.read(client, resource_id)))


def _describe_and_scan(known, client, resource_id):
    """Returns (what it is, what is wrong with it) from one read.

    The settings were always being fetched and then discarded once the
    scanner had finished with them, which left the API able to say a bucket's
    versioning is off without being able to say what its versioning is. A
    caller rendering the resource needed a second round trip for data that
    had already been in memory.
    """
    settings = known.read(client, resource_id)
    return known.describe(settings), _acknowledge(known.check(settings))


# ------------------------------------------------------------------ Discovery


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/resources")
def list_resource_types():
    """What this tool knows about. Lets the frontend build its own menu.

    read_only is advertised so a caller can leave out the buttons that would
    only be refused, rather than offering them and explaining afterwards.
    """
    return {
        "resources": [
            {"key": r.key, "label": r.label, "id_label": r.id_label,
             "read_only": r.read_only}
            for r in registry.REGISTRY.values()
        ]
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
def check_spec(resource_type: str, spec: models.ResourceSpec):
    """Scans settings that have not been created yet.

    Separate from create on purpose: the form can call this on every keystroke
    and show warnings live, before anything exists in the account.
    """
    known = _resource(resource_type)
    warnings = known.check_spec(spec.as_dict())

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

    blocking = [w for w in known.check_spec(spec.as_dict())
                if w["level"] == CRITICAL]
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

    ok, result, problems = known.create(client, spec.as_dict())
    if not ok:
        raise HTTPException(status_code=400, detail=result)

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
    if known.plan_deletion is None:
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

    items = [models.DeletionPlanItem(**item)
             for item in known.plan_deletion(client, resource_id)]

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


@app.delete("/resources/{resource_type}/{resource_id}",
            response_model=models.ActionResponse)
def delete(resource_type: str, resource_id: str, force: bool = False,
           confirm: Optional[str] = None, region: str = "us-east-1"):
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
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

    if force and confirm != resource_id:
        plan = _deletion_plan(known, client, resource_type, resource_id)
        raise HTTPException(status_code=400, detail=plan.model_dump())

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
        instructions=bastion.connection_instructions(details) if ok else [],
        teardown=bastion.teardown_instructions(created),
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

if _PAGE.is_dir():
    app.mount("/ui", StaticFiles(directory=_PAGE, html=True), name="ui")
