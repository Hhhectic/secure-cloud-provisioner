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

from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api import models, registry
from aws.s3_buckets import PermissionDenied
from scanner.common import summarize, fixable, worst_level

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


def _scan(known, client, resource_id):
    return known.check(known.read(client, resource_id))


def _describe_and_scan(known, client, resource_id):
    """Returns (what it is, what is wrong with it) from one read.

    The settings were always being fetched and then discarded once the
    scanner had finished with them, which left the API able to say a bucket's
    versioning is off without being able to say what its versioning is. A
    caller rendering the resource needed a second round trip for data that
    had already been in memory.
    """
    settings = known.read(client, resource_id)
    return known.describe(settings), known.check(settings)


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
def create(resource_type: str, spec: models.ResourceSpec, region: str = "us-east-1"):
    """Creates the resource, then reports what is actually live.

    The warnings returned are from reading the created resource back, not from
    the submitted form. Those can differ: a bucket may fail to encrypt, a group
    may fail to take its rules. Reporting the request rather than the result
    would be reporting an intention.
    """
    known = _resource(resource_type)
    _must_be_writable(known)
    client = known.get_client(region)

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

    if force and confirm != resource_type:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This would delete every {known.label.lower()} tagged as "
                "created by this tool, and force means destroying what is "
                "inside them as well - for networks, that terminates running "
                f"machines. Repeat with confirm={resource_type} to go ahead."
            ),
        )

    results = [
        models.CleanupResult(id=rid, ok=ok, message=msg)
        for rid, ok, msg in known.cleanup(client, {"force": force})
    ]
    return models.CleanupResponse(resource_type=resource_type, results=results)
