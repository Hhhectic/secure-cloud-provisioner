"""Request and response shapes for the API.

FastAPI validates incoming JSON against these classes before any handler runs,
so a malformed request fails at the edge with a readable message instead of
raising a KeyError somewhere inside a boto3 call. They also generate the
interactive docs at /docs, which is the fastest way to try an endpoint without
writing a frontend first.
"""

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class FirewallRule(BaseModel):
    """One inbound rule as the form would submit it.

    No rule_id: a rule being proposed does not have one yet. AWS assigns it at
    creation, and that assigned ID is what later makes the rule fixable.
    """

    protocol: str = "tcp"
    from_port: Optional[int] = Field(default=None, ge=0, le=65535)
    to_port: Optional[int] = Field(default=None, ge=0, le=65535)
    source: str

    @field_validator("to_port")
    @classmethod
    def _to_port_not_below_from_port(cls, to_port, info):
        from_port = info.data.get("from_port")
        if to_port is not None and from_port is not None and to_port < from_port:
            raise ValueError("to_port cannot be lower than from_port")
        return to_port


class ResourceSpec(BaseModel):
    """Everything either resource type might need to be created.

    One model rather than two because the routes are generic. Fields not
    relevant to a given resource are ignored by that resource's adapter, and
    the adapter is the only place that knows which are which.
    """

    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None

    # Security group
    vpc_id: Optional[str] = None
    rules: Optional[list[FirewallRule]] = None

    # Bucket
    region: Optional[str] = None
    secure_by_default: bool = True

    # Key pair. The public half only: this API has no field for a private key
    # and adding one would defeat the point of importing rather than generating.
    public_key: Optional[str] = None

    # Instance. instance_type is validated against an allowlist in the AWS
    # layer rather than here, so the refusal lives next to the thing that
    # spends money.
    instance_type: Optional[str] = None
    key_name: Optional[str] = None
    security_group_ids: Optional[list[str]] = None
    subnet_id: Optional[str] = None
    assign_public_ip: bool = False

    # Network. with_nat_gateway exists so the refusal can explain itself
    # rather than the option appearing not to exist.
    cidr: Optional[str] = None
    with_nat_gateway: bool = False

    def as_dict(self):
        """Plain dict for the registry adapters, which predate these models."""
        spec = self.model_dump(exclude_none=True)
        if self.rules is not None:
            spec["rules"] = [r.model_dump() for r in self.rules]
        return spec


class FixRequest(BaseModel):
    """Asks the server to apply the fix it already identified for one rule.

    Deliberately carries no action. The server re-reads the resource, re-runs
    the scanner and looks up rule_id among its own findings. A tool that
    executed whatever action a caller posted would be a larger hole than any it
    reports.
    """

    rule_id: str = Field(min_length=1)
    new_cidr: Optional[str] = None


class DeleteOptions(BaseModel):
    force: bool = False


class Warning_(BaseModel):
    level: Literal["critical", "warning", "info"]
    message: str
    rule_id: Optional[str] = None
    resource_id: Optional[str] = None
    rule: Optional[Any] = None
    fix: Optional[dict] = None


class ScanResponse(BaseModel):
    resource_type: str
    resource_id: Optional[str] = None

    # What the resource is, as opposed to what is wrong with it. Deliberately
    # untyped: a bucket's settings and a network's subnets have nothing in
    # common, and forcing them into one model would mean a class with thirty
    # optional fields, most of them null in any given response. A caller
    # already knows which resource type it asked about.
    #
    # Absent when scanning settings that have not been created yet, since
    # there is nothing to describe.
    settings: Optional[Any] = None

    warnings: list[Warning_]
    counts: dict
    fixable_count: int


class CreateResponse(BaseModel):
    resource_type: str
    resource_id: str
    problems: list[str]
    settings: Optional[Any] = None
    warnings: list[Warning_]
    counts: dict


class ResourceSummary(BaseModel):
    id: str
    name: str
    vpc_id: Optional[str] = None
    worst_level: Optional[str] = None
    counts: Optional[dict] = None
    unreachable: Optional[str] = None


class ListResponse(BaseModel):
    resource_type: str
    resources: list[ResourceSummary]


class ActionResponse(BaseModel):
    ok: bool
    message: str


class DeletionPlanItem(BaseModel):
    kind: str
    id: str
    label: str
    created_by_this_tool: bool


class DeletionPlanResponse(BaseModel):
    """What a forced delete would destroy, before anything is destroyed.

    preview_available is separate from an empty items list, and the difference
    is the whole point. "Nothing else would be destroyed" and "this tool
    cannot tell you what would be destroyed" are opposite answers, and a
    frontend that rendered them the same way would put a reassuring empty
    table in front of the most destructive button it has.
    """

    resource_type: str
    resource_id: str
    preview_available: bool
    items: list[DeletionPlanItem]
    destroys: dict
    foreign_count: int
    confirm_with: str
    message: str


class CleanupResult(BaseModel):
    id: str
    ok: bool
    message: str


class CleanupResponse(BaseModel):
    resource_type: str
    results: list[CleanupResult]
