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


class AzureSecurityRule(BaseModel):
    """One Azure network security group rule as a form would submit it.

    Separate from FirewallRule because the two clouds genuinely describe a
    firewall rule differently - Azure names a direction and an access decision
    on every rule and writes ports as a string range, where AWS splits from
    and to into integers and infers direction from which list the rule is in.
    Forcing one model to carry both would mean a rule where half the fields are
    null whichever cloud you are using.
    """

    name: Optional[str] = None
    direction: Literal["Inbound", "Outbound"] = "Inbound"
    access: Literal["Allow", "Deny"] = "Allow"
    protocol: str = "*"
    source_address_prefix: str
    destination_port_range: str
    # Azure evaluates rules in priority order and reserves everything below
    # 100 for its own defaults.
    priority: Optional[int] = Field(default=None, ge=100, le=4096)


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

    # Azure. A separate rule list rather than reusing `rules`, because the
    # two clouds describe a firewall rule differently enough that one model
    # would be half-null whichever one you were using.
    azure_rules: Optional[list[AzureSecurityRule]] = None

    # Azure again. Every Azure resource lives in a resource group and there is
    # no AWS equivalent to borrow, so this is the one field a second cloud
    # actually cost the shared model. `region` carries the Azure location
    # rather than a second field beside it: they are the same idea under two
    # names, and two fields would be one more pair to keep in step.
    resource_group: Optional[str] = None

    # Azure virtual machine. These were missing entirely, and a field this
    # model does not declare is dropped in silence - pydantic ignores unknown
    # input - so `_az_vm_create` and `check_vm_spec` both read them as None no
    # matter what was submitted. Four of the eight things the machine form asks
    # for went nowhere.
    #
    # The pre-flight was the dangerous half. Ports come to check_vm_spec as the
    # rules it judges, so a form asking to open 22 to the entire internet with
    # a public address answered "0 critical" - the tool declaring safe the
    # exact configuration this resource type exists to warn about. The create
    # then ignored the ports as well, so the machine was built without the
    # access somebody asked for and nothing said so either way.
    #
    # allow_password_login is deliberately still absent. check_vm_spec reads it
    # with a default of False and az/vm.py never accepts a password at all, so
    # leaving it undeclared is what keeps "passwords are refused" true of the
    # HTTP surface too. Adding it here would make it settable.
    vm_size: Optional[str] = None
    open_ports: Optional[list[str]] = None
    allowed_source: Optional[str] = None
    encryption_at_host: bool = False

    # Alarm. threshold has no default and is not optional in practice: an
    # alarm without one is reported critical by the scanner and refused by the
    # create route, which is a better answer than a number this module
    # invented. notify defaults to on because an alarm that tells nobody is
    # the single most common way monitoring is useless, and defaulting to the
    # broken case to save a field would be choosing it for the user.
    namespace: Optional[str] = None
    metric_name: Optional[str] = None
    threshold: Optional[float] = None
    period: Optional[int] = Field(default=None, ge=60)
    evaluation_periods: int = Field(default=2, ge=1, le=100)
    treat_missing_data: Optional[
        Literal["missing", "ignore", "breaching", "notBreaching"]] = None
    dimensions: Optional[list[dict]] = None
    notify: bool = True
    email: Optional[str] = None

    def as_dict(self):
        """Plain dict for the registry adapters, which predate these models."""
        spec = self.model_dump(exclude_none=True)
        if self.rules is not None:
            spec["rules"] = [r.model_dump() for r in self.rules]
        if self.azure_rules is not None:
            spec["azure_rules"] = [r.model_dump() for r in self.azure_rules]
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

    # Who decided to live with this, and why. Declared here because a response
    # model silently drops anything it does not name: the scanner was marking
    # findings, summarize() was counting them, and the page received none of
    # it. An acknowledgement that does not reach the reader is a suppression,
    # which is exactly what scanner/acknowledged.py refuses to be.
    acknowledged: Optional[dict] = None


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


class BastionSpec(BaseModel):
    """What the blueprint needs, and pointedly not what it must never receive.

    public_keys carries the public half of two pairs the caller generated
    wherever the private halves are meant to live. There is no field for a
    private key here for the same reason ResourceSpec has none: the blueprint
    generates keys locally when driven from a terminal, because there the
    local machine is the user's own, and over HTTP it is not.
    """

    name: str = Field(min_length=1, max_length=64)
    region: Optional[str] = None
    with_instances: bool = True

    # {"bastion-key": "ssh-ed25519 AAAA…", "private-key": "ssh-ed25519 AAAA…"}
    public_keys: dict[str, str] = Field(default_factory=dict)


class BastionResponse(BaseModel):
    ok: bool
    name: str
    created: dict
    problems: list[str]
    log: list[str]
    connection: Optional[dict] = None
    instructions: list[str]
    teardown: list[str]


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
