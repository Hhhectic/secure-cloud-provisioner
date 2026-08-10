# Secure Cloud Provisioner

Provisions AWS resources with safe defaults, explains what is unsafe about them
in plain language, and fixes what it can. Capstone project.

## Reviewing the AWS branch

`aws-provisioner-and-web-interface` fills the `backend/` scaffold this
repository already had: `backend/main.py`, `backend/scanner/rules.py` and
`backend/providers/aws.py` were empty placeholders. Nothing existing was
removed or rewritten — the Azure work, `main.py`, README and LICENSE are
untouched, and `.gitignore` keeps this repository's template in full with
private-key patterns appended.

Read it in this order, which is roughly hardest-to-undo first:

1. **`scanner/`** — the rules, and the only part with no cloud calls in it.
   Start at `common.py`; every rule returns that one shape and that is why
   the API has one set of routes rather than one per resource type.
2. **`api/registry.py`** — the seam. Adding a resource type is an `aws/`
   module, a `scanner/` module and one entry here. No route changes.
3. **`api/app.py`** — the routes, plus the middleware. Every destructive
   path is guarded; see *Destroying something needs it named twice*.
4. **`frontend/`** — plain HTML and two scripts, no build step.
5. **`docs/iam-setup.md`** — why the policy is three files, and how to stop
   using a long-lived access key.

**Two things the group should decide rather than inherit:**

- This repository scaffolded `backend/providers/aws.py`, one module per
  provider. The AWS work is arranged as `backend/aws/` with a module per
  resource type and `backend/scanner/` beside it, because the rules have to
  stay free of boto3 to be testable without an account. `providers/aws.py` is
  left empty and untouched. Which shape Azure adopts is a conversation.
- The Azure scanner and `scanner/` are solving the same problem twice. The
  warning contract in `scanner/common.py` was built to be provider-agnostic
  and nothing about it is AWS-specific.

**One operational hazard, worth agreeing on before a demo.** We share one AWS
account, and cleanup deletes by *tag*, not by author: `make_vulnerable.py
--clean`, the cleanup button and the smoke test's sweep will each destroy
resources a teammate created. `--region` is supported everywhere, so a region
each is free isolation.

## There are two applications in this repository

This matters before anything else, because nothing in the rest of this file
says it and the obvious assumption is wrong.

```
main.py                 app = FastAPI()   /api/v1/azure/scan, /api/v1/azure/deploy
backend/api/app.py      app = FastAPI()   /resources/..., /blueprints/..., /ui, /docs
```

Two `FastAPI()` instances, neither mounting the other. Two scanners
(`azure_scanner_engine.run_azure_security_scan` and `backend/scanner/`), two
warning formats, two ports. `frontend/` is served by the AWS app at `/ui` and
calls only its routes, so the page covers half the tool the README describes.

Both halves work. They have simply never been introduced.

**Check `group/main` before judging the Azure code.** The Azure files on this
branch are the ones the initial commit carried and are several commits behind;
the working version lives on `group/main` and differs in all five files. Read
against the stale copy, the Azure half looks broken — `azure_scanner` imports a
function name that does not exist, the engine imports another, `azure_crud`
provisions a resource group and a storage account as import-time side effects,
and a wide-open NSG rule written in lower case scores clean. Every one of those
is fixed on `group/main`, which imports cleanly, and which carries
`test_azure_scanner.py` — six tests, passing. Anyone reviewing the Azure work
from this branch alone will report bugs that were fixed weeks ago.

**The README is the scope, and it is one tool:** *"provisions AWS and Azure
resources through guided forms and flags unsecure configurations before
deployment."* Against that, the AWS half is complete and past its ticket — KAN-8
capped it at one storage type, one compute type and one network rule, and there
are now seven resource types. What is missing is not features. It is that a
demonstration currently means starting two servers and explaining that the page
only drives one of them.

**Two ways to join them, and they are not equally interesting.**

Mounting one app inside the other is an afternoon. `app.mount("/aws", ...)` or
the reverse, one process, one port, and the frontend can reach both. It solves
the demo and nothing else: there would still be two scanners disagreeing about
what a finding looks like. One process also means one dependency set, so the
Azure SDK becomes a hard requirement of starting the AWS half — today the two
halves can at least fail independently.

Making Azure a `ResourceType` in `api/registry.py` is the version worth doing.
`scanner/common.py` has claimed since the first commit that its warning shape is
provider-agnostic, and `api/app.py` has one set of routes on the strength of
that claim. Registering an Azure resource would be the first evidence either
statement is true, and "why is it built this way?" is the obvious question in a
viva. The cost is rewriting `azure_scanner_engine` to return the common warning
shape, and agreeing whether Azure lives in `backend/azure/` beside `backend/aws/`
or stays where it is.

The group should pick one deliberately. Drifting into the first because it is
Friday is a defensible choice; doing it without noticing the second existed is
not.

## Running things

The AWS half, which is what the rest of this file is about:

```bash
cd backend
source ../.venv/bin/activate

pytest -v                                   # offline, moto, no credentials
python main.py                              # the CLI
uvicorn api.app:app --reload --host 127.0.0.1   # API, /docs and the page at /ui
python scripts/smoke_test.py                # live AWS, free
python scripts/smoke_test.py --with-instances   # live, launches a t3.micro
python scripts/smoke_test.py --with-blueprint   # live, the whole bastion, two t3.micro
python scripts/smoke_test.py --with-alarm-email you@example.com  # live, sends one email
python scripts/make_vulnerable.py           # deliberately weak demo resources
python scripts/make_vulnerable.py --with-public-snapshot   # also publishes a blank snapshot
python scripts/make_vulnerable.py --clean   # remove everything tagged as ours
python scripts/cloudwatch_harness.py        # live, free tier, creates alarms
```

The alarm section of the smoke test runs on every pass — ten alarms are free
forever and it creates at most one, skipping itself if the account is already
near the limit. `--with-alarm-email` is separate because subscribing an address
sends a real confirmation email to a real person, and the state it produces
(`PendingConfirmation`, an alarm that reaches nobody) is the one thing moto
cannot show.

`cloudwatch_harness.py` came from a notebook and still runs top to bottom, so
importing it would create an SNS topic and two alarms as a side effect. It
refuses to be imported and says so. Everything it makes is inside the always-free
tier, and it deletes what it made at the end.

Everything runs from `backend/`. `pytest.ini` sets `pythonpath = .`, and
uvicorn resolves imports from the working directory. The page is served by the
same process at <http://127.0.0.1:8000/ui>, so there is no second server and no
CORS between them.

The frontend tests need Node, and the jsdom half additionally needs
`npm install` in `frontend/`. Both skip themselves when their tools are absent,
so a checkout without either still gets a green suite — CI installs both and
asserts they are not skipping, because a skip and a pass look the same in a
tick.

Two external scanners were used to benchmark this one, and both fight this
machine's Python 3.14. Neither belongs in `.venv`: Prowler pins `pydantic<2`
and `boto3 1.26`, which silently breaks `api/app.py`. `uv` fetches its own
CPython without root, and everything below lives outside the repository:

```bash
uv python install 3.12
uv venv --python 3.12 /tmp/prowler && VIRTUAL_ENV=/tmp/prowler uv pip install prowler
/tmp/prowler/bin/prowler aws --services ec2 s3 iam cloudwatch vpc
```

CloudGoat needs Terraform and an IAM identity that can write IAM, which this
tool's own policy denies. Use the separate `cloudgoat` AWS profile for
deploying and the default profile for scanning. `docs/benchmark.md` records
what both found, and the two hazards that cost an hour each.

The Azure half runs from the repository root, is a separate process, and needs
a different set of dependencies:

```bash
pip install -r requirements.txt          # on group/main: the Azure SDK
uvicorn main:app --reload --port 8001    # Azure scan and deploy
python -m pytest test_azure_scanner.py   # on group/main: six tests
```

`.venv` holds boto3 and fastapi, not `azure-identity` or the three
`azure-mgmt-*` packages, so that uvicorn line fails on a checkout set up for
the AWS half. `main.py` imports `azure_crud` at module scope, which pulls the
Azure SDK in before anything runs — so `/api/v1/azure/scan`, which needs
neither credentials nor the SDK, cannot start without them either. Worth
knowing before a demo: one `pip install` stands between the two halves and
running side by side.

It has no `/ui`, and shares nothing with `backend/` but the repository.
Nothing below this line applies to it.

## Layout

```
main.py                 the Azure app. Separate FastAPI instance, root of repo
azure_scanner*.py       the Azure scanner, separate from backend/scanner/
azure_crud.py           Azure provisioning. Functions on group/main; on this
                        branch it still runs at import and creates real things
security_messages.py    Azure's warning text
test_azure_scanner.py   on group/main only. Six tests, no cloud calls
requirements.txt        on group/main only. The Azure SDK, not boto3

backend/
  scanner/     pure rule logic, no boto3 anywhere, no cloud calls
  aws/         all boto3, one module per resource type (iam.py reads only)
  api/         FastAPI over a resource registry, generic across types
  blueprints/  compositions of several resources into a correct architecture
  scripts/     live smoke test and demo helpers, plus the CloudWatch harness
frontend/      the page: two plain scripts, no build step, no shipped deps
docs/          IAM policy (three files, see iam-setup.md), bastion walkthrough,
               benchmark.md: what Prowler finds that this does not
```

`backend/providers/aws.py` is the empty placeholder this repository scaffolded
before the AWS work started. It stayed empty; `backend/aws/` is where the code
went. Deleting it is a five-second job nobody has wanted to do unilaterally.

`scanner/` must never import from `aws/`. That separation is what lets the
rules be tested without an account, and what would make a second cloud
feasible rather than a rewrite.

## The decisions worth knowing

**Every scanner returns the same warning shape.** `scanner/common.py` defines
it. That contract is why `api/app.py` has one set of routes rather than one per
resource type. Adding a resource means writing an `aws/` module, a `scanner/`
module, and one entry in `api/registry.py` — no route changes.

**A reader returns None when the thing is not there.** AWS reports "no such
resource" by raising, not by returning nothing, so every reader catches its own
NotFound code and returns None; the routes turn that into a 404. Every scanner
also has to tolerate None — four of the five had that guard and the fifth did
not, which surfaced as an AttributeError three layers below the question.

**A scan reports the resource as well as its findings.** `ScanResponse.settings`
carries what the thing *is*; the settings were being read to run the scanner
over them and then discarded. `ResourceType.describe` exists because security
groups and instances wrap their read output for the scanner's benefit
(`{"rules", "usage"}`, `{"instance", "firewall"}`), and that wrapper is this
module's arrangement rather than a description of the resource.

**Some resources are audited, not provisioned.** `ResourceType.read_only` makes
`create`, `delete` and `cleanup` optional, and the routes return 405 with a
sentence about what the tool does instead. IAM posture and existing snapshots
are things to look at, not things to make; a `create` that always returned an
error would let `/docs` advertise an endpoint that can never work.

**The browser generates key pairs, and so does the blueprint's caller.**
`frontend/keygen.js` makes the pair with WebCrypto, writes the private half
straight to a download and submits only the public half — the same bargain
`ssh-keygen` gets from the CLI, moved to where the secret already is. A test
asserts that module contains no `fetch`, `XMLHttpRequest`, `WebSocket`,
`sendBeacon` or `api(` at all: it cannot reach the network, so it cannot leak
what it holds. `bastion.build` takes `public_keys` for the same reason —
`generate_locally` writes private halves to the machine running it, which from
a terminal is the user's and over HTTP is the server's, and
`POST /blueprints/bastion` refuses rather than defaulting when they are
missing. The OpenSSH byte layouts in `keygen.js` were verified by mirroring
them in Python and having `ssh-keygen -y` derive the same public key.

**Key pairs are import-only.** `create_key_pair` returns private key material
in the response body, so `aws/key_pairs.py` never calls it and the IAM policy
denies it outright. `ssh-keygen` generates locally, only the public half is
sent. `test_this_module_never_calls_create_key_pair` parses the AST to enforce
it. Do not add a private key field to any model.

**The demo publishes an exposure, never data.** `make_vulnerable.py` weakens a
bucket by turning Block Public Access off and deliberately stops there, so the
finding is real and nothing is readable. A snapshot has no such halfway state:
either every AWS account can restore it or none can, and the finding only
fires on the first. So the exposure is made genuine and the *data* is removed
instead — the snapshot comes from a 1 GiB volume created seconds earlier,
never attached, never written to. `_safe_to_publish` verifies all three of
those before the permission changes, because the failure it prevents is
publishing somebody's actual disk. It is behind `--with-public-snapshot`, asks
a second time, and `--clean` removes snapshots unconditionally regardless of
which flags made them.

**One finding is about money rather than exposure.** `_check_workload` in
`scanner/instance_rules.py` reads a machine's processor use and says whether it
is idle, comfortable, working hard or saturated — the second half of KAN-12,
ported from the CloudWatch harness with only the wording changed. It earns its
place because a machine nobody uses costs the same as one carrying the service,
every hour, until somebody notices, and on a small shared account that is a
likelier loss than most of what the rest of the file reports. Only saturation
is a warning; idleness is a note, because a standby is idle on purpose. No
readings is not zero readings: a machine that launched two minutes ago has
published nothing yet and a stopped one never will, so `read_cpu_usage` returns
None and the rule stays quiet rather than advising someone to switch off
something that may be busy. Verified against a real machine launched with
user-data pegging both cores: readings climbed 0% → 50% → 66.7% → 83.2% as
CloudWatch published, and the saturated band fired at the top. The same scan
reported the machine as having a public address and an unencrypted disk,
because that launch was raw boto3 rather than `launch_instance` — a reminder
that the two settings the tool always states are the two an ordinary
`run_instances` call gets wrong by omission.

**An alarm fails by being quiet, which is why it is scanned at all.**
Everything else here is dangerous when it is doing something; an alarm is
dangerous when it is doing nothing, and the two look identical in the console.
`scanner/alarm_rules.py` reports the three separate ways to be silent — no
destination, a destination nobody subscribed to, and a subscriber who never
clicked the confirmation link — because each is fixed somewhere different.
`aws/alarms.py` reads the SNS topic alongside the alarm for that reason: the
rules cannot judge whether an alarm can speak without knowing who is listening.
Two things are refusals rather than findings, both matching existing patterns
here: a billing alarm outside `us-east-1` cannot ever receive data, and the
eleventh alarm starts a monthly charge the way a NAT gateway does. Nothing in
this scanner carries a citation — CIS section 4 is metric filters over
CloudTrail, a different mechanism, and citing it would claim a check this does
not perform.

**A critical finding stops the create.** `POST /resources/{type}` runs
`check_spec` before it provisions and refuses on anything critical;
`accept_risk=true` proceeds anyway. `/check` could always say a configuration
was dangerous, but saying so and building it regardless leaves the decision to
whoever reads the response, which is nobody when the caller is a script. Only
critical blocks — if warnings did too, the flag would be needed every time and
would stop meaning anything. The refusal carries the findings, and the page
renders them before offering *Create it anyway*, so the way through is not
reachable without seeing the cost. This came from AbuRadid's `aws/deploy.py`
and is the one thing that branch had which this one did not.

**Guardrails are refusals, not warnings.** Instance types are an allowlist the
tool physically cannot exceed, mirrored as an IAM `Deny`. NAT gateways are
refused outright — about $32/month billed from creation to deletion regardless
of traffic, and nothing here needs one. A confirmation prompt does not survive a
typo; a refusal does.

**Placement is asked for, never assumed.** The network and subnet decide more
about a machine's exposure than any setting on it, and neither can be changed
after creation. The menus ask, and the choice narrows what comes next: only
groups in that network are offered, because a group cannot be attached across
one. Where a caller gives security groups but no subnet, `launch_instance`
takes the network from the groups rather than the account default — they are
the only statement of intent available, and the mismatch otherwise fails with
`InvalidParameterValue`, naming neither.

**Reading everything is a finding, not only changing everything.** CIS 1.15
asks who holds `*:*`, and an identity with `iam:List*` on `*` holds nothing of
the sort while being able to map every user, role and policy in the account.
That is the first thing done with a stolen credential and the last thing to
leave a trace, because it is all reads. `grants_account_wide_iam_read` reports
it separately from full admin rather than stretching 1.15 to cover it, and a
policy that names its reads individually is not flagged — that is somebody who
thought about it, and it is the shape of this tool's own audit policy. Found
by running CloudGoat against a real account; see `docs/benchmark.md`.

**A skipped check is a finding, not a silence.** Every IAM check runs
independently and a failure lands in `unreadable` rather than aborting the
scan, exactly as `s3_buckets` does per setting. `iam_rules` reports those
first, before anything else, because a partial scan that looks clean is the one
way this tool can actively mislead. Never let an unanswered question default to
a pass: `policy_is_attached_to_anyone` returns `None` rather than `False` when
the policy lookup fails, because `AWSSupportAccess` exists in every real
account and not finding it means the read broke, not that nobody holds it.

**CIS section 1 renumbered in v5.0.0.** v3.0.0's 1.3, "security questions", was
dropped and everything after it moved down by one — root access keys 1.4→1.3,
the support role 1.17→1.16, CloudShell 1.22→1.21. Two thirds of these IDs are
one away from a plausible wrong answer, and nothing a wrong one produces looks
broken. `test_section_one_uses_the_v5_numbering_not_the_v3_numbering` pins all
sixteen. Verified against AWS's published mapping of Security Hub controls to
CIS v5.0.0 and v3.0.0 requirements, which agrees at every point it covers.

**Uncited findings are deliberate.** `scanner/controls.py` holds every control
ID. A finding with no `control` is not an oversight — an exposed MySQL port is
critical and CIS 5.3 covers only administration ports, so stretching it would
be a fabricated citation. `scanner/snapshot_rules.py` carries no citation at
all: CIS has no control governing who may restore a snapshot, and the
recommendation usually quoted for it belongs to a different AWS standard than
either of the two cited here. CIS numbering shifts between benchmark versions;
the IDs here were read from the v5.0.0 PDF directly. Verify against the
document before bumping `CIS_VERSION`.

**Destroying something needs it named twice.** `force=true` means "also
destroy what is inside", and a boolean is one character from being set by a
copied example or an unread checkbox. So every forced delete requires
`confirm` to repeat the resource's own ID, and forced cleanup requires the
resource type — the same demand the CLI has always made by asking for a typed
ID. `GET /resources/{type}/{id}/deletion-plan` shows the inventory first, and
the refusal carries that same plan so a caller learns what it nearly did at
the moment it is stopped. `ResourceType.plan_deletion` is None for types with
no preview, which the route reports as *no preview* rather than as an empty
list: for a bucket, whose forced delete empties it first, "nothing else would
be destroyed" would be a lie told in front of the most destructive button
there is.

**An acknowledgement makes a finding quieter, never absent.** Intent is not
in the control plane: a bucket readable by the world looks identical whether
it is a leak or a personal website, and benchmarking against Prowler made that
concrete — both tools call a deliberately public CV site critical and both are
right. `scanner/acknowledged.py` takes the answer from the only place it
exists, which is a person, and writes it down. An acknowledged finding keeps
its level, its place in the list and its entry in the counts, and gains a
fourth tally of its own; the page dims it and says who accepted it and why. A
suppression that empties the screen is how people stop reading the screen.
There are no wildcards, entries expire, and the acknowledgements are
themselves audited — one that has lapsed or that matches nothing is reported.
Nothing in the tool writes the file: an endpoint that created acknowledgements
would be a remote "stop reporting this" API on a service holding credentials
with no login, and one cross-site POST from being the thing the middleware in
`api/app.py` exists to stop.

**Fixes are re-derived server-side.** `POST /fix` takes a `rule_id` and nothing
else. The server re-reads the resource, re-runs the scanner, and finds the
warning itself. Accepting an action from the caller would make the API a remote
execution endpoint for arbitrary AWS changes.

**Nothing rolls back.** Partial failures report exactly what exists. Silently
destroying half-built infrastructure is worse than leaving it and saying so,
especially when a piece might be a machine already doing something.

## Things reality taught us that moto could not

The offline suite passes against a model of the API. These were all found by
`scripts/smoke_test.py` against a real account, and each one is a case where
the code was correct and an assumption was not.

- **An absent setting is not a safe setting.** `assign_public_ip=False` was
  implemented as *not mentioning it*, so the subnet's `MapPublicIpOnLaunch`
  decided instead and every instance got a public address. Always state the
  value.
- **EC2 is eventually consistent.** `RunInstances` returns an ID
  `DescribeInstances` cannot see for a second or two. `launch_instance` waits
  for `instance_exists` so every caller is safe.
- **The `InstanceTerminated` waiter fails on the `pending` state.** Terminating
  a machine mid-launch makes it report terminal failure for something
  proceeding normally. `vpcs.wait_for_interfaces_to_clear` polls network
  interfaces instead, which is also what actually gates a subnet delete.
- **`ParamValidationError` is not a `ClientError`.** `modify_vpc_attribute`
  wants `EnableDnsSupport`; the AWS docs write `enableDnsSupport`. The wrong
  spelling raised an exception that walked straight past a handler written to
  make that call non-fatal.
- **AWS closed off the easy mistakes.** Since Jan 2023 every new bucket is
  encrypted, and since Apr 2023 every new bucket blocks public access. Two
  rules here cannot fire on anything created today. They still fire on older
  buckets and on ones someone has since weakened, which is why
  `scripts/make_vulnerable.py` exists.
- **Deleting a subnet frees its route table association, and AWS keeps
  reporting the association anyway.** Disassociating it then fails on an ID
  that no longer exists. The failure was not the stale ID but that one such
  error abandoned the rest of the step, so `vpcs` forgives "already gone" codes
  and collects failures rather than returning on the first.
- **A global service throws your region away.** IAM resolves any region to the
  pseudo-region `aws-global`, and both `meta.region_name` and
  `meta.config.region_name` then report that instead of what was asked for.
  Access Analyzer and STS are not global and have no endpoint in a
  pseudo-region, so building either from the IAM client's region fails to
  resolve at all. `iam.get_client` remembers the caller's choice on the client;
  `client_region` reads it back.
- **moto's credential report has no root row.** Real AWS includes a
  `<root_account>` row, which is the only place most of what CIS asks about
  root can be read. Nothing offline exercises those findings, so root MFA and
  root access keys come from `GetAccountSummary` — a direct statement of
  current state rather than a snapshot up to four hours old, and the only
  source in an account whose report has never been generated.
- **moto answers `GetCredentialReport` immediately.** AWS starts a job and
  raises `ReportInProgress` until it finishes, so the polling this needs never
  runs against the fake. `_ReportStub` in `test_iam.py` models the raising
  version, with an injected clock so the timeout is exercised without spending
  real seconds.
- **`GetMetricStatistics` refuses more than 1440 data points, as a
  `ClientError`.** `read_cpu_usage` turns a `ClientError` into "no readings",
  so a window wider than five days at five-minute sampling reported a busy
  machine as unmeasured rather than failing. `period_for_window` widens the
  sampling period to stay under the limit instead. moto accepts any
  combination of period and window, so nothing offline could have shown this;
  it surfaced from asking a real account for a fortnight of history.
- **moto confirms an email subscription instantly; AWS does not.** A real
  email subscription comes back as the literal string `PendingConfirmation`
  until somebody opens the message and clicks, and delivers nothing until then.
  moto hands back a real subscription ARN immediately, so every subscriber it
  reports is confirmed and the finding for an alarm nobody will ever hear
  cannot fire against the fake. `_PendingSubscription` in `test_alarms.py`
  models AWS.
- **moto implements neither `EnableAlarmActions` nor `DisableAlarmActions`,**
  though it honours `ActionsEnabled` on `PutMetricAlarm`. The tempting fix is
  to flip the flag by rewriting the whole alarm, which moto would accept — and
  which is worse, because `PutMetricAlarm` replaces an alarm entirely and every
  field not resent reverts to a default. The one-purpose call stays, the
  offline test asserts the call rather than its effect, and the smoke test
  confirms against a real account that both calls exist and that the fix lands.
- **A new alarm starts in `INSUFFICIENT_DATA`, and moto says `OK`.** That is
  the same state a permanently dead alarm sits in — a billing alarm in the
  wrong region never leaves it — so an offline test asserting the state would
  have encoded the one answer that makes the two indistinguishable. The smoke
  test prints the state rather than asserting it, because a real alarm with
  data legitimately reaches `OK` within minutes.
- **moto sometimes passes the broken version.** It does not enforce the
  cross-VPC rejection that group-derived placement works around, so the old
  code — reaching for the account default while holding a group from elsewhere
  — succeeds against the fake and fails against AWS. It also gives its default
  VPC no internet route, and permits deleting a VPC with a gateway attached.
  Assertions about *how AWS behaves* belong in the smoke test or in a stub that
  models AWS explicitly; the offline suite is for *does this logic do what I
  meant*.
- **moto ignores the tag filter on `DescribeTags`, which hides the one thing
  `not_ours` exists to show.** It answers with every tag it holds, so any
  resource carrying any tag at all — a machine somebody merely gave a `Name` —
  comes back looking like something this tool created, and the `!` marking a
  stranger's machine in a cascade never appears. Real AWS honours the filter;
  verified against an account, where filtering on a value nothing carries
  returns empty. The existing coverage missed it because its stranger had no
  tags and so was absent either way. `_TagsFilteredLikeAws` in `test_vpcs.py`
  models AWS's filtering; without it the assertion passes for the wrong
  reason.
- **moto ignores the two filters the snapshot audit is built on.** The plan
  for `aws/snapshots.py` was one `describe_snapshots` call with
  `RestorableByUserIds=['all']`. moto implements neither that filter nor
  `OwnerIds`, and answers both with every snapshot it holds — which is about
  twelve hundred, because it seeds the public AMI snapshots belonging to
  Amazon, Canonical and Red Hat. Trusting the sweep would report a clean
  account's entire snapshot list as world-readable, and an offline test would
  have agreed. So ownership is checked in `list_snapshots` rather than asked
  for, and `publicly_restorable` confirms each candidate with
  `describe_snapshot_attribute` instead of believing the filter ran. Both are
  right against AWS *and* against the fake.
- **"No such snapshot" has three error codes and moto knows one.** A
  well-formed ID that does not exist is `InvalidSnapshot.NotFound`, a
  wrong-length one is `InvalidSnapshotID.Malformed`, and something that is not
  an ID at all is `InvalidParameterValue`. moto answers the first to all
  three. Handling only what the fake returns turns two thirds of the bad-ID
  cases into a 500 where a 404 belongs, against real accounts only. The smoke
  test asserts both of the codes moto cannot produce.
- **A correct policy can still be unattachable.** All of an IAM user's inline
  policies together may not exceed 2,048 non-whitespace characters; the full
  permission set was 2,282. It fails at paste time, and the obvious way to make
  it fit is to drop a statement — which is how the account this was developed
  against lost the entire IAM audit block and reported nine "could not check"
  notes that read like an account with nothing to say. The audit reads now live
  in a separate customer managed policy (`docs/iam-policy-account-audit.json`,
  6,144-character limit, does not touch the inline budget). Every `Deny` stayed
  inline: a guardrail that detaches separately from what it guards is not a
  guardrail.

Run the smoke test before believing anything works. It drives the registry
and `aws/` directly, and since the web page arrived it drives the HTTP routes
and, behind `--with-blueprint`, the whole bastion architecture. It executes no
JavaScript at all; the page is covered separately by the two Node suites in
`frontend/`, described under *Not done*.

## Style

Comments explain *why*, not what. Test names are sentences describing the
behaviour being protected. Warning messages are aimed at someone who does not
know the jargon: acronyms and IP addresses are jargon, ordinary words are not.
Severity means something — if everything is critical, nothing is.

## Not done

- **The frontend's untested half is its rendering, not its logic.**
  `frontend/` is plain HTML and JS served at `/ui`, with no build step and
  nothing shipped but two script tags. It is tested by Node rather than by
  pytest, which is why nothing in the smoke test touches it.

  `keygen.test.mjs` runs the real generator and has `ssh-keygen` derive the
  public half from the private file it produced, for both the Ed25519 path and
  the forced RSA fallback. That is possible because WebCrypto, `btoa`, `atob`
  and `TextEncoder` are globals in Node and are the only browser APIs that
  module touches, so it runs there unmodified — the byte layouts were
  previously checked by writing the same encoder a second time in Python,
  which proves the algorithm and not the file a browser loads.

  `app.test.mjs` loads `index.html`, `keygen.js` and `app.js` into jsdom and
  drives them against a stub API, replacing only `fetch`. It is the one place
  the path from a chosen menu value to a request body can be checked at all,
  and a rule that is not the one somebody picked is the failure this whole
  project exists to prevent. jsdom is a devDependency; the page itself has
  none.

  What remains uncovered is whether any of it *looks* right — layout, the
  modal, whether a button is reachable — and that is still only ever found by
  a person opening the page.
- **Benchmarked against Prowler and CloudGoat.** `docs/benchmark.md` has both
  and is the first thing to read before adding a rule; it records what was
  measured rather than what was assumed.

  Prowler agrees on eight findings and covers four this tool does not: a
  bucket policy granting another account access, password expiry, per-user
  hardware MFA, and resources spread across regions. Two apparent gaps were
  not gaps, and the reasoning is written down so nobody re-files them.

  CloudGoat is the other direction — deliberately broken infrastructure, 13 of
  29 scenarios run. Of those 13 it named the planted vulnerability in 3, named
  part of the chain in 2, and reported something real that was not the point in
  8. Two of the 8 are correct silence on services this tool does not scan. The
  rest have one cause, which is the next item below: every CloudGoat scenario
  is a chain of role to something, and this sees the first link only.

  Do not quote the four CIS 5.7 hits as a result on their own. The metadata
  service fired in four scenarios, but it is the actual attack path in two
  (`ec2_ssrf`, `cloud_breach_s3`) and merely true in the others. Enabling
  conditions are what this tool is reliably good at; escalation paths are what
  CloudGoat is built to teach, and that is the half it misses.

- **Nothing reports what an attached role can reach.** The largest remaining
  gap, and both benchmarks found it from different angles. This tool says an
  instance profile is attached and never what it grants, so on every CloudGoat
  privilege-escalation chain it sees the first link and none of the rest.
  Prowler's `s3_bucket_cross_account_access` is the same shape. Closing it
  means reading role policies and saying what they reach, which is a new
  `scanner/` module rather than a rule.

- **The alarm scanner has no external benchmark.** `detection_evasion` is the
  only CloudGoat scenario creating CloudWatch alarms and CloudTrail, and this
  tool reported nothing about alarms on it, because `aws/alarms.py` only
  enumerates alarms carrying its own tag. The newest rule set is the one least
  tested against anything somebody else wrote.

- **The snapshot audit covers one region.** Snapshots are regional and
  `list_snapshots` sees only the client's region, the same limit as the Access
  Analyzer check below. An account passing this check has been shown to pass
  it in one place.
- **The least-privilege policy currently bounds nothing.** `EC2_Dude` also
  holds `AmazonEC2FullAccess`, `AmazonS3FullAccess` and others, so every
  narrow `Allow` in `docs/iam-policy.json` is redundant and the separation of
  `iam-policy-demo.json` provides no actual isolation — the demo's EBS writes
  succeed whether or not it is attached, which was discovered by running the
  demo expecting a refusal and getting a published snapshot instead. The
  `Deny` statements still hold, since an explicit deny always wins. Detaching
  the FullAccess policies would make the documented policy the real one and
  make "this runs on 1,797 characters of permissions" a claim the smoke test
  proves rather than an aspiration.
- **The Access Analyzer check covers one region.** CIS 1.19 asks for an
  analyzer in every region; `read_analyzers` looks at the one the client was
  built for. The finding says so rather than implying a sweep, but an account
  passing this check has only been shown to pass it once.
- **Five of CIS section 1 is unimplemented, on purpose.** 1.1, 1.2, 1.10, 1.17
  and 1.20 have no API that answers them; the reasoning per control is at the
  foot of `scanner/controls.py`. Sixteen of twenty-one are covered.
- **`GET /resources/{type}` with `with_scan=true` is serial.** Seven AWS calls
  per bucket, one after another. Fine for a demo account, visibly slow past
  that. Either concurrency or default the flag off and load findings per row.
- **`_sg_create` still falls back to the default VPC** when a spec omits
  `vpc_id`. The CLI always passes one now, so only API callers can place a
  group somewhere they did not choose.
- **Azure and AWS are two applications.** See the section at the top. The
  abstraction was built for a second provider and a second provider exists;
  they have never met.
- **The frontend covers AWS only.** It is served by the AWS app and calls only
  its routes. Either it grows an Azure half or the README stops promising one.

## Where this stands against the scope

The README is the scope: *provisions AWS and Azure resources through guided
forms and flags unsecure configurations before deployment.*

Done: the AWS provisioning and scanning, well past KAN-8 — seven resource
types, CIS citations across sections 1, 2, 3 and 5, a blueprint, guarded
destructive paths, a live smoke test, and a browser key generator that cannot
reach the network. The guided form exists at `/ui`. Pre-deployment scanning
exists on both halves; `POST /resources/{type}/check` creates nothing.

Not done, and it is one thing wearing several hats: the two halves are separate
programs. Everything in *Not done* above other than that is a refinement.

## Next

1. **Report what an attached role can reach.** The biggest gap, found
   independently by both benchmarks. A new `scanner/` module reading role
   policies, not another rule in an existing one.
2. Decide how Azure and AWS become one application — mount, or register Azure
   as a `ResourceType`. Read the section at the top before choosing; this is a
   group decision rather than a task.
3. Detach `AmazonEC2FullAccess` and friends from `EC2_Dude`, so the documented
   least-privilege policy is the one actually in force and the smoke test
   proves it. Already done for EC2 and S3; SNS, CloudWatch and SSM remain and
   belong to a teammate.
4. The four smaller Prowler gaps: cross-account bucket policies, password
   expiry, per-user hardware MFA, multi-region.
