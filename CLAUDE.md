# Secure Cloud Provisioner

Provisions AWS resources with safe defaults, explains what is unsafe about them
in plain language, and fixes what it can. Capstone project.

## Running things

```bash
cd backend
source ../.venv/bin/activate

pytest -v                                   # offline, moto, no credentials
python main.py                              # the CLI
uvicorn api.app:app --reload --host 127.0.0.1   # API + /docs
python scripts/smoke_test.py                # live AWS, free
python scripts/smoke_test.py --with-instances   # live, launches a t3.micro
python scripts/make_vulnerable.py           # deliberately weak demo resources
python scripts/make_vulnerable.py --clean   # remove everything tagged as ours
```

Everything runs from `backend/`. `pytest.ini` sets `pythonpath = .`, and
uvicorn resolves imports from the working directory.

## Layout

```
scanner/     pure rule logic, no boto3 anywhere, no cloud calls
aws/         all boto3, one module per resource type (iam.py reads only)
api/         FastAPI over a resource registry, generic across types
blueprints/  compositions of several resources into a correct architecture
scripts/     live smoke test and demo helpers
docs/        IAM policy (two files, see iam-setup.md), bastion walkthrough
```

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

Run the smoke test before believing anything works. It drives the
registry and `aws/` directly, and since the web page arrived it drives
the HTTP routes too - but nothing in it executes a line of the
frontend's JavaScript, and the bastion blueprint has no live coverage
in it at all.

## Style

Comments explain *why*, not what. Test names are sentences describing the
behaviour being protected. Warning messages are aimed at someone who does not
know the jargon: acronyms and IP addresses are jargon, ordinary words are not.
Severity means something — if everything is critical, nothing is.

## Not done

- **The frontend is unexercised by anything automated.** `frontend/` is plain
  HTML and JS served by FastAPI at `/ui`, with no build step and no
  dependencies. Tests cover that it is served, that the mount did not shadow
  the API, and that the key generation module cannot reach the network — but
  no test executes a line of the JavaScript, because there is no engine in the
  development environment. Every bug found in it so far was found by a person
  looking at it.
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
- Azure. The abstraction was built for it but nothing has been attempted.

## Next

1. The frontend.
