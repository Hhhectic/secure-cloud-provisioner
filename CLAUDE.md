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

## The two halves are merged

This section used to say the opposite, at length. It is worth knowing that it
did, because the merge is recent and anything else describing this repository
as two applications is out of date.

```
main.py                 the Azure app. Still a separate FastAPI instance
backend/api/app.py      the tool. /resources/..., /blueprints/..., /ui, /docs
```

`main.py` still exists and still runs on its own, and nothing depends on it any
more — and as of the Azure provisioning work it can no longer do anything
`backend/` cannot. Azure is reached through `backend/api/app.py` like
everything else: `azure-nsg`, `azure-storage`, `azure-keyvault`, `azure-vnet`
and `azure-vm` are `ResourceType` entries in `api/registry.py`, their rules
live in `scanner/azure_*_rules.py` and return the same warning shape as every
AWS rule, and the page at `/ui` grows tabs for them without being told they
exist.

That settled a claim this project had been making without evidence.
`scanner/common.py` has said since the first commit that its warning shape is
provider-agnostic and `api/app.py` has had one set of routes on the strength of
it. Registering a second cloud needed two registry entries, no route changes,
and no change to `scanner/common.py`.

**Four things about the Azure layer that will look wrong until you know why.**

- The package is `backend/az/`, not `backend/azure/`. The Azure SDK owns
  `azure` as a namespace package, and `pytest.ini` puts `backend/` on the path,
  so a directory called `backend/azure/` becomes the top-level `azure` module
  and every `import azure.identity` in the process resolves to it and fails.
  Verified, not assumed. Do not rename it.
- Every SDK import in `az/` happens **inside a function**. `api/registry.py`
  imports every provider module at startup, so a module-level import would make
  the Azure SDK a hard requirement of starting the AWS half — the exact
  objection this file used to record against mounting the two apps into one
  process. `test_azure_provider.py` asserts this by reading the source.
- **All five Azure types provision now, and the firewall was the last one.**
  This bullet used to say storage and vaults provisioned and firewalls did
  not, because an NSG rule carries a priority deciding which of several
  overlapping rules wins and nothing here read the ordered set.
  `scanner/azure_nsg_effective.py` reads it, which is what unblocked
  `create_nsg`, `apply_fix`, and the two types built on top of them —
  `az/vnet.py` and `az/vm.py`. `azure-nsg`, `azure-storage`, `azure-keyvault`,
  `azure-vnet` and `azure-vm` are all `ResourceType` entries with create,
  delete and cleanup, and none of it needed a route change.
- **`az/` has now run against a real subscription.** This bullet used to say
  the opposite and it was the largest gap in this file. Storage accounts, key
  vaults, security groups and virtual networks create, scan, fix, delete and
  clean up against subscription `74baf379-b419-4e16-a50b-98bc450901c9`. Four
  bugs came out of the first run and none could have been found offline — see
  *What a real subscription taught us*. Virtual machines too: one has been
  built, scanned and destroyed, after three refusals that are worth reading —
  see *Three refusals stood between here and a running machine*.

**Neither SDK is a hard requirement, and that is now symmetric.** The paragraph
above was true of Azure from the first commit and false of AWS the whole time:
`aws/*.py` imported boto3 at module scope, `api/registry.py` imports every
provider module at startup, and so a checkout without boto3 could not import
`api/app.py` at all — the entire page, both clouds, refusing to start over a
dependency belonging to one of them. `aws/common.py` is the mirror of
`az/common.py` and closes it. boto3 is imported inside `client()`, and
`ClientError` and its two siblings resolve to placeholder classes when botocore
is absent, which nothing can ever raise because `client()` refuses first.

The page now starts with either SDK missing, or both, and answers 503 with a
sentence naming what to install. `test_the_page_starts_without` proves all
three cases by blocking the imports in a subprocess, so it holds on any machine
rather than only on one that happens to lack an SDK — which is what the
previous version of this test did, and why it started failing the day somebody
installed the Azure SDK.

**There were briefly three user interfaces.** The merge brought a Streamlit
frontend into `frontend/` beside the served page, with `app.py` next to
`app.js` doing an unrelated job. The served page was kept: it needs no process
of its own and reaches every registered type, including Azure. The other is at
`archive/streamlit-frontend/` with a README explaining the choice and what
would need changing to revive it.

## Where this stands, for whoever picks it up next

Everything below this line was true at commit `61881b5`.

**Pushed to three places, all at the same commit.** `origin` (Hhhectic) has it
on `main` and on `aws-provisioner-and-web-interface`; `group` (gavingonzo) has
the branch. The tag `aws-half-complete` is pinned to `42b0e1f`, the state
before the merge, and is the restore point if any of this turns out to be
wrong: `git reset --hard aws-half-complete`.

**Verification as of that commit.** 673 tests from `backend/`, 677 from the
repository root (the extra six are the Azure half's own suite, which CI had
never run until the merge). The live smoke test is 154 passed, 0 failed against
account 679140927523, including instances and the whole bastion blueprint.

Since then, on this branch: the merge with `group/main`, Azure storage and key
vault provisioning, the first live Azure run, and then network security group,
virtual network and virtual machine provisioning take it to **779 from
`backend/`**, 7 skipped. The live *AWS* smoke test has not been re-run. The
Azure half of it has, against a real subscription: `python
scripts/smoke_test.py --azure-only --with-azure-resources
--azure-resource-group scp-demo` is **47 passed, 0 failed**, and that includes
building and destroying a real virtual machine.

**The root suite does not collect, and it arrived that way.** `ebdb579` renamed
`run_azure_security_scan` to `scan_azure_payload` in `azure_scanner_engine.py`
and `test_azure_scanner.py` still imports the old name, so `pytest` from the
repository root stops before running anything. Verified against a clean export
of `group/main`, where it fails identically; every root file here is
byte-identical to that branch. `group/feature/key-vault` restores the old name,
so this resolves when that branch lands rather than by being patched twice.
Until then, run the suite from `backend/`.

**Two things were changed in AWS by hand and are not in any file here.** The
`iam-audit` customer managed policy was extended twice, first with the six role
reads and then with `iam:GetUserPolicy` and the three group reads;
`docs/iam-policy-account-audit.json` is the record of what it should contain.
And a billing alarm, `scp-billing-5-usd`, was created deliberately and left in
place — it is the only thing standing between a shared account and a surprise
bill, and the smoke test reports it as a leftover every run.

**The account is clean otherwise.** No instances, no non-service roles, no
non-default VPCs. Two orphaned CloudGoat roles were found by this tool's own
first live role scan and deleted; one of them could pass any role and create a
function, which is a live privilege escalation that had been sitting unused for
five hours.

**CloudGoat is not installed any more.** It lived in a session scratch
directory that no longer exists. `docs/benchmark.md` records how to set it up
again, including four traps that cost real time: it reads `whitelist.txt` and
`config.yml` from its *package* directory, `config.yml` must be a YAML list,
`destroy` prompts and dies silently on EOF while still reporting success, and
it leaves every destroyed scenario's Terraform provider cache in `trash/` until
that fills the disk. A separate `cloudgoat` AWS profile with admin deploys the
scenarios; `EC2_Dude` scans them.

## Running things

The AWS half, which is what the rest of this file is about:

```bash
cd backend
source /home/user/scp-venv/bin/activate      # not ../.venv: see below

pytest -v                                   # offline, moto, no credentials
                                            # run from backend/, not the root:
                                            # see the note above about ebdb579
python main.py                              # the CLI, both clouds, 11 options
uvicorn api.app:app --reload --host 127.0.0.1   # API, /docs and the page at /ui
python scripts/smoke_test.py                # live AWS, free
python scripts/smoke_test.py --with-instances   # live, launches a t3.micro
python scripts/smoke_test.py --with-blueprint   # live, the whole bastion, two t3.micro
python scripts/smoke_test.py --with-alarm-email you@example.com  # live, sends one email
python scripts/make_vulnerable.py           # deliberately weak demo resources
python scripts/make_vulnerable.py --with-public-snapshot   # also publishes a blank snapshot
python scripts/make_vulnerable.py --clean   # remove everything tagged as ours
python scripts/cloudwatch_harness.py        # live, free tier, creates alarms

python scripts/smoke_test.py --azure-only   # live Azure, free, no AWS call
python scripts/smoke_test.py --azure-only --with-azure-resources \
    --azure-resource-group scp-demo         # live Azure, creates and deletes
```

`--azure-only` skips every AWS section and does not ask STS who it is, so it
runs on a machine holding no AWS credential. It exists because the AWS half
creates and destroys real resources in an account this team shares, and making
that the unavoidable price of checking Azure is how somebody ends up deleting a
colleague's demo to test a storage account.

`--with-azure-resources` creates and deletes one storage account and one key
vault. Both are free; the vault is not free of consequences, because soft
delete is mandatory and every write run consumes a vault name for its retention
period. Pass `--azure-resource-group` with a group that already exists:
inventing one needs permission to create resource groups across the
subscription, while reusing one needs only Contributor on that group.

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

Azure itself is reached through `backend/` like everything else — option 10 in
the CLI, and `/resources/azure-storage` over HTTP. What still runs from the
repository root is the *older* Azure app, which is a separate process and needs
a different set of dependencies:

```bash
pip install -r requirements.txt          # on group/main: the Azure SDK
uvicorn main:app --reload --port 8001    # Azure scan and deploy
python -m pytest test_azure_scanner.py   # on group/main: six tests
```

**The virtualenv is `/home/user/scp-venv`, and this file used to say
`../.venv`.** There is no `.venv` in the repository and there does not appear
ever to have been one on this machine, so the documented activation line fails
before anything else is tried. It also arrived without `pytest` or `moto`, so
the offline suite could not run until both were installed — the SDKs were
there and the test tools were not, which is a confusing way to be broken
because the application starts fine. If you are setting this up again:

```bash
python3 -m venv /home/user/scp-venv
/home/user/scp-venv/bin/pip install -r backend/requirements.txt -r requirements.txt
/home/user/scp-venv/bin/pip install pytest moto
```

A checkout is also missing `.env`, which is gitignored and therefore absent
from any fresh clone and from every git worktree — `backend/environment.py`
looks for it beside the worktree's own root, not the main checkout's, so a
worktree needs its own copy or a symlink to one.

That virtualenv holds both SDKs, so `/ui` scans Azure as well as AWS. It did not
until recently, and the reason for the change is worth knowing: the page is one
process, so whether it can reach Azure is decided by the interpreter running
uvicorn. A second virtualenv beside it does not help — `main.py` and the
archived Streamlit page are separate processes and can have their own, but
`/ui` cannot.

What that costs is nothing, now that `test_the_page_starts_without` blocks the
imports in a subprocess rather than relying on `.venv` being a machine that
lacks one. Before that, installing the Azure SDK made two tests fail, and the
obvious reaction to a test that fails on your machine is to delete it.

`main.py` still imports `azure_crud` at module scope, which pulls the Azure SDK
in before anything runs — so `/api/v1/azure/scan`, which needs neither
credentials nor the SDK, cannot start without them either. That one is
unchanged; only `backend/` is symmetric.

It has no `/ui`, and shares nothing with `backend/` but the repository.
Nothing below this line applies to it.

## Layout

```
main.py                 the Azure app. Separate FastAPI instance, root of repo
azure_scanner*.py       the Azure scanner, separate from backend/scanner/
azure_crud.py           Azure provisioning, reached only by main.py. Fully
                        superseded now: every create in it exists in backend/az/
                        with a guard it does not have (it replaces an existing
                        group's whole rule list and reports success)
security_messages.py    Azure's warning text. Orphaned: azure_scanner.py is the
                        only thing that reads it and nothing reads that
test_azure_scanner.py   six tests, no cloud calls. Does not currently import
requirements.txt        the Azure SDK, not boto3. backend/requirements.txt is
                        the AWS one

archive/       two Streamlit frontends, kept and not used. See their READMEs
backend/
  environment.py  reads the repository's .env at whichever entrypoint starts
  az/          Azure. Named az/ and not azure/ on purpose; SDK imported lazily.
               Five types, all provisioning: storage, keyvault, nsg, vnet, vm.
               names.py holds what Azure will accept as a name, as refusals
  scanner/     pure rule logic, no boto3 anywhere, no cloud calls
  aws/         all boto3, one module per resource type (iam.py reads only).
               common.py imports the SDK lazily, mirroring az/common.py
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

**Escalation is one engine, pointed at three identity kinds.**
`scanner/escalation.py` holds the matching and knows nothing about what an
identity is; `role_rules` and `iam_rules` both ask it. Roles were built first
because the benchmark said "role to something", and re-running one CloudGoat
scenario immediately showed the other end: in `iam_privesc_by_ec2` the tool
named the `AdministratorAccess` role sitting on a machine and said nothing
about the *user* who could put it there, because the escalation was in that
user's inline policy and nothing read it. A user's policies now include the
ones inherited through a group, because arriving that way is the recommended
arrangement and an escalation assembled there is if anything likelier than one
pinned to a person.

**Azure is a `ResourceType`, and the contract held.** `scanner/common.py` has
claimed since the first commit that its warning shape is provider-agnostic, and
`api/app.py` has had one set of routes on the strength of it. Registering
`azure-nsg` and `azure-storage` is the first evidence either statement is true:
two entries in `api/registry.py`, no route changes, no change to
`scanner/common.py`. An Azure finding is counted and rendered by code that does
not know which cloud it just described.

Storage now writes as well as reads, and that cost nothing outside `az/` either:
three adapters in `api/registry.py`, one field in `api/models.py`, and
`read_only` going false is what opens create, delete, cleanup and the deletion
plan. The registry claim was only ever tested against a read path before this.

**One switch, not a field per setting.** `create_account` and
`check_storage_spec` both read `secure_by_default`, which is what makes the
warnings shown before creation the ones shown after it — the contract
`_bucket_check_spec` states for S3, asserted across a cloud boundary by a
parametrized test. The alternative is on `group/main` and shows why: its form
offered a TLS dropdown beside a scanner with no TLS rule, so it could provision
a TLS 1.0 account and report it clean. A single switch cannot drift from the
rules that judge it.

**An account name is checked, not attempted.** `begin_create` on a name you
already own *updates* that account rather than failing, so the obvious
try-it-and-catch-the-error would silently rewrite a live account's settings to
whatever the form said, and report success. `_name_is_available` asks first.
The same hazard is still live in `create_network_security_group` on
`group/main`, where the whole rule list is replaced.

**An Azure delete refuses without force.** S3 gives an unforced delete a safe
failure — a bucket with anything in it refuses, so force there means "empty it
first". `storage_accounts.delete` succeeds on a full account and takes every
container and blob with it. Leaving force optional would have made the Azure
path the quiet one, which is backwards. With force, the routes already demand
`confirm` repeat the id, and the CLI asks for the account name typed back.

**A key vault is judged by what can be destroyed, not by who can reach it.**
Every other rule set here asks about exposure. `scanner/azure_keyvault_rules.py`
asks whether what is inside can be lost beyond recovery, because a vault holds
the keys other resources' data is encrypted with — destroying one can destroy
data that was never in it. The finding with no counterpart in the version this
was ported from is the third: access granted by a vault's own policy list
appears in no role audit anywhere, so `scanner/role_rules.py` can read an
identity's entire permission set and still not know it can open the vault. Same
shape as `grants_account_wide_iam_read` — not a way in by itself, but the thing
that makes a way in impossible to see.

**Three Azure constraints on vaults are stated rather than worked around.**
Soft delete has been mandatory since 2020, so the deliberately-weak option
cannot weaken it and does not pretend to — the value is still sent explicitly,
for the reason `assign_public_ip` taught the AWS half. Purge protection is sent
as *absent* rather than false when off, because the API rejects an explicit
false: once enabled it can never be disabled. And a deleted vault keeps its
name for the whole retention period, so "name taken" routinely means "you
deleted it last week" — `create` says so and `delete` says what a delete does
*and does not* do, because reporting success and leaving somebody to discover
the name is still gone would be true and misleading.

**`backend/` reads `.env` now, and did not before.** Only the root `main.py`
called `load_dotenv`, so credentials put where every instruction in this
project says to put them reached the Azure app and not the tool. The failure
was quiet in the worst way: `az/common.py` raises the same "Azure needs
AZURE_TENANT_ID…" whether the file is missing or merely unread, so the message
sent people to fix a file that was already correct. `backend/environment.py` is
called by both entrypoints rather than from `az/common.py` or `aws/common.py`,
because reading configuration is what a program does when it starts and a
library should only read what is already there. A variable already set in the
environment always wins over the file — which is what lets one checkout point
at two subscriptions without editing anything.

**The CLI's Azure menu is generic; the AWS menus are not.** That is not
inconsistency for its own sake. Each AWS menu asks for something genuinely
different — a network to place a group in, an instance size, a metric and a
threshold — while every Azure type takes the same four answers: a name, a
resource group, a location, and whether to build it safely. So the next Azure
type needs a registry entry and no menu at all. What the deliberately-weak
option would build is shown by running `check_spec` and printing the findings
rather than by a sentence per type, because a sentence goes stale the moment a
rule is added, and showing the findings is the thing this tool exists to do.

**The Azure package cannot be called `azure`, and the SDK is imported lazily.**
Two constraints, both invisible until they bite, both verified rather than
assumed. The SDK owns `azure` as a namespace package, and `pytest.ini` puts
`backend/` on the path — so `backend/azure/` would become the top-level `azure`
module and every `import azure.identity` in the process would resolve to it and
fail. Hence `backend/az/`. And every SDK import happens inside a function,
because `api/registry.py` imports every provider module at startup: a
module-level import would make the Azure SDK a hard requirement of starting the
AWS half, which is the exact objection recorded against mounting the two
applications into one process. `test_azure.py` asserts both properties directly
rather than inferring them from the suite passing.

**Nothing in the Azure rules carries a CIS citation.** CIS AWS Foundations is
an AWS benchmark; citing it against a storage account would borrow authority
that does not extend there. The CIS Microsoft Azure Foundations Benchmark is a
separate document nobody here has read, and inventing IDs from it would be the
fabricated citation `scanner/controls.py` warns about.

**A role is judged by its corridor, not its door alone.** Every other scanner
here judges a setting; `scanner/role_rules.py` judges a route, and the danger
is rarely one permission. `iam:PassRole` grants nothing and `ec2:RunInstances`
grants nothing, but together they let the holder start a machine carrying a
more powerful role and read its credentials from the metadata service — which
is CloudGoat's `iam_privesc_by_ec2` exactly. So the rules match combinations
across the union of a role's policies: an escalation assembled from one inline
policy and one attached one works as well as one written in a single statement.
Where the role can be reached from is folded into each finding rather than
reported separately, because "this can become administrator" and "this can
become administrator and is on a machine answering HTTP requests" are not the
same finding. Only unconditional `Allow` counts and `NotAction` is skipped, for
the reason `grants_full_admin` already gives. Nothing is cited but full admin:
CIS has no control for escalation paths.

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

## What a real subscription taught us

The Azure half passed 96 offline tests and had never once spoken to Azure. The
first run against subscription `74baf379-b419-4e16-a50b-98bc450901c9` found
four bugs, three of them in code the offline suite covered. They are worth
reading as a set, because three of the four are the same mistake: **a stub
written to match the code cannot disagree with it.**

- **A dict handed to the SDK is the request body, not a model.** `create_vault`
  sent `tenant_id`, `enable_soft_delete`, `enable_purge_protection`. Those are
  the *model's* Python names; a plain dict is serialized as written, so what
  Azure received had no `tenantId` in it at all and answered "an invalid value
  was provided for 'tenantId'" — which sends you to look at the value, and the
  value was fine. The keys are camelCase now, which is what `az/storage.py` had
  always written and why storage worked while vaults did not. The read path is
  unaffected and stays snake_case: `vaults.get` returns a model, where the
  Python names are the real ones.
- **Absent and false are different requests.** Purge protection off was sent as
  `None`, which a model would omit and a raw dict sends as an explicit `null`.
  It is now left out of the body entirely, and the offline test asserts the key
  is missing rather than that its value is None.
- **A key vault delete is synchronous.** The code called `begin_delete`, which
  does not exist on `VaultsOperations` — the creates next door are long-running
  and do have a poller, which is what made the wrong spelling look right. The
  stub had grown a `begin_delete` because the code called one. It failed as an
  `AttributeError` at the moment of deleting, and left a vault behind.
- **The SDK's enums are `str` subclasses that lie to `str()`.** This is the bad
  one. `SecurityRuleDirection.INBOUND == "Inbound"` is true, `isinstance(...,
  str)` is true, and `json.dumps` writes `"Inbound"` — so it looks like a
  string in every way anyone would check, including in a debugger. But since
  Python 3.11 a `class X(str, Enum)` renders through `str()` as
  `'SecurityRuleDirection.INBOUND'`, and `scanner/azure_nsg_rules.py` filters
  on `str(rule["direction"]).lower() != "inbound"`. Every rule of every real
  group was skipped. **A network security group opening SSH, RDP and all
  65,535 other ports to the entire internet scanned completely clean** — one
  informational note saying it was not attached to anything. Found by building
  the worst group that could be built and getting a clean scan back.

  `az/common.plain` reduces an enum to its value, and the readers call it on
  every field a scanner reads. It is fixed at the boundary rather than in the
  scanners, because the boundary is where the SDK's types are supposed to stop
  and `scanner/` is not allowed to know the SDK exists. The same trap in
  `az/storage.py` and `az/keyvault.py` runs the other way and invents findings
  instead of hiding them: an account whose network access is `Disabled` would
  be reported as reachable from anywhere.

  `_SdkEnum` in `test_azure_provider.py` models it, and
  `test_the_sdk_enum_stub_really_does_reproduce_the_trap` asserts the stub
  still fails the way the SDK does — because if a future Python makes `str()`
  return the value again, the three tests underneath it would all start passing
  for a new reason.

Two smaller things measured rather than assumed:

- **A deleted storage account name comes back; a deleted vault name does not.**
  The smoke test claimed the storage name was "retained for the soft-delete
  period", which is the vault's constraint borrowed by a section that had never
  run. Storage accounts have no such retention. But the name is not free
  *immediately* either — the delete returns while the account is still going
  away — so the check polls, and reports how long it took. Ten seconds, in
  practice.
- **An absent property is an answer, not a silence.** Azure reports
  `enablePurgeProtection` only when it is on, so a vault without it returns
  null — and the reader filed that under `unreadable`, which suppressed the
  `no_purge_protection` finding and replaced it with "could not check". That
  split the contract this project asserts everywhere else: `check_spec` said
  `no_purge_protection` before the vault was built and the scan said
  `unreadable_purge_protection` after, about the same vault and the same
  setting. `rbac_authorization` already had this reasoning written next to it;
  purge protection needed the same and did not have it.

## The five Azure types, and what each one refused to do

Everything the root app and the archive could do that `backend/` could not is
now here. That was four capabilities and they arrived together, because the
first of them unblocked the rest.

**The priority problem, solved once.** `scanner/azure_nsg_effective.py` reads a
security group's whole ordered rule set and answers what Azure would actually
do with a packet: rules sort by priority, lowest first, the first match decides,
and nothing after it is consulted. That sentence is why `az/nsg.py` was
read-only for its whole life, why it offered no fix, and therefore why the root
app could not retire. Three things depend on it now — creating a group, fixing
a rule, and judging a machine's exposure — and all three would have been
guesses without it.

It also makes the scanner right in a way it was not. The same two rules in two
orders are two different firewalls, and the per-rule version called both of
them critical. An Allow sitting behind a Deny is now reported as *shadowed* —
an informational note rather than a crisis, because it is one priority change
from being live, and dropping it entirely would hide that. Verified against a
real subscription: identical rules, priorities swapped, opposite verdicts.

**What each type will not do, and why it is a decision rather than a gap.**

- `az/storage.py` fixes three findings and refuses two. Turning off the account
  key is one property and would break every application still using it, which
  this tool cannot see — that is a migration, not a fix. Restricting network
  access needs to know which addresses keep it, and the obvious default locks
  out whoever pressed the button.
- `az/keyvault.py` fixes nothing, and the reason changed rather than
  disappeared. It used to be "nothing here has ever run"; it is now that every
  vault fix is a one-way door and `POST /fix` carries a rule id and nothing
  else — no `confirm`, none of the guards `DELETE` demands. Purge protection
  can never be switched off. Moving to role-based authorization revokes every
  access policy at once. Offering an irreversible change through the one
  unguarded path would make the quiet route the dangerous one.
- `az/nsg.py` fixes a rule by setting it to **Deny**, not by deleting it and
  not by narrowing it. Narrowing needs an address the finding does not carry,
  and `POST /fix` deliberately accepts nothing from the caller. Denying leaves
  the name, the ports and the priority intact, so what was intended stays
  legible and re-opening it is one field.
- `az/vnet.py` fixes nothing: a subnet with no security group is fixed by
  attaching one, and which one decides what the subnet allows. An empty group
  would cut off whatever is running there and a permissive one would be this
  tool writing somebody's firewall and calling it a fix.
- `az/vm.py` fixes nothing, because every finding it reports is about a
  resource that is not the machine. An open port is a rule on its security
  group, which `az/nsg.py` now fixes. Password authentication is set at
  creation and cannot be changed afterwards.

**A machine's exposure is not on the machine.** An EC2 instance carries its
security groups; an Azure machine is filtered by a group on its network card,
or on its subnet, or both, or neither. `read_vm_for_scanning` reads all of
them and hands one list to the same evaluator a group's own scan uses, so the
two cannot disagree about what a rule set means.

**Passwords are refused rather than discouraged.** `deploy_azure_vm` in the
archive reads `AZURE_VM_ADMIN_PASSWORD` and sends it. This does not, and the
refusal is the same position as *Key pairs are import-only*: a password logs
in, so putting one in a request body puts it in the logs and in everything
between. Only the public half of a key is accepted.
`test_this_module_never_asks_for_a_password` parses the AST to enforce it —
parses rather than greps, because the module's own docstring names the variable
while explaining that it does not use it.

**Sizes are an allowlist.** `ALLOWED_VM_SIZES` is four burstable sizes and
anything else is refused outright, mirroring `aws/instances.py`. The difference
between the smallest of them and a size somebody reaches for by habit is about
a hundred times the hourly cost, and a confirmation prompt does not survive a
typo.

**Name rules are refusals, checked before Azure is called.** `az/names.py` came
from `archive/streamlit-gui/preflight.py`, where it could only be applied to a
form. Azure answers a malformed storage account name with the same generic
refusal it gives a taken one, so somebody who typed a capital letter is told
only that the name is unavailable.

## Three refusals stood between here and a running machine

A machine has now been built, scanned and destroyed against a real
subscription. Getting there took three separate refusals, each invisible until
the one before it was cleared, and none of them a defect in this code. They are
worth reading in order, because the shape repeats: **Azure reports "you may
not" and "there is none" in the same words.**

**One: the compute provider was not registered.** A subscription that has never
created a machine has `Microsoft.Compute` switched off, and the create fails
with `MissingSubscriptionRegistration`. The service principal could not fix it
— registering a provider is an owner's action and this principal holds
Contributor on a resource group. Cleared by an owner running `az provider
register --namespace Microsoft.Compute`. It is free.

**Two: every size in the allowlist was refused.** `Standard_B1s` came back
`SkuNotAvailable`, which reads exactly like a region being full — and was not.
`resource_skus.list` showed all four classic B-series sizes restricted
`NotAvailableForSubscription` in nine regions, while the quota was four cores
and entirely unused. Azure declines to offer some machine families to some
subscriptions regardless of capacity or quota, and says so in the language of
capacity. The allowlist now spans three generations — classic B, Bsv2, and the
1-2 vCPU v7 sizes — and nothing in it exceeds 2 vCPU, which is what keeps the
guardrail meaningful. `available_sizes` asks which of them the subscription can
actually start, so the refusal names what would work instead of relaying
Azure's message. This subscription is offered none of the burstable families
and runs `Standard_F1als_v7`.

**Three: nothing, and it booted.** 1 vCPU, running, public address, password
authentication off, port 22 open to the world and correctly reported critical
because the machine had a public address. Deleted with its disk, and the four
resources built around it removed after it.

**Two things the failures taught, both now fixed.** The exception escaped
`create_vm` and took `problems` with it, so the caller got a traceback and the
subscription quietly held a network, a security group, a card and a *static
public address* it never heard about — against this project's own stated
position that partial failures report exactly what exists. And the smoke test
cleaned up only the machine, so a create that failed before making one leaked
all four. `_remove_vm_scaffolding` removes them in the order Azure enforces,
whether or not the machine was ever built.

**And a fourth time, from the CLI.** Somebody typed a resource group name that
did not exist, and got a traceback about an HTTP response. The service
principal holds Contributor on particular resource groups rather than on the
subscription, so Azure answered "does this group exist?" with **403, not 404** —
and `ensure_resource_group` handled only 404 and re-raised everything else. The
same bug was in `_name_is_taken` for security groups and virtual networks,
independently, because each was written to the same wrong assumption.

`az/common.denied` and `az/common.not_allowed_to_look` are the one place that
distinction is now made, and every create catches `AzureRefused` and returns it
as the error half of `(ok, error, problems)` — so a permission failure arrives
through the same channel as "that name is taken" rather than as a stack trace.
Worth stating plainly, because it is the fourth instance and will not be the
last: **a read that only handles 404 is a read that turns a missing role into a
crash.**

**The smoke test asks which size to use rather than naming one.** A hardcoded
size makes that section pass or fail on which subscription it is pointed at
rather than on whether the code works, which is the same failure as a test that
only holds on a machine lacking an SDK.

**Two tests were reaching the network without meaning to.** Once
`backend/environment.py` started reading `.env` and somebody put real
credentials in it, `test_an_unconfigured_azure_is_a_503` began answering 200 —
the offline suite had quietly started listing a live subscription. They now
delete the four `AZURE_*` variables through a fixture, which is the same
correction `test_the_page_starts_without` already made one layer along: a test
for the unconfigured case has to *build* the unconfigured case rather than hope
the machine provides it.

## Style

Comments explain *why*, not what. Test names are sentences describing the
behaviour being protected. Warning messages are aimed at someone who does not
know the jargon: acronyms and IP addresses are jargon, ordinary words are not.
Severity means something — if everything is critical, nothing is.

## Not done

- **The page can create Azure resources now, except a firewall with rules.**
  `frontend/app.js` had a hardcoded `FIELDS` map with no Azure entries, so
  every Azure create fell back to a name-only form, submitted without a
  resource group and was refused. All five types have entries now. The
  exception is `azure-nsg`, whose form creates an *empty* group: the existing
  `rules` widget produces AWS-shaped rules and an Azure rule is a different
  shape carrying a priority, so submitting one as the other would be exactly
  the drift recorded under *One switch, not a field per setting*. Rules come
  from the API or the CLI until a widget exists that knows about priority.
  Nothing about the page's rendering is covered by a test; see below.

- **The four Azure capabilities that lived outside `backend/` have landed.**
  Network security group creation was in `azure_crud.py`; virtual networks,
  `deploy_azure_vm` and the name-validation rules were in
  `archive/streamlit-gui/`. All four are in `az/` now — see *The five Azure
  types*. The root app can retire whenever somebody decides to delete it; it
  no longer does anything `backend/` cannot. Note that CLAUDE.md used to say
  virtual networks were in `azure_crud.py` and they were not — that file has
  resource groups, security groups, storage and vaults, and nothing else.

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

- **Role reachability covers identity, not resources.** `scanner/role_rules.py`
  now says what a role can reach, which was the largest gap and is why the
  `role` type exists. What it does not cover is the other direction: Prowler's
  `s3_bucket_cross_account_access` asks who can reach *into* a bucket, and that
  lives in the bucket's own policy rather than in any role. Same shape, other
  end, still open.

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
- **The Azure smoke test covers all five types; three gaps are left.**
  This entry used to say there was no Azure half and no live run at all, which
  was the single largest gap in this file. `--azure-only
  --with-azure-resources` is 47 passed, 0 failed, and builds and destroys a
  real virtual machine. What is still open:

  - **No `apply_fix` for vaults, virtual networks or machines.** Each is a
    deliberate refusal with a reason written next to it rather than an
    omission — see *The five Azure types*. Storage and security groups fix.
  - **One subscription, one region, one service principal.** Everything
    measured was measured in `eastus` against one tenant. The role the
    principal holds was never enumerated — `azure-mgmt-authorization` is not
    installed and adding it just to ask was not worth it — so "the writes
    worked" is what is known, rather than which grant made them work. It
    demonstrably cannot register a resource provider.
- **`main.py` is still a second application, and now a second copy of
  provisioning.** `backend/` is one program serving both clouds; the Azure app
  at the repository root is not part of it and shares nothing but the
  directory. Nothing depends on it any more, so the open question is whether it
  is deleted or kept as the Azure-only deployment `/ui` cannot be — see *The
  two halves are merged*. What decides it is no longer only taste: storage is
  now built in both places, which is the duplication the scanner had before the
  merge, and the root app is the only thing that can still create an Azure NSG.
  It cannot retire until `az/nsg.py` can. The two entries that used to sit
  here, saying the halves had never met and that the frontend covered AWS only,
  were made false by that merge and by Azure becoming a `ResourceType`; the
  page grows Azure tabs without being told they exist.

## Where this stands against the scope

The README is the scope: *provisions AWS and Azure resources through guided
forms and flags unsecure configurations before deployment.*

Done: the AWS provisioning and scanning, well past KAN-8 — seven resource
types, CIS citations across sections 1, 2, 3 and 5, a blueprint, guarded
destructive paths, a live smoke test, and a browser key generator that cannot
reach the network. The guided form exists at `/ui`. Pre-deployment scanning
exists on both halves; `POST /resources/{type}/check` creates nothing.

Azure is now met rather than claimed, and on the same terms as AWS. Five types
— storage accounts, key vaults, security groups, virtual networks and virtual
machines — create, scan, fix, delete and clean up through the same registry,
the same routes, the same CLI and the same page as every AWS type. All of it
has run against a real subscription, including a machine that booted, was
scanned with an administration port open to the internet, and was destroyed.

Not done: the page cannot yet submit firewall *rules*, only an empty group.
Everything else in *Not done* above is a refinement.

## Next

1. **Follow a chain, not one identity at a time.** The CloudGoat re-run is
   done and `docs/benchmark.md` has it: six of twelve scenarios named, one
   partial, and the partial and both remaining misses share one shape. This
   tool judges an identity's own policies. A
   privilege-escalation chain is a graph — who can assume what, and what that
   reaches in turn — and following it means traversing edges rather than
   matching statements. Everything cheap in that direction is now done; what
   is left is a different program and should be started as one.
2. **The Azure half is done; what is left is the page and the benchmark.**
   This item has been "run Azure against a real subscription" and then
   "register the compute provider" and both are finished — all five types
   create, scan, fix, delete and clean up against
   `74baf379-b419-4e16-a50b-98bc450901c9`, machines included. What remains on
   the Azure side is small: a rules widget so the page can submit a firewall
   with rules rather than an empty group, and no external benchmark has ever
   been pointed at the Azure rules the way Prowler and CloudGoat were pointed
   at the AWS ones. The second is the more valuable and the more honest gap.

   Two things still worth knowing before touching a subscription. Being Global
   Administrator in Entra grants no role on a subscription; that is a separate
   permission system, and *Access management for Azure resources* in Entra ID →
   Properties is the elevation. And a secure-by-default key vault turns on
   purge protection, which can never be turned off and locks the vault and its
   name for 90 days — so test vaults with the weak option, which is what the
   smoke test does deliberately, and let the offline spec test cover the secure
   path.
3. **Azure NSG provisioning, or a decision not to.** The one thing root
   `main.py` can still do that `backend/` cannot, and therefore the thing
   keeping it alive. It needs the whole ordered rule set read before a single
   rule can be created or narrowed — the same problem blocking `az/nsg.py`'s
   `apply_fix`, and worth solving once for both.
4. Detach `AmazonEC2FullAccess` and friends from `EC2_Dude`, so the documented
   least-privilege policy is the one actually in force and the smoke test
   proves it. Already done for EC2 and S3; SNS, CloudWatch and SSM remain and
   belong to a teammate.
5. The four smaller Prowler gaps: cross-account bucket policies, password
   expiry, per-user hardware MFA, multi-region.
