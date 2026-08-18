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
  stay free of boto3 to be testable without an account. Both questions here
  have since been answered rather than discussed: Azure took the same shape as
  `backend/az/`, and the empty `providers/` scaffold has been deleted.
- The Azure scanner and `scanner/` are solving the same problem twice. The
  warning contract in `scanner/common.py` was built to be provider-agnostic
  and nothing about it is AWS-specific. Settled the same way — the root Azure
  scanner is gone and `scanner/` judges both clouds.

**One operational hazard, worth agreeing on before a demo.** We share one AWS
account, and cleanup deletes by *tag*, not by author: `make_vulnerable.py
--clean`, the cleanup button and the smoke test's sweep will each destroy
resources a teammate created. `--region` is supported everywhere, so a region
each is free isolation.

## There is one application now

This section has said three things in its life: that the repository held two
applications, then that they were merged but both still existed, and now this.
Anything describing this repository as two programs is out of date.

```
backend/api/app.py      the tool. /resources/..., /blueprints/..., /ui, /docs
```

**The root Azure application has been deleted.** `main.py`, `azure_crud.py`,
`azure_scanner.py`, `azure_scanner_engine.py`, `security_messages.py` and
`test_azure_scanner.py` are gone, with the CI job that ran the last of them.
They were a closed loop — each imported the next and nothing outside imported
any of them — and every capability they had exists in `backend/` with a guard
they did not have. This file had said for a long time that the root app "can
retire whenever somebody decides to delete it"; somebody decided. It is
recoverable from git history, and it still exists on `group/main`, which is
where the provenance comments throughout `backend/az/` and `backend/scanner/`
point when they say "ported from".

`requirements.txt` stayed. It reads like part of that application and is not:
it is the only declaration of the Azure SDK in the repository, and the modules
its own comments name — `az/nsg.py`, `az/keyvault.py`, `az/vm.py` — are
`backend/` ones. Deleting it alongside its neighbours would have left the
working Azure half with no dependencies declared anywhere.

Azure is reached through `backend/api/app.py` like
everything else: `azure-nsg`, `azure-storage`, `azure-keyvault`, `azure-vnet`
and `azure-vm` are `ResourceType` entries in `api/registry.py`, their rules
live in `scanner/azure_*_rules.py` and return the same warning shape as every
AWS rule, and the page at `/ui` grows entries for them without being told they
exist — it reads the registry's own list, and the only thing it is told about
Azure is which cloud each type belongs to, because it shows one at a time.

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
  delete and cleanup.

  "And none of it needed a route change" used to end that sentence, and it was
  not true: three of the five answered 500 on their deletion plan and on their
  delete, because the planners return a shape the route never accepted. The
  registry claim survives — no route *knows* about Azure — but it was being
  made about a path nothing had run. See *What driving the page found*.
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
virtual network and virtual machine provisioning, and then telling a resource
group you may not see apart from one that is not there, took it to 794 from
`backend/`. Then five bugs found by driving the page in a real browser — see
*What driving the page found* — and the redesign, take it to 824 from
`backend/`.

Then the `claude/smoke-test-suite-7c34eb` branch merged: the Azure firewall
rules widget, the first Prowler run against Azure, a fifth instance of the
403-vs-404 mistake in all five Azure readers, and the `chmod` the bastion
instructions were missing — 863. Reviewing that merge found one defect, a
`provider` field declared twice in `ResourceType` because the merge kept both
sides' version of it. Then moving acknowledgement writing out of the CLI and
into the page, and the bastion instructions' second gap, take it to 878.

Then twenty-five commits rebuilding the page — see *The page is three tabs
now* — plus bucket contents, took it to 915 from `backend/`. Then root
collection and the seven create-path defects took it to 929. Then the audit pass
below — see *What reading the scanner found that driving it could not* — takes
it to 964 from `backend/` and 970 from the repository root. Then the pass over
the four surfaces nobody had audited — see *What comparing the two surfaces
found* — and the instance-size gap a second look at the CLI turned up, take it
to 979 from `backend/`. Then the two account-wide checks and the
`azure-monitor` type — see *An account-wide type, and what it cost* — take it
to 1005 from `backend/`, 0 skipped — and 1005 from the repository root too,
now that retiring the root application took its six tests with it,
plus **244 checks** across the two Node suites in `frontend/`. Then the monitor
import defect and the guard that had to be written rather than widened to catch
it — see *The two are not interchangeable* — take it to 1011 from either
directory. Then the bucket read that answered 500 and the inline policy that
had stopped fitting — four tests for the first, three for the second — take it
to **1018 from either directory**, 0 skipped. Every figure here is re-run
rather than carried forward, which is how two of them were once
found to be one low — and re-running is also how the 977 that sat here was
found to be two short of what the suite actually reports.

**`main` on `origin` (Hhhectic) is now the branch to read.** Everything this
file describes was developed on `aws-provisioner-and-web-interface` and merged
to `origin/main` through pull request #1, which is also where the root
application was retired. `group` (gavingonzo) has the work up to that merge on
`aws-provisioner-and-web-interface` and has **not** received the retirement —
that was deliberately kept to one repository so a deletion of this size could
not disturb the shared one. Whoever reconciles the two should read *There is
one application now* first, because the merge will present as "deleted by us,
modified by them" rather than as a conflict between two versions of a file.

No tip hash is named here on purpose. The previous three attempts each named
one and each was stale the moment it was written, this paragraph included.

The junk acknowledgement is gone. `backend/acknowledged.json` carried an entry
for `richard-huo-resume-2026:deny_http` whose reason and author were keyboard
mash, written while trying the feature out, and this file spent a paragraph
explaining why it was being kept out of the commit. It has been taken back
rather than left in limbo. The two entries that remain are the real ones, for
the public CV site, and they are committed.

That file's own `_comment` was also stale in the way this file keeps warning
about: it still said "nothing in this tool writes this file. It is edited by
hand and committed", which stopped being true when `POST /acknowledgements`
landed. Prose next to a mechanism, describing the mechanism, with nothing
failing when they disagree.

**Nothing in that stretch was found by a test.** Every one of those defects
came from opening the page and looking at it, or from measuring something in
a browser: a dashboard that scanned the whole account twice on every load, a
list rendering one type's rows against another type's cached verdicts, a menu
truncating the port somebody had just chosen, a bare "Nothing here." that read
as a clean account. The suites cover behaviour and cannot see any of that.
Whoever picks this up should assume the same is still true of whatever they
change: `frontend/browse.mjs` and a real browser are the instrument, and the
green tick is not.

**And then a stretch where none of it was found by a browser either.** The
section below is a reading pass over `scanner/`, and the two worst things in
this file's history came out of it — a firewall rule opening SSH to two
billion addresses that both clouds reported as nothing, and an escalation
engine blind to the ordinary spelling of "any role". Neither is visible from
the page, because the page faithfully displays a verdict that is wrong. So the
instruments are now three, and they find different things: the suite finds
regressions, the browser finds what the suite cannot see, and reading the rules
against what the cloud actually does finds what both of them agree about and
are wrong about.

**The virtualenv is `/home/huori/scp-venv`.** This file named
`/home/user/scp-venv` throughout for a while, which is a different machine —
there is no `/home/user` here, so every documented activation line failed
before anything ran, including the recipe for rebuilding the thing. The same
shape as the `resource_skus` timing below: something true of one machine,
written down as a property of the project. Built with `python3 -m venv` and
both requirements files plus `pytest` and `moto`, exactly as the setup block
near the bottom describes.

**All three live instruments have been re-run against the current tree, and
two of them were broken.** That is the finding, not the figures: the offline
suite was green the whole time, and both breakages were in the things this
file calls its real instruments.

Where they stand now, all in `us-west-2` rather than the shared `us-east-1` —
`--region` is free isolation and is now the recommended way to run this:

- `smoke_test.py --region us-west-2` — **119 passed, 0 failed**
- the same plus `--with-instances --with-workload --with-blueprint` —
  **183 passed, 0 failed**, the whole bastion built and torn down
- `--azure-only --with-azure-resources --azure-resource-group scp-demo` —
  **47 passed, 0 failed**, including building and destroying a real machine
- `browse.mjs` — every tab of both clouds, no console errors, 28 screenshots

Nothing was left running afterwards: no instances, no non-default networks, no
NAT gateways and no unattached elastic addresses in either region, checked
independently of the smoke test's own leftover assertions. `scp-billing-5-usd`
remains, deliberately.

**And then every route was driven directly, on `main` after the merge.** The
smoke test drives the registry and a good deal of HTTP; this went through the
routes themselves for each type in turn — options, pre-flight, create, read
back, scan, fix, deletion plan, delete, verify gone — plus the audit-only
refusals, cleanup plans, the blueprint and the acknowledgement routes. **88
passed and then 16 passed, 0 failed, nothing left behind.**

Three things it established that nothing had before. **The fix path works on
every type that offers one**, against both clouds: a security group narrowed
to one address, an Azure storage account's public access closed, an NSG rule
flipped to Deny, each re-scanning clean afterwards. **The acknowledgement
routes round-trip** — written, the finding kept at full severity while tallied
as accepted, an invented rule id refused, then taken back and the finding loud
again. And **the blueprint builds and reports all five of its pieces** through
the route, with instructions and a teardown script.

**One hazard, worth knowing before a demo.** The first attempt to start the
server on the merged tree failed with *address already in use*: an older
uvicorn from earlier in the day still held port 8000, running the pre-merge
code. It errored, which is the only reason it was caught — a stale process that
binds successfully would have served the old application to every one of these
checks and passed. Kill the old server before trusting a run.

**The smoke test broke when the placement refusal landed, and nobody re-ran
it.** `_sg_create` stopped falling back to the account's default VPC — rightly,
since placement cannot be changed afterwards — but `smoke_security_group` and
the HTTP section both built specs without a `vpc_id`, so three checks failed
against real AWS while every offline test stayed green. Both read the network
off `resource.options` now, the same list the page and the CLI choose from, so
the script picks the way a person does. This is the second time a correct
change has broken the script that proves it: worth making the pair one habit,
because the offline suite cannot see either half.

**`browse.mjs` had been sweeping nothing since the three-tab redesign.** It
read `#types` immediately after load, and the page opens on the Dashboard,
which has no type picker — so it enumerated zero tabs, walked none of them,
and printed *no console errors on any tab of any cloud*. That output is
identical to a clean run unless somebody notices the list is empty, which is
why it survived a redesign it was supposed to be checking. It selects each
page tab before enumerating now, screenshots the Dashboard as a surface in its
own right, and **an empty picker is a reported problem rather than a silent
one**.

It is worth naming plainly what that was: a scan that looked at nothing and
reported clean, inside the instrument this project trusts most — the exact
failure `unreadable` and *Scan incomplete* exist to prevent everywhere else.
`app.test.mjs` now pins the anchors it steers by, because `browse.mjs` is not
in `npm test` and nothing else would notice it going blind again.

**Every provisionable type has now been driven through the browser**, against
both real clouds, which had never been done for anything before this. All nine
AWS types and all five Azure ones create, scan, fix and delete from the page;
the bastion blueprint builds and tears down from it, with and without its two
machines. What that found is the section below, and it is the reason the
Node suites are not the whole story: `app.test.mjs` answers a stub, and a stub
written to match the code cannot disagree with it.

**There is one suite now: `pytest` answers 1018 from the root and 1018 from
`backend/`, because they are the same tests.** The six that used to make the
root figure larger were `test_azure_scanner.py`, which went with the
application it covered.

The rest of this entry is history rather than instruction, and is kept because
the mistake in it is one this project keeps making. For a long time the root
suite did not collect at all, and this file recorded the cause wrongly twice.

The entry that used to sit here said the breakage was a rename and that it
would resolve when `group/feature/key-vault` landed. Both halves were wrong.
`ebdb579` did not rename `run_azure_security_scan`; it **replaced
`azure_scanner_engine.py` wholesale** with an ARM-shaped scanner reading
`network_security_group`/`storage_account`/`key_vault`, deleting the
aggregator and with it the only importer of `azure_scanner.py`. So the obvious
one-line fix — point the test at the new name — would have collected and then
failed all six tests, because the two functions take different payload shapes
and return different types. `azure_scanner.py` still matches the tests exactly;
what was missing was the eleven lines that call it.

Both functions live in `azure_scanner_engine.py` now. `scan_azure_payload` is
untouched and still serves `main.py`'s two routes; `run_azure_security_scan` is
restored beside it, delegating to `azure_scanner.py` so the wording stays in
`security_messages.py` rather than being written a second time. That also
un-orphans both of those modules, which this file lists as read by nothing.

**Waiting for `group/feature/key-vault` was never going to fix it.** That
branch is a divergent design rather than a later version: its `main.py` imports
`run_azure_security_scan` and has no `scan_azure_payload` at all, so the flat
payload shape is the whole root app there, while `ebdb579` moved this side to
the ARM-shaped one. It is dated 2026-08-10 and is still not an ancestor of
`group/main`. When it lands, expect a real conflict — and note that this side
has since deleted all three files, so the conflict is now "deleted by us,
modified by them" rather than two versions of a function. Resolving it means
deciding whether the root application comes back, not merging it. The branch
also carries `check_key_vault_governance`, a fourth rule that never existed
here; if any of that work is wanted, it belongs in `backend/scanner/`.

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
source /home/huori/scp-venv/bin/activate     # ../.venv too, minus one: see below

pytest -v                                   # offline, moto, no credentials
                                            # 1018, and the same 1018 from the
                                            # repository root: one suite now
python main.py                              # the CLI, both clouds, 14 options
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

```bash
cd frontend && npm test                     # offline: keygen + jsdom
npx playwright install chromium             # once, for the one below
node browse.mjs http://127.0.0.1:8001/ui/ /tmp/shots   # live, real browser
```

`browse.mjs` is deliberately outside `npm test`: it needs a running server and
a real account, so it belongs beside `scripts/smoke_test.py` rather than beside
the offline suites. It clicks every sidebar entry, collects console errors and
screenshots each one. Five bugs came out of it and its throwaway siblings — see
*What driving the page found*.

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

Azure is reached through `backend/` like everything else — option 10 in the
CLI, and `/resources/azure-storage` over HTTP. There is nothing to run from the
repository root any more: the older Azure app that lived there has been
deleted, so the three commands that used to sit here — `uvicorn main:app` on
port 8001, and `pytest test_azure_scanner.py` — no longer refer to anything.
Both still work against `group/main`, where those modules remain.

`requirements.txt` at the root is still installed, and still holds the Azure
SDK. It was never part of that application, whatever its position suggested.

**The virtualenv is `/home/huori/scp-venv`, this file has twice named one
that does not exist, and it then denied one that does.** The two wrong names
were `../.venv` and `/home/user/scp-venv`. The entry correcting them overshot:
it said there is "no `.venv` in the repository and there does not appear ever
to have been one on this machine". There is one. `/home/huori/code/.venv` was
built on 9 August by `/usr/bin/python3 -m venv`, six days before `scp-venv`,
holds 443 MB, and **runs the whole offline suite — 1018 passed in 3m48s**,
measured rather than reasoned about, and re-measured every time the count
moved rather than adjusted by the number of tests added. An absence inferred from one shell not
finding something, and then written down as a property of the machine, is the
`resource_skus` mistake pointed the other way: that one recorded a number
taken under load as the call's cost, this one recorded a failed lookup as the
world.

What stands from that entry is its other half. `scp-venv` did arrive without
`pytest` or `moto`, so the offline suite could not run until both were
installed — the SDKs were there and the test tools were not, which is a
confusing way to be broken because the application starts fine. If you are
setting this up again:

```bash
python3 -m venv /home/huori/scp-venv
/home/huori/scp-venv/bin/pip install -r backend/requirements.txt -r requirements.txt
/home/huori/scp-venv/bin/pip install pytest moto
```

**The two are not interchangeable, and no test can tell them apart.**
`scp-venv` holds `azure-mgmt-monitor` 7.0.0 and `.venv` does not; `.venv`
holds `azure-mgmt-authorization`, `azure-mgmt-security`, `azure-mgmt-sql` and
`azure-mgmt-subscription`, and `scp-venv` does not. The suite answers 1018
under either, `az/monitor.py`'s fifteen included, because those run against a
stub and every SDK import here is lazy. The difference was visible only live,
and there it was a defect rather than a missing package: under `.venv`,
`GET /resources/azure-monitor` failed with `ModuleNotFoundError` where every
other Azure type answers **503 naming what to install**.

`az/monitor.get_client` did a bare `from azure.mgmt.monitor import
MonitorManagementClient`. Every other client in `az/` goes through
`az/common._import`, which is the one place an absent SDK becomes
`AzureNotConfigured` and a sentence somebody can act on, and it was the only
bare SDK import in the package. So the newest Azure type was the one place the
lazy-import design half held — the page still started, which was the point,
but that tab answered a traceback instead of an explanation, on exactly the
checkout most likely to be missing the package. Found by driving one route
under two virtualenvs, which is an instrument this file did not have: both are
green, both start, and only one of them could answer.

**It goes through `_import` now, and the interesting part is why neither
existing guard caught it.** `test_asking_for_an_absent_client_explains_itself`
named `az.nsg` and stopped, so the case chosen to stand for the others was one
of the five that reach the SDK through `az/common` — it is parametrized over
all six types now. `test_the_azure_modules_import_no_sdk_at_module_scope` read
three files by name, which is a list that stops covering whatever is added
next; it reads every file in `az/` now. **Neither would have caught this even
after widening**, because both ask about *module scope* and this import sat
inside a function, which is where every SDK import in this package is supposed
to sit. So the guard that pins it is a new one:
`test_every_azure_sdk_import_goes_through_the_one_helper` parses each module in
`az/` and refuses an `azure.*` import at any indentation. The first two are
about the page starting; the third is about what a tab says when it cannot.

A checkout is also missing `.env`, which is gitignored and therefore absent
from any fresh clone and from every git worktree — `backend/environment.py`
looks for it beside the worktree's own root, not the main checkout's, so a
worktree needs its own copy or a symlink to one.

That virtualenv holds both SDKs, so `/ui` scans Azure as well as AWS. It did not
until recently, and the reason for the change is worth knowing: the page is one
process, so whether it can reach Azure is decided by the interpreter running
uvicorn. A second virtualenv beside it does not help — the archived Streamlit
page is a separate process and can have its own, but `/ui` cannot.

What that costs is nothing, now that `test_the_page_starts_without` blocks the
imports in a subprocess rather than relying on `.venv` being a machine that
lacks one. Before that, installing the Azure SDK made two tests fail, and the
obvious reaction to a test that fails on your machine is to delete it.

The root app used to spoil that symmetry: `main.py` imported `azure_crud` at
module scope, pulling the Azure SDK in before anything ran, so
`/api/v1/azure/scan` — which needed neither credentials nor the SDK — could not
start without them. It was the one place the lazy-import discipline did not
hold, and it left with the rest of that application. `backend/` is now the
whole program and is symmetric throughout.

## Layout

```
requirements.txt        the Azure SDK, not boto3. backend/requirements.txt is
                        the AWS one, and now also python-multipart — needed
                        only to accept an uploaded file, and the upload route
                        is registered only when it imports, because a
                        dependency belonging to one feature must not stop the
                        whole page starting. Without it that one endpoint
                        answers 503 naming what to install. It stays at the
                        root, and is the one thing there that did NOT go with
                        the Azure app: it is the only declaration of the Azure
                        SDK anywhere, and its own comments name az/nsg.py,
                        az/keyvault.py and az/vm.py — backend/ code. Deleting
                        it with its neighbours would have left the working
                        Azure half with no declared dependencies at all

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
frontend/      the page, served at /ui. Plain HTML and two scripts, no build
               step, no shipped deps. Three tabs — Dashboard, Create, Audit —
               and one cloud at a time behind a toggle. browse.mjs and
               azure-lifecycle.mjs drive it in a real browser and are not in
               npm test. Assets are served with ?v=<mtime>, so a stale page is
               a bug rather than caching
docs/          IAM policy (three files, see iam-setup.md), bastion walkthrough,
               benchmark.md: what Prowler finds that this does not
```

`backend/providers/` no longer exists. It held one empty file, `aws.py`, which
this repository scaffolded before the AWS work started and which stayed empty
for the whole project — the code went to `backend/aws/` instead. It was removed
along with the root application, and the directory went with its only file.

`scanner/` must never import from `aws/`. That separation is what lets the
rules be tested without an account, and what would make a second cloud
feasible rather than a rewrite.

## The decisions worth knowing

**Every scanner returns the same warning shape.** `scanner/common.py` defines
it. That contract is why `api/app.py` has one set of routes rather than one per
resource type. Adding a resource means writing an `aws/` module, a `scanner/`
module, and one entry in `api/registry.py` — no route changes.

**The page is told which cloud a type is in; it does not work it out.**
`ResourceType.provider` is served by `GET /resources`, and the toggle groups by
it. The alternative was matching on the `azure-` key prefix, which is the
frontend inferring a provider from a naming convention nothing enforces and
which would need editing again for a third cloud — the one thing adding a
second was supposed to prove unnecessary. `short_label` travels with it,
because every Azure label starts with the word Azure for the CLI's benefit and
a page showing one cloud has already said which. A missing `provider` defaults
to `aws` on both sides: the failure without a default is silent and total, since
a type whose provider does not match is skipped, so a server that stopped
sending the field would render an empty sidebar and look like an empty account.

**A row's id is whatever the routes accept.** For AWS that is `sg-…`, and for
Azure it is the name — not the ARM path, which carries eight slashes and
therefore cannot be one segment of a URL. This is stated because it was got
wrong, and the wrongness was invisible from either side alone: the readers take
both forms, so every offline test passed while the page 404'd on every resource
it had just created.

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

**The connection instructions are written for the route the page offers, and
twice they were not.** `bastion.connection_instructions` is rendered by both
the CLI and the page, and both gaps were the same shape: correct for somebody
who ran `ssh-keygen` into `~/.ssh`, unusable for somebody who followed the
browser generator this project recommends. First the missing `chmod 600` —
ssh refuses a key others on the machine could read, a download is 0644 every
time, and the keygen panel said so while these did not. Then the paths: every
command named `~/.ssh` and a browser puts nothing there, so the chmod and both
`ssh-add`s pointed at a directory the files were not in.
`keys_were_downloaded=True` prefixes the move, and `POST /blueprints/bastion`
passes it for every caller — that route refuses to generate key pairs at all,
so whoever called it holds two private halves this server has never seen. Both
tests assert *order*, not presence: a move after the chmod is a chmod against
nothing, which is the same failure with more words in it.

The page renders both blocks through `commandBlock`, which adds a Copy button.
They were a bare `<pre>` before, so the recommended path ended in transcribing
six commands carrying generated filenames and addresses, where a typo is
silent until ssh fails on something that looks right.

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

**And the page can now put files in a bucket, under the same rule.** Files
can be attached on bucket creation; `aws/s3_buckets.put_objects` **refuses to
write into a bucket anyone outside the account can read** — policy, ACL or the
four blocks — and refuses if it cannot tell. That refusal is the feature, not
a safety rail bolted on: an upload button in the same interface that turns
Block Public Access off puts "make an exposure" and "put data behind it" one
click apart, and the half that goes wrong is silent. It does not prevent the
demo, it orders it: upload first, open the bucket after, and the scan then
reports a public bucket *with something in it*, which is the sharper
demonstration and the order that never strands data by accident. The check is
made at the moment of writing, because a bucket created secure ten minutes ago
may not be secure now.

Writing that turned up a bug of exactly the shape this file keeps recording.
`reachable_by_anyone` folded an absent public-access-block configuration into
`{}`, and `all({})` is True — so a bucket with *no* block configuration at
all, which is the least protected state there is, read as fully blocked and
was accepted for upload. Exactly backwards, and only ever wrong in the
direction that publishes something.

**A scan can see inside a bucket now.** It could not, so a world-readable
empty bucket and a world-readable bucket holding two hundred files were
reported in identical words — "anyone who knows the address can reach the
files inside", with no idea whether there were any. One is a misconfiguration
and the other is an incident. `list_objects` reads one page and the public
finding gains a clause: "and there are 12 objects in it". Silent when the
contents could not be read, because a missing clause must not be read as
"nothing in it"; `unreadable` carries that as it does for every other setting.

**That last sentence was false for as long as it had been written, and the way
it failed was a 500.** `scanner/s3_rules` did have the branch — it checks
`unreadable["objects"]` and returns no clause — and nothing could ever reach
it, because `list_objects` never put anything there. Every other reader in
`_READERS` ends in `_denied(e, ...)`, which turns AccessDenied into
`PermissionDenied` so `read_bucket_for_scanning` can record it per setting.
This one called `list_objects_v2` bare, so botocore's own error walked past
that `except PermissionDenied`, out of the route, and into the browser.

What made it reachable is a bucket that **exists and belongs to somebody
else**. `bucket_exists` treats a 403 as existing — deliberately, and
documented there — so the read proceeds and every setting answers AccessDenied.
`GET /resources/bucket/{name}` answered **500** for any such name while the
same name, absent, answered a clean 404: the "not there" path was right and the
"not allowed" path crashed. It is the seventh instance of that family in this
file and the first on the AWS side, where the lesson was already written down
about Azure — *a read that only handles 404 is a read that turns a missing role
into a crash.*

It now answers 200 with all nine settings null, nine `unreadable` entries and
nine "could not check" warnings, no criticals and nothing claimed clean. Found
by driving the routes against a real account, not by the suite: moto grants
everything, so the fake cannot produce the denial. `POST /acknowledgements`
was hit by the same bug, because it re-scans the resource before accepting
anything, and it answers 400 to an invented rule id now rather than 500.

Fixing it exposed a smaller one. `SETTING_LABELS` in `scanner/s3_rules.py` had
seven entries against `_READERS`' nine, and the lookup falls back to the key —
so the newly reachable message read "Could not check **other_accounts** on this
bucket", an identifier in front of somebody, which *Style* says a warning
message is never for. Both have wording now, and the guard is derived from
`_READERS` rather than kept beside it, so the next reader cannot be added
without it.

`s3:PutObject` is in `docs/iam-policy-account-audit.json` rather than the
inline policy, and measuring said why: `docs/iam-policy.json` was **2,379
non-whitespace characters against the 2,048 inline limit**, 331 over, so the
documented inline policy had not been pasteable as one for some time. That
quietly undid the fix recorded below about the 2,048-character budget — the
audit reads were moved out *specifically* to get under it, and the remainder
grew back past it.

**Fixed the same way, and then guarded so it cannot happen a third time.**
`ReadOnlyAcrossEverythingThisToolAudits` followed the other reads into the
managed policy: inline is **1,966 of 2,048** and managed **1,517 of 6,144**.
It was the only statement that could move. The four remaining Allows are the
ones the Denies guard, and separating a guardrail from what it guards is the
one thing this split must not do; the read block is guarded by nothing.

`docs/iam-setup.md` was worse than the file it described. Its table said
**1797 / 2048** — typed once, never re-derived, and stale in the only
direction that matters: it advertised a policy that fitted while pasting it
had been failing. Every figure in that table is measured from the files now,
and three tests in `test_iam.py` pin the two limits and assert that no `Deny`
has drifted into a policy that can be detached on its own.

**A live account needs both halves applied together.** Taking the statement
out of the inline policy without adding it to the managed one costs the tool
thirteen reads, and that failure is the near-silent one this project already
paid for once: every provisioning path keeps working and the audit degrades
into nine "could not check" notes that read like an account with nothing to
report.

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
different — a network to place a group in, a subnet and a key for a machine, a
metric and a threshold — while every Azure type takes the same four answers: a
name, a resource group, a location, and whether to build it safely. So the next
Azure type needs a registry entry and no menu at all. What the
deliberately-weak option would build is shown by running `check_spec` and
printing the findings rather than by a sentence per type, because a sentence
goes stale the moment a rule is added, and showing the findings is the thing
this tool exists to do.

This paragraph named **an instance size** in that list for a long time while
the instance menu did not ask for one, which is worth keeping because of how it
hid. `instance_menu` asked for a network, a subnet, a key pair, security groups
and a public address, then built a spec with no `instance_type` in it, so
`launch_instance` fell through to `DEFAULT_INSTANCE_TYPE` and every machine the
CLI ever started was a `t3.micro` while the page offered twelve. Harmless in
itself — that is the smallest size on the allowlist, and the refusal above it
still held — but it is the third instance of one surface being quietly narrower
than the other, after the alarm metric and the bucket pre-flight.

`azure_vm_menu` had always asked, off `resource.options`, and that is what made
it invisible: the CLI looked as though both machine menus offered a size. The
AWS one now reads the same allowlist the same way, and marks the default rather
than assuming position one. Both are pinned by one parametrized test, which
fails for `instance_menu` and passes for `azure_vm_menu` against the old code —
the discrimination is the point, since a test that passed for both would prove
nothing about the one that was broken.

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

**"Quieter, never absent" is about the detail panel, and applying it to the
summary was a mistake.** The dashboard counted an accepted critical as a
critical on the grounds that anything else was suppression. It is not: an
acknowledgement is a record that somebody has already looked at the finding and
written down why they are living with it, so repeating it at full volume on the
landing page tells them the one thing they went to the trouble of recording
that they know. A dashboard that never gets quieter as you work through it
makes the mechanism pointless.

So the two halves answer different questions. The **summary leads with what is
outstanding** — `1 warning (2 C, 1 W accepted)` on a card, `1 critical finding`
in the headline with "already accepted, and not counted above" underneath,
because without that clause a net figure beside an accepted count is
unreadable. The card's colour follows the outstanding count too; a red card
reading "1 warning" is a contradiction the eye resolves before the text does.
The **detail panel is unchanged** and still lists every accepted finding at its
own severity with its reason and author. Nothing is hidden in either; one says
what is left, the other says what is here.

A type where everything has been accepted says `all accepted (1 C, 1 W)` and is
left neutral rather than green, and the headline says *Nothing outstanding*.
Deliberately not "clean", which would claim nobody ever had to decide anything.

**An acknowledgement can be taken back.** `DELETE /acknowledgements/{rule_id}`,
and a *Stop accepting this* button sitting inside the note it undoes. The
guards are deliberately much lighter than the write's: every one of
`check_entry` exists to make *quietening* a finding expensive, on a service
holding credentials with no login, and none of that reasoning survives being
pointed the other way. The worst a wrong call here does is report something
loudly that somebody had decided about, which is the state the tool ships in.
`confirm` is still asked for and still repeats the id — not as a barrier, since
the page fills it in from the finding the button belongs to, but because it is
the one thing separating a request meaning *this* acknowledgement from one
cross-wired to another. No re-scan, unlike the write: an entry matching nothing
is exactly the stale one the audit reports and asks somebody to clear, so
refusing to remove it because the resource is gone would trap the mess it is
meant to clean up. The response echoes the reason back, because the file no
longer holds it and that response is the last place it exists. `remove()` drops
every entry for the id rather than the first — `record()` appends without
looking, so the file can hold two, and leaving one behind would answer "no
longer accepted" while the finding stayed dimmed.

**The page writes them now, and this paragraph used to say nothing could.**
The old rule was that no endpoint may create an acknowledgement, because it
would be a remote "stop reporting this" API on a service holding credentials
with no login. `main.py` had option 15 and the page had a Copy button
producing JSON to paste into a file by hand. A practice demo returned the
feedback that CLI functions should be minimal to nonexistent, which made the
only route to a documented feature the one nobody would use, so
`POST /acknowledgements` writes and the CLI option is gone.

What answers the original objection is that it was never specific to
acknowledgements. The same API already exposes `DELETE /resources/{type}/{id}`
with force; if the guards are trusted for destroying a VPC they are trusted
for dimming a finding. The cross-site POST the rule was written against is
refused by the middleware, on `Origin` and on `Host` —
`test_acknowledging_is_refused_from_another_site` pins exactly that request.

What it did cost is provenance. `by` came from git config, so the name
recorded was the one that would be on the commit; a browser cannot reproduce
that. The guards standing in for it are in `scanner/acknowledged.check_entry`:
`confirm` must repeat the rule id, a reason under fifteen characters and a
blank author are refused, no wildcards, and — new, with no CLI equivalent —
**the route re-scans the resource and refuses a rule id its own scan does not
report**, so an acknowledgement cannot be written for a finding that does not
exist. Newly written entries also expire within a year (`MAX_DAYS`), enforced
on write only: a committed entry with a longer date keeps it, because
re-interpreting somebody's recorded decision is worse than the date is. That
cap exists because a working tree here carried `"until": "2100-06-07"`.

**A rule id does not necessarily contain a colon.** The first version of
`check_entry` required one, on the belief that they are all
`<resource>:<setting>`. A security group's per-rule findings carry the
`SecurityGroupRuleId` straight from AWS — a bare `sgr-…` — so the check
refused acknowledging an administration port open to the internet, which is
this tool's flagship finding and the one most likely to be deliberate on a
jump box. The real guard against an invented id is the re-scan, not the shape.
`test_the_committed_file_parses_and_names_real_rule_ids` asserted the colon
too and had the same fix.

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
- **And once, moto was stricter than AWS**, which is the reverse of every
  other entry here and cost an hour. `secure_by_default` installs a bucket
  policy denying any request where `aws:SecureTransport` is false. moto
  **evaluates that policy**, against its own test client, which speaks plain
  HTTP — so a bucket created the secure way refuses every upload in the
  offline suite and accepts them perfectly against AWS, where boto3 has always
  used HTTPS. A test taking the refusal at face value would conclude uploads
  do not work. `_writable` in `test_s3_reuse.py` explains it; the claim that
  uploads work belongs to the smoke test, against a bucket created normally.
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

- **A read that is refused is not a resource that is absent, and all five
  readers said it was.** The fifth instance of the mistake above, and the one
  missed everywhere: every create path was fixed for it, and
  `read_account_for_scanning`, `read_vault_for_scanning`,
  `read_nsg_for_scanning`, `read_vnet_for_scanning` and `read_vm_for_scanning`
  all still returned None on 404 and re-raised everything else. Reading
  anything in a resource group this identity holds no role on arrived as a 500
  and a traceback about an HTTP response. The subscription makes that ordinary
  rather than theoretical: the service principal is Contributor on two named
  groups, so every other group answers 403 to a read. They check `denied()`
  first now and raise `AzureRefused`, which a handler in `api/app.py` turns
  into a 403 naming the group — 403 rather than 404, because telling somebody
  "there is nothing there" about a resource they merely cannot see is the more
  misleading answer and the one that sends them looking for something they
  never lost. Both halves are pinned: 404 still returns None.

- **A refused machine leaves three resources behind and said nothing about
  them.** `Standard_B1s` is on the allowlist and this subscription is not
  offered it, so `create_vm` builds a virtual network, a security group and a
  card, is then refused for the size, and answers with a clear sentence about
  which sizes would work. Every adapter returns `problems` carrying what it
  built, and the create route discarded that half on failure — so the one
  place a caller could read it was the one place it was thrown away, and
  *Nothing rolls back / partial failures report exactly what exists* held
  everywhere except there. The refusal carries the list now.

  **The leak is closed, and the entry that used to sit here was wrong in a way
  worth keeping.** Asking `available_sizes` before building anything prevents
  it completely, and that check was written, removed, and put back. It was
  removed on a number recorded here as fact — *"`resource_skus.list` takes over
  200 seconds even filtered to one location, measured here rather than
  guessed"* — which made the check look like a three-minute hang on every
  machine create.

  Re-measured on a quiet subscription it is **five to eight seconds** for 1,490
  SKUs, three consecutive runs, and the live refusal answers in 7.6. The slow
  reading was taken immediately after a burst of creates and deletes and was
  almost certainly Azure throttling with SDK backoff. Six seconds on a create
  that already takes a minute, to stop three resources being stranded, is a
  trade worth making — and recording a throttled number as the call's cost is
  what kept a real bug open. **A measurement taken once, under load, and
  written down as a property of the system is worse than no measurement**, and
  this file asserted it twice.

  What survives from that entry: `problems` still travels with a refused
  create, because a create can still fail after building scaffolding for
  reasons other than the size, and *Nothing rolls back* still means the tool
  reports what exists rather than destroying it.

- **Two name rules disagreed with Azure, both found at the edges rather than
  the middle.** A key vault name may not carry doubled hyphens — only the
  container half of that rule was written down, and `check_name_availability`
  answers `scp-edge--probe` with `available=False, reason=Invalid`. And a
  one-character security group name is legal: the pattern needed a first
  character and a last one, so it refused every one-character name while its
  own message promised "1 to 80 characters" — an error naming the rule the
  name had just satisfied. Verified by creating a group called `a` and
  deleting it.

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

**Deleting a machine takes its network card and its address with it, and stops
there.** That is a narrowing of a rule this file used to state more broadly —
`delete_vm` removed the machine and the disk and left four resources, on the
stated grounds that this tool may not have made them. Right about the virtual
network and the security group: both are reusable, another machine may already
be in them, and both are registered types with their own delete route. Wrong
about the card. A card attaches one machine to one network, it is worth nothing
the moment that machine is gone, and *nothing in the registry can delete one* —
so the stranded card stranded the other two as well, because Azure refuses to
delete a subnet or a group a card still references. The API had no route to a
clean subscription at all; clearing up after a machine meant reaching past this
tool with the SDK. Only what carries this tool's tag is removed, so the rule
the original refusal protected is intact, and `plan_deletion` moved the card
and the address from the survivors to the destroyed — it had been agreeing with
a delete that stranded them.

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

## What driving the page found that nothing else did

The offline suite passed, both smoke tests passed, and the page had five bugs
in it. All five were found by opening it in a real browser with Playwright and
doing the ordinary thing — create something, look at it, fix it, delete it —
against real accounts. `frontend/browse.mjs` does the sweep; the lifecycle
scripts that found these were throwaways.

They are worth reading as a set, because four of the five share one shape:
**the page and the API disagreed about something, and every test on each side
of the seam agreed with its own side.**

- **"Not scanned" was rendered as "clean".** `worst_level` is null both when
  nothing was found and when nothing was looked for, and *scan each (slow)*
  was off by default — so every row on first load carried a verdict nobody had
  asked for. A storage account with two critical findings sat in the list
  labelled clean. This is the failure this project warns about in the IAM
  scanner and then shipped on the front page: *a partial scan that looks clean
  is the one way this tool can actively mislead.* `counts` is the signal,
  because it is set only when a scan ran.

  That checkbox is gone — scanning moved to the Dashboard — but the rule it
  taught is now enforced in four more places: the list's "not scanned"
  verdict, the dashboard cards, the account headline, and the empty states.
  Every one of them had to be written twice to get it right, so it is worth
  saying plainly: **nothing on this page may print a verdict it did not earn
  by scanning.**

- **An Azure row was keyed by something that cannot survive a URL.** The list
  returned the full ARM path, which carries eight slashes; a route takes its id
  as one path segment. So `/resources/azure-storage/<that>` matched no route
  and 404'd before any Azure code ran. The readers accept either form quite
  happily, which is exactly why nothing offline noticed — every test that
  called one passed it a name. What it cost was the page, which passes a row's
  id straight into scan, fix and delete: creating an Azure resource worked, and
  then the detail panel said "Not Found" about the thing it had just built and
  the delete modal opened empty with its button disabled forever.

- **Three Azure types could not be deleted through the API at all.** AWS
  returns a flat list of things a delete destroys; all three Azure planners
  return `{"items", "destroys", "message"}`, and the route did
  `DeletionPlanItem(**item)` over it — which iterates a dict as its keys and
  raises on the first one. `azure-nsg`, `azure-vnet` and `azure-vm` answered
  500 on their deletion plan *and* on the delete. The route takes both shapes
  now and keeps the Azure message, because the generic one counts items and
  calls them destroyed, which is false of a security group whose delete
  destroys nothing and merely stops filtering whatever was behind it.

- **The machine size menu offered nine sizes that cannot start.** Azure
  restricts sizes per subscription as well as per region and reports both as
  `SkuNotAvailable`, so `ALLOWED_VM_SIZES` is what this tool permits rather
  than what a subscription can launch. `az/vm.py` already had `available_sizes`
  and already used it to explain a refusal; the form was not asking it. Against
  the real subscription the menu offered fourteen and five worked — and all
  three `Standard_B1*` entries, which sit at the top of the list and are what
  somebody picks, were among the nine that fail.

- **The machine form threw away half of what you typed.** `ResourceSpec`
  declared no `vm_size`, `open_ports`, `allowed_source` or
  `encryption_at_host`, and pydantic drops what a model does not declare, so
  `_az_vm_create` and `check_vm_spec` read all four as None however the form
  was filled in. The pre-flight was the dangerous half: a form opening 22 to
  the entire internet on a machine with a public address answered **0
  critical** — this tool declaring safe the exact configuration the type exists
  to warn about. The create then ignored the ports as well, so the machine came
  up without the access somebody asked for and nothing said so either way.

Two smaller things, both from the same runs:

- **The acknowledgement audit was answering a question it could not see.** It
  compared every entry against the rule ids of one resource's scan and reported
  each one that was not about that resource — which is most of them, every
  time. Two entries for a single S3 bucket produced two informational findings
  on every scan of every other resource in both clouds. It was never a
  cross-cloud problem; scanning a second bucket did the same. `audit(...,
  scanned=)` scopes it; `None` keeps the unscoped behaviour for the
  whole-account sweep that could honestly answer it, which nothing runs yet.

- **`azure-mgmt-compute` was listed in no requirements file.** `az/vm.py` has
  needed it since virtual machines arrived. A checkout that installed both
  files still could not open that tab, and said so as a 503 naming a module
  rather than as an import error — which is the lazy-import design working: the
  page starts and one type is unavailable.

**The browser is now part of how this is checked.** `frontend/browse.mjs`
drives every sidebar entry in a real Chromium against the real API, collects
console errors, and screenshots each one, because the class of bug that makes a
button silently do nothing leaves no other trace. It needs `npx playwright
install chromium` once. It is not in `npm test`, because it needs a running
server and a real account; run it before believing the page works, the same way
the smoke test is run before believing the API does.

## Seven things the create path got wrong, and none of them had a test

Found by starting the server and creating every type through its own routes,
against both real clouds — nine of the eleven creatable types, all of it
deleted afterwards. `instance` and `azure-vm` were left out as the two that
cost money; their guardrails were exercised instead. The seventh was then
found in `instance` anyway, by reading the code the first fix had touched
rather than by building a machine.

The suites were green throughout. Four of the seven live on the page/API seam,
which is the same lesson as *What driving the page found* and is now the third
time this file has had to record it.

- **A bucket could not be created outside `us-east-1`.** `region` is a query
  parameter and never a body field. `_spec_for_checking` injected it for the
  pre-flight and the create was handed a bare `spec.as_dict()`, so
  `_bucket_create` fell through to `DEFAULT_REGION` while the client was built
  for the region actually chosen — and `create_bucket` branches on the
  argument, omitting `CreateBucketConfiguration`, which a regional endpoint
  rejects. Verified failing in `us-west-2` and `eu-west-1` and succeeding in
  `us-east-1`. Both now use one dict, so **the pre-flight and the create can no
  longer judge different requests** — which was the larger bug and was not
  bucket-specific. The upload route's hardcoded `us-east-1` went with it: it
  was unreachable only because no bucket could exist anywhere else.

- **A server could only be launched in `us-east-1`, for exactly the same
  reason, and nobody had ever seen it.** `launch_instance` calls
  `latest_ami(region)`, and an AMI id is region-specific — so with `region`
  missing from the create's spec it was pinned to `DEFAULT_REGION` while the
  EC2 client was built for the region actually chosen, and `RunInstances` was
  handed an image belonging to somewhere else. AWS answers
  `InvalidAMIID.NotFound`.

  The same shared dict fixed it, but it is listed separately because of *why*
  it went unseen. Machines **have** been launched here — `--with-instances`
  does it, and the browser sweep did it — and every one of them was launched in
  `us-east-1`, where the pinned `DEFAULT_REGION` happens to equal the region
  the client was built for. The defect is invisible at the default and total
  everywhere else, so the more a thing is exercised in one region the better it
  hides. That is the same shape as the `resource_skus` timing and the
  `/home/user` virtualenv: something true of one setting, mistaken for a
  property of the system.

  It surfaced only when the two remaining adapters that read `region` were
  checked for fallout from the bucket fix. Both were fine, and the check is
  worth recording so nobody repeats it: `create_vpc` takes a `region` argument
  and never uses it, and `create_alarm` already did `region or
  cloudwatch.meta.region_name`, which resolves to the same value either way.
  Pinned by a test that spies on the region reaching `launch_instance` rather
  than by launching anything — and **since proved against AWS**: a `t3.micro`
  was launched, scanned and terminated in `us-west-2` through the HTTP routes,
  which is precisely the case that used to answer `InvalidAMIID.NotFound`. It
  is the only one of the seven whose fix went that long on offline evidence
  alone, for the same reason the defect hid in the first place — it is the type
  that costs money to check.

- **Three of the four networks the menu offers had no subnets.**
  `PUBLIC_SUBNET_CIDR`/`PRIVATE_SUBNET_CIDR` were constants inside
  `10.0.0.0/16` and inside none of the other three choices, so both
  `create_subnet` calls failed and the VPC came back as created with the
  failures in `problems`. `subnet_cidrs` derives them from the CIDR asked for,
  and still answers `10.0.1.0/24` and `10.0.2.0/24` for the default so nothing
  already running moves.

  The two constants are **deleted**, not left beside it. Nothing referenced
  them once the function existed, and a module-level name reading
  `PUBLIC_SUBNET_CIDR` asserts that the public subnet has one address range —
  true of one network in four and false of the rest. An orphan that
  authoritative is worth more than the line it costs to remove, and it is the
  kind of thing a later reader imports precisely because it looks settled.

- **Every Azure create stranded its own resource.** The create answered with
  the full ARM path, and a route takes an id as one path segment — so read,
  scan, fix, the deletion plan and delete all 404'd on the id the create had
  just returned. A resource built from the page could not be deleted from the
  page; three live ones had to be removed by typing their names in. The list
  adapters were fixed for this and the create adapters were not, which is
  exactly why nothing caught it: a list-then-act flow works and a
  create-then-act flow does not. `_az_created` reduces the id at the one place
  all five types return through, and leaves the error half alone — a refusal
  travels on that same channel, and a sentence trimmed to its last word would
  be an error message destroyed by a fix aimed elsewhere.

- **The Azure location box did nothing.** All five Azure forms ask for
  `location`, `ResourceSpec` declared only `region`, and pydantic drops what it
  does not declare — so typing `westeurope` built in `eastus` and reported
  success. Three adapters already read `spec.get("location")` as a fallback
  that could never fire. `location` is declared now and `_az_location` is the
  one place the two spellings meet; `region` still wins, because that is what
  the CLI and the smoke test send.

- **Choosing "CPU usage (%)" built an alarm watching `EstimatedCharges`.** The
  menu picks a namespace and a metric together and only the namespace was
  carried, so `metric_name` fell back to billing unconditionally. That pair has
  no data, CloudWatch accepts it, and the alarm sits in `INSUFFICIENT_DATA`
  forever — *an alarm fails by being quiet*, produced by the tool that exists
  to report exactly that. It could not report it: no rule reads `metric_name`,
  so the pre-flight and the read-back scan both called it clean.

- **A multi-select submitted one value.** `multiChoice` did
  `select.value = () => …`, but `value` is an accessor on
  `HTMLSelectElement.prototype`, so the assignment went through the setter and
  never created an own property. `collectSpec` then took its plain-`<input>`
  branch and split on commas, and a multi-select's getter returns only the
  first selected option. Picking ports 22, 80 and 443 sent `["22"]`. It hit
  `azure-vm.open_ports` and `instance.security_group_ids`, and blinded the
  pre-flight identically — asking to expose RDP alongside 80 reported on 80 and
  said nothing about RDP, so create and check agreed with each other about a
  machine nobody had asked for. The same idiom works elsewhere in the file
  because it is applied to a `<span>` and to `<div>`s, which have no `value`
  accessor to collide with, which is why it looked like a working pattern.

**Every one is pinned by a test that fails without the fix**, checked by
stashing the source and re-running. That is worth stating because the whole
point of this section is that thirteen hundred existing checks did not fail:
`app.test.mjs` had never driven a multi-select at all, and moto records a
bucket's location from the client rather than from the argument, so the
end-to-end version of the bucket test passes against the bug. The bucket test
asserts what the cloud call was handed instead.

## What reading the scanner found that driving it could not

Every previous section here records a defect found by running something. This
one is a reading pass over `scanner/`, module by module, each candidate checked
by calling the rule directly with the values that reach it rather than by
reasoning about the code. It found the two worst defects in this file's
history, and neither could have been found any other way: the page renders them
correctly, the suites pass, and both clouds agree with each other. They are
wrong together.

**Two of these are one mistake.** A check written as string equality against
the literal form of a dangerous value, where the dangerous value has other
spellings. The comment beside each explained why the *narrow* case was
deliberate, and the code quietly swallowed the broad one along with it. Look
for this shape anywhere a rule asks "is this the bad value" rather than "is
this a bad value".

- **A firewall rule could open SSH to two billion addresses and neither cloud
  said anything.** `is_public` was `source in {"0.0.0.0/0", "::/0"}`, and
  Azure's `EVERYONE` was four literals matched the same way. `0.0.0.0/1` and
  `128.0.0.0/1` are two rules covering every address on the internet and both
  were silent; so were `0.0.0.0/4` and `::/1`. Azure was worse than silent —
  `azure_nsg_effective.decide` returned `DenyByDefault`, a positive statement
  that a port was closed, about one it would have opened to half the internet.

  This is the shape somebody adds a backdoor around, because every scanner
  looks for `/0`. The comment on the silent branch was reasoning about
  *private* ranges — "there is nothing to say about port 443 from a private
  range" — and a broad public one is not that.

  `common.open_to_strangers` is the judgement now and both clouds ask it.
  Private, reserved, loopback, carrier-grade-NAT and documentation space stay
  silent however large, via Python's `is_global` rather than a hand-kept
  RFC1918 list: `10.0.0.0/8` is sixteen million addresses and not one of them
  is a stranger. Public space fires at a **/16 or shorter**, because a real
  allowlist is an office, a VPN endpoint or one machine — a /24 or smaller in
  practice — and nothing legitimately permits SSH from sixty-five thousand
  arbitrary hosts. IPv6 is set at **/32**, because the scales do not
  correspond: a site is given a /48 and an internet provider a /32. Anything
  that will not parse is still not open, which is what keeps the promise
  `azure_nsg_effective` makes about never manufacturing an Allow the cloud
  would not make. Both thresholds are constants and both are judgement calls.

- **The escalation engine missed the ordinary spelling of "any role".**
  `escalation.permits` required `Resource` to be a bare `*`, so `iam:PassRole`
  with `ec2:RunInstances` on `arn:aws:iam::123456789012:role/*` — every role in
  the account, written the way the console writes it — reported nothing at all.
  Same for `arn:aws:iam::*:role/*` and `CreatePolicyVersion` on `policy/*`.
  `role_rules` and `iam_rules` share this one matcher, so the gap applied to
  all three identity kinds at once.

  The reasoning beside it was sound and the code did not implement it: "a
  policy that can pass one named role is a deliberate arrangement" is true, and
  a wildcard ARN is not one named role. `_unrestricted` is deliberately narrow
  — **IAM ARNs only**, because `arn:aws:s3:::mybucket/*` is every object in one
  bucket and reading a trailing `/*` as "everything" everywhere would report an
  ordinary bucket policy as unrestricted access to all data; and **prefixes
  excluded**, because `role/build-*` is a family somebody chose the shape of.
  Trading a false negative for a false positive is not a fix.

**Three reads that resolved to the reassuring answer.** Same family as
*A reader returns None when the thing is not there*, in the places that rule
had not reached.

- `aws/vpcs.list_vpcs` answered a denied `DescribeVpcs` with an empty list, so
  the route returned 200 with no networks and the page printed "none" — the one
  word meaning somebody looked and there was nothing there. Every other type
  reports "unreachable" because every other list either raises or lets the
  error out. It raises `PermissionDenied` now, like `roles.py`.
- `az/vm.read_vm_for_scanning` wrapped three reads in one `try` and recorded
  one key, and `public_ip` was the one it did not record. Both the
  administration-port finding and the password one are CRITICAL on a reachable
  machine and WARNING otherwise, so an unreadable address silently bought the
  milder verdict and `describe_vm` then showed the machine as having none.
  Three separate reads now, each failure recorded against the setting it
  actually prevents, and `azure_vm_rules` treats an unknown address as
  reachable rather than as absent.
- `az/vm._os_disk_encrypted` was `True if os_disk is not None`, which is not a
  check of anything: the value could only ever be True or None, so the rule
  testing it for False could never fire — and what that rule is kept for, "an
  older or imported disk", is exactly the case it could not see. It reads the
  disk now: managed is encrypted, unmanaged is a page blob and is not, neither
  is unreadable.

**And the sixth instance of the 404-without-403 mistake**, in `az/nsg.apply_fix`
— the identical read to `read_nsg_for_scanning` 370 lines above it, without the
`denied()` check that one has. `_locate` returns immediately when handed a full
resource id, so nothing enumerates first and absorbs it.

**Two places that discarded what they had already learned.**

- `blueprints/bastion.build` replaced `problems` with one fresh sentence at all
  ten of its failure returns, and the failing step's own problems with it. A
  network that was built and whose DNS attribute could not be set came back as
  `vpc-1` and an unrelated error: the caller was told the network exists and
  not what is wrong with it. The same defect this file records for the Azure
  machine create, in the one other place that accumulates as it goes.
- `api/registry._metric_for` ended `return alarms.BILLING_METRIC`, which pairs
  any third namespace with `EstimatedCharges` and rebuilds the silent alarm the
  fix was written for — the defect reproduced by its own repair. It is a
  mapping returning None now, and the adapter refuses rather than guessing.

**One thing the fix exposed rather than caused.** With `list_vpcs` no longer
swallowing, `test_a_nat_gateway_is_refused_with_the_price_named` failed with
`AuthFailure` — its last assertion sat *outside* the `with mock_aws()` block
and had been talking to real AWS since it was written. The swallow made it pass
vacuously. That is the third offline test in this project found reaching the
network, and it is most of why the suite is now half a minute faster.

**What was read and found correct**, stated because a list of defects reads as
though the package is riddled with them and it is not. `azure_nsg_effective` is
right about everything else it claims — priority ordering both ways, shadowing,
Azure's own default rules, port ranges, protocol matching, an unparseable
priority sorting last rather than first. `s3_rules` and `snapshot_rules` report
every exposure and never resolve an unreadable setting into silence.
`iam_rules` produces seven "could not check" warnings and no misleading quiet
when nothing at all can be read. Every one of the 23 control names cited across
the package resolves, and none is orphaned. All fourteen guards in
`acknowledged.check_entry` refuse what they should.

The `unreadable` discipline is genuinely consistent: where a check fires on
*presence* there is no guard and none is needed, and where it fires on
*absence* the guard is there. That asymmetry looks like an oversight and is
not.

## What comparing the two surfaces found

The four surfaces this file listed as never systematically audited — fix,
delete/cleanup/deletion-plan, the bastion blueprint and the CLI — have now had
the treatment the create path got: not driving them, but sitting down and
comparing what each side sends against what the other reads.

Three of the four came back clean, and that is worth stating as plainly as the
defect below, because a section that only lists faults reads as though the
package is riddled with them. **The fix path** re-derives its action from the
server's own current scan and refuses a rule id that scan does not report;
the three Azure types that decline to fix are wired up and return a reason
rather than doing nothing quietly. **The delete path** enforces `confirm`
repeating the resource's own id before `force` does anything, on the streaming
route as well as the plain one, and takes both the flat AWS plan and the
`{"items", "destroys", "message"}` Azure one. **The blueprint** routes all ten
of its failure returns through one helper that concatenates the accumulated
problems with the failing step's own, so the fix recorded earlier in this file
held everywhere rather than at the places somebody remembered.

**The CLI was the one that had drifted, exactly as this file guessed it would.**
The entry predicting it was right about the surface and wrong about the
mechanism — it expected another namespace/metric pairing, and what was there
was a menu with no pre-flight at all.

- **`bucket_menu` never ran `check_spec`.** Every other creating menu does. It
  described the deliberately-weak option in a hand-written sentence naming
  three problems — no encryption, no versioning, no public access block — and
  the scanner reports **five** for that spec, two of them critical. The
  sentence had quietly stopped mentioning that the bucket accepts plain
  unencrypted connections.

  Which is the failure this file already describes, in the entry explaining why
  the Azure menus show `check_spec` output rather than a sentence per type: *a
  sentence goes stale the moment a rule is added, and showing the findings is
  the thing this tool exists to do*. The reasoning was written down, applied to
  Azure, and never applied to the older menu it was learned from.

  The seam half is worse than the staleness. `POST /resources/bucket` runs
  `_bucket_check_spec` and **refuses** a critical spec unless `accept_risk` is
  passed. The CLI printed its three sentences and took a y/N. So the same tool
  declined a configuration on one surface and built it on the other, which is
  precisely the divergence the alarm bug was, running the other way.

- **`security_group_menu` kept its own copy of which scanner belongs to the
  type**, calling `check_firewall_rules` directly where the registry has
  `_sg_check_spec`. The same call today, so nothing was wrong — and the same
  shape as the alarm defect, which was also two places agreeing until one of
  them changed. It goes through the registry now.

- **`instance_menu` never asked which size to build**, found on a second pass
  over the same surface. It asked for a network, a subnet, a key pair, security
  groups and a public address, then built a spec with no `instance_type` in it
  — so `launch_instance` fell through to `DEFAULT_INSTANCE_TYPE` and every
  machine the CLI has ever started has been a `t3.micro`, against twelve on the
  page. It reads `resource.options` now, the way `azure_vm_menu` always has.

  Harmless on its own: the smallest size on the allowlist, and the refusal that
  makes the allowlist matter was never in question. It is listed because of the
  pattern it completes. Three defects on this surface now — the alarm metric,
  the bucket pre-flight, and this — and all three are the same sentence: two
  front ends over one registry, and the older one quietly does less. None of
  them was a wrong answer. Each was an answer the CLI never asked for.

  It also corrected something this file was asserting. The paragraph explaining
  why the AWS menus are bespoke and the Azure ones generic gave "an instance
  size" as an example of what an AWS menu asks, and that example was the one
  thing in the list that had never been true.

**The CLI had no tests at all**, which is uncomfortable for the surface most
likely to drift and is most of why this went unseen. `backend/tests/test_cli.py`
exists now. It does not drive the menus, which read from stdin; it parses
`main.py` and asserts that every function reaching a create call also reaches
`check_spec`. Two menus are exempt, and the exemption is written so it cannot
rot: a second test re-derives that `key-pair` and `network` really do return
nothing from `check_spec` for any spec, so adding a rule to either scanner
fails the suite rather than letting the omission go quiet.

**Two smaller things, both found by probing rather than reading.**

- A rule can produce several findings sharing one `rule_id` — a port range of
  3306 to 3389 covers two entries in `RISKY_PORTS` and is under the hundred-port
  width that would have caught it earlier. `POST /fix` resolves a rule id with
  `next()`, so it acts on the first. Checked rather than assumed: every finding
  from that path carries the same `narrow_to_my_ip` action, so first-match and
  best-match are the same thing. Not a defect, recorded because the next person
  to read that `next()` will wonder.
- `_sg_create` no longer falls back to the account's default VPC. This was the
  last place in the program that guessed where to put something, it contradicted
  *placement is asked for, never assumed*, and it was only reachable over HTTP
  because both interactive surfaces ask — so the one caller who could hit it was
  a script, the caller least likely to notice its group had landed somewhere it
  did not choose. Removing it broke twenty API tests, all of which had been
  riding the fallback; the fixture chooses a network explicitly now, which is
  the right end for a test about routes to make the choice.

## The two threshold numbers, checked at last

`common.BROAD_PREFIX_V4` is 16 and `BROAD_PREFIX_V6` is 32. This file listed
them as judgement calls with the reasoning written beside them that nobody had
checked against a real allowlist. They have been checked. **Both survive, and
the reasoning written beside them was wrong.**

The claim was that nothing legitimate exceeds a /16 — that a real allowlist is
an office or a VPN endpoint, a /24 or smaller. That is simply false.
Cloudflare publishes `104.16.0.0/12` and egresses from `172.64.0.0/13`; MIT
holds `18.0.0.0/8`. All three are real, all three get named in real firewall
rules, and all three fire here.

What makes firing correct is not the size but **where the judgement is
consulted**. The architecture that names a range that large is an origin lock —
a web server accepting 443 only from its CDN — and `rules.py` returns silently
on 443 whatever the source is, so that case produces nothing regardless of this
number. What fires is `104.16.0.0/12` on port 22, and that is somebody trusting
every host that can rent space behind that CDN. A broad range is not dangerous
because it is broad; it is dangerous because nobody chose who is inside it, and
an administration port is where that distinction costs something.

**One trap, met while checking it, and now written into the code.** The obvious
range to probe the IPv6 threshold with is `2001:db8::/32`, and it proves
nothing: that is the documentation range, `is_global` excludes it before the
prefix is looked at, and the assertion passes for a reason that has nothing to
do with the number being tested. It has to be routable space —
`2606:4700::/32` is a provider allocation and fires, `2606:4700:4700::/48` is
one site inside it and does not. The boundary had never been pinned in either
address family; it is now.

**Then it was measured, and the answer is more interesting than the number.**
The evidence above is six anecdotes, and every one sits on an easy side of the
line: Cloudflare `/12`, Cloudflare `/13` and MIT `/8` above it, `/32`, `/24`
and `/22` below. Nothing had looked at the band between. So 17,662 IPv4 ranges
published by AWS, Cloudflare, GitHub and Google Cloud were counted. **8.2% are
/16 or wider and fire. 55.7% sit between /17 and /24 and are silent on every
port.** The gate does not see most of what these organisations publish.

That alone is only a coverage figure, and it is a proxy — what an organisation
*publishes* is not what a person *pastes*, and the aggregate is dominated by
how finely AWS chooses to enumerate itself. **Cloudflare's own list settles it
properly**, because it is short, canonical, and is the paste-this list: fifteen
ranges, all expressing one decision — *anyone who can put a site behind this
CDN*. On port 22 this gate calls **four of them critical and eleven of them
nothing**. One configuration, two verdicts, decided by which line you look at.

**The conclusion is not that /16 is wrong.** A gate at /22 makes Cloudflare
coherent and then fires on an office /22, which is a range somebody does
control. A gate at /20 splits the list somewhere else. Every candidate is the
same mistake as the incumbent, because *width is a proxy for "nobody chose who
is inside this" and the two come apart*: an office /22 and a CDN /22 are the
same size and opposite decisions, and nothing in a CIDR says which is which.
**No threshold can separate them.** So this is a pragmatic cut, not a
principled boundary, and describing it honestly is worth more than moving it.

It stays at 16 and 32. What changed is the claim made for it — and the study
also closed the question of whether to add a second, tighter threshold for
administration ports, which had looked like the obvious next step and turns out
to relocate the incoherence rather than remove it.

## An account-wide type, and what it cost

Everything registered here had been a *thing*: a bucket, a machine, a firewall.
Two findings were not. CIS 1.19 asks for an Access Analyzer in every region and
Prowler's monitor block asks whether a subscription reports its own security
changes — both are questions about an account rather than about anything in it,
and this file listed both as open on the grounds that `ResourceType` had no
shape for them.

It turned out to need no new shape at all. **The routes take an id as one path
segment, and a subscription id is one.** `azure-monitor` is a read-only
`ResourceType` whose `list_all` returns exactly one row, whose id is the
subscription, and whose `read` refuses to answer about any other subscription
the way `read_account_for_scanning` already refuses about another AWS account.
No route changed. The alternative — a `scope` field taught to every route and
to the page — would have been surgery on the seam every other type depends on,
to serve one entry.

That is now the second time the registry claim has held under a load it was not
designed for, and it is a stronger test than adding Azure was: a second cloud
is still a resource, and this is not.

**What the monitor rules say, and what they refuse to say.** The reasoning is
`scanner/alarm_rules.py`'s, carried across without modification — *an alarm
fails by being quiet*. Three findings, and the ordering between them is the
part worth reading:

- An alert that exists and is **switched off** is worse than one that was never
  written, because it appears in the portal's list exactly like a working one
  and satisfies every glance.
- An alert that is on but has **no action group** is the Azure spelling of an
  alarm with no SNS topic: it fires, it is recorded, and it reaches nobody.
- Whatever is **not watched at all**, as one sentence when there are no alerts
  and as a note when there are some. Five findings on a subscription with none
  teaches people to close the panel.

The trap in that set is the third. Only alerts that are both enabled *and*
reachable count as cover — otherwise a subscription reports "everything is
watched" on the strength of alerts that cannot speak, and the first two
findings quietly buy off the third. Pinned by a test that sets each of the two
broken states in turn and asserts the gap is still reported.

Nothing here carries a citation, for the reason the rest of `az/` already
gives: CIS AWS Foundations plainly does not reach Azure, the CIS Azure
benchmark is a document nobody on this project has read, and Prowler is not a
published benchmark to cite in its place.

**What it does not cover, stated rather than worked around.** Roughly a third
of Prowler's monitor block is about diagnostic settings — whether the activity
log is exported somewhere it outlives the ninety days Azure keeps it.
`azure-mgmt-monitor` 7.0.0 ships **no diagnostic-settings operation group at
all**, so those are unreachable without a different API version or a raw ARM
call. Same treatment as the three Azure vault constraints: named, not guessed
at. Defender is a separate and deliberate no — its checks ask whether paid
Microsoft products are licensed, which is a purchasing decision.

**It has now run against the subscription, once.** This entry said it had
not, and that `az/monitor.py` sat exactly where `az/` as a whole sat before its
first live run found four bugs in code the offline suite covered.
`GET /resources/azure-monitor` answers **200** against
`74baf379-b419-4e16-a50b-98bc450901c9`: the subscription listed as its own
single resource, scanned, **one warning and no criticals**. So the type is
wired to the registry, the credentials reach the monitor API, and the id
round-trips through a route — none of which had been shown.

Everything else here is still offline, on a stub that models two things a naive
fake would not: the SDK enums that render through `str()` as
`'ClassName.MEMBER'`, and `enabled` being *absent* rather than false on an
alert that is on. Both are traps this file has already paid for once. **One
read is not a campaign, and the warning that entry carried has only been half
discharged:** nothing has yet created an activity log alert, switched one off,
or stripped its action group and watched the finding change, which is what
would exercise the three rules against Azure rather than against a fake of
Azure. **A stub written to match the code cannot disagree with it**, and that
still stands for every rule in `scanner/azure_monitor_rules.py`. Read the live
result as evidence the plumbing is real, not as evidence the judgements are.

## Style

Comments explain *why*, not what. Test names are sentences describing the
behaviour being protected. Warning messages are aimed at someone who does not
know the jargon: acronyms and IP addresses are jargon, ordinary words are not.
Severity means something — if everything is critical, nothing is.

## The page is three tabs now

The sidebar used to be one list called RESOURCES holding all fourteen types,
and the panel under it held the form you fill in to make something *and* the
report you read to find out what is wrong with it. Those are different jobs
done at different times. The page is **Dashboard, Create, Audit**.

**Create** offers only the eleven types that can be created, plus the bastion
blueprint. The three audit-only ones are absent: a form whose create route
always answers 405 is an advertised endpoint that can never work, which is
what `read_only` has always meant on the server. It used to be drawn and then
explained away by a panel saying so.

**Audit** lists every type, because scanning a bucket made a minute ago and
auditing a role somebody else made are the same activity. It reads and does
not scan — see below.

**Dashboard** is new. It counts what is in the account (one list call per
type, in parallel, about a second) and then scans it (`with_scan=true` per
type, also in parallel) without being asked. That second part was a button
until it was measured: **3.4 seconds for a whole AWS account and 3.6 for a
whole subscription**, because only the resources *inside* one type are
scanned serially. Three seconds is not a reason to make somebody press a
button, and a card reading "not scanned" has not answered the question the
page exists to answer.

**Scanning happens in one place and its answers are read in another.**
`state.scans` holds what the dashboard found, keyed by type and then by
resource id, with the time it was taken. The Audit list renders from that and
never scans on open — a list that scanned as a side effect of being opened
was a minute of waiting nobody asked for, which is why the old "scan each
(slow)" checkbox was never ticked and the column it filled sat empty.

Two things the cache has to do to stay honest. It shows when it was taken, so
a verdict carries its own age. And it is thrown away for a type the moment
anything in that type is created, fixed, acknowledged, deleted or cleaned up:
a verdict about a resource that has since changed is not merely old, it is
wrong while carrying a timestamp that makes it look checked.

**One sentence says how the account stands**, above the grid. Its wording is
the part that goes wrong quietly, and three rules hold it:

- A type that could not be read is not a type with nothing wrong in it. If
  anything was unreachable it says "Scan incomplete" and names which type, and
  can never reach the clean wording.
- An empty account is empty, not safe.
- No criticals with fourteen warnings is good news *and* unfinished news, so
  it says both rather than hiding the second behind the first.

**Findings are grouped behind their own counts.** Each severity is a drawer
and its count is the handle; one is open at a time; criticals arrive open and
nothing else does. Empty levels stay on screen, disabled, because a level
silently missing cannot be told from one that was never checked. `accepted` is
a count and not a drawer — those findings are still listed under their own
severity, so a fourth drawer would either list them twice or subtract them
from the level they belong to.

**A delete says what it is doing while it does it.** `DELETE …?stream=true`
answers newline-delimited JSON, one object per step, then the outcome.
`aws/vpcs.delete_vpc` takes a `report` callback — the steps were always named
and the names were thrown away, so a cascade gave one answer four or five
minutes after asking and nothing in between, which is indistinguishable from a
hang. Nearly all of that time is `wait_for_interfaces_to_clear`; it reports
when the count *changes*, not once per poll, because fifty identical lines
scroll the earlier steps off the screen. The page runs a clock, which is what
says the thing is alive; the log says what it is doing. Two different
questions, two different elements.

**The visual rules, which are load-bearing rather than taste.**

- **Colour means severity and nothing else.** A drifting three-blob gradient
  used to cover the viewport, tinting every panel a different shade depending
  on where it had drifted to, and the panels were 84% white with a backdrop
  blur so they picked it up. Both are gone. What is left is a fixed wash under
  the header and one accent stripe naming the cloud.
- **No grey text.** Five greys carried hierarchy; they are all ink now, and
  the hierarchy is carried by size, weight, case and spacing. `#82847e` on
  white was also 3.5:1, under the 4.5:1 ordinary text should clear. Two
  exceptions, neither of them hierarchy: input placeholders stay grey, because
  a black placeholder is indistinguishable from a typed value; and an
  acknowledged finding no longer fades, because `opacity: .55` greyed the
  reason somebody wrote for accepting it, which is the part a reviewer is
  there to read.
- **Nothing in a form is smaller than the page's own prose.** Measured at 9.5
  to 13px against a 14px body before it was fixed.
- **A menu label has to fit its closed control.** The scanner's prose and a
  dropdown are different jobs: `RISKY_PORTS` says "the remote login door for
  Windows servers" in a finding, and `PORT_MENU_LABELS` says "Remote Desktop"
  in a menu. Every menu label is *contained in* the scanner's phrase, which is
  what a test asserts — the two have to agree, not be identical.

**Assets are versioned, and this is worth knowing before debugging a stale
page.** `Cache-Control: no-cache` was added and did not help, because a header
only governs responses fetched *after* it exists: a browser holding an old
`style.css` from a response with no cache header gives it a heuristic
freshness lifetime and uses it without asking. The page is served from its own
route with every asset stamped `?v=<mtime>`, so the URL changes exactly when
the file does. If a change does not appear, that is now a real bug rather than
caching.

## Not done

- **The four surfaces have now been audited.** See *What comparing the two
  surfaces found*. The fix, delete/cleanup/deletion-plan and blueprint paths
  came back clean against the specific claims this file makes about them; the
  CLI held one real defect and one latent copy, both fixed, and gained the
  first tests it has ever had.

  What this entry used to say — that an audit was started, ran out of capacity
  partway and returned nothing for or against — happened a second time and is
  worth keeping as a note about method. The audit was first handed to a fan-out
  of parallel readers, one per surface, and was stopped on cost before any of
  them returned. The finished version was done inline, one surface at a time,
  by grepping for the specific claim and then calling the code with the values
  that reach it. That was cheaper and is the approach to repeat.

  It is a narrower pass than the create-path audit, and the difference is worth
  being honest about: that one traced every form field of every type to the
  adapter reading it. This one checked the properties this file asserts, plus
  whatever the probes turned up around them. A field-by-field trace of the fix
  and delete paths would still be a different and more thorough exercise.

- **The page shows one cloud at a time, and builds firewalls with rules in
  them.** A toggle in the header switches between AWS and Azure and the
  page repaints, so which account is in front of you is not a tab label to
  read. What that fixed was not cosmetic: "This talks to a real AWS account"
  and the AWS region selector used to sit above the five Azure tabs, at a
  subscription that has never heard of `us-east-1`, and the bastion blueprint
  rendered as a panel under every one of them. Each now lives in its own
  branch, and the blueprint is a sidebar entry rather than a panel.

  The rest of this entry described a single page with one RESOURCES sidebar.
  That is no longer the shape — see *The page is three tabs now*. The two
  smaller gaps below are still open.

  `azure-nsg` used to be the exception, creating an empty group because the
  AWS `rules` widget emits AWS-shaped rules. It has its own widget now —
  `azureRuleRow` — carrying the three fields an AWS rule has no equivalent
  for: a name, a direction, and an access that can be **Deny**. No priority
  field, because `_priorities_for` numbers them from the row order and the
  arrows are what change it.

  Both smaller gaps against the design are now closed. The Azure table used to
  show the name in both its columns, because an Azure row's id *is* its name;
  it now shows the resource group and the location instead, which is what the
  mockup asked for. That cost one line — `_az_summary` carries both fields
  through where it had been dropping them, and the five list adapters all go
  through it, so none of them needed touching. The readers had always known
  both. The page adds the two columns when the rows carry them rather than
  when the cloud is Azure, because "does this type have a resource group" is a
  question the data answers and matching on provider there would be the page
  inferring a shape from a naming convention — the mistake `ResourceType.provider`
  exists to prevent.

  The wordmark is **Sanctum** on the page and **Secure Cloud Provisioner** in
  the CLI, the README and this package, and that is now a decision rather than
  an oversight: Sanctum is the product's face and Secure Cloud Provisioner is
  the package, the way a program's name and its distribution rarely match.

  Renaming is not the one-line change this file claimed, and the claim was
  wrong before this decision was made rather than because of it.
  `test_api.py` asserts `"Sanctum" in page.text` outright, and `index.html`
  carries it twice — in the `<title>` and in the wordmark. So it is three
  edits and a test, which is still small, but "the served-page test asserts
  the page was served rather than asserting a product name" was simply not
  true of the test as written.

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

  What jsdom cannot see is whether any of it *looks* right, and that gap is
  now half closed rather than open. `frontend/browse.mjs` drives the real page
  in a real Chromium against the real API — every sidebar entry, console errors
  collected, a screenshot of each. It found the three rendering defects in the
  redesign that no test could: a health pill that was green on burnt orange and
  invisible, a field hint landing in the label column so it read as a second
  caption, and a rule row's remove button sitting outside its own border
  because a grid item will not shrink below its content's minimum width.

  It is not in `npm test`: it needs a running server, a real account, and
  `npx playwright install chromium`. Run it the way the smoke test is run.
  What is still only ever found by a person is judgement — whether the thing
  is *good*, as opposed to present and not broken.
- **Benchmarked against Prowler and CloudGoat.** `docs/benchmark.md` has both
  and is the first thing to read before adding a rule; it records what was
  measured rather than what was assumed.

  Prowler agreed on eight findings and covered four this tool did not. Three
  of those four have since been written — a bucket policy granting another
  account access, password expiry, and per-user hardware MFA — leaving
  resources spread across regions as the only one open. Two apparent gaps were
  not gaps, and the reasoning is written down so nobody re-files them.

  All three of the new ones are uncited, and each for its own reason rather
  than by a blanket rule. CIS has no control for cross-account bucket access.
  CIS carried a password-expiry recommendation in v1.2 and **deliberately
  dropped it** by v3.0.0, on the reasoning that forced rotation produces
  predictable variations, so citing one would attribute a control to a document
  that removed it on purpose — the most tempting shape a fabricated citation
  can take, because a plausible number really did once exist. And CIS **1.5**
  asks for hardware MFA on the *root* user only, so stretching it across every
  user would claim a control for a population it does not name.

  That number was written as 1.6 first, in this file and in both places in the
  code. 1.6 is *Eliminate use of the root user for administrative tasks* — a
  different control, one away, and exactly the failure this file records under
  *CIS section 1 renumbered in v5.0.0*: "two thirds of these IDs are one away
  from a plausible wrong answer, and nothing a wrong one produces looks
  broken." It was caught by checking the claim against `scanner/controls.py`
  rather than by reading it back. Uncited findings are safe from this; prose
  about which control was declined is not, and nothing tests prose.

  That broke a real invariant. `test_every_iam_finding_carries_a_citation`
  asserted exactly what its name says, on the correct grounds that section 1
  covers nearly all of IAM and an uncited IAM finding therefore meant a
  forgotten citation. It now allows two findings **named individually**, so a
  citation that genuinely was forgotten still fails it. An exemption that said
  "some findings are uncited" would have retired the guard instead of narrowing
  it.

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

- **The snapshot sweep now asks every region, and is not wired to a route.**
  `publicly_restorable` still sees only its client's region;
  `publicly_restorable_everywhere` asks all of them and returns
  `{checked, found, swept}`. A snapshot shared with the world in a region
  nobody opens is exactly the one nobody notices, and the region somebody
  works in daily is where a mistake gets spotted anyway.

  It has no route, deliberately. Every AWS `ResourceType` here is
  per-resource and this is an account-wide question, so there is no id to hang
  it on — the snapshot type would have to list snapshots from regions its
  single-region reader cannot then resolve, which is the *A row's id is
  whatever the routes accept* rule pointed at itself. The live smoke test
  calls it, which is where the one-region limit was actually costing
  something. Wiring it to a surface wants the account-scoped shape
  `azure-monitor` now demonstrates, applied to AWS.
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
- **The Access Analyzer check asks every region now.** CIS 1.19 says "for
  all regions" and this asked one, admitting so in the finding. The admission
  was honest and the check was still close to worthless: the value of Access
  Analyzer is catching a resource shared out of a region nobody watches, so
  the region somebody is actively working in is the least informative one to
  ask about.

  `read_analyzer_coverage` returns `{home, checked, without, swept}` and the
  finding counts regions rather than hedging. **`swept` is the load-bearing
  half.** Enumerating regions needs `ec2:DescribeRegions`, which a login
  scoped to Access Analyzer will not have, so the sweep narrows to one region
  and says so — because "no analyzer in the one region I could see" reported
  in the words of "no analyzer in your account" is a claim nothing supports.
  `enabled_regions` raises rather than falling back for the same reason: the
  caller decides what to say about a sweep it could not perform, and a silent
  degrade would let every finding built on it claim coverage it never had.

  One bug came out of writing it, and it is a Python detail worth knowing.
  `_denied()` ends in a bare `raise`, which needs an active exception — called
  after the per-region loop rather than inside an `except`, it failed as
  `RuntimeError: No active exception to reraise` and turned a recorded gap into
  a crash on every account. Twelve tests caught it immediately; nothing about
  reading the code would have.
- **Five of CIS section 1 is unimplemented, on purpose.** 1.1, 1.2, 1.10, 1.17
  and 1.20 have no API that answers them; the reasoning per control is at the
  foot of `scanner/controls.py`. Sixteen of twenty-one are covered.
- **`GET /resources/{type}` with `with_scan=true` is still serial inside one
  type.** Seven AWS calls per bucket, one after another. The dashboard works
  around it rather than fixing it, by asking every *type* at once — which is
  what makes a whole account 3.4 seconds rather than thirty, and why
  auto-scanning on arrival is affordable. A single type holding a few hundred
  resources would still be slow, and no account here has one.
- **`_sg_create` no longer falls back to the default VPC, and this entry said
  it did.** The code refuses a spec with no `vpc_id` and answers with the
  options route to read one from — *What comparing the two surfaces found*
  records the removal, and this bullet sat here contradicting it, so the file
  asserted both halves at once. Checked against the code rather than read
  back: `api/registry._sg_create` returns a refusal before it calls anything.
  Confirmed live too — a create with no `vpc_id` is refused, and the drive
  that proved it had to read `GET /resources/security-group/options` to get a
  network the way the page does.
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
    principal holds was never enumerated, so "the writes worked" is what is
    known rather than which grant made them work. It demonstrably cannot
    register a resource provider. The reason recorded here was that
    `azure-mgmt-authorization` is not installed and that adding it just to ask
    was not worth it, and the first half of that is false — it is installed,
    at 4.0.0, in `/home/huori/code/.venv`. Nobody asked. What that changes is
    the size of the question rather than the answer: it is a read away rather
    than an install away, and what it costs now is the writing.
- **The second application is gone.** This entry has been rewritten four times
  and each version was overtaken rather than wrong: first the two halves had
  never met, then they had merged but both still ran, then the only thing
  keeping the root app alive was that it could create an Azure NSG and
  `az/nsg.py` could not. `az/nsg.py` can, so the last reason went, and the
  application went after it — see *There is one application now*.

  What that leaves is a genuine loss worth naming rather than glossing:
  `backend/` has no Azure-only deployment. The root app could be run by
  somebody holding Azure credentials and no AWS ones, as a separate process
  with its own dependencies. `/ui` cannot be, because it is one process serving
  both clouds. Nothing needed that and nobody was using it, but it was a
  capability and it is not one any more. `--azure-only` on the smoke test is
  the nearest thing left.

## Where this stands against the scope

The README is the scope: *provisions AWS and Azure resources through guided
forms and flags unsecure configurations before deployment.*

Done: the AWS provisioning and scanning, well past KAN-8 — seven resource
types, CIS citations across sections 1, 2, 3 and 5, a blueprint, guarded
destructive paths, a live smoke test, and a browser key generator that cannot
reach the network. The guided form exists at `/ui`, on a **Create** tab beside
a **Dashboard** that scans the whole account on arrival and an **Audit** tab
that reads what it found. Pre-deployment scanning exists on both halves;
`POST /resources/{type}/check` creates nothing. A bucket can be given files at
creation, and the tool refuses to put one into a bucket the world can already
read.

Azure is now met rather than claimed, and on the same terms as AWS. Five types
— storage accounts, key vaults, security groups, virtual networks and virtual
machines — create, scan, fix, delete and clean up through the same registry,
the same routes, the same CLI and the same page as every AWS type. All of it
has run against a real subscription, including a machine that booted, was
scanned with an administration port open to the internet, and was destroyed.

**The guided form has now been driven, by a browser, against both real
clouds.** That sentence is the one this section could not make before. Every
provisionable type — nine AWS, five Azure — was created, scanned, fixed and
deleted from the page against real accounts, and the bastion blueprint built
and tore down from it with and without its machines. Five bugs came out of
doing it, all of them invisible to a suite that passes.

It also closed the one claim in this file with nothing behind it. The browser
key generator had been proved correct in the abstract — `keygen.test.mjs` has
`ssh-keygen` derive the public half from the file it produces — but no
browser-generated key had ever been given to a cloud. Building the bastion from
the page generated two pairs in WebCrypto, downloaded the private halves and
sent only the public ones; AWS recorded a fingerprint for the imported key that
matches `ssh-keygen -lf` run on the public half derived from the downloaded
private one. The failure that rules out is the quiet one: machines that exist
and nobody can log into.

Not done: nothing that stops a demo. The page builds every Azure type
including a firewall with ordered rules. Everything in *Not done* above is a
refinement, and the largest remaining one is that defender has no rules —
deliberately; monitor now does
— which Prowler covers and this does not.

## Next

**One small thing first, and it is known and one-line.**

0. **Root collection is no longer a question — there is one suite, and
   `pytest` answers 1018 from either directory.** It was fixed first and then
   made moot: the six tests that only the root run collected belonged to the
   application that has since been deleted. Worth keeping only for the
   diagnosis, which this file twice recorded wrongly before getting it right.

   **The `GroupId`/`group_id` composition bug is fixed, and this entry was the
   last thing here still calling it open.** `sg.group_id_of` normalises all
   three spellings in circulation — `GroupId` off the API, `group_id` out of
   `read_group_usage`, and `id` out of the registry's list adapter — and
   `list_rules` calls it, so `read_group_for_scanning` now takes any of them.
   Verified by composing the two functions the way a script would: the raw dict
   `list_security_groups` returns reads its rules. A dict carrying none of the
   three raises rather than returning None, which is the right half to fail on:
   returning None would send a group that exists down the "no such group" path
   and answer 404 about it. `test_every_spelling_of_a_group_id_reaches_the_same_group`
   pins it.

   The two threshold numbers have also been checked — see *The two threshold
   numbers, checked at last*. This entry used to sit here saying nobody had,
   and stayed after the section above was written, so the file asserted both
   halves at once for a while. Both survive; the reasoning beside them did
   not, and was replaced.

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
   `74baf379-b419-4e16-a50b-98bc450901c9`, machines included.

   **The rules widget is done too, and its stated blocker was never the real
   one.** This entry said rules would wait "until a widget exists that knows
   about priority". Nothing in the page needs to know about priority:
   `az/nsg._priorities_for` assigns one per rule from the order of the list,
   ten apart, and refuses a set that is half hand-numbered. So the widget
   offers arrows rather than a number, because moving a row is what changes
   precedence. What actually made the AWS widget unusable is smaller — an
   Azure rule carries a name, a direction, and an access that can be **Deny**,
   and a security group rule carries none of those because every rule in one
   is an allow. Verified live: two rules, a Deny in front of an Allow, land as
   priority 100 and 110 in the order typed.

   That left one gap of its own, and it is the reason `test_api.py` now posts
   the form's exact body. The first version sent `rules` with a `source`
   field, which is the AWS spelling; `ResourceSpec` ignores fields a resource
   does not use, so the route accepted it, the adapter read an empty
   `azure_rules`, and **Azure built a group with none of the rules in it and
   reported success**. The jsdom suite agreed, because a stub answers whatever
   it is sent — `_StubVaultClient`'s lesson arrived at from the other
   direction.

   **The benchmark gap is closed, and it was never what this entry said it
   was.** Prowler is not an AWS tool — it covers Azure, Google Cloud,
   Kubernetes and M365, and `prowler azure --sp-env-auth` is one word different
   from the command already documented above, reading the same four `.env`
   variables. It has now been run against the subscription and
   `docs/benchmark.md` has the result: five checks overlap and **all five
   agree**, including three where both tools say nothing is wrong; eleven
   further storage checks are Prowler's alone, of which about four are
   security-relevant and the rest are durability or defence in depth; and four
   services — monitor, defender, network watcher, appinsights — have no rules
   here at all. Monitor is the largest block and is the Azure counterpart of
   the AWS alarm scanner.

   What the run does not cover is the four types this project spent most
   effort on. The subscription held two storage accounts and nothing else, so
   vaults, networks, security groups and machines were never scanned by it.
   Re-running while `azure-lifecycle.mjs` has resources up would be a
   materially better test.

   CloudGoat genuinely is AWS-only. Its Azure counterpart is AzureGoat
   (ine-labs/AzureGoat), Terraform-deployed and covering storage, functions,
   CosmosDB and identity escalation. Nobody has run it.

   Two things still worth knowing before touching a subscription. Being Global
   Administrator in Entra grants no role on a subscription; that is a separate
   permission system, and *Access management for Azure resources* in Entra ID →
   Properties is the elevation. And a secure-by-default key vault turns on
   purge protection, which can never be turned off and locks the vault and its
   name for 90 days — so test vaults with the weak option, which is what the
   smoke test does deliberately, and let the offline spec test cover the secure
   path.
3. **Monitor is done and defender is a decided no.** See *An account-wide
   type, and what it cost* below. `azure-monitor` is registered, read-only,
   and its single resource is the subscription.

   Defender stays unimplemented on the reasoning this entry already had: its
   three checks ask whether paid Microsoft products are licensed, and "you
   have not bought Defender" is a purchasing decision rather than a
   configuration mistake. Recorded as a refusal rather than a gap.

   What is genuinely still missing from the monitor block is diagnostic
   settings — whether the activity log is exported somewhere it outlives the
   ninety days Azure keeps it. Not a choice: `azure-mgmt-monitor` 7.0.0 ships
   no diagnostic-settings operation group at all. Reading them needs a
   different API version or a raw ARM call, and guessing at one would be worse
   than the gap.
4. Detach `AmazonEC2FullAccess` and friends from `EC2_Dude`, so the documented
   least-privilege policy is the one actually in force and the smoke test
   proves it. Already done for EC2 and S3; SNS, CloudWatch and SSM remain and
   belong to a teammate.
5. **The last Prowler gap is multi-region.** The other three are done — see
   *Benchmarked against Prowler and CloudGoat*. What is left is the one that
   is not a rule but a shape: `list_snapshots` sees only its client's region,
   `read_analyzers` asks about one region while CIS 1.19 asks for every
   region, and both findings say so rather than implying a sweep. Fixing it
   properly means deciding whether a scan fans out across regions at the
   reader or at the registry, which is a change to how every AWS type is read
   rather than a rule to add.
