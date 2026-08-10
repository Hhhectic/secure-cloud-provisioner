# Benchmarked against Prowler

A scanner tested only against configurations its own authors thought of will
pass every time and prove nothing. The blind spots are the point, and they are
by definition invisible from inside.

So this tool was run against the same AWS account as [Prowler][prowler] 5.37.1,
an established open-source scanner with roughly three hundred AWS checks, and
the two sets of findings compared. Nothing was deployed to do it: both tools
read, neither writes.

    prowler aws --services ec2 s3 iam cloudwatch vpc

| | |
|---|---|
| Prowler | 281 checks run, 38 failing |
| This tool | 21 findings |

The counts are not comparable and it would be dishonest to present them as a
score. Prowler emits one finding per resource per check; this tool groups by
resource. What matters is the three-way split below.

## Prowler runs on a different Python

Every Prowler release from 3.12 onward declares `Requires-Python <3.13` or
`<3.14`. The development machine has only 3.14, so `pip install prowler`
resolves to 3.11.3, which uses pydantic v1 and crashes on import. ScoutSuite
5.14 installs but dies on `asyncio.get_event_loop()`, removed in 3.14.

Installing it into the project's own environment is worse than not running it:
Prowler pins `pydantic<2` and `boto3 1.26`, both incompatible with FastAPI, and
doing so silently breaks `api/app.py`.

`uv` fetches a standalone CPython without root:

```bash
uv python install 3.12
uv venv --python 3.12 /tmp/prowler && VIRTUAL_ENV=/tmp/prowler uv pip install prowler
```

## Where the two agree

Eight findings, reached independently. This is the useful half of a passing
result: the rules fire on the conditions they claim to.

- a bucket readable by anyone, and its four Block Public Access switches off
- no account password policy
- the root user used recently
- root without a hardware MFA device
- bucket versioning off
- bucket access logging off
- a bucket policy that permits plain HTTP
- nobody able to open a support case

## What Prowler found and this tool does not

The list worth acting on. Severities are Prowler's.

| Check | Severity | Note |
|---|---|---|
| `s3_bucket_cross_account_access` | High | a policy granting another account access. Not covered at all, and closest in spirit to what this tool already does |
| `iam_password_policy_expires_passwords_within_90_days_or_less` | Medium | length and reuse are covered; expiry is not |
| `vpc_different_regions` | Medium | resources spread across regions. This tool looks at one region everywhere, which is recorded under *Not done* |
| `iam_user_hardware_mfa_enabled` | High | root hardware MFA is covered; per-user is not |
| `iam_securityaudit_role_created` | Low | no equivalent |
| `ec2_instance_detailed_monitoring_enabled` | Low | no equivalent |
| `s3_bucket_object_lock`, `_lifecycle_enabled`, `_event_notifications_enabled`, `_cross_region_replication` | Low | operational rather than security findings |

`iam_policy_attached_only_to_group_or_roles` is partially covered: this tool
reports it for users (CIS 1.14) and Prowler reported five instances including
roles.

## Two that look like gaps and are not

Both were recorded as blind spots on a first pass and neither survived being
checked, which is worth keeping as a caution about reading a diff too quickly.

**`s3_bucket_no_mfa_delete`.** This tool has the control and did not fire it.
MFA Delete cannot be enabled on a bucket without versioning, and versioning was
off, so the rule is an `elif` behind the versioning finding. Prowler reports
both, and one of them is unactionable until the other is fixed.

**`iam_user_hardware_mfa_enabled` against CIS 1.9.** This tool checks MFA for
users *with a console password*, which is what CIS 1.9 asks. The only user has
no console password, so the rule correctly stays quiet. Prowler's check is a
different question — hardware MFA regardless of console access — and on a
programmatic-only user it is arguable.

**`s3_bucket_kms_encryption`** is a deliberate disagreement rather than a gap.
This tool reports SSE-S3 as informational, because AWS has encrypted every new
bucket since January 2023 and calling that a Medium finding treats a platform
default as a defect.

## What this tool found and Prowler did not

The answer to "why not just use Prowler".

- **Six subnets that assign public addresses on launch.** The setting that
  silently decides whether every future machine in them is exposed, before
  anybody chooses anything.
- **"Every subnet in this network reaches the internet, so there is nowhere to
  put something private."** A statement about the arrangement rather than about
  a resource.
- **VPC flow logs (CIS 3.7).** Prowler's `vpc` service returned only
  `vpc_different_regions` in this run.
- **Idle and saturated machines.** `scanner/instance_rules._check_workload`
  reads processor use and reports a machine nobody is using. Prowler has no
  equivalent, because it is a finding about money rather than exposure.

## The finding neither tool should be trusted on

Both flagged `richard-huo-resume-2026` as critical: public policy, all four
blocks off, `s3:GetObject` for `*`. Both are right, and it is not a problem —
the bucket has static website hosting enabled with `index.html` as its index
document. It is a personal site that is public on purpose.

Neither tool can tell a bucket that is public by mistake from one that is
public by design, and no amount of rule-writing fixes that: the difference is
intent, which is not in the API. Prowler answers this with suppression files.
This tool has no mechanism at all, so the demonstration account will always
show two criticals that are correct and unwanted, and a reader who sees them
every day will stop reading them.

That is the strongest argument in this document for building one, and it is
recorded under *Not done* rather than quietly fixed by removing the rule.

[prowler]: https://github.com/prowler-cloud/prowler

# Benchmarked against CloudGoat

Prowler answers "what do we miss on a clean account". CloudGoat answers the
other half: given infrastructure built to be broken, does this tool say so.
[CloudGoat][cg] deploys deliberately vulnerable AWS environments with
Terraform; 13 of its 29 scenarios were run, scanned and destroyed.

Which 13, and why not the rest: a scenario earns a run only if the resources
it creates are ones this tool inspects. Everything built on RDS, ECS,
Beanstalk or Bedrock was skipped - real money per day if a teardown fails, on
services the scanner does not look at. `vulnerable_cognito` and `sns_secrets`
are mostly API Gateway, so they would have proved nothing either.

## Running it at all

CloudGoat needs IAM write permissions, and this tool's own inline policy
denies every IAM write. That refusal is correct and was left alone: a second
IAM user with AdministratorAccess deploys the scenarios, and `EC2_Dude` scans
them. One identity builds, a different one audits, which is the honest test
and keeps `RefuseEveryIamWrite` intact.

CloudGoat also ignores the region. Each scenario hardcodes
`default = "us-east-1"` in its own `variables.tf`, and neither
`AWS_DEFAULT_REGION` nor `TF_VAR_region` overrides it - both were tried.
Everything lands in us-east-1 regardless, so this tool's own work should move
elsewhere rather than CloudGoat being pushed away. Billing alarms are the
exception and must stay in us-east-1, because AWS publishes the metric
nowhere else.

The whitelist matters. `cloudgoat config whitelist` restricts scenario
security groups to one address; auto-detection failed here and the file was
written by hand from `sg.my_public_ip()`. Without it a deliberately
vulnerable machine is exposed to everyone.

## How much of what CloudGoat plants does it actually find

Counting findings is the wrong measure, and flattering. Every scenario produces
findings, because every scenario deploys real infrastructure with real
weaknesses in it, and this tool is good at spotting those. The narrower
question is the one that matters: did it name the thing the scenario was built
around?

| | Scenarios |
|---|---|
| Named the planted vulnerability | 3 |
| Named part of the chain, not the escalation | 2 |
| Reported something real that was not the point | 8 |

The eight are not noise. On `iam_privesc_by_attachment` the tool reported
IMDSv1 and an unencrypted disk; both are true and neither is the scenario,
which is a user who can attach a policy to a role and then assume it. On
`iam_privesc_by_ec2` — pass a role to EC2 and inherit it — it reported flow
logs and a subnet setting. `lambda_privesc`, `federated_console_takeover` and
`data_secrets` are the same shape: correct findings, wrong ones.
`detection_evasion` produced nothing about alarms at all.

Two of the eight are legitimately out of scope and should be read as correct
silence rather than as misses: `secrets_in_the_cloud` and
`iam_privesc_by_key_rotation` turn on Secrets Manager and DynamoDB, which this
tool does not claim to scan and does not pretend to.

The rest share a single cause, and it is already the first item under *Next*:
the tool reports that a role is attached and never what it grants. Every
CloudGoat scenario is a chain of role to something. This sees the first link
and none of the corridor.

## What it caught

Enabling conditions, reliably — and in two scenarios that is the whole attack.

**The pivot, in four scenarios.** CIS 5.7 - the metadata service handing out
the instance's credentials to anything running on it - fired as critical on
`iam_privesc_by_attachment`, `ec2_ssrf` and `data_secrets`, and as a warning
on `federated_console_takeover`.

The distinction worth drawing is where that finding is the attack rather than
a step near it. In `ec2_ssrf` and `cloud_breach_s3` the metadata service *is*
the path: reach it, take the role, read the bucket. Those are genuine
end-to-end catches — the tool names the vulnerability the scenario exists to
teach, before anybody exploits it. In the other two, 5.7 is true and present
and the escalation happens somewhere the tool cannot see, so naming it is
closer to noticing an unlocked window in a building whose front door is also
open.

**Two public buckets.** `s3_version_rollback_via_cfn` produced four
criticals - the policy and the four blocks, on each of two buckets.

**A rule generalising.** The IAM-enumeration rule added after
`iam_enum_basics` then fired unprompted on `iam_privesc_by_rollback` and
`lambda_privesc`, neither of which it was written for.

## What it did not catch

**What the attached role can reach.** Every one of these scenarios is a
privilege-escalation chain: role to S3, role to Lambda, role to policy
rollback. This tool reports that an instance profile is attached and never
what it grants, so it sees the first link and none of the rest. That is the
single most valuable thing left to build, and it is the same shape as the
cross-account bucket gap Prowler found.

**Anything about alarms.** `detection_evasion` is the only scenario creating
CloudWatch alarms and CloudTrail, and produced three warnings, none of them
about alarms - `aws/alarms.py` only enumerates alarms carrying this tool's
tag. The newest rule set still has no external benchmark.

**Correct silence.** `iam_privesc_by_key_rotation` produced only CIS 1.14
notes. Its vulnerability is in Secrets Manager and a key-rotation path, which
this tool does not scan. That is the right answer, not a miss.

## Re-run after roles and users were read

The figures above were measured before `scanner/role_rules.py` and
`scanner/escalation.py` existed, when the tool reported that an instance
profile was attached and never what it granted. Ten scenarios were deployed,
scanned and destroyed again afterwards, each against a baseline of the account
taken immediately beforehand.

The first attempt at this re-run produced the wrong numbers twice over, and
both faults are recorded under *Measuring it wrongly* below, because a
benchmark that undercounts is indistinguishable from a tool that
underperforms.

| | Before | After |
|---|---|---|
| Named the planted vulnerability | 3 | **6** |
| Named part of the chain | 2 | **1** |
| Reported something real that was not the point | 5 | **2** |
| Correct silence, out of scope | — | 1 |

Counted over the ten re-run rather than the original thirteen, so the columns
compare in shape and not as scores.

### The six named

`iam_enum_basics`, `ec2_ssrf` and `cloud_breach_s3` were named before and still
are; the last two now say what the role reaches rather than only that the
metadata service is open. The three that changed:

**`lambda_privesc`.** Both ends, in two findings. `cg-lambdaManager-role` "can
hand any role in this account to something it starts, and can create a
function", and `cg-debug-role` "can do anything in this account". Assume the
manager role, run a function carrying the debug role, take its credentials.

**`iam_privesc_by_rollback`.** "`raynor` can roll a policy back to an older
version that granted more." One API call, changing nothing about the shape of
the account, which is what made it invisible before.

**`iam_privesc_by_attachment`.** All three links, as three findings: `kerrigan`
"can hand any role in this account to something they start, and can start a
machine"; `cg-ec2-mighty-role` "can do anything in this account"; and the
instance "lets software on it read the machine's AWS credentials with a simple
web request".

### The one partial

**`iam_privesc_by_ec2`** reports `cg_ec2_role` as full administrative access on
a running machine, with the metadata service named, and does not trace the
three hops that lead there. Each hop is individually narrow and correctly
declined: the user holds `sts:AssumeRole` on one named role ARN, and the role
it reaches holds `ec2:ModifyInstanceAttribute` behind a `StringNotEquals`
condition. Flagging a single named ARN would put a finding on most
correctly-built infrastructure, and counting conditioned statements means
evaluating IAM's policy language against a request that does not exist. Both
limits are deliberate and both cost a detection here.

The sink is also the thing worth fixing: remove it and the chain breaks
whichever way somebody arrives.

### The two that are still not the point

**`federated_console_takeover`** produced nine findings, none critical, and
nothing about the federation path.

**`detection_evasion`** produced twenty findings including four criticals, and
this is where the earlier write-up was most wrong. It previously recorded
"nothing about alarms at all", explained by `aws/alarms.py` enumerating only
alarms carrying this tool's own tag. That explanation was false: with
`only_ours=False` it reads every alarm in the region, and it reported both of
this scenario's - `honeytoken_alarm` and `instance_profile_alarm` - as critical,
because nobody had confirmed the subscription and an alarm nobody has confirmed
reaches no one.

It is still not a detection of the planted vulnerability. Those subscriptions
are pending because the deployment was minutes old and nobody had clicked the
confirmation link, which is a true statement about a fresh scenario rather than
a flaw CloudGoat planted. It is worth recording anyway: the alarm rules fire
correctly on somebody else's alarms, which is the external check
`docs/benchmark.md` previously said they had never had.

### Still true, and the reason the rest is hard

Both remaining misses and the partial share a shape this work does not reach.
This tool judges one identity's policies at a time. A chain is a graph - who can
assume what, and what that reaches in turn - and following it means traversing
edges rather than matching statements. That is a different program, and worth
knowing before "role reachability" is read as "detects privilege escalation".

## Measuring it wrongly

Three faults, all in the harness rather than the scanner, and all of a kind
that makes a tool look worse than it is.

**Attribution by name undercounts.** The first method filtered findings by the
`cgid` suffix, on the advice further down this document that CloudGoat "stamps
it on every resource". It does not. `iam_privesc_by_attachment` names its user
`kerrigan`; `detection_evasion` names its alarms `honeytoken_alarm` and
`instance_profile_alarm` and one of its users `r_waterhouse`. Every one of those
findings was discarded before anything was counted, and two scenarios were
written up as failures of rules that had fired correctly.

The safe method is a baseline: list the account before deploying, list it
again afterwards, attribute the difference. That survives fixed names,
leftovers from an earlier scenario, and anything already in the account.

**A scenario that never deployed was scanned anyway.** The first harness
checked only whether it could find a cgid in the output, so a `terraform apply`
that failed halfway still produced a scan. `iam_privesc_by_rollback` never
deployed on that pass - `terraform apply completed with no error code` appears
nowhere in its log - and its findings were recorded as a detection. Check for
that string, not for a scenario id.

**It failed for a reason that looked like something else.** That scenario
drives the `aws` CLI from a `local-exec` provisioner, four times, to create the
older policy versions its escalation rolls back to. The CLI was not installed,
and the resulting error names two unset Terraform variables rather than the
missing binary.

## Two hazards worth knowing before anyone repeats this

**CloudGoat fills the disk, and blames Terraform.** Every destroyed scenario is
moved to `trash/` with its Terraform provider cache intact, about 700 MB each.
After twenty-four scenarios that reached 20 GB, which on a machine where `/tmp`
is a tmpfs is 20 GB of memory. The failure surfaces several scenarios later as
`Error: Failed to install provider ... no space left on device`, which reads
like a Terraform problem. Empty `trash/` between runs.

**`detection_evasion` wants an email** in `config.yml` under `user_email`, and
prompts if it is absent. Feeding `y` to that prompt produces a Terraform error
about an unset variable. It subscribes the address to a real SNS topic.

**`cloudgoat destroy` can report success and leave things behind.**
`s3_version_rollback_via_cfn` left two buckets and an IAM user while printing
no error. The buckets have Object Lock in GOVERNANCE mode with retention to
2099-12-31, so ordinary deletion is impossible - they need
`BypassGovernanceRetention`, which Terraform does not attempt. Check the
account afterwards rather than trusting the summary.

**`cloudgoat destroy` also prompts, and dies silently when nothing answers.**
Piping `/dev/null` into it produces an `EOFError` traceback, destroys nothing,
and can still leave the wrapper reporting success - which happened here, with a
deliberately vulnerable instance carrying an administrator role left running
until the account was checked directly. `yes y |` answers it. Check the account
after every teardown rather than reading the summary, which is the same advice
the next paragraph gives for a different failure.

**Two setup details that are not in CloudGoat's own instructions.** It reads
`whitelist.txt` and `config.yml` from its *package* directory, not the working
directory, and `config.yml` must be a YAML list - `- default-profile: cloudgoat`
- because a bare mapping crashes with `'str' object has no attribute 'keys'`.

**Those leftovers then contaminate every later scan.** Scenarios run after it
picked up the orphaned buckets as their own findings, which is why raw
per-scenario counts from a sequential run cannot be trusted.

**Attribution by name is unsafe, and this document previously said to do it.**
The advice was to attribute findings by the `cgid` suffix "CloudGoat stamps on
every resource". It does not. `iam_privesc_by_attachment` creates a user called
`kerrigan`, with no suffix at all, and a scan filtered on `cgid` therefore
never counted the finding naming that user - which is the whole escalation. It
was written up as a partial detection and a possible gap in the scanner, and it
was neither: the rule fired correctly and the measurement threw the answer
away.

The safe method is a baseline. List the identities and resources before
deploying, list them again afterwards, and attribute the difference. That
survives fixed names, leftovers from an earlier scenario, and anything else
already in the account, none of which a suffix filter does.

The general lesson is worth more than the correction: a benchmark that
undercounts looks exactly like a tool that underperforms, and the failure is
invisible from inside the results. Every number in the *After* column was
produced by the suffix method, so the ones not re-measured since may be
understated in the same way.

[cg]: https://github.com/RhinoSecurityLabs/cloudgoat
