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
