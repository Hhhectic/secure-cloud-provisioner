# Giving the tool an AWS login

The tool needs one IAM identity. Its permissions arrive as **two policies**,
not one, and the split is forced by AWS rather than chosen.

| File | Attach as | Size |
|---|---|---|
| `iam-policy.json` | inline policy on the user | 1797 / 2048 |
| `iam-policy-account-audit.json` | customer managed policy | 523 / 6144 |
| `iam-policy-demo.json` | customer managed, **only while demoing** | 405 / 6144 |

## Why two files

**All of an IAM user's inline policies together may not exceed 2,048
non-whitespace characters.** The complete permission set is 2,282. Pasting it
into the console as a single inline policy fails, and the natural way to make
it fit is to delete whichever statement you are least sure you need — which is
how an account ends up with the audit half missing.

That failure is close to silent. Every provisioning path keeps working; only
the account audit degrades, and it degrades into nine "could not check" notes
that read like an account with nothing to report. `scanner/iam_rules` puts
those first for exactly this reason, but nothing stops you from skimming past
them.

Customer managed policies get 6,144 characters and do not count against the
user's inline budget, so the audit reads live there.

## Why the split falls where it does

The audit **reads** moved out. Every `Deny` stayed inline, including
`RefuseEveryIamWrite`.

Denies are the guardrails — no NAT gateways, nothing bigger than `*.small`, no
`CreateKeyPair`, no IAM write of any kind. A guardrail that can be detached
separately from the permission it guards is not a guardrail. Keeping all four
refusals in the policy that is always attached means the only way to lose them
is to strip the identity of everything else at the same time.

An explicit `Deny` beats any `Allow` from any policy, so these hold even if the
identity also carries something broad.

## Attaching them

Both steps need an identity that can write IAM — root, or an admin user. The
tool's own login cannot do this to itself, by design.

```bash
aws iam put-user-policy \
  --user-name EC2_Dude \
  --policy-name secure-cloud-provisioner \
  --policy-document file://docs/iam-policy.json
```

```bash
aws iam create-policy \
  --policy-name secure-cloud-provisioner-account-audit \
  --policy-document file://docs/iam-policy-account-audit.json
```

```bash
aws iam attach-user-policy \
  --user-name EC2_Dude \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/secure-cloud-provisioner-account-audit
```

In the console: **IAM → Users → the user → Add permissions**. The first is
*Create inline policy → JSON*; the second is *Create policy* under Policies,
then *Attach existing policies directly*.

## The third policy, and why it is not attached

`iam-policy-demo.json` exists for one command:

```bash
python scripts/make_vulnerable.py --with-public-snapshot
```

It grants five EBS writes, including `ModifySnapshotAttribute` — the call that
makes a snapshot readable by every AWS account. **Attach it, run the demo,
detach it.**

Keeping it off by default is not caution for its own sake. `aws/snapshots.py`
states in its own code that the tool holds no permission to change a snapshot,
and that its refusal to auto-fix a public one is backed by the policy rather
than resting on the code being polite. Folding these grants into the main
policy would quietly make that false, and the next person to read that
docstring would be reading a comment that no longer describes the system.

The demo policy also refuses to create a volume larger than 1 GiB. The script
only ever asks for 1, so the condition never fires in normal use — it is there
because a demo that publishes a disk should be unable to publish a large one
even if the script is edited.

## Checking it worked

```bash
cd backend && python scripts/smoke_test.py
```

A correctly permissioned identity reports `every check ran; nothing was skipped
for want of a permission`, and the credential report comes back with its root
row. Any `could not check X: missing Y` note names the permission that is
absent.

## Better than a long-lived access key

Everything above assumes an IAM user with an access key in
`~/.aws/credentials`. That key does not expire. If the file is read — by
another account on the machine, by a backup, by a commit — whoever has it
holds this account until somebody notices and revokes it.

This tool audits accounts for exactly that. CIS 1.12 and 1.13 exist because
static keys accumulate and outlive the person who made them.

**First, if you keep the key:**

```bash
chmod 700 ~/.aws && chmod 600 ~/.aws/credentials
```

The default on some systems is world-readable, which means every account on
the machine can read it.

**Better: swap it for a role the user assumes.** Move the permissions from the
user to a role, leave the user able to do nothing except assume it, and take
an hour-long session when you work.

Create a role — call it `secure-cloud-provisioner` — with this trust policy,
substituting the account ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT_ID:user/EC2_Dude"},
    "Action": "sts:AssumeRole",
    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
  }]
}
```

Attach `iam-policy.json` and `iam-policy-account-audit.json` to the **role**
rather than the user, and leave the user with only `sts:AssumeRole` on it.
Then add to `~/.aws/config`:

```ini
[profile scp]
role_arn = arn:aws:iam::ACCOUNT_ID:role/secure-cloud-provisioner
source_profile = default
mfa_serial = arn:aws:iam::ACCOUNT_ID:mfa/YOUR_DEVICE
region = us-east-1
```

and run everything with `AWS_PROFILE=scp`. boto3 handles the assume-role and
the MFA prompt itself; nothing in this codebase changes.

What that buys: a leaked credentials file expires within the hour instead of
never, the MFA condition means a stolen key alone is not enough, and every
action arrives in CloudTrail as the role rather than as a shared user, so the
log says which session did what.

The cost is a prompt when the session expires. That is the whole cost.

## What this policy assumes

It assumes it is the **only** thing granting the identity access. Alongside
something like `AmazonEC2FullAccess` or `AmazonS3FullAccess` the allow-side
least privilege here stops meaning anything — the broad policy grants what this
one carefully does not, and the tool can then reach resources it was never
scoped to touch.

The refusals survive that, since an explicit `Deny` always wins. The narrow
allows do not.
