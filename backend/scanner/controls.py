"""The published controls this tool checks against.

Every control ID lives here and nowhere else. Rules reference the symbolic name,
so a benchmark version bump is one edit in this file rather than a search across
two scanners, and findings can report which version they were assessed against.

Two frameworks are cited, and the distinction matters. CIS is a formal benchmark
with numbered, versioned controls. The AWS Startup Security Baseline is guidance
rather than a benchmark, so its items are cited as what they are instead of
being dressed up as CIS coverage.

A rule with no control is not a defect. Several findings here are ordinary good
practice that no published benchmark covers, and inventing a citation for them
would be worse than leaving the field empty.

CIS numbering has shifted between benchmark versions. These IDs were read from
the v5.0.0 PDF directly; before bumping CIS_VERSION, check every ID against the
new document rather than assuming the numbering held.
"""

from dataclasses import dataclass, asdict
from typing import Optional

CIS = "CIS AWS Foundations Benchmark"
CIS_VERSION = "5.0.0"

SSB = "AWS Startup Security Baseline"
SSB_VERSION = "2023-06"


@dataclass(frozen=True)
class Control:
    """One published recommendation.

    level follows the CIS profile split: 1 is broadly applicable with little
    operational cost, 2 is defence in depth that may get in the way. It is
    deliberately separate from this tool's own severity, which answers a
    different question: CIS level is how hard a control is to live with,
    severity is how bad it is to be without it.

    automated mirrors the benchmark's own Automated/Manual marking. A Manual
    control is one CIS considers unverifiable by machine, which is a strong
    signal that this tool should report it rather than offer to fix it.
    """

    id: str
    title: str
    level: int
    automated: bool
    framework: str = CIS
    version: str = CIS_VERSION

    def to_dict(self):
        return asdict(self)

    @property
    def citation(self):
        return f"{self.framework} v{self.version} §{self.id}"


CONTROLS = {
    # ---- Identity and access management ------------------------------------
    #
    # Section 1 renumbered in v5.0.0. v3.0.0's 1.3, "Ensure security questions
    # are registered in the AWS account", was dropped when AWS retired the
    # feature, and every control after it moved down by one: root access keys
    # went from 1.4 to 1.3, the support role from 1.17 to 1.16, and so on to
    # the end of the section. Anything citing the older numbering is one out
    # for two thirds of this list. Checked against AWS's own published mapping
    # of Security Hub controls to CIS v5.0.0 and v3.0.0 requirements, which
    # agrees with the shift at every point it covers.
    "ROOT_ACCESS_KEY": Control(
        id="1.3",
        title="Ensure no 'root' user account access key exists",
        level=1,
        automated=True,
    ),
    "ROOT_MFA": Control(
        id="1.4",
        title="Ensure MFA is enabled for the 'root' user account",
        level=1,
        automated=True,
    ),
    "ROOT_HARDWARE_MFA": Control(
        id="1.5",
        title="Ensure hardware MFA is enabled for the 'root' user account",
        level=2,
        automated=True,
    ),
    "ROOT_DAILY_USE": Control(
        id="1.6",
        title="Eliminate use of the 'root' user for administrative and "
              "daily tasks",
        level=1,
        automated=True,
    ),
    "PASSWORD_LENGTH": Control(
        id="1.7",
        title="Ensure IAM password policy requires minimum length of 14 or "
              "greater",
        level=1,
        automated=True,
    ),
    "PASSWORD_REUSE": Control(
        id="1.8",
        title="Ensure IAM password policy prevents password reuse",
        level=1,
        automated=True,
    ),
    "USER_MFA": Control(
        id="1.9",
        title="Ensure multi-factor authentication (MFA) is enabled for all "
              "IAM users that have a console password",
        level=1,
        automated=True,
    ),
    "UNUSED_CREDENTIALS": Control(
        id="1.11",
        title="Ensure credentials unused for 45 days or greater are disabled",
        level=1,
        automated=True,
    ),
    "ONE_ACTIVE_KEY": Control(
        id="1.12",
        title="Ensure there is only one active access key available for any "
              "single IAM user",
        level=1,
        automated=True,
    ),
    "KEY_ROTATION": Control(
        id="1.13",
        title="Ensure access keys are rotated every 90 days or less",
        level=1,
        automated=True,
    ),
    "PERMISSIONS_VIA_GROUPS": Control(
        id="1.14",
        title="Ensure IAM users receive permissions only through groups",
        level=1,
        automated=True,
    ),
    "NO_FULL_ADMIN_POLICY": Control(
        id="1.15",
        title="Ensure IAM policies that allow full \"*:*\" administrative "
              "privileges are not attached",
        level=1,
        automated=True,
    ),
    "SUPPORT_ROLE": Control(
        id="1.16",
        title="Ensure a support role has been created to manage incidents "
              "with AWS Support",
        level=1,
        automated=True,
    ),
    "EXPIRED_CERTIFICATES": Control(
        id="1.18",
        title="Ensure that all the expired SSL/TLS certificates stored in "
              "AWS IAM are removed",
        level=1,
        automated=True,
    ),
    "ACCESS_ANALYZER": Control(
        id="1.19",
        title="Ensure that IAM Access Analyzer is enabled for all regions",
        level=1,
        automated=True,
    ),
    "CLOUDSHELL_FULL_ACCESS": Control(
        id="1.21",
        title="Ensure access to AWSCloudShellFullAccess is restricted",
        level=1,
        automated=True,
    ),

    # ---- Storage -----------------------------------------------------------
    "S3_DENY_HTTP": Control(
        id="2.1.1",
        title="Ensure S3 Bucket Policy is set to deny HTTP requests",
        level=2,
        automated=True,
    ),
    "S3_MFA_DELETE": Control(
        id="2.1.2",
        title="Ensure MFA Delete is enabled on S3 buckets",
        level=2,
        automated=False,
    ),
    "S3_BLOCK_PUBLIC_ACCESS": Control(
        id="2.1.4",
        title="Ensure that S3 is configured with 'Block Public Access' enabled",
        level=1,
        automated=True,
    ),

    # ---- Networking --------------------------------------------------------
    "SG_ADMIN_PORTS_V4": Control(
        id="5.3",
        title="Ensure no security groups allow ingress from 0.0.0.0/0 to "
              "remote server administration ports",
        level=1,
        automated=True,
    ),
    "SG_ADMIN_PORTS_V6": Control(
        id="5.4",
        title="Ensure no security groups allow ingress from ::/0 to "
              "remote server administration ports",
        level=1,
        automated=True,
    ),
    "DEFAULT_SG_RESTRICTS_ALL": Control(
        id="5.5",
        title="Ensure the default security group of every VPC restricts "
              "all traffic",
        level=2,
        automated=True,
    ),
    "VPC_FLOW_LOGS": Control(
        id="3.7",
        title="Ensure VPC flow logging is enabled in all VPCs",
        level=2,
        automated=True,
    ),
    "IMDSV2_REQUIRED": Control(
        id="5.7",
        title="Ensure that the EC2 Metadata Service only allows IMDSv2",
        level=1,
        automated=True,
    ),

    # ---- Not CIS -----------------------------------------------------------
    "UNUSED_SECURITY_GROUPS": Control(
        id="ACCT.09",
        title="Delete unused VPCs, subnets, and security groups",
        level=1,
        automated=True,
        framework=SSB,
        version=SSB_VERSION,
    ),
}


def control(name) -> Optional[Control]:
    """Looks up a control by symbolic name. Unknown names return None.

    Returning None rather than raising is deliberate: a typo in a rule should
    cost a citation, not crash a security scan mid-run.
    """
    return CONTROLS.get(name)


# Five of section 1's controls are deliberately absent, and all five for the
# same reason: there is no API that answers them.
#
# CIS 1.1 (current contact details) and 1.2 (security contact registered) are
# account billing and contact records. 1.2 is readable through the account
# service, but only from the organisation's management account or with
# delegated admin, so for the single-account case this tool is aimed at the
# call fails for reasons that have nothing to do with the answer.
#
# CIS 1.10 (no access keys created during initial user setup) needs the intent
# behind a key, not its existence. A key made the same minute as its user might
# be setup boilerplate or a deliberate choice, and the credential report shows
# only the timestamps. CIS marks it Manual for exactly this reason. The related
# 1.12 is implemented, because "two active keys" is a fact rather than a guess.
#
# CIS 1.17 (instance roles used for resource access) would mean proving no
# instance holds long-lived keys, which requires reading what is on the disk of
# every machine. Not knowable from the control plane.
#
# CIS 1.20 (users managed centrally via federation) has no signal distinguishing
# an account that federates from one that has few users.

# CIS 3.4, "Ensure that server access logging is enabled on the CloudTrail S3
# bucket", is deliberately not attached to this tool's access-logging rule. That
# control is about one specific bucket, the one CloudTrail writes to. This tool
# reports logging on any bucket it is pointed at, which is reasonable advice but
# is not what 3.4 asks for, and citing it would be claiming a compliance check
# the rule does not perform.
#
# CIS 2.1.3, "Ensure all data in Amazon S3 has been discovered, classified and
# secured when necessary", is deliberately not implemented. It requires Macie or
# equivalent content inspection, which means reading customer data. That is a
# different class of tool from this one and a much larger privacy surface.
#
# Nothing in scanner/snapshot_rules.py carries a citation, and the absence is
# checked rather than assumed. CIS AWS Foundations has no control governing who
# may restore an EBS snapshot; the recommendation usually quoted for it,
# "EBS snapshots should not be publicly restorable", is an AWS Foundational
# Security Best Practices control, which is a different standard from either of
# the two cited here. Snapshot encryption is the same shape of near-miss as CIS
# 3.4 above: the benchmark covers encrypting volumes, this rule reports on
# snapshots taken from them, and the two are not the same claim. If a snapshot
# control is added in a later benchmark, it belongs here rather than inline.
#
# CIS has no control for S3 default encryption. Since 5 January 2023 AWS applies
# SSE-S3 to every new bucket and the setting can no longer be removed, so the
# control had nothing left to check. This tool still reads encryption state,
# both to report the weaker AES256 case and because a scanner that trusts a
# platform guarantee it never verifies is not a scanner.
