"""Security rules for evaluating Azure virtual machines.

Pure evaluation logic, no cloud calls. The counterpart of
`scanner/instance_rules.py`, and the judgement is deliberately the same where
the question is the same: a machine with a public address and an open
administration port is the same fact on either cloud, and if this file
disagreed with the AWS one about what that means, one of them would be wrong.

Three differences from the AWS instance rules, all because Azure is arranged
differently rather than because the judgement is:

- **Filtering is not on the machine.** An EC2 instance carries its security
  groups. An Azure machine's traffic is filtered by a group attached to its
  network card or to its subnet, either, neither or both - so "is this machine
  exposed" cannot be answered from the machine alone. `az/vm.py` reads the
  effective set and hands it over, and `scanner/azure_nsg_effective.py` decides
  what it adds up to.
- **Password authentication is a finding of its own.** Azure Linux machines
  allow it and it is a checkbox on the portal's create form, so it is a
  configuration somebody chose rather than a default they inherited. There is
  no equivalent on the AWS side because EC2 does not offer it.
- **No workload finding.** `_check_workload` on the AWS side reads processor
  use and says whether a machine is idle or saturated. The Azure equivalent
  needs Azure Monitor, which is a separate client and a separate permission
  this tool does not ask for. Its absence is recorded in CLAUDE.md rather than
  guessed at here.

Nothing here carries a CIS citation, for the reason recorded in CLAUDE.md: CIS
AWS Foundations is an AWS benchmark and the Azure one is a separate document
nobody on this project has read.
"""

from scanner import azure_nsg_effective as effective
from scanner.common import CRITICAL, WARNING, INFO, warning as _warning

# The same two doors, with the same words, as scanner/azure_nsg_rules.py and
# scanner/rules.py. A reader who has seen one finding should not have to learn
# a second vocabulary for the other cloud or the other resource type.
ADMIN_PORTS = {
    "22": "SSH, the remote login door for Linux servers",
    "3389": "RDP, the remote desktop door for Windows servers",
}


def _target(vm_name, setting):
    return {
        "rule_id": f"{vm_name}:{setting}",
        "resource_id": vm_name,
        "setting": setting,
    }


def check_vm(settings):
    """Evaluates one virtual machine and returns detected risks.

    Expects the shape produced by az.vm.read_vm_for_scanning():
        {
          "vm_name": str, "resource_group": str, "location": str,
          "vm_size": str, "power_state": str | None,
          "public_ip": str | None,
          "password_authentication_disabled": bool | None,
          "os_disk_encrypted": bool | None,
          "encryption_at_host": bool | None,
          "effective_rules": [ ...flattened nsg rules... ],
          "unreadable": {setting: why},
        }
    """
    if not settings:
        return []

    name = settings.get("vm_name", "this machine")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    # A skipped check is a finding, not a silence. Reported first.
    for setting, why in sorted(unreadable.items()):
        warnings.append(_warning(
            WARNING,
            f"Could not check {setting} on '{name}': {why}. This part of the "
            "audit did not run, so treat it as unanswered rather than as "
            "passed.",
            _target(name, f"unreadable_{setting}"),
        ))

    public_ip = settings.get("public_ip")
    rules = settings.get("effective_rules") or []

    # ---- An administration port open to the internet -------------------------
    #
    # Only reported as critical when the machine can actually be reached from
    # outside. A wide-open rule on a machine with no public address is a
    # warning, not a crisis: it is one public IP away from being one, and that
    # is exactly how it usually happens, so it is not silence either.
    if "effective_rules" not in unreadable:
        for port, description in ADMIN_PORTS.items():
            decision, rule = effective.decide(rules, port)
            if decision != "Allow":
                continue

            rule_name = (rule or {}).get("name", "a rule")

            if public_ip:
                warnings.append(_warning(
                    CRITICAL,
                    f"Port {port} ({description}) on '{name}' is open to the "
                    f"entire internet, through the rule '{rule_name}', and the "
                    f"machine has a public address ({public_ip}). Anyone can "
                    "reach it and try to log in.",
                    _target(name, f"open_{port}"),
                ))
            else:
                warnings.append(_warning(
                    WARNING,
                    f"Port {port} ({description}) on '{name}' is open to any "
                    f"source, through the rule '{rule_name}'. The machine has "
                    "no public address today, so nothing outside can reach it "
                    "yet - but the rule permits it, and adding a public "
                    "address is one setting.",
                    _target(name, f"open_{port}_no_public_address"),
                ))

    # ---- Whether it is reachable from outside at all -------------------------
    if public_ip:
        warnings.append(_warning(
            INFO,
            f"'{name}' has a public address ({public_ip}), so it is reachable "
            "from the internet. That is not a fault - plenty of machines need "
            "one - but it means the rules above are what stands between it and "
            "everybody.",
            _target(name, "has_public_address"),
        ))

    # ---- Passwords ----------------------------------------------------------
    if "password_authentication_disabled" not in unreadable:
        if settings.get("password_authentication_disabled") is False:
            warnings.append(_warning(
                CRITICAL if public_ip else WARNING,
                f"'{name}' accepts a password for logging in. A password can "
                "be guessed, and a machine reachable from the internet is "
                "guessed at continuously by people who are not aiming at you "
                "in particular. A key cannot be guessed. This is the single "
                "setting that decides whether an exposed administration port "
                "is an annoyance or a break-in.",
                _target(name, "password_login_allowed"),
            ))

    # ---- The disk -----------------------------------------------------------
    #
    # Azure encrypts every managed disk at rest with platform-managed keys and
    # has done since 2017, so this cannot be off. It is stated rather than
    # assumed, and reported as a note rather than left silent, for the same
    # reason the S3 rules still check encryption on buckets Azure's equivalent
    # of which cannot be unencrypted: an older or imported disk can be
    # different, and a check that never runs is a check nobody notices has
    # stopped working.
    if settings.get("os_disk_encrypted") is False:
        warnings.append(_warning(
            WARNING,
            f"The operating system disk on '{name}' reports as unencrypted. "
            "Every managed disk Azure creates is encrypted at rest, so this "
            "is either an imported disk or something worth looking at "
            "directly.",
            _target(name, "unencrypted_disk"),
        ))

    if settings.get("encryption_at_host") is not True:
        warnings.append(_warning(
            INFO,
            f"'{name}' does not use encryption at host. The disk itself is "
            "still encrypted; what this adds is encryption of the temporary "
            "disk and of the caches on the physical machine underneath. It is "
            "off by default and has to be enabled on the subscription before "
            "a machine can use it.",
            _target(name, "no_encryption_at_host"),
        ))

    return warnings


def check_vm_spec(spec):
    """Scans a machine form, before the machine exists.

    Reads the same fields under the same names as `az/vm.py` writes them, which
    is what makes the warnings shown before creation the ones shown after it -
    the contract `check_storage_spec` states, across a fourth type.

    A form has no effective rule set yet, because the security group it will
    sit behind may not exist. So the ports it opens are taken from what the
    form says it wants open, which is the same question asked one step earlier.
    """
    if not spec:
        return []

    name = spec.get("name") or "this machine"
    ports = [str(p) for p in (spec.get("open_ports") or [])]
    source = spec.get("allowed_source") or "*"

    rules = [{
        "name": f"allow-{port}",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "priority": 100 + index,
        "source_address_prefix": source,
        "destination_port_range": port,
    } for index, port in enumerate(ports)]

    return check_vm({
        "vm_name": name,
        "vm_size": spec.get("vm_size"),
        # A form asking for a public address is treated as having one, because
        # the finding it changes is about what the machine will be when it
        # exists rather than what it is now.
        "public_ip": "pending" if spec.get("assign_public_ip") else None,
        "password_authentication_disabled": not spec.get(
            "allow_password_login", False),
        "os_disk_encrypted": True,
        "encryption_at_host": spec.get("encryption_at_host", False),
        "effective_rules": rules,
        "unreadable": {},
    })
