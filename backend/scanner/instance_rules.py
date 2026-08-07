"""Security rules for evaluating EC2 instances.

Contains pure Python evaluation logic with no external AWS dependencies.

One thing here works differently from the other scanners. An instance's most
important security property is not a setting on the instance at all: it is which
firewall rules apply to it and whether it has a public address. "This security
group allows SSH from anywhere" is a finding about a configuration object.
"This machine is reachable from the internet on port 22" is a finding about
something real. check_instance therefore accepts the findings from the instance's
security groups and reframes them in terms of the machine, rather than making
the reader join those two facts up themselves.
"""

from scanner.common import (
    CRITICAL,
    WARNING,
    INFO,
    warning as _warning,
    summarize,
    fixable,
    cited,
    worst_level,
    print_warnings,
)


def _target(instance_id, setting):
    return {
        "rule_id": f"{instance_id}:{setting}",
        "resource_id": instance_id,
        "setting": setting,
    }


def check_instance(settings, firewall_warnings=None):
    """Evaluates one instance and returns detected risks.

    Expects the shape produced by aws.instances.read_instance_for_scanning().
    firewall_warnings, if given, are the findings from this instance's security
    groups; they are used to say whether the instance is actually exposed.
    """
    if not settings:
        return []

    instance_id = settings.get("instance_id", "unknown")
    name = settings.get("name") or instance_id
    public_ip = settings.get("public_ip")
    warnings = []

    # ---- The metadata service. CIS 5.7 ---------------------------------------
    #
    # This is the most consequential check in the file and the least obvious.
    # Every instance can reach a service at 169.254.169.254 that hands out the
    # instance's IAM credentials. Under IMDSv1 that is a plain GET, so any bug
    # that makes the instance fetch a URL an attacker chooses will fetch those
    # credentials and hand them over. That is how the 2019 Capital One breach
    # worked. IMDSv2 requires a PUT to obtain a token first, which a request
    # forgery bug cannot perform.
    if not settings.get("metadata_endpoint_enabled"):
        warnings.append(_warning(
            INFO,
            f"The metadata service is switched off entirely on {name}. That is "
            "the strongest setting available. Anything on this machine that "
            "needs AWS credentials will have to be given them another way.",
            _target(instance_id, "imds_disabled"),
            control="IMDSV2_REQUIRED",
        ))
    elif not settings.get("imdsv2_required"):
        warnings.append(_warning(
            CRITICAL,
            f"{name} lets software on it read the machine's AWS credentials "
            "with a simple web request. If any program on this machine can be "
            "tricked into fetching a web address chosen by someone else, that "
            "someone gets the credentials and everything they can do. Requiring "
            "the newer metadata version closes this and breaks nothing that is "
            "up to date.",
            _target(instance_id, "imdsv2"),
            fix={
                "action": "enforce_imdsv2",
                "label": "Require the secure metadata version",
            },
            control="IMDSV2_REQUIRED",
        ))
    elif (settings.get("metadata_hop_limit") or 1) > 1:
        warnings.append(_warning(
            WARNING,
            f"The metadata service on {name} answers requests forwarded one "
            "more step than necessary. On a machine running containers, that "
            "is usually enough for a container to read the host's AWS "
            "credentials. Reduce the hop limit to 1 unless something genuinely "
            "needs otherwise.",
            _target(instance_id, "metadata_hop_limit"),
            fix={
                "action": "enforce_imdsv2",
                "label": "Reduce the metadata hop limit to 1",
            },
            control="IMDSV2_REQUIRED",
        ))

    # ---- Reachability --------------------------------------------------------
    exposed_ports = sorted({
        w["rule"]["from_port"]
        for w in (firewall_warnings or [])
        if w.get("rule") and w["rule"].get("from_port") is not None
        and w["level"] == CRITICAL
    })

    if public_ip and exposed_ports:
        ports = ", ".join(str(p) for p in exposed_ports)
        warnings.append(_warning(
            CRITICAL,
            f"{name} has a public address ({public_ip}) and its firewall "
            f"allows the whole internet in on port(s) {ports}. This is not a "
            "risk of exposure, it is exposure: anyone in the world can reach "
            "those ports on this machine right now. Fix the firewall rules, or "
            "take away the public address.",
            _target(instance_id, "reachable_from_internet"),
        ))
    elif public_ip:
        warnings.append(_warning(
            INFO,
            f"{name} has a public address ({public_ip}), so its firewall rules "
            "are the only thing between it and the internet. They currently "
            "look sound. An instance with no public address is safer still, if "
            "it does not need one.",
            _target(instance_id, "public_ip"),
        ))
    elif exposed_ports:
        warnings.append(_warning(
            INFO,
            f"{name}'s firewall allows the whole internet in, but the machine "
            "has no public address, so nothing can reach it from outside. The "
            "rules would take effect immediately if a public address were ever "
            "added.",
            _target(instance_id, "latent_exposure"),
        ))

    # ---- Storage -------------------------------------------------------------
    encrypted = settings.get("root_volume_encrypted")
    if encrypted is False:
        warnings.append(_warning(
            WARNING,
            f"The disk on {name} is not encrypted. Anyone who obtains a copy "
            "of it, including from a snapshot shared by accident, can read "
            "everything on it. This cannot be changed on a running instance: "
            "it has to be set when the machine is created.",
            _target(instance_id, "root_volume_encryption"),
        ))
    elif encrypted is None:
        # Two quite different causes, and the common one is not a problem.
        # A machine that has only just started has no disk attached yet, so
        # there is nothing to ask about. Naming the permission first, as this
        # message used to, sends people to rewrite an IAM policy that was
        # never wrong.
        starting = settings.get("state") in ("pending", None)
        warnings.append(_warning(
            INFO,
            f"Could not tell whether the disk on {name} is encrypted. "
            + ("The machine is still starting and its disk is not attached "
               "yet; scan again shortly."
               if starting else
               "The disk is not attached yet, or the login this tool uses is "
               "missing ec2:DescribeVolumes. Scanning again in a moment will "
               "tell you which."),
            _target(instance_id, "root_volume_unknown"),
        ))

    # ---- Access --------------------------------------------------------------
    #
    # A key pair on its own grants nothing. Logging in needs three things at
    # once: the key, a route to the machine, and a firewall rule permitting it.
    # Reporting on the key without the other two invites the mistake of
    # assuming access works, or of adding a public address to "fix" a login
    # problem that was never about the key.
    key_name = settings.get("key_name")
    ssh_allowed = 22 in (exposed_ports or []) or settings.get("ssh_reachable")

    # A key pair on a machine with no public address is deliberately not
    # reported. It is the recommended arrangement - reach the machine through
    # a bastion or Session Manager rather than exposing it - and flagging it
    # would nudge people toward adding a public address to silence a warning,
    # which is precisely the wrong lesson.
    if key_name and public_ip and not ssh_allowed:
        warnings.append(_warning(
            INFO,
            f"{name} has the key pair '{key_name}' and a public address, but "
            "no firewall rule permitting SSH, so logins will not connect. Add "
            "a rule for port 22 limited to your own address if you need one.",
            _target(instance_id, "key_without_firewall_rule"),
        ))

    if not key_name and public_ip:
        warnings.append(_warning(
            INFO,
            f"{name} has no key pair, so nobody can log into it over SSH. If "
            "you need a shell, EC2 Instance Connect or Session Manager will "
            "give you one without a key to look after.",
            _target(instance_id, "no_key_pair"),
        ))

    return warnings
