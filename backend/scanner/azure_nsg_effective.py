"""Which rule actually wins, once the whole ordered set is taken into account.

This module is the answer to the sentence that has sat in CLAUDE.md since the
Azure half arrived: *an NSG rule carries a priority deciding which of several
overlapping rules wins, so neither creating one nor fixing one can be judged
without reading the whole ordered set.* That was the reason `az/nsg.py` was
read-only, the reason it offered no fix, and therefore the reason the root
Azure app could not retire. It is one problem and it is solved once, here, for
all three callers.

**How Azure decides.** Rules are sorted by priority, lowest number first, and
the first one matching a packet decides it - Allow or Deny - and no later rule
is consulted. A rule matches on direction, protocol, source, destination and
port. Priorities are unique within a direction, and every group carries three
default rules per direction at priorities 65000-65500 that cannot be removed;
the last of them denies everything, which is why an NSG is closed until
something opens it.

**Why this matters to a scanner.** Judging rules one at a time gives two wrong
answers, in both directions:

  - A group with `allow-ssh` from `*` at priority 100 and `deny-ssh` from `*`
    at priority 4096 is open. A group with those priorities the other way round
    is closed. The rules are identical; only the order differs, and a
    per-rule scanner calls both of them critical.
  - A group with `deny-all` at priority 100 is closed no matter what follows
    it, and a per-rule scanner reports every later Allow as an exposure that
    cannot happen.

The second is the expensive one. A tool that cries wolf about rules that are
already shadowed teaches people to skim its output, and the finding they skim
past is the one that was real.

**What this does not model.** Application security groups, service tags other
than `Internet` and `VirtualNetwork`, and destination address prefixes are read
but not resolved - a rule naming a service tag this does not know is treated as
matching nothing, so it can never manufacture an Allow that Azure would not
make. Erring towards silence rather than towards invention is deliberate: a
false "you are exposed" is the failure mode above, and a missed finding here is
one the per-rule pass in `azure_nsg_rules.py` still reports separately.
"""

# Azure's own defaults, which exist on every group and cannot be deleted. The
# last one is why a group with no rules at all allows nothing inbound from
# outside.
DEFAULT_DENY_PRIORITY = 65500

# What Azure writes where AWS writes 0.0.0.0/0. Kept in step with
# OPEN_TO_EVERYONE in azure_nsg_rules.py, which is the same idea for the
# per-rule pass.
EVERYONE = {"*", "0.0.0.0/0", "internet", "::/0"}


def _matches_everyone(source):
    return str(source or "").strip().lower() in EVERYONE


def _covers_port(rule, port):
    """Whether a rule's destination range includes `port`.

    Accepts the single range the reader flattens to. `az/nsg.py` has already
    expanded a rule naming several ranges into one entry per range, so this
    never has to deal with a list.
    """
    text = str(rule.get("destination_port_range") or "").strip()
    if not text:
        return False
    if text == "*":
        return True
    if "-" in text:
        try:
            low, high = (int(part) for part in text.split("-", 1))
        except ValueError:
            return False
        return low <= int(port) <= high
    return text == str(port)


def _covers_protocol(rule, protocol="Tcp"):
    """Whether a rule's protocol includes the one being asked about.

    "*" is Azure's any. Anything else has to match, because a rule allowing UDP
    on port 22 does not open SSH.
    """
    written = str(rule.get("protocol") or "").strip().lower()
    return written in ("*", "any", str(protocol).lower())


def _priority(rule):
    """A rule's priority, with anything unreadable sorted last.

    A rule whose priority cannot be read must not be allowed to sort *first*
    and shadow everything behind it, which is what a default of 0 would do.
    Sorting it last means the worst it can do is be ignored, and being ignored
    is the direction this module errs in everywhere else.
    """
    try:
        return int(rule.get("priority"))
    except (TypeError, ValueError):
        return DEFAULT_DENY_PRIORITY


def decide(rules, port, direction="Inbound", protocol="Tcp",
           source_is_everyone=True):
    """What Azure would do with one packet. Returns (decision, rule).

    decision is "Allow", "Deny" or "DenyByDefault"; rule is the rule that
    decided it, or None when nothing matched and Azure's own final deny
    applied.

    Only the packet's source being the whole internet is modelled, because that
    is the only question every rule in this package asks. Answering "can this
    specific address reach this port" would need the full CIDR arithmetic, and
    nothing here has ever asked it.
    """
    candidates = []
    for rule in rules or []:
        if str(rule.get("direction") or "").strip().lower() != direction.lower():
            continue
        if not _covers_port(rule, port):
            continue
        if not _covers_protocol(rule, protocol):
            continue
        if source_is_everyone and not _matches_everyone(
                rule.get("source_address_prefix")):
            # A rule scoped to particular addresses does not decide a packet
            # arriving from everywhere else. It is not evidence of safety
            # either - it simply is not this packet's rule.
            continue
        candidates.append(rule)

    for rule in sorted(candidates, key=_priority):
        access = str(rule.get("access") or "").strip().lower()
        if access == "allow":
            return "Allow", rule
        if access == "deny":
            return "Deny", rule

    return "DenyByDefault", None


def shadowed_by(rules, rule, port, direction="Inbound"):
    """The rule that stops `rule` ever applying to `port`, or None.

    Used to keep the per-rule findings honest: an Allow sitting behind a Deny
    at a lower priority is not an exposure, and reporting it as one is how a
    scanner's output stops being read. Returns the deciding rule only when it
    is a different rule and it denies.
    """
    decision, decider = decide(rules, port, direction=direction)
    if decision == "Allow":
        return None
    if decider is None:
        # Nothing matched at all, so this rule cannot be the one that decides -
        # which happens when the rule being asked about is scoped to named
        # addresses rather than to everyone.
        return None
    if decider.get("name") == rule.get("name"):
        return None
    return decider


def describe(rules, ports, direction="Inbound"):
    """A decision per port, for showing a person what the set adds up to.

    The point of this is that it is the same computation the findings use. A
    summary derived separately from the judgement is a second thing to keep in
    step, and CLAUDE.md already records what that costs - a form offering a TLS
    dropdown beside a scanner with no TLS rule.
    """
    out = {}
    for port in ports:
        decision, rule = decide(rules, port, direction=direction)
        out[str(port)] = {
            "decision": decision,
            "rule": (rule or {}).get("name"),
            "priority": _priority(rule) if rule else None,
        }
    return out
