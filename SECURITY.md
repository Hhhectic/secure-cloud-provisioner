# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting instead: go to the
[Security tab](https://github.com/Hhhectic/secure-cloud-provisioner/security)
and choose **Report a vulnerability**. That opens a private thread visible only
to the maintainers.

Useful things to include: what an attacker can do, the smallest set of steps
that shows it, and which version or commit you saw it on. A concrete failing
case is worth more than a description.

This is a student-built project maintained in people's spare time, not a funded
product. Expect a first reply within about a week. There is no bounty. Credit in
the fix commit if you want it, and no credit if you would rather not.

## What this tool is, and is not

**It is not an audited security product.** It began as a capstone project. It
checks a specific, documented set of controls drawn from the CIS AWS Foundations
Benchmark v5.0.0 and the AWS Startup Security Baseline. Passing every check does
not mean an account is secure — it means those checks passed.

The gaps are written down rather than glossed over.
[docs/benchmark.md](docs/benchmark.md) lists, by name, every finding that
[Prowler](https://github.com/prowler-cloud/prowler) 5.37.1 reported on the same
account and this tool did not. Read it before relying on a clean result. Use
this alongside your cloud provider's own tooling, not instead of it.

## Running it safely

The tool holds credentials that can open network access and delete storage. Its
threat model assumes it is running on a machine where you are the only user.

**It has no authentication and binds to `127.0.0.1`.** That is deliberate, not an
oversight — a login screen on a process that already trusts whoever is sitting at
the machine would be theatre. The consequence is the important part: **exposing
this on a public interface, a shared host, or through a tunnel hands your cloud
account to whoever reaches it.** There is no second line of defence behind the
network boundary.

Things worth knowing before pointing it at an account:

- **Give it its own IAM identity, not your admin user.**
  [docs/iam-setup.md](docs/iam-setup.md) has two least-privilege policy documents
  and explains why AWS forces them to be two files. The demo policy is separate
  and should be detached when you are not demoing.
- **Cleanup deletes by tag, not by author.** Bulk cleanup destroys everything
  carrying the tool's tag in the target region, including resources someone else
  created. On a shared account, give each person a region.
- **`backend/scripts/make_vulnerable.py` creates genuinely insecure resources**
  on purpose, so the scanner has something to find. It is a demo fixture. Run it
  only where you do not mind being wrong for a few minutes, and clean up after.
- **Overriding a critical finding is possible by design.** Re-sending the create
  with `accept_risk=true` proceeds regardless. It is recorded in the audit log,
  but it is not prevented. If you have wired this into anything automated, that
  is the parameter to review — a script that sets it unconditionally turns the
  preflight gate off.
- **Writes are logged** to `~/.secure-cloud-provisioner/audit.log`
  (`SCP_AUDIT_LOG` moves it). Reads are not. The log is local and unsigned —
  it is a record for you, not tamper-evident evidence.

## Handling of keys and credentials

- **Private keys are never downloaded from the cloud.** The page generates SSH
  key pairs in the browser with WebCrypto and uploads only the public half; the
  tool never calls `CreateKeyPair`. The private half goes straight to a browser
  download and never crosses the network.
- **The browser chooses where that download lands.** `.gitignore` carries
  patterns for every name the page and the bastion blueprint give a key file, so
  a key saved into the repository is not one `git add -A` from being published.
  Check before committing anyway.
- **Credentials go in a `.env` at the repository root**, which is gitignored, or
  in real environment variables, which take precedence. Nothing reads a
  credential out of a command-line argument or writes one to the audit log.
- **Long-lived access keys are the fallback, not the recommendation.**
  [docs/iam-setup.md](docs/iam-setup.md) covers moving off them.

If you find a case where a secret does reach a log, a URL, an error message, or
a file that is not gitignored, that is a vulnerability — please report it through
the private channel above.
