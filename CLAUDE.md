# Notes for Claude Code

Start with [README.md](README.md) for what this is. This file is the
repository-specific guidance that is easy to get wrong.

## The rules that are not negotiable

- **`backend/scanner/` imports no cloud SDK, ever** — not directly, not through
  anything it imports. Rules take a plain settings dict and return one warning
  shape. This is what lets the offline suite run with no credentials and one set
  of HTTP routes serve fifteen resource types.
- **Adding a resource type does not change `api/app.py`.** It is a provider
  module in `aws/` or `az/`, a rules module in `scanner/`, and one adapter block
  plus one `REGISTRY` line in `api/registry.py`. Needing a route change means
  the adapter shape is wrong.
- **A new or changed rule needs a test that fails without it.** A rule that
  fails open is worse than no rule. Cover the near-misses: checking
  `0.0.0.0/0` by string equality is silent on `0.0.0.0/1` and `128.0.0.0/1`,
  which between them are every address there is. That was a real bug on both
  clouds.
- **Control IDs live in `scanner/controls.py` only.** Reference the symbolic
  name. A rule with no published control leaves the field empty rather than
  citing something invented.

## Running things

```bash
cd backend  && pytest       # 1041 tests, ~3.5 min, no account needed
cd frontend && npm test     # needs `npm install` first (jsdom)
cd backend  && uvicorn api.app:app --reload --host 127.0.0.1
cd backend  && python main.py
```

`pip install -r requirements.txt` from the root installs both clouds, and is
what CI installs. `backend/requirements.txt` alone is the AWS half — enough to
*run* the AWS side, but **not enough to run the tests**:
`tests/test_azure_provisioning.py` imports `azure.core` at module level, so
without the Azure SDK pytest cannot collect it and the whole run is interrupted
before anything executes. That exact mistake kept CI red for weeks while every
development machine passed.

## Green tests do not mean it works

The suite runs against moto, which fakes AWS in memory and **has been wrong
about real AWS more than once here** — it permits unencrypted buckets AWS has
refused since January 2023, and it enforces `aws:SecureTransport` over its own
plain-HTTP endpoint, which real boto3 never hits.

Anything touching an actual cloud call needs `backend/scripts/smoke_test.py`
against a real account before it can be called done. Use a region nobody else is
in — cleanup deletes by tag, not by author.

Do not claim a live behaviour was verified unless a live call actually ran.

## Two environment facts

- **Two virtualenvs exist and are not interchangeable.** `~/scp-venv` has
  `azure-mgmt-monitor`; `~/code/.venv` has `azure-mgmt-authorization`,
  `-security`, `-sql`, `-subscription`. Both run the whole offline suite green,
  so no test distinguishes them — only a live call does.
- **The shared AWS account is free-tier restricted.** `t2.micro` is refused in
  `us-west-2` as not eligible; `t3.micro` works and is `DEFAULT_INSTANCE_TYPE`.
  The instance-type menu lists `t2.micro` first and marks the default only
  inside the label text, so taking position one launches nothing.

## Style

Comments here say **why**, not what, and they are load-bearing — most record a
decision or a failure not visible from the code. If you change behaviour a
comment describes, change the comment in the same commit. Error messages name
the fix rather than the failure. Commit messages are an imperative sentence
saying what the commit does.

## Where the reasoning is

[docs/development-log.md](docs/development-log.md) is the working log the project
was built from: design arguments, dead ends, and every place moto disagreed with
real AWS. It is ~2,700 lines, it describes the repository as it was at the time
each section was written, and it contradicts itself in places. **Where it and
the code disagree, the code is right.** Check its claims before repeating them.
