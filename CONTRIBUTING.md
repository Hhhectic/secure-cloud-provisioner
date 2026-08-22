# Contributing

Thanks for looking at this. It started as a capstone project and is now open,
which means the conventions below were mostly discovered the hard way rather
than chosen up front. Where one seems arbitrary, it usually is not — the
reasoning is in [docs/development-log.md](docs/development-log.md).

## Setting up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # both clouds
cd frontend && npm install               # test tooling only
```

**Install the root `requirements.txt`, not `backend/requirements.txt`**, even if
you only care about the AWS half. The backend file runs the AWS side and its
tests, but it declares no Azure SDK, and without one
`tests/test_azure_provisioning.py` skips — 110 tests you are not running, said
plainly in the summary line rather than silently. The Azure tests need the SDK,
not an account: they mock their clients and run with no `AZURE_*` variable set.

If you see `1 skipped` at the end of a run, that is what it is.

The page itself has no dependencies and never will — `npm install` fetches
jsdom and playwright so the frontend can be executed somewhere other than a
person's browser, and neither is ever shipped.

## Running the tests

```bash
cd backend  && pytest       # 1041 tests, no cloud account, no credentials
cd frontend && npm test     # runs keygen.js under Node, checks it with ssh-keygen
```

Both suites must pass before a pull request. CI runs both on every push and pull
request, including from forks, because nothing in either needs an account.

**Do not add a test that needs credentials.** The offline suite's whole value is
that a stranger's pull request can be verified without one, and that property is
easy to lose by accident.

### The part the offline suite cannot tell you

The Python tests run against [moto](https://github.com/getmoto/moto), which fakes
AWS in memory. moto has been wrong about real AWS more than once here — it
permits unencrypted buckets that AWS has refused since January 2023, and it
enforces `aws:SecureTransport` over its own plain-HTTP endpoint, which real boto3
never hits. Both were found by accident.

So if your change touches an actual cloud call, run it against a real account
before opening the pull request, and say in the description that you did:

```bash
cd backend && python scripts/smoke_test.py --region eu-west-2
```

Use a region nobody else is working in. Cleanup is by tag, not by author, and it
will delete a teammate's resources without asking whose they are.

Changes confined to `scanner/`, `frontend/`, docs, or tests do not need this.

## Adding a resource type

Three pieces, in this order:

1. **`backend/aws/<thing>.py`** or **`backend/az/<thing>.py`** — the cloud calls.
   Import the SDK through the module's `_import` helper so a missing SDK costs
   one tab instead of the whole page starting.
2. **`backend/scanner/<thing>_rules.py`** — the rules. See below.
3. **One entry in `backend/api/registry.py`** — the adapter block, then add the
   name to `REGISTRY`.

**No route changes.** If you find yourself editing `api/app.py` to add a
resource type, the adapter shape in `registry.py` is wrong and that is the thing
to fix. Every route is generic across types; that is only possible because every
scanner returns one warning shape.

## Adding or changing a rule

This is the part to be careful with. **A rule that fails open is worse than no
rule**, because it converts "unknown" into "checked, and fine."

- **No cloud SDK imports in `scanner/`, or in anything it imports.** Rules take a
  plain settings dict. This is what makes them testable without an account, and
  it is not negotiable.
- **A new rule needs a test that fails without it.** Write the failing case
  first and watch it fail.
- **Test the near-misses, not just the obvious case.** Both clouds checked for a
  world-open firewall with string equality against `0.0.0.0/0` for months.
  `0.0.0.0/1` and `128.0.0.0/1` are two rules covering every address there is,
  and both were silent. So were `0.0.0.0/4` and `::/1`.
- **Control IDs live in `scanner/controls.py` and nowhere else.** Reference the
  symbolic name so a benchmark version bump is one edit. A rule with no published
  control is fine — leave the field empty rather than inventing a citation.
- **Do not add a wildcard to acknowledgements.** One pattern silencing a class of
  finding is how these go wrong.

Severity is about how bad it is to be without the control. CIS *level* is about
how hard the control is to live with. They are different questions and are
deliberately stored separately.

## Style

Match the file you are in. A few things that hold throughout:

- **Comments say why, not what.** The repository is unusually heavily commented
  and the comments are load-bearing: most of them record a decision or a failure
  that is not visible from the code. If you change behaviour a comment describes,
  change the comment in the same commit.
- **Error messages name the fix.** A missing IAM permission returns a 403 that
  says which permission and where to add it, not a 500 with a traceback. Hold new
  code to that.
- **Commit messages are a sentence in the imperative** saying what the commit
  does — `Stop a bucket nobody may read from answering 500`. Not `fix bug`.

## Pull requests

Say what you changed, why, and how you checked it. If it touches a live cloud
call, say which account and region you ran the smoke test in.

Small and separable beats one large branch. If a change turns out to need a
decision rather than an implementation, open an issue first.

## Reporting security problems

Not through a pull request or a public issue. See [SECURITY.md](SECURITY.md).
