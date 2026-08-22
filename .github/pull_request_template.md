<!--
Security vulnerabilities do not go here. Report them privately:
https://github.com/Hhhectic/secure-cloud-provisioner/security
-->

## What this changes

<!-- And why. If it fixes an issue, "Fixes #123". -->

## How it was checked

- [ ] `cd backend && pytest` passes
- [ ] `cd frontend && npm test` passes (if the page or `keygen.js` changed)
- [ ] Ran against a real cloud account — **required if this touches an actual
      cloud call**, because moto has disagreed with real AWS in this project
      more than once

<!-- If you ran the smoke test, say which region: `scripts/smoke_test.py --region ...` -->

Not needed for changes confined to `scanner/`, `frontend/`, docs, or tests.

## If this adds or changes a rule

- [ ] There is a test that **fails without the change**
- [ ] `scanner/` still imports no cloud SDK
- [ ] Near-misses are covered, not just the obvious case — a rule matching
      `0.0.0.0/0` by string equality is silent on `0.0.0.0/1`
- [ ] Any control ID is referenced from `scanner/controls.py`, not written
      inline — and left empty rather than invented if no published control fits

## If this adds a resource type

- [ ] A provider module in `aws/` or `az/`, importing the SDK through `_import`
- [ ] A rules module in `scanner/`
- [ ] One adapter block and one `REGISTRY` entry in `api/registry.py`
- [ ] **No changes to `api/app.py`** — needing them means the adapter shape is
      wrong
- [ ] Any new dependency is declared in the right requirements file

## Anything reviewers should know

<!-- Decisions you made that could reasonably have gone the other way, things
     you are unsure about, follow-up work you are deliberately leaving out. -->
