# The Streamlit GUI, kept but not used

The second of two Streamlit interfaces, and the later one. `../streamlit-frontend/`
is the first; it talked to the Azure API over HTTP at `/api/v1` and covered Azure only.
This one imports the backend directly and covers both clouds.

It is here for the reason given next door: it works, and deleting a working interface on
the strength of one decision is not a decision anyone should have to take twice.

## Why the group chose `frontend/`

The comparison in `../streamlit-frontend/README.md` is still the right one, and its
fourth row no longer separates the two — this page reaches both clouds. What decided it
was the rest:

| | This one | `frontend/` |
|---|---|---|
| Runs as | its own Streamlit process, its own port | served by the API itself at `/ui` |
| Risk gate | in the page — the button is disabled | **in the API** — it refuses a critical spec unless `accept_risk=true` |
| Covers | 4 form flows | every registered `ResourceType` |
| Can | create | list, scan, create, fix, delete, clean up, build a bastion |
| Tests | none | `app.test.mjs`, in CI |

The gate is the deciding row. Disabling a button is a convention anyone calling the API
directly walks straight past; refusing the request is a control. The rest follows from
`frontend/` being built on the registry rather than beside it.

## What was taken out of it first

Two Azure storage rules were moved into `backend/scanner/azure_storage_rules.py`, where
the JS console reads them through the registry like any other finding:

- **which containers are public** — the account switch says a container *may* be served
  anonymously, not which ones are
- **whether the account key still works** — it never expires, cannot be scoped, and names
  nobody in the logs

Nothing else here was ported. What is still only in this directory:

- **`deploy_azure_vm()`** — creates a resource group, virtual network, NSG, NIC, optional
  public IP and a Linux VM with SSH-key authentication. `backend/az/` covers NSGs and
  storage but not compute, and is read-only by choice: a create path nobody has run
  against a real subscription is a claim rather than a feature. This one has not been run
  against real Azure either, which is exactly why it was not moved across.
- **The Azure VM rules** — password authentication, a predictable administrator username,
  a public address, encryption at host. Portable and testable without a subscription, but
  there is no `az/compute.py` reader for them to run against yet. They are in
  `security_messages.py` at the repository root, under `AZURE_VM_*`, and would move with
  the reader.

## Running it, if the decision is revisited

```bash
pip install -r requirements.txt
pip install streamlit python-dotenv azure-mgmt-network azure-mgmt-compute azure-storage-blob
streamlit run archive/streamlit-gui/app.py
```

`backend_path.py` searches upwards for `backend/`, so it works from this directory. Note
that installing `azure-mgmt-network` makes two tests in `backend/tests/test_azure_provider.py`
fail — they assert the Azure SDK is *absent*, which is what proves the AWS half starts
without it. CI installs `backend/requirements.txt` only, so CI is unaffected.

## How it was put together

| Module | Role |
| --- | --- |
| `app.py` | The GUI: provider/resource selection, forms, warning banners, acknowledgement gate |
| `preflight.py` | `scan_config(config)` — adapts a form to the backend's rules; the Azure form rules |
| `cloud_deploy.py` | `deploy_aws_vm`, `deploy_aws_bucket`, `deploy_azure_vm`, `deploy_azure_storage` |
| `backend_path.py` | Puts `backend/` and the repository root on `sys.path` |

The AWS half was never a second implementation. `preflight.py` builds the settings
snapshot each backend rule expects and calls `check_bucket_settings`,
`check_firewall_rules` and `check_instance`; `cloud_deploy.py` calls `aws/s3_buckets.py`,
`aws/security_groups.py` and `aws/instances.py` and never touches boto3 itself. So its
AWS findings carried the same control citations, and anything it created got the
instance-type allowlist, the managed-resource tagging and the forced IMDSv2.

`check_firewall_rules` was reused for Azure NSG rules, with its CIS **AWS** citation and
its AWS fix action stripped — the ports logic carries across, the benchmark does not.

It is called `preflight.py` rather than `scanner.py` because `scanner` is the backend's
package name.

## One thing that was right, and is worth keeping wherever the gate ends up

Findings whose only level is `info` never asked for an acknowledgement. The rules report
context as well as faults — a fully hardened bucket comes back with three notes — and
making somebody tick *"I acknowledge the security risk"* to deploy a correct bucket is how
that checkbox becomes a reflex.

## Testing

There was never automated coverage for `preflight.py` or `cloud_deploy.py`. They were
verified by hand against moto and in a browser: a hardened bucket deployed with all four
public-access blocks on, AES256, versioning and an HTTPS-only policy; a weak one was left
genuinely unencrypted; an EC2 launch came up with `HttpTokens: required` and ingress
scoped to the CIDR given; and an instance type off the allowlist was refused before any
security group was created.
