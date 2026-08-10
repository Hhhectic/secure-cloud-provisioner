# The Streamlit GUI

A guided provisioning form for AWS and Azure, run as its own Streamlit process:

```bash
pip install -r requirements.txt
streamlit run app.py
```

It starts in **dry-run mode**, so it works with no cloud credentials at all: the scan is real, the
deployment is simulated, and the exact list of API calls that would run is printed. Turning off
"Dry run (simulate only)" in the sidebar provisions for real.

## Status: this is a second frontend, and the group has not settled which one wins

`frontend/` is served by the API at `/ui/`, reaches every registered `ResourceType`, and enforces
its risk gate in the API rather than the page. This one is a separate process covering four
form flows. `archive/streamlit-frontend/README.md` records why the earlier Streamlit page was set
aside; most of that argument applies here too, with one exception — the fourth row of that table.
That page talked to `/api/v1` and covered Azure only. This one imports the backend directly and
covers both clouds.

Nothing here is wired into `frontend/` or the API. It can be archived beside the other one, kept as
a second interface, or reduced to a thin page over `/resources/...` so that there is one set of
rules and one gate. That decision is open.

## How it is put together

| Module | Role |
| --- | --- |
| `app.py` | The GUI: provider/resource selection, forms, warning banners, acknowledgement gate |
| `preflight.py` | `scan_config(config)` — adapts a form to the backend's rules; holds the Azure form rules |
| `cloud_deploy.py` | `deploy_aws_vm`, `deploy_aws_bucket`, `deploy_azure_vm`, `deploy_azure_storage` |
| `backend_path.py` | Puts `backend/` on `sys.path` so its modules import under their own names |

There is no REST layer between the page and the logic — Streamlit is Python, so it imports the
modules directly.

### The AWS rules and provisioning are the backend's

`preflight.py` builds the settings snapshot each backend rule expects and calls
`check_bucket_settings`, `check_firewall_rules` and `check_instance`. `cloud_deploy.py` calls
`aws/s3_buckets.py`, `aws/security_groups.py` and `aws/instances.py` and does not touch boto3
itself. So AWS findings arrive with their citations to published controls, and anything this page
creates gets the instance-type allowlist, the managed-resource tagging and the forced IMDSv2.

The instance size menu is read from `ALLOWED_INSTANCE_TYPES`, so it cannot offer a size the launch
path would refuse.

Two consequences worth knowing:

- `check_firewall_rules` is reused for Azure NSG rules, because a port opened to `0.0.0.0/0` is the
  same fault on either provider. Its CIS **AWS** citation and its AWS fix action are stripped from
  Azure findings rather than repeated, since neither applies there.
- `preflight.py` is not called `scanner.py` because `scanner` is the backend's package name.

### Azure

Written before `backend/az/` and `backend/scanner/azure_*_rules.py` existed, so it overlaps them and
should be reconciled. Two rules here have no counterpart there and are worth porting across:

- **container access level** — a container set to `blob` or `container` serves its contents
  anonymously, which is a separate switch from the account's `allow_blob_public_access`
- **shared key authorization** — account keys never expire, grant full control, and leak through
  config files and screenshots

Going the other way, `azure_storage_rules.py` checks `public_network_access` and handles unreadable
settings, and it carries `fix` actions; this module does neither.

`deploy_azure_vm()` has no counterpart in `backend/az/`, which covers NSGs and storage but not
compute. It creates a resource group, virtual network, NSG, NIC, optional public IP and a Linux VM
with SSH-key authentication.

## The gate

`scan_config()` separates three outcomes:

- **Blockers** — invalid configuration (bad bucket name, a private key pasted into the public key
  box, malformed CIDR). The deploy button is not shown; there is nothing to acknowledge, because the
  provider would reject the call anyway.
- **critical / warning** — deployable but insecure. The deploy button unlocks only after
  *"I acknowledge the security risk and wish to proceed anyway"* is ticked.
- **info** — context rather than fault. The backend rules report these on healthy resources too, so
  they never demand an acknowledgement. A hardened bucket still returns three of them, and a risk
  acknowledgement that gets ticked every time has stopped meaning anything.

This gate is in the page, not the API — which is the weaker arrangement, and one of the reasons
`frontend/` is the better foundation.

The scan is re-run against the exact payload immediately before deploying, so the configuration
cannot drift between review and provisioning.

## Credentials

No password or secret is accepted through a form field. Azure VM password authentication — which the
scanner flags anyway — reads `AZURE_VM_ADMIN_PASSWORD` from `.env` at deploy time. SSH access uses a
public key pasted into the form; private keys are refused with a blocker.

## Testing

There is no automated coverage for `preflight.py` or `cloud_deploy.py`. They were verified by hand
against moto and in a browser: a hardened bucket deploys with all four public-access blocks on,
AES256, versioning and an HTTPS-only policy; a weak one is left genuinely unencrypted; an EC2 launch
comes up with `HttpTokens: required` and ingress scoped to the CIDR given; and an instance type off
the allowlist is refused before any security group is created. Porting those checks into
`backend/tests/` is the obvious next step.
