"""
app.py
Secure Cloud Provisioner - Streamlit GUI.

    streamlit run app.py

Everything is Python-native: there is no REST layer between the UI and the logic. The pre-flight
scan and the deployment functions are imported directly as modules:

    from preflight import scan_config
    from cloud_deploy import deploy_aws_vm, deploy_aws_bucket, deploy_azure_vm, deploy_azure_storage

The AWS findings and provisioning come from backend/scanner/ and backend/aws/ underneath those two
modules, so this page and the project's other web interface report the same things about the same
resources. See preflight.py and backend_path.py.

Flow: pick a provider and a resource category in the sidebar -> fill in the provisioning form ->
submit runs the pre-flight scan -> insecure settings are shown as banners and must be explicitly
acknowledged before the deploy button unlocks -> deployment streams its progress into st.status().
"""

import datetime as dt
from typing import Any, Dict, List

import streamlit as st

from cloud_deploy import (
    DeploymentError,
    allowed_instance_types,
    credential_status,
    deploy_aws_bucket,
    deploy_aws_vm,
    deploy_azure_storage,
    deploy_azure_vm,
)
from preflight import scan_config

# ==========================================================================
# 1. APP CONFIGURATION & SESSION STATE
# ==========================================================================
st.set_page_config(page_title="Secure Cloud Provisioner", page_icon="☁️", layout="wide")

DEPLOY_FUNCTIONS = {
    ("aws", "vm"): deploy_aws_vm,
    ("aws", "storage"): deploy_aws_bucket,
    ("azure", "vm"): deploy_azure_vm,
    ("azure", "storage"): deploy_azure_storage,
}

# The three levels of backend/scanner/common.py, plus the banner each one is drawn in.
LEVEL_STYLE = {
    "critical": {"icon": "🛑", "label": "CRITICAL"},
    "warning": {"icon": "🟠", "label": "WARNING"},
    "info": {"icon": "🔵", "label": "FOR INFORMATION"},
}

COMMON_PORTS = [
    ("SSH (22)", 22, "Remote shell access - restrict to your own IP."),
    ("HTTP (80)", 80, "Unencrypted web traffic."),
    ("HTTPS (443)", 443, "Encrypted web traffic - the safe way to publish a site."),
    ("RDP (3389)", 3389, "Windows Remote Desktop - the top ransomware entry point."),
    ("MySQL (3306)", 3306, "Database port - should never face the internet."),
    ("PostgreSQL (5432)", 5432, "Database port - should never face the internet."),
]

DEFAULTS = {
    "scan_result": None,
    "scanned_config": None,
    "scan_seq": 0,
    "deployment_history": [],
    "last_deployment": None,
}
for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


def reset_scan() -> None:
    """Drops any previous scan so a stale result can never gate a new configuration."""
    st.session_state.scan_result = None
    st.session_state.scanned_config = None
    st.session_state.last_deployment = None


def store_scan(config: Dict[str, Any]) -> None:
    st.session_state.scan_result = scan_config(config)
    st.session_state.scanned_config = config
    st.session_state.scan_seq += 1
    st.session_state.last_deployment = None


# ==========================================================================
# 2. SIDEBAR - PROVIDER AND RESOURCE SELECTION
# ==========================================================================
st.sidebar.title("☁️ Service Catalog")

provider_label = st.sidebar.radio(
    "Cloud provider",
    ["Amazon Web Services", "Microsoft Azure"],
    key="provider_choice",
    on_change=reset_scan,
)
provider = "aws" if provider_label.startswith("Amazon") else "azure"

resource_label = st.sidebar.selectbox(
    "Resource category",
    ["Virtual Machine", "Object Storage"],
    key="resource_choice",
    on_change=reset_scan,
)
resource_type = "vm" if resource_label == "Virtual Machine" else "storage"

st.sidebar.divider()
st.sidebar.subheader("Deployment mode")
dry_run = st.sidebar.toggle(
    "Dry run (simulate only)",
    value=True,
    help="On: the scan runs and the deployment is simulated, no cloud API is called. "
         "Off: resources are really created in your account and will incur cost.",
)
if dry_run:
    st.sidebar.caption("🧪 Simulation mode - nothing will be created.")
else:
    st.sidebar.caption("🚨 Live mode - real resources will be created and billed.")

credentials = credential_status(provider)
st.sidebar.divider()
st.sidebar.subheader("Credentials")
if credentials["ready"]:
    st.sidebar.success(credentials["detail"])
else:
    st.sidebar.warning(credentials["detail"])
    st.sidebar.caption("Dry run works without credentials.")

st.sidebar.divider()
st.sidebar.caption(
    "Secure defaults are pre-selected in every form. Anything you loosen is flagged before it ships."
)


# ==========================================================================
# 3. HEADER
# ==========================================================================
st.title("Secure Cloud Provisioner")
st.caption(
    "Provision AWS and Azure resources through guided forms - with an inline security review "
    "at the moment of deployment, not weeks later in an audit."
)
st.markdown(f"**Selected:** `{provider_label}` → `{resource_label}`")


# ==========================================================================
# 4. PROVISIONING FORMS
# ==========================================================================
def aws_vm_form() -> None:
    st.subheader("🟠 EC2 Instance")
    with st.form("deploy_form"):
        col1, col2 = st.columns(2)
        with col1:
            vm_name = st.text_input("Instance name", value="web-01", help="Letters, numbers and hyphens.")
            region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-2"])
            instance_type = st.selectbox(
                "Instance size",
                allowed_instance_types(),
                index=allowed_instance_types().index("t3.micro") if "t3.micro" in allowed_instance_types() else 0,
                help="Read from the backend's own allowlist, so the menu cannot offer a size the "
                     "launch path would refuse. The allowlist is what stops a mistyped instance "
                     "type costing hundreds of dollars.",
            )
            key_pair_name = st.text_input("EC2 key pair name", value="", help="Name of an SSH key pair that already exists in this region.")
            st.caption(
                "The AMI is resolved at launch to the current Amazon Linux 2023 image for the "
                "instance's architecture, and IMDSv2 is always required — neither is offered as a "
                "choice because neither has a safe wrong answer."
            )
        with col2:
            st.markdown("**Network exposure**")
            open_ports = port_checkboxes()
            allowed_cidr = st.text_input(
                "Allowed source IP range (CIDR)",
                value="0.0.0.0/0",
                help="0.0.0.0/0 means the whole internet. Use x.x.x.x/32 for a single address.",
            )
            assign_public_ip = st.checkbox("Assign a public IP address", value=False)

            st.markdown("**Hardening**")
            encrypt_os_disk = st.toggle("Encrypt the EBS root volume", value=True)

        submitted = st.form_submit_button("🔍 Run pre-flight security scan", use_container_width=True, type="primary")

    if submitted:
        store_scan({
            "provider": "aws",
            "resource_type": "vm",
            "dry_run": dry_run,
            "vm_name": vm_name.strip(),
            "region": region,
            "instance_type": instance_type,
            "key_pair_name": key_pair_name.strip(),
            "open_ports": open_ports,
            "allowed_cidr": allowed_cidr.strip(),
            "assign_public_ip": assign_public_ip,
            "encrypt_os_disk": encrypt_os_disk,
        })


def azure_vm_form() -> None:
    st.subheader("🔷 Azure Virtual Machine")
    with st.form("deploy_form"):
        col1, col2 = st.columns(2)
        with col1:
            vm_name = st.text_input("VM name", value="web-01")
            resource_group = st.text_input("Resource group", value="rg-capstone-dev")
            region = st.selectbox("Region", ["eastus", "westus2", "westeurope", "northeurope", "australiaeast"])
            vm_size = st.selectbox("VM size", ["Standard_B1s", "Standard_B2s", "Standard_D2s_v5", "Standard_D4s_v5"])
            admin_username = st.text_input("Administrator username", value="cloudadmin")
            auth_label = st.selectbox(
                "Authentication method",
                ["SSH public key (recommended)", "Password"],
                help="This tool never accepts a password through the form. Password auth reads "
                     "AZURE_VM_ADMIN_PASSWORD from your .env at deploy time.",
            )
            ssh_public_key = st.text_area(
                "SSH public key",
                value="",
                height=90,
                placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... you@laptop",
                help="Paste the contents of your .pub file. Never paste a private key.",
            )
        with col2:
            st.markdown("**Network exposure**")
            open_ports = port_checkboxes()
            allowed_cidr = st.text_input(
                "Allowed source IP range (CIDR)",
                value="0.0.0.0/0",
                help="0.0.0.0/0 means the whole internet. Use x.x.x.x/32 for a single address.",
            )
            assign_public_ip = st.checkbox("Assign a public IP address", value=False)

            st.markdown("**Hardening**")
            encrypt_os_disk = st.toggle("Enable encryption at host for the OS disk", value=True)

        submitted = st.form_submit_button("🔍 Run pre-flight security scan", use_container_width=True, type="primary")

    if submitted:
        store_scan({
            "provider": "azure",
            "resource_type": "vm",
            "dry_run": dry_run,
            "vm_name": vm_name.strip(),
            "resource_group": resource_group.strip(),
            "region": region,
            "vm_size": vm_size,
            "admin_username": admin_username.strip(),
            "auth_type": "ssh_key" if auth_label.startswith("SSH") else "password",
            "ssh_public_key": ssh_public_key.strip(),
            "open_ports": open_ports,
            "allowed_cidr": allowed_cidr.strip(),
            "assign_public_ip": assign_public_ip,
            "encrypt_os_disk": encrypt_os_disk,
        })


def aws_storage_form() -> None:
    st.subheader("🟠 S3 Bucket")
    with st.form("deploy_form"):
        col1, col2 = st.columns(2)
        with col1:
            bucket_name = st.text_input("Bucket name", value="team-reports-2026", help="Globally unique, lowercase.")
            region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-2"])
            acl = st.selectbox("Bucket ACL", ["private", "public-read", "public-read-write"])
        with col2:
            st.markdown("**Privacy & data protection**")
            block_public_access = st.toggle("Block all public access", value=True)
            enable_encryption = st.toggle("Default server-side encryption (AES-256)", value=True)
            enable_versioning = st.toggle("Object versioning", value=True)
            enforce_tls = st.toggle("Deny plain-HTTP requests (bucket policy)", value=True)

        submitted = st.form_submit_button("🔍 Run pre-flight security scan", use_container_width=True, type="primary")

    if submitted:
        store_scan({
            "provider": "aws",
            "resource_type": "storage",
            "dry_run": dry_run,
            "bucket_name": bucket_name.strip().lower(),
            "region": region,
            "acl": acl,
            "block_public_access": block_public_access,
            "enable_encryption": enable_encryption,
            "enable_versioning": enable_versioning,
            "enforce_tls": enforce_tls,
        })


def azure_storage_form() -> None:
    st.subheader("🔷 Azure Storage Account")
    with st.form("deploy_form"):
        col1, col2 = st.columns(2)
        with col1:
            account_name = st.text_input("Storage account name", value="capstonestore2026", help="3-24 lowercase letters and numbers.")
            resource_group = st.text_input("Resource group", value="rg-capstone-dev")
            region = st.selectbox("Region", ["eastus", "westus2", "westeurope", "northeurope", "australiaeast"])
            sku = st.selectbox("Redundancy (SKU)", ["Standard_LRS", "Standard_ZRS", "Standard_GRS"])
            container_name = st.text_input("Blob container name (optional)", value="secure-data")
            container_public_access = st.selectbox(
                "Container access level",
                ["private", "blob", "container"],
                help="'private' requires authentication. 'blob' and 'container' serve data anonymously.",
            )
        with col2:
            st.markdown("**Privacy & transport security**")
            allow_blob_public_access = st.toggle("Allow anonymous public blob access", value=False)
            supports_https_traffic_only = st.toggle("Require HTTPS for all traffic", value=True)
            minimum_tls_version = st.selectbox("Minimum TLS version", ["TLS1_2", "TLS1_1", "TLS1_0"])
            allow_shared_key_access = st.toggle("Allow shared key (account key) authorization", value=True)

        submitted = st.form_submit_button("🔍 Run pre-flight security scan", use_container_width=True, type="primary")

    if submitted:
        store_scan({
            "provider": "azure",
            "resource_type": "storage",
            "dry_run": dry_run,
            "account_name": account_name.strip().lower(),
            "resource_group": resource_group.strip(),
            "region": region,
            "sku": sku,
            "container_name": container_name.strip().lower(),
            "container_public_access": container_public_access,
            "allow_blob_public_access": allow_blob_public_access,
            "supports_https_traffic_only": supports_https_traffic_only,
            "minimum_tls_version": minimum_tls_version,
            "allow_shared_key_access": allow_shared_key_access,
        })


def port_checkboxes() -> List[Any]:
    """Renders one checkbox per common inbound port and returns the selected ports."""
    selected: List[Any] = []
    for label, port, help_text in COMMON_PORTS:
        if st.checkbox(f"Open {label}", value=(port == 443), key=f"port_{port}", help=help_text):
            selected.append(port)
    if st.checkbox("Open ALL ports", value=False, key="port_all", help="Allows every inbound port - almost never correct."):
        selected.append("all")
    return selected


FORMS = {
    ("aws", "vm"): aws_vm_form,
    ("aws", "storage"): aws_storage_form,
    ("azure", "vm"): azure_vm_form,
    ("azure", "storage"): azure_storage_form,
}

FORMS[(provider, resource_type)]()


# ==========================================================================
# 5. SECURITY WARNING BANNERS & DEPLOYMENT GATE
# ==========================================================================
def render_finding(finding: Dict[str, Any], banner) -> None:
    """Draws one warning in the shape backend/scanner/common.py defines.

    The AWS rules put everything in `message`. The Azure rules add `title` and `remediation`, so
    those are rendered when present rather than being required.
    """
    style = LEVEL_STYLE.get(finding.get("level", "warning"), LEVEL_STYLE["warning"])
    # The AWS findings say everything in the message, so the level alone is the heading. The Azure
    # ones carry a title, which goes after it.
    title = finding.get("title")
    heading = f"{style['label']} - {title}" if title else style["label"]
    lines = [
        f"{style['icon']} **{heading}**",
        finding.get("message", ""),
    ]
    if finding.get("remediation"):
        lines.append(f"**How to fix:** {finding['remediation']}")

    # A published control the finding maps to. Present only where one genuinely applies - the AWS
    # rules leave it off rather than citing something that does not cover the case.
    control = finding.get("control")
    if control:
        lines.append(
            f"📕 **{control.get('framework', '')} v{control.get('version', '')} "
            f"§{control.get('id', '')}** — {control.get('title', '')}"
        )

    # A remediation the other interface can perform on a live resource. Nothing exists yet at scan
    # time, so it is named rather than offered as a button.
    fix = finding.get("fix")
    if fix and fix.get("label"):
        lines.append(f"*Once created, this is fixable: {fix['label']}.*")

    trailer = finding.get("rule_id") or finding.get("resource_id")
    if trailer:
        lines.append(f"`{trailer}`")

    banner("\n\n".join(line for line in lines if line))


def render_scan_results() -> bool:
    """Draws the scan verdict. Returns True when deployment is allowed to proceed."""
    result = st.session_state.scan_result
    if not result:
        st.info("Fill in the form above and run the pre-flight scan to see the security review.")
        return False

    st.divider()
    st.subheader("📋 Pre-flight security review")

    counts = result["counts"]
    metric_cols = st.columns(4)
    metric_cols[0].metric("Blockers", len(result["blockers"]))
    metric_cols[1].metric("Critical", counts.get("critical", 0))
    metric_cols[2].metric("Warnings", counts.get("warning", 0))
    metric_cols[3].metric("For information", counts.get("info", 0))

    # CASE 1: the configuration is invalid - the cloud API would reject it outright.
    if result["blocked"]:
        st.error(
            "⛔ **Deployment blocked.** The configuration below is invalid, so the cloud provider "
            "would reject it. These cannot be acknowledged away - fix them in the form and re-scan."
        )
        for finding in result["blockers"]:
            render_finding(finding, st.error)
        return False

    # CASE 2: clean configuration.
    if result["passed"]:
        st.success("✅ **No findings.** This configuration follows the secure defaults for every rule that applies to it.")
        return True

    total = len(result["warnings"])
    worst = result["worst"]
    headline = f"{total} finding(s), most severe: {LEVEL_STYLE.get(worst, LEVEL_STYLE['warning'])['label']}."

    # CASE 3: only notes. The scanner reports context as well as faults, so a fully hardened
    # resource still says things - and asking someone to acknowledge a security risk that is not
    # one is how the acknowledgement stops meaning anything.
    if not result["needs_acknowledgement"]:
        st.success(f"✅ **No risks found.** {total} note(s) for information, listed below.")
    elif worst == "critical":
        st.error(f"🛑 **{headline}** Review each one before continuing.")
    else:
        st.warning(f"⚠️ **{headline}** Review each one before continuing.")

    order = {"critical": 0, "warning": 1, "info": 2}
    for finding in sorted(result["warnings"], key=lambda w: order.get(w.get("level"), 9)):
        level = finding.get("level", "warning")
        banner = st.error if level == "critical" else (st.warning if level == "warning" else st.info)
        render_finding(finding, banner)

    if not result["needs_acknowledgement"]:
        return True

    # CASE 4: deployable, but insecure - require an explicit acknowledgement.
    st.markdown("### ")
    acknowledged = st.checkbox(
        "I acknowledge the security risk and wish to proceed anyway",
        value=False,
        key=f"risk_ack_{st.session_state.scan_seq}",
    )
    if not acknowledged:
        st.caption("The deploy button unlocks once you acknowledge the findings above.")
    return acknowledged


def execute_deployment(config: Dict[str, Any], result: Dict[str, Any]) -> None:
    deployer = DEPLOY_FUNCTIONS[(config["provider"], config["resource_type"])]
    label = "Simulating deployment..." if config.get("dry_run", True) else "Provisioning live resources..."

    with st.status(label, expanded=True) as status:
        st.write("🔐 Re-running the security scan against the exact payload being deployed...")
        confirm = scan_config(config)
        if confirm["blocked"]:
            status.update(label="❌ Deployment aborted", state="error")
            st.error("The configuration became invalid between the scan and the deploy. Nothing was created.")
            return

        try:
            deployment = deployer(config, status_callback=st.write)
        except DeploymentError as exc:
            status.update(label="❌ Provisioning failed", state="error", expanded=True)
            st.error(str(exc))
            return
        except Exception as exc:  # defensive: never leak a raw traceback into the UI
            status.update(label="❌ Unexpected error", state="error", expanded=True)
            st.error(f"Unexpected error during provisioning: {exc}")
            return

        if deployment.get("status") == "DRY_RUN":
            status.update(label="🧪 Dry run complete - nothing was created", state="complete", expanded=True)
        else:
            status.update(label="🎉 Resource provisioned successfully", state="complete", expanded=False)
            st.balloons()

    st.session_state.last_deployment = deployment
    st.session_state.deployment_history.append({
        "timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "provider": config["provider"].upper(),
        "resource": deployment.get("resource", config["resource_type"]),
        "name": deployment.get("name", ""),
        "mode": deployment.get("mode", ""),
        "findings_at_deploy": len(result["warnings"]),
        "acknowledged_risk": result["needs_acknowledgement"],
    })


ready_to_deploy = render_scan_results()

if st.session_state.scan_result and not st.session_state.scan_result["blocked"]:
    st.divider()
    # The sidebar toggle can move after the scan, so the live/simulated choice is read at click time.
    config = dict(st.session_state.scanned_config, dry_run=dry_run)
    button_label = (
        f"🧪 Simulate {resource_label.lower()} deployment"
        if dry_run else f"🚀 Deploy {resource_label.lower()} to {provider.upper()}"
    )
    if not dry_run and not credentials["ready"]:
        st.warning("Live mode is selected but no credentials were found. Add them to `.env`, or switch on dry run.")

    if st.button(button_label, type="primary", disabled=not ready_to_deploy, use_container_width=True):
        execute_deployment(config, st.session_state.scan_result)

if st.session_state.last_deployment:
    with st.expander("📄 Deployment details", expanded=True):
        st.json(st.session_state.last_deployment)
    if st.button("Start a new configuration"):
        reset_scan()
        st.rerun()


# ==========================================================================
# 6. SESSION AUDIT TRAIL
# ==========================================================================
if st.session_state.deployment_history:
    st.divider()
    st.subheader("🧾 This session's deployments")
    # Rendered as markdown rather than st.dataframe so the audit trail never depends on pandas.
    rows = [
        "| Time | Provider | Resource | Name | Mode | Findings | Risk acknowledged |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for entry in st.session_state.deployment_history:
        rows.append(
            f"| {entry['timestamp']} | {entry['provider']} | {entry['resource']} | {entry['name']} "
            f"| {entry['mode']} | {entry['findings_at_deploy']} | {'yes' if entry['acknowledged_risk'] else 'no'} |"
        )
    st.markdown("\n".join(rows))
