import streamlit as st
import requests

# ==========================================
# 1. APP CONFIGURATION & STATE
# ==========================================
st.set_page_config(page_title="Secure Cloud Provisioner", page_icon="☁️", layout="wide")

# API Base URL (Easy to change for production)
API_BASE_URL = "http://127.0.0.1:8000/api/v1"

# Initialize Session State Variables
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "current_payload" not in st.session_state:
    st.session_state.current_payload = None

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def run_security_scan(endpoint: str, payload: dict, provider_name: str):
    """Handles API communication for scanning and updates session state."""
    try:
        with st.spinner(f"Running {provider_name} static policy scan..."):
            response = requests.post(f"{API_BASE_URL}/{endpoint}", json=payload)
            if response.status_code == 200:
                st.session_state.scan_results = response.json()
                st.session_state.current_payload = payload
                st.session_state.active_provider = provider_name
                st.session_state.deploy_endpoint = f"{endpoint.replace('scan', 'deploy')}"
            else:
                st.error(f"Scan failed (HTTP {response.status_code}): {response.text}")
                st.session_state.scan_results = None
    except requests.exceptions.ConnectionError:
        st.error("❌ Could not connect to FastAPI backend. Is Uvicorn running?")
        st.session_state.scan_results = None

def render_security_gate():
    """Renders pure Python display logic for warnings, errors, and the deploy gate."""
    if not st.session_state.scan_results:
        return

    st.divider()
    st.subheader("📋 Pre-Flight Security Scan Results")
    
    warnings = st.session_state.scan_results.get("warnings", [])
    
    # CASE 1: No Flags -> Direct Deploy
    if not warnings:
        st.success("✅ **Zero governance violations found.** Resource is secure and ready for deployment.")
        ready_to_deploy = True
    
    # CASE 2: Security Flags Exist -> Render Alerts & Require Acknowledgment
    else:
        for warn in warnings:
            severity = warn.get("severity", "MEDIUM")
            code = warn.get("code", "SEC_FLAG")
            title = warn.get("title", "Security Risk")
            desc = warn.get("description", "Potential misconfiguration detected.")
            
            msg = f"**[{code}] {title}**: {desc}"
            
            if severity in ["HIGH", "CRITICAL"]:
                st.error(f"🛑 **CRITICAL RISK:** {msg}")
            else:
                st.warning(f"⚠️ **SECURITY RISK:** {msg}")

        st.markdown("###")
        # The exact acknowledgement checkbox requested
        acknowledged = st.checkbox(
            "I acknowledge the security risk and wish to proceed anyway",
            value=False,
            key="risk_ack_checkbox"
        )
        ready_to_deploy = acknowledged

    # Final Deploy Button Logic
    st.markdown("---")
    provider = st.session_state.get("active_provider", "Cloud")
    
    if st.button(f"🚀 Provision {provider} Infrastructure", type="primary", disabled=not ready_to_deploy, use_container_width=True):
        execute_deployment()

def execute_deployment():
    """Handles the final API deployment call with a dynamic status expander."""
    endpoint = st.session_state.deploy_endpoint
    payload = st.session_state.current_payload
    
    with st.status(f"Provisioning resources...", expanded=True) as status:
        st.write("📡 Authenticating with cloud provider...")
        st.write("📦 Deploying infrastructure as code...")
        try:
            response = requests.post(f"{API_BASE_URL}/{endpoint}", json=payload)
            if response.status_code == 200:
                status.update(label="🎉 Infrastructure Provisioned Successfully!", state="complete", expanded=False)
                st.balloons()
                st.success("Deployment finished without errors!")
                with st.expander("View Resource Details"):
                    st.json(response.json())
                
                # Clear state after successful deployment
                st.session_state.scan_results = None
            else:
                status.update(label="❌ Provisioning Failed", state="error", expanded=True)
                st.error(f"API Error ({response.status_code}):")
                st.json(response.json())
        except Exception as e:
            status.update(label="❌ Network Error", state="error", expanded=True)
            st.error(f"Backend communication failed: {e}")

# ==========================================
# 3. MAIN UI LAYOUT
# ==========================================
st.title("☁️ Secure Multi-Cloud Provisioner")
st.caption("Policy-enforced provisioning engine with pre-flight security scanning.")

# Sidebar Navigation (Ready for more modules)
st.sidebar.title("Service Catalog")
selected_service = st.sidebar.radio("Select Resource to Provision:", ["Azure Storage Account", "AWS S3 Bucket"])
st.sidebar.divider()
st.sidebar.info("Backend Status: 🟢 Online (Port 8000)")

# ------------------------------------------
# VIEW: AZURE STORAGE
# ------------------------------------------
if selected_service == "Azure Storage Account":
    st.header("🔷 Azure Storage Configuration")
    
    with st.form("azure_form"):
        col1, col2 = st.columns(2)
        with col1:
            rg_name = st.text_input("Resource Group", value="rg-backend-dev")
            location = st.selectbox("Region", ["eastus", "westus2", "westeurope"])
            sa_name = st.text_input("Storage Account Name", value="mysecstorage2026")
        
        with col2:
            create_container = st.checkbox("Create Blob Container?", value=True)
            container_name = st.text_input("Container Name", value="secure-data-container")
            st.markdown("**Security Controls**")
            allow_public = st.checkbox("Allow Public Blob Access (Insecure)", value=False)
            min_tls = st.selectbox("Minimum TLS Version", ["TLS1_2", "TLS1_0"])
            
        if st.form_submit_button("🔍 Run Pre-Flight Scan", use_container_width=True):
            payload = {
                "resource_group_name": rg_name,
                "location": location,
                "storage_account_name": sa_name,
                "container_name": container_name if create_container else None,
                "storage_config": {
                    "allow_blob_public_access": allow_public,
                    "minimum_tls_version": min_tls
                }
            }
            run_security_scan("azure/scan", payload, "Azure")

# ------------------------------------------
# VIEW: AWS S3 BUCKET
# ------------------------------------------
elif selected_service == "AWS S3 Bucket":
    st.header("🟠 AWS S3 Bucket Configuration")
    
    with st.form("aws_form"):
        col1, col2 = st.columns(2)
        with col1:
            bucket_name = st.text_input("Bucket Name", value="my-secure-aws-bucket-2026")
            region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
        
        with col2:
            st.markdown("**Security Controls**")
            block_public = st.checkbox("Block All Public Access", value=True)
            enable_enc = st.checkbox("Enable AES-256 Encryption", value=True)
            
        if st.form_submit_button("🔍 Run Pre-Flight Scan", use_container_width=True):
            payload = {
                "bucket_name": bucket_name,
                "region": region,
                "block_public_access": block_public,
                "enable_encryption": enable_enc
            }
            run_security_scan("aws/scan", payload, "AWS")

# ==========================================
# 4. RENDER RESULTS & DEPLOYMENT GATE
# ==========================================
render_security_gate()
