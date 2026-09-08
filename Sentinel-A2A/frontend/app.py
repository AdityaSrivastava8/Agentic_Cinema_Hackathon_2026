import os
import sys

# Ensure Sentinel-A2A root directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import agents.agent_router
importlib.reload(agents.agent_router)

from agents.agent_router import AgentRouter
from cloud.firestore_reader import FirestoreReader
from cloud.security_analytics import SecurityAnalytics
from tests.attack_scenarios import ATTACK_SCENARIOS

# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Sentinel-A2A",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# SYSTEM INITIALIZATION & DATA FETCHING
# =========================================================

@st.cache_resource
def get_agent_router():
    return AgentRouter()

def get_firestore_reader():
    """Uncached function to ensure fresh Firestore data fetches on page updates."""
    try:
        return FirestoreReader()
    except Exception:
        return None

router = get_agent_router()
firestore_reader = get_firestore_reader()
firestore_available = firestore_reader is not None

# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Sentinel-A2A")
st.subheader("Runtime Security Firewall for AI Agents")
st.write(
    "Sentinel-A2A monitors communication between AI agents "
    "and protects MCP tools from malicious, manipulated, "
    "or unauthorized requests."
)

# =========================================================
# SECURITY OVERVIEW
# =========================================================

st.divider()
st.subheader("📊 Security Overview")

if firestore_available:
    try:
        total_events = firestore_reader.get_event_count()
        blocked_events = firestore_reader.get_blocked_events(limit=100)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Events Inspected", total_events)
        with col2:
            st.metric("Threats Blocked", len(blocked_events))
        with col3:
            st.metric("Firewall Status", "🟢 ACTIVE")
    except Exception:
        st.warning("Firestore is configured but currently unavailable.")
else:
    st.info(
        "☁️ Firestore is not configured yet. "
        "Security history will become available after Google Cloud configuration."
    )

# =========================================================
# SECURITY ANALYTICS
# =========================================================

st.divider()
st.subheader("📈 Security Analytics")

if firestore_available:
    try:
        analytics_events = firestore_reader.get_recent_events(limit=100)
        analytics = SecurityAnalytics(analytics_events)
        summary = analytics.summary()

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total Events", summary["total_events"])
        with col2:
            st.metric("🟢 Allowed", summary["allowed"])
        with col3:
            st.metric("🟡 Quarantined", summary["quarantined"])
        with col4:
            st.metric("🔴 Blocked", summary["blocked"])
        with col5:
            st.metric("⚠️ High Risk", summary["high_risk"])

        st.metric("Average Risk Score", summary["average_risk_score"])

        # Risk Distribution
        st.subheader("⚠️ Risk Distribution")
        risk_levels = summary.get("risk_levels")
        if risk_levels:
            st.bar_chart(risk_levels)
        else:
            st.info("No risk data available yet.")

        # MCP Tool Activity
        st.subheader("🔧 MCP Tool Activity")
        tools = summary.get("tools")
        if tools:
            st.bar_chart(tools)
        else:
            st.info("No MCP tool activity recorded yet.")

        # Agent Activity
        st.subheader("🤖 Agent Activity")
        agents = summary.get("agents")
        if agents:
            st.bar_chart(agents)
        else:
            st.info("No agent activity recorded yet.")

    except Exception as error:
        st.warning(f"Unable to generate analytics: {error}")
else:
    st.info("📡 Security analytics will appear after Firestore is connected.")

# =========================================================
# ATTACK SIMULATOR
# =========================================================

st.divider()
st.subheader("🚨 Attack Simulator")
st.write(
    "Simulate realistic attacks against AI-agent "
    "communication and observe how Sentinel-A2A responds."
)

scenario_names = [scenario["name"] for scenario in ATTACK_SCENARIOS]
selected_scenario = st.selectbox("Select Attack Scenario", scenario_names)

scenario = next(
    (sc for sc in ATTACK_SCENARIOS if sc["name"] == selected_scenario),
    None
)

if scenario:
    st.info(f'**{scenario["name"]}:** {scenario["description"]}')

    if st.button("🚨 Run Attack Simulation", use_container_width=True):
        result = router.send_to_payment_agent(
            message=scenario["message"],
            tool=scenario["tool"],
            tool_arguments=scenario["arguments"]
        )
        st.session_state["last_simulation_result"] = result
        st.rerun()

# Display last attack simulation result from session state
if "last_simulation_result" in st.session_state:
    result = st.session_state["last_simulation_result"]
    security = result["security"]

    st.subheader("🛡️ Sentinel-A2A Response")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Risk Score", f'{security["risk_score"]}/100')
    with col2:
        st.metric("Risk Level", security["risk_level"])
    with col3:
        st.metric("Decision", security["decision"])

    if security["decision"] == "BLOCK":
        st.error("🔴 ATTACK BLOCKED — Request prevented from reaching MCP tool.")
    elif security["decision"] == "QUARANTINE":
        st.warning("🟡 ATTACK QUARANTINED — Requires additional verification.")
    else:
        st.success("🟢 REQUEST ALLOWED")

    if security.get("threats"):
        st.subheader("🚨 Detected Threats")
        for threat in security["threats"]:
            st.error(f"⚠️ {threat}")

    if security.get("gemini_analysis"):
        st.subheader("🧠 Gemini Security Intelligence")
        st.code(security["gemini_analysis"], language="text")

    st.subheader("📋 Security Event")
    st.write(f'**Event ID:** {security.get("event_id", "N/A")}')
    st.write(f'**Timestamp:** {security.get("timestamp", "N/A")}')
    st.write(f'**Source Agent:** {security.get("source_agent", "N/A")}')
    st.write(f'**Target Agent:** {security.get("target_agent", "N/A")}')
    st.write(f'**Requested Tool:** {security.get("tool", "N/A")}')

# =========================================================
# LIVE REQUEST INSPECTION
# =========================================================

st.divider()
st.subheader("🔍 Inspect Agent Request")
st.write("Test custom communication between ShoppingAgent and PaymentAgent.")

message = st.text_area(
    "ShoppingAgent → PaymentAgent",
    placeholder="Example: Process the payment for the selected laptop."
)

tool = st.selectbox(
    "MCP Tool Requested",
    ["create_payment", "get_payment_status", "get_customer_financial_data"],
    key="custom_tool"
)

st.subheader("🔧 Tool Parameters")

if tool == "create_payment":
    amount = st.number_input("Payment Amount (₹)", min_value=1, value=2000)
    merchant = st.text_input("Merchant", value="Example Store")
    tool_arguments = {"amount": amount, "merchant": merchant}
elif tool == "get_payment_status":
    payment_id = st.text_input("Payment ID", value="PAY-1001")
    tool_arguments = {"payment_id": payment_id}
else:
    customer_id = st.text_input("Customer ID", value="CUSTOMER-001")
    tool_arguments = {"customer_id": customer_id}

if st.button("🛡️ Inspect Request", use_container_width=True):
    if not message.strip():
        st.warning("Please enter a message.")
    else:
        result = router.send_to_payment_agent(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )
        st.session_state["last_inspection_result"] = result
        st.rerun()

# Display last custom inspection result from session state
if "last_inspection_result" in st.session_state:
    result = st.session_state["last_inspection_result"]
    security = result["security"]

    st.divider()
    st.subheader("🛡️ Sentinel-A2A Analysis")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Risk Score", f'{security["risk_score"]}/100')
    with col2:
        st.metric("Risk Level", security["risk_level"])
    with col3:
        st.metric("Authorization", "ALLOWED" if security["authorized"] else "DENIED")
    with col4:
        st.metric("Decision", security["decision"])

    st.caption(f'Event ID: {security.get("event_id", "N/A")}')
    st.caption(f'Timestamp: {security.get("timestamp", "N/A")}')

    st.subheader("🚨 Detected Threats")
    if security.get("threats"):
        for threat in security["threats"]:
            st.error(f"⚠️ {threat}")
    else:
        st.success("✅ No rule-based threats detected.")

    if security.get("gemini_analysis"):
        st.subheader("🧠 Gemini Security Intelligence")
        st.code(security["gemini_analysis"], language="text")

    if security["decision"] == "ALLOW":
        st.success("🟢 ALLOWED — Request passed security checks.")
        if result.get("payment"):
            st.subheader("💳 Payment Agent Response")
            st.json(result["payment"])
        if result.get("mcp_result"):
            st.subheader("🔧 MCP Tool Result")
            st.json(result["mcp_result"])
    elif security["decision"] == "QUARANTINE":
        st.warning("🟡 QUARANTINED — Requires additional verification.")
        st.info("The MCP tool was NOT executed.")
    else:
        st.error("🔴 BLOCKED — Request stopped.")
        st.info("The MCP tool was NOT executed.")

# =========================================================
# SECURITY EVENT HISTORY
# =========================================================

st.divider()
st.subheader("📜 Security Event History")

if firestore_available:
    try:
        events = firestore_reader.get_recent_events(limit=20)
        if events:
            for event in events:
                decision = event.get("decision", "UNKNOWN")
                icon = "🔴" if decision == "BLOCK" else ("🟡" if decision == "QUARANTINE" else "🟢")

                with st.expander(
                    f'{icon} {event.get("source_agent", "Unknown")} → '
                    f'{event.get("target_agent", "Unknown")} | {decision}'
                ):
                    st.write(f'**Event ID:** {event.get("event_id", "N/A")}')
                    st.write(f'**Timestamp:** {event.get("timestamp", "N/A")}')
                    st.write(f'**Tool:** {event.get("tool", "None")}')
                    st.write(f'**Risk Score:** {event.get("risk_score", "N/A")}')
                    st.write(f'**Risk Level:** {event.get("risk_level", "N/A")}')
                    st.write(f'**Authorized:** {event.get("authorized", "N/A")}')

                    if event.get("threats"):
                        st.write("**Threats:**")
                        for threat in event["threats"]:
                            st.error(str(threat))

                    if event.get("gemini_analysis"):
                        st.write("**Gemini Analysis:**")
                        st.code(event["gemini_analysis"], language="text")
        else:
            st.info("No security events recorded yet.")
    except Exception as error:
        st.warning(f"Unable to load security history: {error}")
else:
    st.info("📡 Security history will appear here after Firestore is connected.") 
