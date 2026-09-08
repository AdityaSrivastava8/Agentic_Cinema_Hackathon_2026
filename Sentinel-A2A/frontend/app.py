import os
import sys

# Ensure root directory is present in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st

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
# SYSTEM INITIALIZATION & CACHING
# =========================================================

@st.cache_resource
def get_agent_router():
    return AgentRouter()

# Cache Firestore data fetching with a 2-second TTL for live updates
@st.cache_data(ttl=2)
def fetch_firestore_events():
    try:
        reader = FirestoreReader()
        
        # Check if reader successfully connected to a Firestore DB instance
        if reader.db is None or reader.collection is None:
            return {
                "available": False,
                "error": "Firestore client not initialized",
                "total_count": 0,
                "recent_events": [],
                "blocked_events": []
            }

        recent_events = reader.get_recent_events(limit=100) or []
        
        # Get count safely
        try:
            total_count = reader.get_event_count()
        except AttributeError:
            total_count = len(recent_events)

        # Get blocked events safely
        try:
            blocked_events = reader.get_blocked_events(limit=100)
        except AttributeError:
            blocked_events = [e for e in recent_events if isinstance(e, dict) and e.get("decision") == "BLOCK"]

        return {
            "available": True,
            "total_count": max(total_count, len(recent_events)),
            "recent_events": recent_events,
            "blocked_events": blocked_events
        }
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "total_count": 0,
            "recent_events": [],
            "blocked_events": []
        }

router = get_agent_router()
fs_data = fetch_firestore_events()
firestore_available = fs_data["available"]

# Helper to clear cache when a new event occurs
def refresh_security_data():
    st.cache_data.clear()

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
    total_events = fs_data["total_count"]
    blocked_events = fs_data["blocked_events"]

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Events Inspected", total_events)
    with col2:
        st.metric("Threats Blocked", len(blocked_events))
    with col3:
        st.metric("Firewall Status", "🟢 ACTIVE")
else:
    st.info(
        "☁️ Firestore is not configured or unavailable. "
        "Security history will become available after Google Cloud configuration."
    )

# =========================================================
# SECURITY ANALYTICS
# =========================================================

st.divider()
st.subheader("📈 Security Analytics")

if firestore_available and fs_data["recent_events"]:
    try:
        analytics_events = fs_data["recent_events"]
        analytics = SecurityAnalytics(analytics_events)
        summary = analytics.summary()

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total Events", summary.get("total_events", 0))
        with col2:
            st.metric("🟢 Allowed", summary.get("allowed", 0))
        with col3:
            st.metric("🟡 Quarantined", summary.get("quarantined", 0))
        with col4:
            st.metric("🔴 Blocked", summary.get("blocked", 0))
        with col5:
            st.metric("⚠️ High Risk", summary.get("high_risk", 0))

        st.metric("Average Risk Score", summary.get("average_risk_score", 0.0))

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
    st.info("📡 Security analytics will appear after Firestore events are logged.")

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
        st.session_state["simulation_result"] = router.send_to_payment_agent(
            message=scenario["message"],
            tool=scenario["tool"],
            tool_arguments=scenario["arguments"]
        )
        refresh_security_data()
        st.rerun()

if "simulation_result" in st.session_state:
    result = st.session_state["simulation_result"]
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
        st.session_state["inspection_result"] = router.send_to_payment_agent(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )
        refresh_security_data()
        st.rerun()

if "inspection_result" in st.session_state:
    result = st.session_state["inspection_result"]
    security = result["inspection_result"] if "inspection_result" in result else result.get("security", {})

    st.divider()
    st.subheader("🛡️ Sentinel-A2A Analysis")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Risk Score", f'{security.get("risk_score", 0)}/100')
    with col2:
        st.metric("Risk Level", security.get("risk_level", "LOW"))
    with col3:
        st.metric("Authorization", "ALLOWED" if security.get("authorized", True) else "DENIED")
    with col4:
        st.metric("Decision", security.get("decision", "ALLOW"))

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

    if security.get("decision") == "ALLOW":
        st.success("🟢 ALLOWED — Request passed security checks.")
        if result.get("payment"):
            st.subheader("💳 Payment Agent Response")
            st.json(result["payment"])
        if result.get("mcp_result"):
            st.subheader("🔧 MCP Tool Result")
            st.json(result["mcp_result"])
    elif security.get("decision") == "QUARANTINE":
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
    events = fs_data["recent_events"]
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
else:
    st.info("📡 Security history will appear here after Firestore is connected.") 
