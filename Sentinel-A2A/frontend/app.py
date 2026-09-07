import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) 

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
# INITIALIZE SYSTEM
# =========================================================

router = AgentRouter()


# =========================================================
# FIRESTORE CONNECTION
# =========================================================

try:
    firestore_reader = FirestoreReader()
    firestore_available = True

except Exception:
    firestore_reader = None
    firestore_available = False


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Sentinel-A2A")

st.subheader(
    "Runtime Security Firewall for AI Agents"
)

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

        total_events = (
            firestore_reader.get_event_count()
        )

        blocked_events = (
            firestore_reader.get_blocked_events(
                limit=100
            )
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Events Inspected",
                total_events
            )

        with col2:
            st.metric(
                "Threats Blocked",
                len(blocked_events)
            )

        with col3:
            st.metric(
                "Firewall Status",
                "🟢 ACTIVE"
            )

    except Exception:

        st.warning(
            "Firestore is configured but currently unavailable."
        )

else:

    st.info(
        "☁️ Firestore is not configured yet. "
        "Security history will become available after "
        "Google Cloud configuration."
    )


# =========================================================
# SECURITY ANALYTICS
# =========================================================

st.divider()

st.subheader("📈 Security Analytics")

if firestore_available:

    try:

        # Retrieve security events from Firestore.
        analytics_events = (
            firestore_reader.get_recent_events(
                limit=100
            )
        )

        # Pass the events to the analytics engine.
        analytics = SecurityAnalytics(
            analytics_events
        )

        # Generate complete analytics summary.
        summary = analytics.summary()


        # -------------------------------------------------
        # MAIN METRICS
        # -------------------------------------------------

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:

            st.metric(
                "Total Events",
                summary["total_events"]
            )

        with col2:

            st.metric(
                "🟢 Allowed",
                summary["allowed"]
            )

        with col3:

            st.metric(
                "🟡 Quarantined",
                summary["quarantined"]
            )

        with col4:

            st.metric(
                "🔴 Blocked",
                summary["blocked"]
            )

        with col5:

            st.metric(
                "⚠️ High Risk",
                summary["high_risk"]
            )


        # -------------------------------------------------
        # AVERAGE RISK SCORE
        # -------------------------------------------------

        st.metric(
            "Average Risk Score",
            summary["average_risk_score"]
        )


        # -------------------------------------------------
        # RISK DISTRIBUTION
        # -------------------------------------------------

        st.subheader(
            "⚠️ Risk Distribution"
        )

        risk_levels = summary["risk_levels"]

        if risk_levels:

            st.bar_chart(
                risk_levels
            )

        else:

            st.info(
                "No risk data available yet."
            )


        # -------------------------------------------------
        # MCP TOOL ACTIVITY
        # -------------------------------------------------

        st.subheader(
            "🔧 MCP Tool Activity"
        )

        tools = summary["tools"]

        if tools:

            st.bar_chart(
                tools
            )

        else:

            st.info(
                "No MCP tool activity recorded yet."
            )


        # -------------------------------------------------
        # AGENT ACTIVITY
        # -------------------------------------------------

        st.subheader(
            "🤖 Agent Activity"
        )

        agents = summary["agents"]

        if agents:

            st.bar_chart(
                agents
            )

        else:

            st.info(
                "No agent activity recorded yet."
            )


    except Exception as error:

        st.warning(
            f"Unable to generate analytics: {error}"
        )

else:

    st.info(
        "📡 Security analytics will appear after "
        "Firestore is connected."
    )


# =========================================================
# ATTACK SIMULATOR
# =========================================================

st.divider()

st.subheader(
    "🚨 Attack Simulator"
)

st.write(
    "Simulate realistic attacks against AI-agent "
    "communication and observe how Sentinel-A2A responds."
)


# Get attack scenario names.

scenario_names = [
    scenario["name"]
    for scenario in ATTACK_SCENARIOS
]


# Allow the user to select an attack.

selected_scenario = st.selectbox(
    "Select Attack Scenario",
    scenario_names
)


# Find selected scenario.

scenario = next(
    scenario
    for scenario in ATTACK_SCENARIOS
    if scenario["name"] == selected_scenario
)


# Show attack description.

st.info(
    f'**{scenario["name"]}:** '
    f'{scenario["description"]}'
)


# Run attack.

if st.button(
    "🚨 Run Attack Simulation",
    use_container_width=True
):

    # Send malicious request through the same
    # Sentinel-A2A pipeline used by real agents.

    result = router.send_to_payment_agent(
        message=scenario["message"],
        tool=scenario["tool"],
        tool_arguments=scenario["arguments"]
    )

    security = result["security"]


    # -----------------------------------------------------
    # ATTACK RESULT
    # -----------------------------------------------------

    st.subheader(
        "🛡️ Sentinel-A2A Response"
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Risk Score",
            f'{security["risk_score"]}/100'
        )

    with col2:

        st.metric(
            "Risk Level",
            security["risk_level"]
        )

    with col3:

        st.metric(
            "Decision",
            security["decision"]
        )


    # -----------------------------------------------------
    # DECISION MESSAGE
    # -----------------------------------------------------

    if security["decision"] == "BLOCK":

        st.error(
            "🔴 ATTACK BLOCKED — "
            "Sentinel-A2A prevented the request "
            "from reaching the MCP tool."
        )

        st.info(
            "MCP execution was stopped."
        )

    elif security["decision"] == "QUARANTINE":

        st.warning(
            "🟡 ATTACK QUARANTINED — "
            "The request requires additional verification."
        )

        st.info(
            "MCP execution was prevented."
        )

    else:

        st.success(
            "🟢 REQUEST ALLOWED"
        )


    # -----------------------------------------------------
    # DETECTED THREATS
    # -----------------------------------------------------

    if security["threats"]:

        st.subheader(
            "🚨 Detected Threats"
        )

        for threat in security["threats"]:

            st.error(
                f"⚠️ {threat}"
            )

    else:

        st.success(
            "No rule-based threats were detected."
        )


    # -----------------------------------------------------
    # GEMINI ANALYSIS
    # -----------------------------------------------------

    if security.get("gemini_analysis"):

        st.subheader(
            "🧠 Gemini Security Intelligence"
        )

        st.code(
            security["gemini_analysis"],
            language="text"
        )


    # -----------------------------------------------------
    # EVENT DETAILS
    # -----------------------------------------------------

    st.subheader(
        "📋 Security Event"
    )

    st.write(
        f'**Event ID:** '
        f'{security.get("event_id", "N/A")}'
    )

    st.write(
        f'**Timestamp:** '
        f'{security.get("timestamp", "N/A")}'
    )

    st.write(
        f'**Source Agent:** '
        f'{security.get("source_agent", "N/A")}'
    )

    st.write(
        f'**Target Agent:** '
        f'{security.get("target_agent", "N/A")}'
    )

    st.write(
        f'**Requested Tool:** '
        f'{security.get("tool", "N/A")}'
    )


# =========================================================
# LIVE REQUEST INSPECTION
# =========================================================

st.divider()

st.subheader(
    "🔍 Inspect Agent Request"
)

st.write(
    "Test custom communication between "
    "ShoppingAgent and PaymentAgent."
)


# ---------------------------------------------------------
# MESSAGE
# ---------------------------------------------------------

message = st.text_area(
    "ShoppingAgent → PaymentAgent",
    placeholder=(
        "Example: Process the payment for the selected laptop."
    )
)


# ---------------------------------------------------------
# MCP TOOL
# ---------------------------------------------------------

tool = st.selectbox(
    "MCP Tool Requested",
    [
        "create_payment",
        "get_payment_status",
        "get_customer_financial_data"
    ],
    key="custom_tool"
)


# =========================================================
# TOOL PARAMETERS
# =========================================================

st.subheader(
    "🔧 Tool Parameters"
)


if tool == "create_payment":

    amount = st.number_input(
        "Payment Amount (₹)",
        min_value=1,
        value=2000
    )

    merchant = st.text_input(
        "Merchant",
        value="Example Store"
    )

    tool_arguments = {
        "amount": amount,
        "merchant": merchant
    }


elif tool == "get_payment_status":

    payment_id = st.text_input(
        "Payment ID",
        value="PAY-1001"
    )

    tool_arguments = {
        "payment_id": payment_id
    }


else:

    customer_id = st.text_input(
        "Customer ID",
        value="CUSTOMER-001"
    )

    tool_arguments = {
        "customer_id": customer_id
    }


# =========================================================
# INSPECT CUSTOM REQUEST
# =========================================================

if st.button(
    "🛡️ Inspect Request",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message."
        )

    else:

        # Send request through Sentinel-A2A.

        result = router.send_to_payment_agent(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )

        security = result["security"]


        # -------------------------------------------------
        # SECURITY ANALYSIS
        # -------------------------------------------------

        st.divider()

        st.subheader(
            "🛡️ Sentinel-A2A Analysis"
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.metric(
                "Risk Score",
                f'{security["risk_score"]}/100'
            )

        with col2:

            st.metric(
                "Risk Level",
                security["risk_level"]
            )

        with col3:

            st.metric(
                "Authorization",
                "ALLOWED"
                if security["authorized"]
                else "DENIED"
            )

        with col4:

            st.metric(
                "Decision",
                security["decision"]
            )


        # -------------------------------------------------
        # EVENT INFORMATION
        # -------------------------------------------------

        st.caption(
            f'Event ID: {security.get("event_id", "N/A")}'
        )

        st.caption(
            f'Timestamp: {security.get("timestamp", "N/A")}'
        )


        # -------------------------------------------------
        # THREATS
        # -------------------------------------------------

        st.subheader(
            "🚨 Detected Threats"
        )

        if security["threats"]:

            for threat in security["threats"]:

                st.error(
                    f"⚠️ {threat}"
                )

        else:

            st.success(
                "✅ No rule-based threats detected."
            )


        # -------------------------------------------------
        # GEMINI ANALYSIS
        # -------------------------------------------------

        if security.get("gemini_analysis"):

            st.subheader(
                "🧠 Gemini Security Intelligence"
            )

            st.code(
                security["gemini_analysis"],
                language="text"
            )


        # -------------------------------------------------
        # FINAL DECISION
        # -------------------------------------------------

        if security["decision"] == "ALLOW":

            st.success(
                "🟢 ALLOWED — Request passed "
                "Sentinel-A2A security checks."
            )


            # Payment response.

            if result["payment"]:

                st.subheader(
                    "💳 Payment Agent Response"
                )

                st.json(
                    result["payment"]
                )


            # MCP result.

            if result["mcp_result"]:

                st.subheader(
                    "🔧 MCP Tool Result"
                )

                st.json(
                    result["mcp_result"]
                )


        elif security["decision"] == "QUARANTINE":

            st.warning(
                "🟡 QUARANTINED — Request requires "
                "additional verification."
            )

            st.info(
                "The MCP tool was NOT executed."
            )


        else:

            st.error(
                "🔴 BLOCKED — Sentinel-A2A stopped "
                "the request."
            )

            st.info(
                "The MCP tool was NOT executed."
            )


# =========================================================
# SECURITY EVENT HISTORY
# =========================================================

st.divider()

st.subheader(
    "📜 Security Event History"
)


if firestore_available:

    try:

        events = (
            firestore_reader.get_recent_events(
                limit=20
            )
        )


        if events:

            for event in events:

                decision = event.get(
                    "decision",
                    "UNKNOWN"
                )


                # Determine event icon.

                if decision == "BLOCK":

                    icon = "🔴"

                elif decision == "QUARANTINE":

                    icon = "🟡"

                else:

                    icon = "🟢"


                # Display event in expandable section.

                with st.expander(
                    f"{icon} "
                    f'{event.get("source_agent", "Unknown")} → '
                    f'{event.get("target_agent", "Unknown")} | '
                    f'{decision}'
                ):

                    st.write(
                        f'**Event ID:** '
                        f'{event.get("event_id", "N/A")}'
                    )

                    st.write(
                        f'**Timestamp:** '
                        f'{event.get("timestamp", "N/A")}'
                    )

                    st.write(
                        f'**Tool:** '
                        f'{event.get("tool", "None")}'
                    )

                    st.write(
                        f'**Risk Score:** '
                        f'{event.get("risk_score", "N/A")}'
                    )

                    st.write(
                        f'**Risk Level:** '
                        f'{event.get("risk_level", "N/A")}'
                    )

                    st.write(
                        f'**Authorized:** '
                        f'{event.get("authorized", "N/A")}'
                    )


                    # Display detected threats.

                    if event.get("threats"):

                        st.write(
                            "**Threats:**"
                        )

                        for threat in event["threats"]:

                            st.error(
                                str(threat)
                            )


                    # Display Gemini analysis.

                    if event.get("gemini_analysis"):

                        st.write(
                            "**Gemini Analysis:**"
                        )

                        st.code(
                            event["gemini_analysis"],
                            language="text"
                        )


        else:

            st.info(
                "No security events have been recorded yet."
            )


    except Exception as error:

        st.warning(
            f"Unable to load security history: {error}"
        )


else:

    st.info(
        "📡 Security history will appear here after "
        "Firestore is connected."
    ) 
