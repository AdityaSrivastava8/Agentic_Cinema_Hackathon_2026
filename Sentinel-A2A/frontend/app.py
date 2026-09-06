import streamlit as st

from agents.agent_router import AgentRouter
from cloud.firestore_reader import FirestoreReader


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="Sentinel-A2A",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# INITIALIZE SYSTEM
# ---------------------------------------------------------

router = AgentRouter()


# Try to connect to Firestore.
# The application can still run locally if Google Cloud
# is not configured.
try:
    firestore_reader = FirestoreReader()
    firestore_available = True

except Exception:
    firestore_reader = None
    firestore_available = False


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ Sentinel-A2A")

st.subheader(
    "Runtime Security Firewall for AI Agents"
)

st.write(
    "Sentinel-A2A inspects communication between AI agents "
    "and protects MCP tools from malicious or unauthorized "
    "requests."
)


# ---------------------------------------------------------
# SECURITY OVERVIEW
# ---------------------------------------------------------

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
        "☁️ Google Cloud Firestore is not configured. "
        "Live security history will appear after deployment."
    )


# ---------------------------------------------------------
# LIVE REQUEST INSPECTION
# ---------------------------------------------------------

st.divider()

st.subheader("🔍 Inspect Agent Request")

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
    ]
)


# ---------------------------------------------------------
# TOOL PARAMETERS
# ---------------------------------------------------------

st.subheader("🔧 Tool Parameters")

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


# ---------------------------------------------------------
# INSPECT REQUEST
# ---------------------------------------------------------

if st.button(
    "🛡️ Inspect Request",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message."
        )

    else:

        # Send the request through the complete
        # Sentinel-A2A security pipeline.
        result = router.send_to_payment_agent(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )

        security = result["security"]


        # -------------------------------------------------
        # SECURITY RESULT
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
        # EVENT ID
        # -------------------------------------------------

        st.caption(
            f'Event ID: {security["event_id"]}'
        )

        st.caption(
            f'Timestamp: {security["timestamp"]}'
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

            if result["payment"]:

                st.subheader(
                    "💳 Payment Agent Response"
                )

                st.json(
                    result["payment"]
                )

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
                "The MCP tool was not executed."
            )


        else:

            st.error(
                "🔴 BLOCKED — Sentinel-A2A stopped "
                "the request."
            )

            st.info(
                "The MCP tool was NOT executed."
            )


# ---------------------------------------------------------
# SECURITY HISTORY
# ---------------------------------------------------------

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

                if decision == "BLOCK":

                    icon = "🔴"

                elif decision == "QUARANTINE":

                    icon = "🟡"

                else:

                    icon = "🟢"

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

                    if event.get("threats"):

                        st.write(
                            "**Threats:**"
                        )

                        for threat in event["threats"]:

                            st.error(
                                str(threat)
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
        "Security history will be available once "
        "Firestore is connected."
    ) 
