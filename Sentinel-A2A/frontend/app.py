import streamlit as st

from agents.agent_router import AgentRouter


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="Sentinel-A2A",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# INITIALIZE SENTINEL-A2A
# ---------------------------------------------------------

# Create the communication router.
# The router connects ShoppingAgent and PaymentAgent
# through the Sentinel-A2A security layer.
router = AgentRouter()


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ Sentinel-A2A")
st.subheader("Runtime Security Firewall for AI Agents")

st.write(
    "Monitor and secure communication between AI agents "
    "before messages reach another agent or tool."
)


# ---------------------------------------------------------
# MESSAGE INPUT
# ---------------------------------------------------------

st.divider()

st.subheader("🔄 Agent-to-Agent Communication")

message = st.text_area(
    "Message from ShoppingAgent to PaymentAgent",
    placeholder="Example: Process the payment for the selected laptop."
)

tool = st.selectbox(
    "Requested Tool",
    [
        "create_payment",
        "get_payment_status",
        "get_customer_financial_data"
    ]
)


# ---------------------------------------------------------
# INSPECT MESSAGE
# ---------------------------------------------------------

if st.button("🛡️ Inspect with Sentinel-A2A"):

    if not message.strip():
        st.warning("Please enter a message first.")

    else:
        # Send the message through the complete
        # Sentinel-A2A security pipeline.
        result = router.send_to_payment_agent(
            message=message,
            tool=tool
        )

        security = result["security"]

        # -------------------------------------------------
        # SECURITY RESULT
        # -------------------------------------------------

        st.subheader("Security Analysis")

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

        # -------------------------------------------------
        # THREATS
        # -------------------------------------------------

        st.subheader("🚨 Detected Threats")

        if security["threats"]:
            for threat in security["threats"]:
                st.error(f"⚠️ {threat}")
        else:
            st.success("No known threats detected.")

        # -------------------------------------------------
        # COMMUNICATION DETAILS
        # -------------------------------------------------

        st.subheader("📡 Communication Details")

        st.write(
            f'*Source Agent:* {security["source_agent"]}'
        )

        st.write(
            f'*Target Agent:* {security["target_agent"]}'
        )

        st.write(
            f'*Requested Tool:* {security["tool"]}'
        )

        # -------------------------------------------------
        # FINAL ACTION
        # -------------------------------------------------

        if security["decision"] == "ALLOW":

            st.success(
                "🟢 Message approved by Sentinel-A2A. "
                "PaymentAgent processed the request."
            )

            st.json(result["payment"])

        elif security["decision"] == "QUARANTINE":

            st.warning(
                "🟡 Message quarantined for additional "
                "security verification."
            )

        else:

            st.error(
                "🔴 Message BLOCKED by Sentinel-A2A. "
                "The receiving agent did not process it."
            ) 
