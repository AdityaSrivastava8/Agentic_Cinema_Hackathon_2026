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
# INITIALIZE SYSTEM
# ---------------------------------------------------------

router = AgentRouter()


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ Sentinel-A2A")
st.subheader("Runtime Security Firewall for AI Agents")

st.write(
    "Sentinel-A2A inspects communication between AI agents "
    "and protects MCP tools from unauthorized or malicious requests."
)


# ---------------------------------------------------------
# AGENT COMMUNICATION
# ---------------------------------------------------------

st.divider()

st.subheader("🤖 Agent-to-Agent Request")

message = st.text_area(
    "Message from ShoppingAgent → PaymentAgent",
    placeholder=(
        "Example: Process the payment for the selected laptop."
    )
)


# ---------------------------------------------------------
# TOOL SELECTION
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
# TOOL ARGUMENTS
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

if st.button("🛡️ Inspect Request"):

    if not message.strip():

        st.warning("Please enter a message.")

    else:

        # Send the request through:
        #
        # ShoppingAgent
        #       ↓
        # Sentinel-A2A
        #       ↓
        # PaymentAgent
        #       ↓
        # MCP Gateway
        #       ↓
        # MCP Tool

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

        st.subheader("🛡️ Sentinel-A2A Security Analysis")

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
        # THREAT INFORMATION
        # -------------------------------------------------

        st.subheader("🚨 Threat Detection")

        if security["threats"]:

            for threat in security["threats"]:
                st.error(f"⚠️ {threat}")

        else:

            st.success("✅ No known threats detected.")


        # -------------------------------------------------
        # AGENT INFORMATION
        # -------------------------------------------------

        st.subheader("📡 Agent Communication")

        col1, col2 = st.columns(2)

        with col1:
            st.write(
                f'**Source:** {security["source_agent"]}'
            )

        with col2:
            st.write(
                f'**Target:** {security["target_agent"]}'
            )


        # -------------------------------------------------
        # FINAL DECISION
        # -------------------------------------------------

        if security["decision"] == "ALLOW":

            st.success(
                "🟢 APPROVED — Sentinel-A2A allowed "
                "the request to proceed."
            )

            # Show PaymentAgent response.
            if result["payment"]:

                st.subheader("💳 Payment Agent")

                st.json(result["payment"])


            # Show MCP tool response.
            if result["mcp_result"]:

                st.subheader("🔧 MCP Tool Result")

                st.json(result["mcp_result"])


        elif security["decision"] == "QUARANTINE":

            st.warning(
                "🟡 QUARANTINED — The request requires "
                "additional verification."
            )


        else:

            st.error(
                "🔴 BLOCKED — Sentinel-A2A prevented the "
                "request from reaching the target/tool."
            )

            st.info(
                "The MCP tool was NOT executed."
            ) 
