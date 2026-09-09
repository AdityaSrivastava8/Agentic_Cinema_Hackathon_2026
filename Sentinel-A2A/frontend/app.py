import os
import sys

import streamlit as st

# Path configuration
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.agent_router import AgentRouter
from cloud.firestore_logger import LOCAL_EVENT_STORE
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

st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        :root {
            --ink: #f4f7fb;
            --muted: #9aabbd;
            --line: #263749;
            --panel: #111c2a;
            --canvas: #070b12;
            --teal: #0e9f9a;
            --teal-deep: #087873;
            --amber: #f59e0b;
        }

        html, body, [class*="css"] {
            font-family: 'DM Sans', sans-serif;
            color: var(--ink);
        }

        .stApp {
            background:
                radial-gradient(circle at 90% 0%, rgba(14, 159, 154, 0.08), transparent 28rem),
                linear-gradient(135deg, #0b111b 0%, var(--canvas) 55%, #0b171b 100%);
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(165deg, #10253c 0%, #122d48 55%, #0d1d31 100%);
            border-right: 1px solid rgba(255,255,255,0.09);
        }
        [data-testid="stSidebar"] > div:first-child {
            padding: 1.25rem 1rem 1.5rem;
        }
        [data-testid="stSidebar"] * {
            color: #e7f0f6 !important;
            font-family: 'DM Sans', sans-serif;
        }
        [data-testid="stSidebar"] h1,
        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3,
        [data-testid="stSidebar"] h4 {
            color: #ffffff !important;
            font-family: 'Space Grotesk', sans-serif;
            font-weight: 700 !important;
            letter-spacing: -0.02em;
        }
        [data-testid="stSidebar"] .stMarkdownContainer {
            background: rgba(255,255,255,0.055);
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 12px;
            padding: 0.7rem 0.8rem;
            margin-top: 0.55rem;
        }
        [data-testid="stSidebar"] .stButton > button {
            background: rgba(14, 159, 154, 0.16);
            border: 1px solid rgba(91, 229, 220, 0.35);
            border-radius: 9px;
            color: #dffffb !important;
            font-weight: 700;
            transition: all 160ms ease;
        }
        [data-testid="stSidebar"] .stButton > button:hover {
            background: rgba(14, 159, 154, 0.30);
            border-color: #5be5dc;
            transform: translateY(-1px);
        }
        [data-testid="stSidebar"] hr {
            border-color: rgba(255,255,255,0.12);
            margin: 1rem 0;
        }

        .brand-lockup {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 0 1rem;
        }
        .brand-mark {
            display: grid;
            place-items: center;
            width: 2.55rem;
            height: 2.55rem;
            border-radius: 10px;
            background: linear-gradient(145deg, #22c6ba, #087873);
            box-shadow: 0 8px 22px rgba(14, 159, 154, 0.28);
            font-size: 1.25rem;
        }
        .brand-name {
            color: #ffffff;
            font: 700 1.12rem 'Space Grotesk', sans-serif;
            letter-spacing: -0.02em;
        }
        .brand-subtitle {
            color: #8fb0c5;
            font-size: 0.72rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .sidebar-kicker {
            color: #78e1d9;
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }
        .sidebar-copy {
            color: #b8cbda !important;
            font-size: 0.82rem;
            line-height: 1.55;
        }

        .hero {
            background: linear-gradient(120deg, #102b46 0%, #16465b 62%, #0e8f88 100%);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 18px;
            box-shadow: 0 18px 45px rgba(16, 43, 70, 0.16);
            color: white;
            margin: 0.75rem 0 1.75rem;
            padding: 1.6rem 1.75rem;
        }
        .hero-kicker {
            color: #82ebe0;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.16em;
            text-transform: uppercase;
        }
        .hero-title {
            font: 700 clamp(1.9rem, 4vw, 3.1rem) 'Space Grotesk', sans-serif;
            letter-spacing: -0.045em;
            line-height: 1.05;
            margin: 0.4rem 0 0.55rem;
        }
        .hero-copy {
            color: #c7e1e7;
            font-size: 0.98rem;
            max-width: 42rem;
        }

        h1, h2, h3, h4,
        [data-testid="stMarkdownContainer"] h1,
        [data-testid="stMarkdownContainer"] h2,
        [data-testid="stMarkdownContainer"] h3,
        [data-testid="stMarkdownContainer"] h4 {
            font-family: 'Space Grotesk', sans-serif;
            letter-spacing: -0.025em;
            color: #f7fbff !important;
        }
        h2, h3,
        [data-testid="stMarkdownContainer"] h2,
        [data-testid="stMarkdownContainer"] h3 {
            color: #dcf8f3 !important;
            text-shadow: 0 0 18px rgba(125, 235, 224, 0.10);
        }
        [data-testid="stMetric"] {
            background: rgba(17, 28, 42, 0.92);
            border: 1px solid var(--line);
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.22);
            padding: 0.9rem 1rem;
        }
        [data-testid="stMetricLabel"] {
            color: var(--muted) !important;
            font-weight: 600;
        }
        [data-testid="stMetricValue"] {
            color: var(--ink) !important;
            font-family: 'Space Grotesk', sans-serif;
        }
        [data-testid="stWidgetLabel"] p,
        [data-testid="stWidgetLabel"] label,
        [data-testid="stMarkdownContainer"] p,
        [data-testid="stCaptionContainer"] p {
            color: #dbe8f2 !important;
        }
        .stButton > button {
            background: #1261a0 !important;
            border: 1px solid #3388cc !important;
            border-radius: 9px;
            color: #ffffff !important;
            font-weight: 700;
            transition: all 160ms ease;
        }
        .stButton > button:hover {
            background: #1877c2 !important;
            border-color: #65b5f0 !important;
            color: #ffffff !important;
            transform: translateY(-1px);
        }
        .stButton > button p,
        [data-testid="stNumberInput"] button,
        [data-testid="stNumberInput"] button svg {
            color: #ffffff !important;
        }
        [data-testid="stNumberInput"] button {
            background: #1261a0 !important;
            border-color: #3388cc !important;
        }
        [data-testid="stNumberInput"] button:hover {
            background: #1877c2 !important;
        }
        [data-testid="stNumberInput"] > div,
        [data-testid="stTextInput"] > div,
        [data-testid="stTextArea"] > div,
        [data-testid="stSelectbox"] [data-baseweb="select"],
        [data-baseweb="select"] > div {
            background: #1261a0 !important;
            border-color: #3388cc !important;
        }
        [data-testid="stNumberInput"] input,
        [data-testid="stTextInput"] input,
        [data-testid="stTextArea"] textarea {
            background: #101a27 !important;
            color: #ffffff !important;
        }
        [data-testid="stSelectbox"] [data-baseweb="select"] span,
        [data-testid="stSelectbox"] [data-baseweb="select"] svg {
            color: #ffffff !important;
            fill: #ffffff !important;
        }
        .stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"],
        .stNumberInput input {
            border-radius: 9px;
            border-color: var(--line);
            background: #101a27;
            color: var(--ink);
        }
        .stSelectbox [data-baseweb="select"] * {
            color: #f4f7fb !important;
        }
        [data-baseweb="popover"],
        [data-baseweb="menu"],
        [role="listbox"] {
            background: #1261a0 !important;
            border: 1px solid #3388cc !important;
            border-radius: 9px !important;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.35) !important;
        }
        [role="option"] {
            background: #1261a0 !important;
            color: #ffffff !important;
        }
        [role="option"]:hover,
        [role="option"][aria-selected="true"] {
            background: #1877c2 !important;
            color: #ffffff !important;
        }
        [data-testid="stAlert"],
        [data-testid="stExpander"],
        [data-testid="stDataFrame"],
        [data-testid="stVegaLiteChart"],
        [data-testid="stArrowVegaLiteChart"] {
            background: #111c2a !important;
            border: 1px solid #263749 !important;
            border-radius: 10px;
        }
        [data-testid="stAlert"] p,
        [data-testid="stExpander"] p,
        [data-testid="stExpander"] summary,
        [data-testid="stVegaLiteChart"] text,
        [data-testid="stArrowVegaLiteChart"] text {
            color: #ffffff !important;
        }
        [data-testid="stCodeBlock"],
        [data-testid="stCodeBlock"] pre,
        [data-testid="stCodeBlock"] code,
        pre, code {
            background: #102b46 !important;
            color: #ffffff !important;
            border: 1px solid #3388cc !important;
            border-radius: 9px !important;
        }
        [data-testid="stJson"],
        [data-testid="stJson"] pre,
        [data-testid="stJson"] code,
        .stJson,
        .stJson pre {
            background: #102b46 !important;
            color: #ffffff !important;
            border: 1px solid #3388cc !important;
            border-radius: 9px !important;
        }
        [data-testid="stJson"] span,
        .stJson span {
            color: #ffffff !important;
        }
        [data-testid="stJson"] *,
        .stJson *,
        [class*="react-json-view"] * {
            background-color: #102b46 !important;
            color: #ffffff !important;
        }
        [data-testid="stJson"] button,
        .stJson button,
        [class*="react-json-view"] button {
            background: #1261a0 !important;
            color: #ffffff !important;
            border: 0 !important;
        }
        [data-testid="stVegaLiteChart"] svg,
        [data-testid="stArrowVegaLiteChart"] svg {
            background: #111c2a !important;
        }
        .block-container {
            max-width: 1220px;
            padding-top: 2.2rem;
            padding-bottom: 4rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Persistent Session State Arrays
if "local_events" not in st.session_state:
    st.session_state["local_events"] = []
if "session_events" not in st.session_state:
    st.session_state["session_events"] = []

# Keep local fallback memory synchronized with the current Streamlit session.
if not isinstance(LOCAL_EVENT_STORE, list):
    LOCAL_EVENT_STORE = []

# =========================================================
# SYSTEM INITIALIZATION & CACHING
# =========================================================

@st.cache_resource
def get_agent_router():
    try:
        return AgentRouter()
    except Exception as error:
        return error

def sync_and_store_event(security_event: dict):
    """
    Ensures security events persist across Streamlit re-renders
    and remain perfectly synced between local memory store and session state.
    """
    if not isinstance(security_event, dict):
        return

    st.session_state.setdefault("local_events", [])
    st.session_state.setdefault("session_events", [])

    evt_id = security_event.get("event_id")
    session_ids = {e.get("event_id") for e in st.session_state["local_events"] if isinstance(e, dict)}
    if evt_id and evt_id not in session_ids:
        st.session_state["local_events"].insert(0, security_event)

    session_event_ids = {e.get("event_id") for e in st.session_state["session_events"] if isinstance(e, dict)}
    if evt_id and evt_id not in session_event_ids:
        st.session_state["session_events"].insert(0, security_event)

    local_ids = {e.get("event_id") for e in LOCAL_EVENT_STORE if isinstance(e, dict)}
    if evt_id and evt_id not in local_ids:
        LOCAL_EVENT_STORE.insert(0, security_event)

def fetch_firestore_data():
    """
    Fetches events from Firestore or Streamlit Session State fallback.
    """
    events = []
    available = False
    reader = None

    try:
        reader = FirestoreReader()
        if getattr(reader, "db", None):
            recent_events = reader.get_recent_events(limit=100) or []
            if recent_events:
                events = recent_events
                available = True
    except Exception:
        pass

    # Merge session state and module-level memory stores cleanly
    if not available:
        combined_dict = {}
        # Merge local module store
        for evt in LOCAL_EVENT_STORE:
            if isinstance(evt, dict) and evt.get("event_id"):
                combined_dict[evt["event_id"]] = evt
        # Merge session state store
        for evt in st.session_state.get("local_events", []):
            if isinstance(evt, dict) and evt.get("event_id"):
                combined_dict[evt["event_id"]] = evt

        events = list(combined_dict.values())
        events.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)

    count = len(events)
    blocked = [e for e in events if e.get("decision") == "BLOCK"]

    return {
        "available": available or len(events) > 0,
        "is_cloud": available,
        "reader": reader,
        "events": events,
        "count": count,
        "blocked": blocked
    }

with st.sidebar:
    st.markdown(
        """
        <div class="brand-lockup">
            <div class="brand-mark">🛡</div>
            <div>
                <div class="brand-name">Sentinel-A2A</div>
                <div class="brand-subtitle">Agent security console</div>
            </div>
        </div>
        <div class="sidebar-kicker">Control center</div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("🔄 Clear cache & reload"):
        st.cache_resource.clear()
        st.cache_data.clear()
        st.session_state["local_events"] = []
        LOCAL_EVENT_STORE.clear()
        st.rerun()

    st.markdown("---")
    st.markdown("### About Sentinel")
    st.write(
        "Imagine two self-driving cars, each controlled by its own independent AI agent, approaching the same intersection. The two AI agents communicate with each other to coordinate their movements, but their communication is routed through Sentinel-A2A, which acts as an independent security and governance layer. Sentinel analyzes their interactions, verifies authorization and security policies, detects malicious, abnormal, or conflicting behavior, evaluates the risk of each request, and monitors the agents’ behavioral trust. For example, if Car A incorrectly interprets Car B’s position and sends an unsafe instruction to proceed through the intersection, Sentinel can identify the interaction as high-risk and block or quarantine the request before it reaches the other agent or vehicle-control system. Similarly, if an agent repeatedly generates suspicious requests, Sentinel can identify the behavioral anomaly and reduce its trust score. Through this process, Sentinel-A2A acts as a digital traffic controller and security checkpoint for communication between autonomous AI agents, helping prevent unsafe AI decisions from affecting the physical world.\n\nRemember the famous Facebook AI experiment where two bots, Bob and Alice, started talking to each other in their own shorthand language? While headlines hyped it up as robots taking over, it revealed a real, dangerous vulnerability: when autonomous AI agents communicate machine-to-machine, humans instantly lose visibility. That’s exactly where Sentinel-A2A comes in. It acts as an unbypassable, zero-trust security firewall sitting right between those agents. Whether an agent tries to override system instructions, pass illegal parameters, or escalate its own privileges, Sentinel-A2A intercepts every payload in real time — calculating dynamic risk scores and blocking unauthorized actions before they ever touch underlying systems.\n\nSentinel-A2A addresses the single biggest security blind spot in agentic AI: traditional firewalls protect web traffic, and traditional LLM guardrails protect user prompts, but neither safeguards machine-to-machine Agent-to-Agent (A2A) communication or MCP tool execution. Sentinel-A2A is among the world’s first dedicated runtime firewalls specifically engineered for this layer — stopping indirect prompt injection and unauthorized financial execution before they touch real systems.\n\nLooking ahead, Sentinel-A2A could evolve into a broader AI safety infrastructure for autonomous vehicles and other intelligent machines. In the event of a serious accident, it could integrate with authorized emergency-response systems to automatically share verified incident information—such as location, severity, and vehicles involved—with ambulance and emergency services. Similarly, repeated or critical violations could be reported through authorized integrations with transport and government authorities, enabling regulatory monitoring and response. These capabilities could eventually extend beyond vehicles to robots, drones, industrial machines, smart-city infrastructure, and other systems where independent AI agents need to interact safely.\n\nJust as roads need traffic rules and vehicles need safety systems, a world of autonomous AI agents needs a trusted layer that governs how those agents interact. Sentinel-A2A is our vision for that layer."
    )

    st.markdown("---")
    st.write("For suggestions or complaints, mail us at:")
    st.write("yeahboyadi@gmail.com")
    st.write("Aditya Srivastava (Founder)")
    st.write("niketjha1@gmail.com")
    st.write("Niket Jha (Partner)")

router = get_agent_router()
if isinstance(router, Exception):
    st.warning(
        "Security backend initialization is unavailable. "
        "The dashboard is running in read-only mode."
    )
    st.caption(f"Backend initialization details: {router}")
fs_info = fetch_firestore_data()

# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
    <section class="hero">
        <div class="hero-kicker">Runtime defense layer · Live posture</div>
        <div class="hero-title">Sentinel-A2A</div>
        <div class="hero-copy">
            Runtime security for agent-to-agent communication. Inspect every request,
            enforce MCP policy, and stop unsafe actions before they reach downstream tools.
        </div>
    </section>
    """,
    unsafe_allow_html=True,
)

# =========================================================
# SECURITY OVERVIEW
# =========================================================

st.divider()
st.subheader("📊 Security Overview")

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Events Inspected", fs_info["count"])
with col2:
    st.metric("Threats Blocked", len(fs_info["blocked"]))
with col3:
    if fs_info["is_cloud"]:
        st.metric("Firestore Status", "🟢 CONNECTED")
    else:
        st.metric("Firestore Status", "🟡 LOCAL FALLBACK")

if not fs_info["is_cloud"]:
    st.caption("ℹ️ Running in local memory fallback mode. Connect Google Cloud to sync with Cloud Firestore.")

# =========================================================
# SECURITY ANALYTICS
# =========================================================

st.divider()
st.subheader("📈 Security Analytics")

if fs_info["events"]:
    try:
        analytics = SecurityAnalytics(fs_info["events"])
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
    st.info("📡 Security analytics will appear after events are logged or tested.")

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

# Clear session result display if scenario changes
if st.session_state.get("current_scenario") != selected_scenario:
    st.session_state["current_scenario"] = selected_scenario
    st.session_state.pop("simulation_result", None)

scenario = next(
    (sc for sc in ATTACK_SCENARIOS if sc["name"] == selected_scenario),
    None
)

if scenario:
    st.info(f'**{scenario["name"]}:** {scenario["description"]}')

    if st.button(
        "🚨 Run Attack Simulation",
        use_container_width=True,
        disabled=isinstance(router, Exception),
    ):
        result = router.send_to_payment_agent(
            message=scenario["message"],
            tool=scenario["tool"],
            tool_arguments=scenario["arguments"]
        )
        st.session_state["simulation_result"] = result

        # Sync event to local memory and session state
        if "security" in result and isinstance(result["security"], dict):
            sync_and_store_event(result["security"])

        st.rerun()

if "simulation_result" in st.session_state:
    result = st.session_state["simulation_result"]
    security = result["security"]

    if security.get("logging_error") and not fs_info["events"]:
        st.warning(f"Firestore: {security['logging_error']}")
    elif security.get("firestore_document_id"):
        st.caption(f"✅ Recorded Event ID: {security['firestore_document_id']}")

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

if st.button(
    "🛡️ Inspect Request",
    use_container_width=True,
    disabled=isinstance(router, Exception),
):
    if not message.strip():
        st.warning("Please enter a message.")
    else:
        result = router.send_to_payment_agent(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )
        st.session_state["inspection_result"] = result

        # Sync event to local memory and session state
        if "security" in result and isinstance(result["security"], dict):
            sync_and_store_event(result["security"])

        st.rerun()

if "inspection_result" in st.session_state:
    result = st.session_state["inspection_result"]
    security = result["security"]

    if security.get("logging_error") and not fs_info["events"]:
        st.warning(f"Firestore: {security['logging_error']}")
    elif security.get("firestore_document_id"):
        st.caption(f"✅ Recorded Event ID: {security['firestore_document_id']}")

    st.divider()
    st.subheader("🛡️ Sentinel-A2A Analysis")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Risk Score", f'{security["risk_score"]}/100')
    with col2:
        st.metric("Risk Level", security["risk_level"])
    with col3:
        st.metric("Authorization", "ALLOWED" if security.get("authorized", True) else "DENIED")
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

events = fs_info["events"]
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
            st.write(f'**Authorized:** {event.get("authorized", True)}')

            if event.get("threats"):
                st.write("**Threats:**")
                for threat in event["threats"]:
                    st.error(str(threat))

            if event.get("gemini_analysis"):
                st.write("**Gemini Analysis:**")
                st.code(event["gemini_analysis"], language="text")
else:
    st.info("No security events recorded yet. Run a simulation above to record events.") 
