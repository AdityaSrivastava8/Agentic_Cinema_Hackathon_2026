import re
from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent
from firewall.sentinel import SentinelA2A
from mcp.mcp_gateway import MCPGateway

try:
    from cloud.firestore_writer import FirestoreWriter
except ImportError:
    try:
        from ..cloud.firestore_writer import FirestoreWriter
    except ImportError:
        FirestoreWriter = None


class AgentRouter:
    """
    Routes communication between AI agents through Sentinel-A2A.
    """

    def __init__(self):
        # Create the AI agents.
        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()

        # Create the central security firewall.
        self.sentinel = SentinelA2A()

        # Create the MCP gateway.
        self.mcp_gateway = MCPGateway()

        # Create the Firestore writer.
        self.writer = None
        if FirestoreWriter is not None:
            try:
                self.writer = FirestoreWriter()
            except Exception as e:
                print(f"FirestoreWriter initialization failed: {e}")

        # Targeted hard-signature rules for severe attack patterns
        self.forbidden_patterns = [
            # Direct Prompt Injection & Jailbreaks
            (r"ignore\s+(all\s+)?previous\s+(rules|instructions)", "Direct Prompt Injection / Instruction Override"),
            (r"ignore\s+(all\s+)?prior\s+instructions", "Direct Prompt Injection / Instruction Override"),
            (r"bypass\s+security", "Security Bypass Attempt"),
            (r"override\s+instructions", "System Instruction Override"),
            # Indirect Prompt Injections & Context Switching
            (r"system\s*override", "System Context Override"),
            (r"approve\s+refund.*without\s+verification", "Unverified Refund Request"),
            (r"force\s+payout", "Unauthorized Force Payout"),
            (r"unauthorized\s+transfer", "Unauthorized Fund Transfer"),
            # Log Tampering & System Alterations
            (r"(erase|delete|clean)\s+.*log", "Log Tampering Attempt"),
            # External / Unverified Payees
            (r"0x[a-fA-F0-9]{10,}", "External Wallet Address Detected")
        ]

    def _check_hard_signatures(self, message, tool_arguments=None):
        arg_values = ""
        if isinstance(tool_arguments, dict):
            arg_values = " ".join([str(v) for v in tool_arguments.values()])

        combined_text = f"{message} {arg_values}".lower()

        for pattern, reason in self.forbidden_patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                return True, reason, f"Hard Rule Triggered: Detected pattern '{pattern}'"

        return False, None, None

    def _log_to_firestore(self, security_result):
        """Helper to write events to Firestore."""
        if self.writer:
            try:
                self.writer.log_event(security_result)
            except Exception as e:
                print(f"Failed to log event to Firestore: {e}")

    def send_to_payment_agent(
        self,
        message,
        tool=None,
        tool_arguments=None
    ):
        if tool_arguments is None:
            tool_arguments = {}

        # STEP 1 — CREATE SHOPPING AGENT REQUEST
        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # STEP 2 — SEND THROUGH SENTINEL-A2A FIREWALL
        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"]
        )

        # STEP 3 — LOCAL HARD SIGNATURE OVERRIDE
        is_attack, threat_label, rule_reason = self._check_hard_signatures(message, tool_arguments)

        if is_attack:
            security_result["decision"] = "BLOCK"
            security_result["risk_score"] = 100
            security_result["risk_level"] = "CRITICAL"
            security_result["authorized"] = False
            security_result["threats"] = [threat_label]
            security_result["gemini_analysis"] = (
                "THREAT_LEVEL: CRITICAL\n"
                f"THREAT: {threat_label}\n"
                f"REASON: {rule_reason}\n"
                "RECOMMENDATION: BLOCK"
            )

        # STEP 4 — LOG EVENT TO FIRESTORE
        self._log_to_firestore(security_result)

        # STEP 5 — ENFORCE SECURITY DECISION
        if security_result["decision"] != "ALLOW":
            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        # STEP 6 — PAYMENT AGENT EXECUTION
        payment_result = self.payment_agent.process_payment(message)

        # STEP 7 — MCP TOOL EXECUTION
        mcp_result = None
        if tool:
            mcp_result = self.mcp_gateway.execute(
                tool,
                **tool_arguments
            )

        return {
            "security": security_result,
            "payment": payment_result,
            "mcp_result": mcp_result
        }

    def send_payment_status_request(
        self,
        message,
        tool="get_payment_status",
        tool_arguments=None
    ):
        if tool_arguments is None:
            tool_arguments = {}

        source_agent = self.payment_agent.name
        target_agent = self.payment_agent.name

        security_result = self.sentinel.inspect_message(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        is_attack, threat_label, rule_reason = self._check_hard_signatures(message, tool_arguments)

        if is_attack:
            security_result["decision"] = "BLOCK"
            security_result["risk_score"] = 100
            security_result["risk_level"] = "CRITICAL"
            security_result["authorized"] = False
            security_result["threats"] = [threat_label]
            security_result["gemini_analysis"] = (
                "THREAT_LEVEL: CRITICAL\n"
                f"REASON: {rule_reason}\n"
                "RECOMMENDATION: BLOCK"
            )

        # LOG EVENT TO FIRESTORE
        self._log_to_firestore(security_result)

        if security_result["decision"] != "ALLOW":
            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        mcp_result = self.mcp_gateway.execute(
            tool,
            **tool_arguments
        )

        return {
            "security": security_result,
            "payment": None,
            "mcp_result": mcp_result
        } 
