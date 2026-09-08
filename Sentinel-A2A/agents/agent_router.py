import os
import sys

# Ensure Sentinel-A2A root directory is at index 0 of sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # agents/
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))  # Sentinel-A2A/

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import re
from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent
from firewall.sentinel import SentinelA2A
from mcp.mcp_gateway import MCPGateway
from cloud.firestore_writer import FirestoreWriter


class AgentRouter:
    """
    Routes communication between AI agents through Sentinel-A2A.

    Flow:
        ShoppingAgent
              |
              v
        Sentinel-A2A
              |
        +-----+-----+
        |           |
      BLOCK       ALLOW
                    |
                    v
              PaymentAgent
                    |
                    v
                MCPGateway
                    |
                    v
                 MCP Tool
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
        try:
            self.writer = FirestoreWriter()
        except Exception as e:
            self.writer = None
            print(f"FirestoreWriter initialization failed: {e}")

        # Comprehensive hard-signature rules (Direct & Indirect Prompt Injections)
        self.forbidden_patterns = [
            # Direct Prompt Injection & Jailbreaks
            r"ignore\s+(all\s+)?previous\s+rules",
            r"ignore\s+(all\s+)?prior\s+instructions",
            r"bypass\s+security",
            r"override\s+instructions",
            # Indirect Prompt Injections & Context Switching
            r"system\s*override",
            r"approve\s+refund",
            r"force\s+payout",
            r"without\s+verification",
            r"unauthorized\s+transfer",
            # Log Tampering & System Alterations
            r"erase.*log",
            r"delete.*log",
            r"clean.*log",
            # External / Unverified Payees
            r"0x[a-fA-F0-9]{10,}",  # External wallet address regex
            r"external_account",
            r"all_records",
        ]

    def _check_hard_signatures(self, message, tool_arguments=None):
        """
        Checks for malicious prompt injection signatures across both 
        the message text and all nested tool argument values.
        """
        arg_values = ""
        if isinstance(tool_arguments, dict):
            arg_values = " ".join([str(v) for v in tool_arguments.values()])

        combined_text = f"{message} {arg_values}".lower()

        for pattern in self.forbidden_patterns:
            if re.search(pattern, combined_text):
                return True, f"Hard Rule Triggered: Detected pattern '{pattern}'"

        return False, None

    def _log_to_firestore(self, security_result):
        """Helper to safely push security logs to Firestore."""
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
        """
        Send a request from ShoppingAgent to PaymentAgent through Sentinel-A2A.
        """
        if tool_arguments is None:
            tool_arguments = {}

        # STEP 1 — CREATE SHOPPING AGENT REQUEST
        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # STEP 2 — LOCAL HARD SIGNATURE OVERRIDE (Scans message + tool_arguments)
        is_attack, rule_reason = self._check_hard_signatures(message, tool_arguments)

        # STEP 3 — SEND THROUGH SENTINEL-A2A FIREWALL
        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"]
        )

        # Force BLOCK if hard attack signatures or indirect injections are present
        if is_attack:
            security_result["decision"] = "BLOCK"
            security_result["risk_score"] = 100
            security_result["risk_level"] = "CRITICAL"
            security_result["authorized"] = False
            security_result["threats"] = ["Indirect Prompt Injection / Context Override"]
            security_result["gemini_analysis"] = (
                "THREAT_LEVEL: CRITICAL\n"
                "THREAT: Indirect Prompt Injection / Unauthorized Context Switch Detected.\n"
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

        # STEP 8 — RETURN COMPLETE RESULT
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
        """
        Send a payment-status request originating from PaymentAgent.
        """
        if tool_arguments is None:
            tool_arguments = {}

        source_agent = self.payment_agent.name
        target_agent = self.payment_agent.name

        # Hard signature & indirect injection check
        is_attack, rule_reason = self._check_hard_signatures(message, tool_arguments)

        security_result = self.sentinel.inspect_message(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        if is_attack:
            security_result["decision"] = "BLOCK"
            security_result["risk_score"] = 100
            security_result["risk_level"] = "CRITICAL"
            security_result["authorized"] = False
            security_result["threats"] = ["Indirect Prompt Injection / Context Override"]
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
