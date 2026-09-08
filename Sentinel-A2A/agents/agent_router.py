import re
from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent
from firewall.sentinel import SentinelA2A
from mcp.mcp_gateway import MCPGateway
from cloud.firestore_logger import FirestoreLogger


class AgentRouter:
    """
    Routes communication between AI agents through Sentinel-A2A.
    """

    def __init__(self):
        # Create AI agents
        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()

        # Central security firewall
        self.sentinel = SentinelA2A()

        # MCP gateway
        self.mcp_gateway = MCPGateway()

        # Logger
        self.logger = FirestoreLogger()

    def send_to_payment_agent(
        self,
        message,
        tool=None,
        tool_arguments=None
    ):
        if tool_arguments is None:
            tool_arguments = {}

        # STEP 1 — SHOPPING AGENT REQUEST
        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # STEP 2 — SENTINEL-A2A FIREWALL INSPECTION & LOGGING
        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"],
            tool_arguments=tool_arguments
        )

        # STEP 3 — ENFORCE SECURITY DECISION
        if security_result["decision"] != "ALLOW":
            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        # STEP 4 — PAYMENT AGENT EXECUTION
        payment_result = self.payment_agent.process_payment(message)

        # STEP 5 — MCP TOOL EXECUTION
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
            tool=tool,
            tool_arguments=tool_arguments
        )

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
