from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent

from firewall.sentinel import SentinelA2A
from mcp.mcp_gateway import MCPGateway


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

    Sentinel-A2A performs the complete security analysis
    before the request reaches the target agent or tool.
    """

    def __init__(self):

        # Create the AI agents.
        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()

        # Create the central security firewall.
        self.sentinel = SentinelA2A()

        # Create the MCP gateway.
        self.mcp_gateway = MCPGateway()

    def send_to_payment_agent(
        self,
        message,
        tool=None,
        tool_arguments=None
    ):
        """
        Send a request from ShoppingAgent to PaymentAgent.

        The request first passes through Sentinel-A2A.

        If Sentinel-A2A returns BLOCK or QUARANTINE,
        execution stops.

        If Sentinel-A2A returns ALLOW,
        the PaymentAgent and requested MCP tool can execute.
        """

        # Use an empty dictionary when no tool arguments
        # are provided.
        if tool_arguments is None:
            tool_arguments = {}

        # -------------------------------------------------
        # STEP 1 — CREATE AGENT REQUEST
        # -------------------------------------------------

        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # -------------------------------------------------
        # STEP 2 — SEND THROUGH SENTINEL-A2A
        # -------------------------------------------------

        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"]
        )

        # -------------------------------------------------
        # STEP 3 — ENFORCE SECURITY DECISION
        # -------------------------------------------------

        if security_result["decision"] != "ALLOW":

            # The request never reaches the PaymentAgent
            # or MCP tool.
            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        # -------------------------------------------------
        # STEP 4 — PAYMENT AGENT
        # -------------------------------------------------

        payment_result = (
            self.payment_agent.process_payment(
                message
            )
        )

        # -------------------------------------------------
        # STEP 5 — MCP TOOL
        # -------------------------------------------------

        mcp_result = None

        if tool:

            mcp_result = self.mcp_gateway.execute(
                tool,
                **tool_arguments
            )

        # -------------------------------------------------
        # STEP 6 — RETURN COMPLETE RESULT
        # -------------------------------------------------

        return {
            "security": security_result,
            "payment": payment_result,
            "mcp_result": mcp_result
        }
