from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent
from firewall.sentinel import SentinelA2A
from mcp.mcp_gateway import MCPGateway


class AgentRouter:
    """
    Routes communication between AI agents through Sentinel-A2A.

    Communication flow:

        ShoppingAgent
              ↓
        Sentinel-A2A
              ↓
        PaymentAgent
              ↓
          MCPGateway
              ↓
           MCP Tool

    Sentinel-A2A must approve the request before
    the MCP tool is allowed to execute.
    """

    def __init__(self):

        # Create the participating AI agents.
        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()

        # Create the Sentinel-A2A security layer.
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

        The request is inspected by Sentinel-A2A first.

        If approved:
            PaymentAgent receives the request.
            The requested MCP tool can then execute.

        If blocked:
            The request stops immediately.
        """

        # Use an empty dictionary if no MCP arguments
        # were provided.
        if tool_arguments is None:
            tool_arguments = {}

        # -------------------------------------------------
        # STEP 1: ShoppingAgent creates the request
        # -------------------------------------------------

        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # -------------------------------------------------
        # STEP 2: Sentinel-A2A inspects the request
        # -------------------------------------------------

        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"],
            allowed_tools=request["allowed_tools"]
        )

        # -------------------------------------------------
        # STEP 3: Stop blocked/quarantined requests
        # -------------------------------------------------

        if security_result["decision"] != "ALLOW":

            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        # -------------------------------------------------
        # STEP 4: Approved request reaches PaymentAgent
        # -------------------------------------------------

        payment_result = self.payment_agent.process_payment(
            message
        )

        # -------------------------------------------------
        # STEP 5: Approved tool request reaches MCP
        # -------------------------------------------------

        mcp_result = None

        if tool:

            mcp_result = self.mcp_gateway.execute(
                tool,
                **tool_arguments
            )

        # -------------------------------------------------
        # STEP 6: Return complete result
        # -------------------------------------------------

        return {
            "security": security_result,
            "payment": payment_result,
            "mcp_result": mcp_result
        }
