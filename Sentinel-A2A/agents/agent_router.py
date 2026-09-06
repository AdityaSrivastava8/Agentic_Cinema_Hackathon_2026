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

    Sentinel-A2A controls whether the request is allowed
    before the target agent or MCP tool can execute it.
    """

    def __init__(self):

        # Create the two AI agents.
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

        The request must pass Sentinel-A2A before
        reaching the PaymentAgent or MCP tool.
        """

        # Use an empty dictionary when no tool arguments
        # are provided.
        if tool_arguments is None:
            tool_arguments = {}

        # -------------------------------------------------
        # STEP 1: Create the agent request
        # -------------------------------------------------

        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # -------------------------------------------------
        # STEP 2: Send request through Sentinel-A2A
        # -------------------------------------------------

        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"]
        )

        # -------------------------------------------------
        # STEP 3: Check Sentinel-A2A decision
        # -------------------------------------------------

        if security_result["decision"] != "ALLOW":

            # Blocked or quarantined requests stop here.
            #
            # The PaymentAgent and MCP tool never receive
            # the request.
            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }

        # -------------------------------------------------
        # STEP 4: Request approved
        # -------------------------------------------------

        payment_result = self.payment_agent.process_payment(
            message
        )

        # -------------------------------------------------
        # STEP 5: Execute MCP tool
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
