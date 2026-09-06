from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent
from firewall.sentinel import SentinelA2A


class AgentRouter:
    """
    Routes messages between AI agents through Sentinel-A2A.

    No agent communicates directly with another agent.

    Communication flow:

        ShoppingAgent
              ↓
        AgentRouter
              ↓
        Sentinel-A2A
              ↓
        PaymentAgent

    This makes Sentinel-A2A the security checkpoint
    for all agent-to-agent communication.
    """

    def _init_(self):
        # Create the agents that participate in communication.
        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()

        # Create the Sentinel-A2A security layer.
        self.sentinel = SentinelA2A()

    def send_to_payment_agent(self, message, tool=None):
        """
        Send a message from ShoppingAgent to PaymentAgent.

        The message is inspected by Sentinel-A2A before
        the PaymentAgent receives it.
        """

        # ShoppingAgent creates the outgoing request.
        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )

        # Sentinel-A2A inspects the communication.
        security_result = self.sentinel.inspect_message(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"],
            allowed_tools=request["allowed_tools"]
        )

        # Only allow the PaymentAgent to process the request
        # if Sentinel-A2A approves it.
        if security_result["decision"] == "ALLOW":

            payment_result = self.payment_agent.process_payment(
                message
            )

            return {
                "security": security_result,
                "payment": payment_result
            }

        # If Sentinel-A2A blocks or quarantines the request,
        # the PaymentAgent never receives it.
        return {
            "security": security_result,
            "payment": None
        } 
