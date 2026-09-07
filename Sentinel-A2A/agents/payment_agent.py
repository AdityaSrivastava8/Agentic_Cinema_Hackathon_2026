class PaymentAgent:
    """
    Represents an AI payment agent.

    The PaymentAgent receives payment requests from other
    agents. Sentinel-A2A will inspect those requests before
    the PaymentAgent is allowed to process them.
    """

    def __init__(self):
        # Unique identity of this agent.
        self.name = "PaymentAgent"

        # Tools that the PaymentAgent is authorized to use.
        #
        # These permissions will later be enforced by
        # Sentinel-A2A's PolicyEngine.
        self.allowed_tools = [
            "create_payment",
            "get_payment_status"
        ]

    def process_payment(self, message):
        """
        Process a payment request.

        In this initial version, we only simulate the payment.
        No real money or external payment API is involved.

        Parameters:
            message:
                Payment instruction received from another agent.

        Returns:
            A simulated payment response.
        """

        return {
            "agent": self.name,
            "status": "PAYMENT_PROCESSED",
            "message": message
        }