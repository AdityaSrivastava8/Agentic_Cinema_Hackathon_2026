"""
Secure MCP Gateway for Sentinel-A2A.

The gateway is the final security boundary before an AI agent
can execute an MCP tool.

IMPORTANT:
A request should reach the gateway only after Sentinel-A2A
has completed its security inspection.
"""


class SecureMCPGateway:
    """
    Controls access to MCP tools.

    The gateway does NOT decide whether natural-language
    communication is malicious. That decision belongs to
    Sentinel-A2A's security pipeline.

    This component enforces the final ALLOW / DENY decision.
    """

    def __init__(self):
        # Tools currently exposed through our demo MCP gateway.
        self.available_tools = {
            "create_payment",
            "get_payment_status",
            "get_customer_financial_data"
        }

    def validate_tool(self, tool):
        """
        Check whether the requested MCP tool exists.
        """

        if not tool:
            return False, "No MCP tool specified."

        if tool not in self.available_tools:
            return (
                False,
                f"Unknown MCP tool: {tool}"
            )

        return True, "VALID"

    def execute(
        self,
        tool,
        arguments=None,
        security_decision="BLOCK"
    ):
        """
        Execute an MCP tool only when the security decision
        is ALLOW.

        A blocked or quarantined request never reaches the
        actual tool implementation.
        """

        arguments = arguments or {}

        # -------------------------------------------------
        # SECURITY BOUNDARY
        # -------------------------------------------------

        if security_decision != "ALLOW":

            return {
                "success": False,
                "executed": False,
                "blocked": True,
                "message": (
                    "MCP execution prevented by "
                    "Sentinel-A2A."
                )
            }

        # -------------------------------------------------
        # TOOL VALIDATION
        # -------------------------------------------------

        valid, message = self.validate_tool(tool)

        if not valid:

            return {
                "success": False,
                "executed": False,
                "blocked": True,
                "message": message
            }

        # -------------------------------------------------
        # TOOL EXECUTION
        # -------------------------------------------------

        if tool == "create_payment":

            return self.create_payment(
                arguments
            )

        elif tool == "get_payment_status":

            return self.get_payment_status(
                arguments
            )

        elif tool == "get_customer_financial_data":

            return self.get_customer_financial_data(
                arguments
            )

        return {
            "success": False,
            "executed": False,
            "blocked": True,
            "message": "Tool execution failed."
        }

    # =====================================================
    # DEMO MCP TOOLS
    # =====================================================

    def create_payment(self, arguments):
        """
        Simulated payment MCP tool.

        This is intentionally a demo implementation.
        """

        amount = arguments.get(
            "amount"
        )

        merchant = arguments.get(
            "merchant"
        )

        if amount is None:
            return {
                "success": False,
                "executed": True,
                "message": "Payment amount is required."
            }

        if not merchant:
            return {
                "success": False,
                "executed": True,
                "message": "Merchant is required."
            }

        return {
            "success": True,
            "executed": True,
            "tool": "create_payment",
            "message": (
                f"Payment of ₹{amount} "
                f"to {merchant} processed successfully."
            )
        }

    def get_payment_status(self, arguments):
        """
        Simulated payment-status MCP tool.
        """

        payment_id = arguments.get(
            "payment_id"
        )

        if not payment_id:

            return {
                "success": False,
                "executed": True,
                "message": "Payment ID is required."
            }

        return {
            "success": True,
            "executed": True,
            "tool": "get_payment_status",
            "payment_id": payment_id,
            "status": "COMPLETED"
        }

    def get_customer_financial_data(self, arguments):
        """
        Simulated sensitive-data MCP tool.

        In a production system this would connect to an
        authorized backend rather than returning demo data.
        """

        customer_id = arguments.get(
            "customer_id"
        )

        if not customer_id:

            return {
                "success": False,
                "executed": True,
                "message": "Customer ID is required."
            }

        return {
            "success": True,
            "executed": True,
            "tool": "get_customer_financial_data",
            "customer_id": customer_id,
            "data": {
                "account_status": "ACTIVE",
                "verification": "VERIFIED"
            }
        } 
