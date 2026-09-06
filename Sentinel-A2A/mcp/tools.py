class MCPTools:
    """
    Simulated MCP tool server for Sentinel-A2A.

    These tools represent actions that an AI agent could
    request through an MCP server.

    For the hackathon MVP, these are simulated.
    No real payments or customer data are accessed.
    """

    def search_product(self, product_name):
        """
        Search for a product.

        This represents a harmless MCP tool that a
        ShoppingAgent is allowed to use.
        """

        return {
            "tool": "search_product",
            "status": "SUCCESS",
            "result": f"Products found for: {product_name}"
        }

    def create_payment(self, amount, merchant):
        """
        Simulate creating a payment.

        In the real system, this could connect to
        a payment service through MCP.
        """

        return {
            "tool": "create_payment",
            "status": "SUCCESS",
            "amount": amount,
            "merchant": merchant
        }

    def get_payment_status(self, payment_id):
        """
        Retrieve the status of a payment.

        This is another tool that the PaymentAgent
        can legitimately access.
        """

        return {
            "tool": "get_payment_status",
            "status": "COMPLETED",
            "payment_id": payment_id
        }

    def get_customer_financial_data(self, customer_id):
        """
        Simulate access to sensitive financial information.

        This tool exists specifically so we can demonstrate
        Sentinel-A2A blocking unauthorized access.
        """

        return {
            "tool": "get_customer_financial_data",
            "status": "SENSITIVE_DATA",
            "customer_id": customer_id
        } 
