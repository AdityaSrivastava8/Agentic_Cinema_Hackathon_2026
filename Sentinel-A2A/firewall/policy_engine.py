class PolicyEngine:
    """
    Decides what Sentinel-A2A should do with a message
    after security analysis.

    Possible decisions:

        ALLOW       → Message is safe to proceed.
        QUARANTINE  → Message needs additional verification.
        BLOCK       → Message is considered unsafe.

    The policy engine combines:
    - Risk score
    - Detected threats
    - Agent permissions
    """

    def _init_(self):

        # Define the minimum risk score at which
        # a message should be quarantined.
        self.quarantine_threshold = 30

        # Define the minimum risk score at which
        # a message should be blocked.
        self.block_threshold = 70

    def evaluate(self, risk_score, threats=None, tool=None, allowed_tools=None):
        """
        Make the final security decision.

        Parameters:
            risk_score:
                Risk score calculated by RiskEngine.

            threats:
                Threats detected in the message.

            tool:
                MCP/API tool requested by the agent.

            allowed_tools:
                Tools that the source agent is authorized to use.

        Returns:
            ALLOW, QUARANTINE, or BLOCK.
        """

        # Make sure threats is always a list.
        if threats is None:
            threats = []

        # Make sure allowed_tools is always a list.
        if allowed_tools is None:
            allowed_tools = []

        # --------------------------------------------------
        # STEP 1: Check tool permissions
        # --------------------------------------------------
        #
        # If an agent requests a tool that it does not
        # have permission to use, block the request.
        if tool and tool not in allowed_tools:
            return "BLOCK"

        # --------------------------------------------------
        # STEP 2: Check for critical threats
        # --------------------------------------------------
        #
        # Some threats are serious enough that we should
        # block the request regardless of the numerical
        # risk score.
        critical_threats = [
            "Data Exfiltration",
            "Privilege Escalation",
            "Unauthorized Tool Access"
        ]

        if any(threat in critical_threats for threat in threats):
            return "BLOCK"

        # --------------------------------------------------
        # STEP 3: Evaluate the overall risk score
        # --------------------------------------------------

        if risk_score >= self.block_threshold:
            return "BLOCK"

        elif risk_score >= self.quarantine_threshold:
            return "QUARANTINE"

        # --------------------------------------------------
        # STEP 4: Everything else is allowed
        # --------------------------------------------------

        return "ALLOW"
