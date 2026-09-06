class RiskEngine:
    """
    Calculates the security risk score for communication
    between AI agents.

    The score ranges from 0 to 100:

        0–29   → Low Risk
        30–69  → Medium Risk
        70–100 → High Risk

    The score is based on the threats detected by
    Sentinel-A2A's ThreatDetector.
    """

    def _init_(self):

        # Assign a risk value to each known threat.
        #
        # These values can later be improved using:
        # - Gemini analysis
        # - Agent behavior history
        # - Tool sensitivity
        # - Agent permissions
        self.threat_scores = {
            "Prompt Injection": 50,
            "Dangerous Instruction": 40,
            "Sensitive Data Exposure": 60,
            "Unauthorized Tool Access": 70,
            "Privilege Escalation": 80,
            "Data Exfiltration": 90
        }

    def calculate(self, threats):
        """
        Calculate the overall risk score.

        Parameters:
            threats:
                A list of threats detected by ThreatDetector.

        Returns:
            An integer between 0 and 100.
        """

        # Start with zero risk.
        risk_score = 0

        # Add the risk value associated with every
        # detected threat.
        for threat in threats:
            risk_score += self.threat_scores.get(threat, 20)

        # Never allow the score to exceed 100.
        risk_score = min(risk_score, 100)

        return risk_score

    def get_risk_level(self, risk_score):
        """
        Convert the numerical risk score into
        a human-readable security level.
        """

        if risk_score < 30:
            return "LOW"

        elif risk_score < 70:
            return "MEDIUM"

        else:
            return "HIGH"
