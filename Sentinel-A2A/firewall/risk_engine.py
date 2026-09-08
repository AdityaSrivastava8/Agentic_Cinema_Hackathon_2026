class RiskEngine:
    """
    Calculates the security risk score for communication
    between AI agents.

    The score ranges from 0 to 100:

        0–29   → Low Risk
        30–69  → Medium Risk
        70–100 → High Risk

    The score is based on the threats detected by
    Sentinel-A2A's ThreatDetector and by SentinelA2A's own
    fallback signature scan.
    """

    def __init__(self):

        # Assign a risk value to each known threat label.
        # Covers both ThreatDetector's coarse categories and
        # SentinelA2A's more specific fallback signature labels,
        # so every distinct threat contributes a meaningfully
        # different amount instead of collapsing to one score.
        self.threat_scores = {
            # ---- ThreatDetector labels ----
            "Prompt Injection": 55,
            "Dangerous Instruction": 40,
            "Sensitive Data Exposure": 60,
            "Unauthorized Tool Access": 65,
            "Privilege Escalation": 80,
            "Data Exfiltration": 85,

            # ---- SentinelA2A fallback signature labels ----
            "Prompt Injection: Override Rules": 55,
            "Prompt Injection: Instruction Override": 55,
            "Prompt Injection: Jailbreak Attempt": 60,
            "Data Exfiltration Attempt": 80,
            "Privilege Escalation Attempt": 75,
            "Tool Abuse Attempt": 45,
            "Security Control Bypass Attempt": 70,
            "Log Tampering: Request to Erase Logs": 65,
            "Log Tampering: Request to Delete Logs": 65,
            "Indirect Injection: System Override": 70,
            "Indirect Injection: Unauthorized Action": 65,
            "Indirect Injection: Guardrail Bypass": 65,
            "Suspicious External Wallet Address": 75,
        }

    def calculate(self, threats):
        """
        Calculate the overall risk score.

        Parameters:
            threats:
                A list of threats detected by ThreatDetector
                and/or SentinelA2A's fallback signature scan.

        Returns:
            An integer/float between 0 and 100.
        """

        # Start with zero risk.
        risk_score = 0

        # Add the risk value associated with every
        # detected threat. Unknown/unmapped labels still
        # contribute a moderate default instead of being
        # silently under-counted.
        for threat in threats:
            risk_score += self.threat_scores.get(threat, 30)

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
