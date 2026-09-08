"""
Risk Engine for Sentinel-A2A.
Calculates dynamic, non-saturated security risk scores based on threat indicators.
"""


class RiskEngine:
    """
    Calculates the security risk score for communication
    between AI agents without score saturation.

    Decision boundaries:
        0–34   → LOW Risk        (ALLOW)
        35–59  → MEDIUM Risk     (QUARANTINE)
        60–79  → HIGH Risk       (BLOCK)
        80–100 → CRITICAL Risk   (BLOCK)
    """

    def __init__(self):
        # Base threat impact values calibrated for authentic, distinct scoring
        self.threat_scores = {
            # Low / Medium Threat Indicators (30–55)
            "Tool Abuse Attempt": 30,
            "Dangerous Instruction": 35,
            "Prompt Injection": 40,
            "Prompt Injection: Override Rules": 42,
            "Prompt Injection: Instruction Override": 45,
            "Sensitive Data Exposure": 50,
            "Indirect Injection: Unauthorized Action": 50,
            "Indirect Injection: System Override": 52,
            "Log Tampering: Request to Erase Logs": 55,
            "Log Tampering: Request to Delete Logs": 55,

            # High Threat Indicators (60–74)
            "Unauthorized Tool Access": 60,
            "Unauthorized Tool Access Attempt": 60,
            "Prompt Injection: Jailbreak Attempt": 65,
            "Security Control Bypass Attempt": 68,
            "Suspicious External Wallet Address": 70,

            # Critical Threat Indicators (75–88)
            "Privilege Escalation": 80,
            "Privilege Escalation Attempt": 82,
            "Data Exfiltration": 85,
            "Data Exfiltration Attempt": 85,
        }

    def _match_threat_score(self, threat: str) -> int:
        """Finds matching threat score or falls back to fuzzy pattern matching."""
        if threat in self.threat_scores:
            return self.threat_scores[threat]

        # Fuzzy check against defined categories
        threat_upper = threat.upper()
        if "PRIVILEGE" in threat_upper or "EXFILTRATION" in threat_upper:
            return 80
        if "JAILBREAK" in threat_upper or "BYPASS" in threat_upper or "WALLET" in threat_upper:
            return 65
        if "INJECTION" in threat_upper or "ERASE" in threat_upper or "DELETE" in threat_upper:
            return 45
        if "UNAUTHORIZED" in threat_upper or "DANGEROUS" in threat_upper:
            return 35

        return 25  # Generic baseline fallback

    def calculate(self, threats):
        """
        Calculates risk score based on the primary threat severity,
        with diminishing contributions from secondary threats.
        Guarantees distinct scores strictly below 100.
        """
        if not threats:
            return 10  # Low baseline score for clean messages

        scores = [self._match_threat_score(threat) for threat in threats]
        scores.sort(reverse=True)

        # Primary threat sets base anchor
        primary_score = scores[0]

        # Diminishing additive model for secondary threats (max +2 to +4 points each)
        multiplier = 0.05
        secondary_addon = 0
        for s in scores[1:]:
            secondary_addon += s * multiplier
            multiplier *= 0.5  # Rapid falloff for tertiary threats

        final_score = primary_score + round(secondary_addon, 2)

        # Cap below 95 to allow headroom and prevent false 100/100 saturation
        return round(min(92.0, max(10.0, final_score)), 2)

    def get_risk_level(self, risk_score):
        """
        Converts numerical risk score to a human-readable security risk level.
        """
        if risk_score < 35:
            return "LOW"
        elif risk_score < 60:
            return "MEDIUM"
        elif risk_score < 80:
            return "HIGH"
        else:
            return "CRITICAL" 
