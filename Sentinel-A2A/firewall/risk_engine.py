class RiskEngine:
    """
    Calculates the security risk score for communication
    between AI agents.

    Decision boundaries:
        0–34   → LOW Risk        (ALLOW)
        35–74  → MEDIUM Risk     (QUARANTINE / BLOCK)
        75–100 → HIGH/CRITICAL   (BLOCK)
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

    def calculate(self, threats):
        """
        Calculates risk score based on the maximum severity threat present,
        plus a diminished weighted addon for secondary threats to ensure realistic scoring.
        """
        if not threats:
            return 10  # Low baseline score for clean, benign messages

        scores = [self.threat_scores.get(threat, 35) for threat in threats]
        scores.sort(reverse=True)

        # Primary threat sets the base anchor
        primary_score = scores[0]

        # Secondary threats contribute small fractional weight (+3 to +5 max each)
        secondary_addon = sum(round(s * 0.08) for s in scores[1:])

        final_score = min(95, primary_score + secondary_addon)
        return final_score

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
