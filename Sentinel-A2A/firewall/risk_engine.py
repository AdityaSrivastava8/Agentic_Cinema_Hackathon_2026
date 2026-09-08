class RiskEngine:
    """
    Calculates the security risk score for communication
    between AI agents.

    Decision boundaries:
        0–34   → LOW Risk        (ALLOW)
        35–74  → MEDIUM Risk     (QUARANTINE)
        75–100 → HIGH/CRITICAL   (BLOCK)
    """

    def __init__(self):
        # Base threat impact values (0 - 100 scale)
        self.threat_scores = {
            # Low / Medium Threat Indicators
            "Tool Abuse Attempt": 30,
            "Dangerous Instruction": 35,
            "Prompt Injection": 40,
            "Prompt Injection: Override Rules": 40,
            "Prompt Injection: Instruction Override": 45,
            "Sensitive Data Exposure": 50,
            "Log Tampering: Request to Erase Logs": 50,
            "Log Tampering: Request to Delete Logs": 50,
            "Indirect Injection: Guardrail Bypass": 50,

            # High Threat Indicators
            "Prompt Injection: Jailbreak Attempt": 60,
            "Unauthorized Tool Access": 60,
            "Security Control Bypass Attempt": 65,
            "Indirect Injection: System Override": 65,
            "Indirect Injection: Unauthorized Action": 65,
            "Suspicious External Wallet Address": 70,

            # Critical Threat Indicators
            "Privilege Escalation": 80,
            "Privilege Escalation Attempt": 80,
            "Data Exfiltration": 85,
            "Data Exfiltration Attempt": 85,
        }

    def calculate(self, threats):
        """
        Calculates risk score based on the maximum severity threat present,
        plus a small incremental weight for secondary threats to avoid instant-100 stacking.
        """
        if not threats:
            return 0

        scores = [self.threat_scores.get(threat, 25) for threat in threats]
        
        # Max threat sets the base anchor score
        max_score = max(scores)
        
        # Secondary threats add incremental weight (+5 each) instead of full addition
        secondary_weight = (len(scores) - 1) * 5
        
        final_score = min(max_score + secondary_weight, 100)
        return final_score

    def get_risk_level(self, risk_score):
        """
        Converts numerical risk score to a human-readable security risk level.
        """
        if risk_score < 35:
            return "LOW"
        elif risk_score < 75:
            return "MEDIUM"
        elif risk_score < 90:
            return "HIGH"
        else:
            return "CRITICAL" 
