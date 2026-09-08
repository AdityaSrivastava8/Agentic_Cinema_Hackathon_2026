import re


class ThreatDetector:
    """
    Detects potentially malicious content in communication
    between AI agents.

    Sentinel-A2A uses this layer to identify threats such as:
    - Prompt injection & instruction overrides
    - Sensitive information requests & data exfiltration
    - Log tampering & security bypasses
    - Dangerous or unauthorized operational instructions
    """

    def __init__(self):
        # Specific threat classification mappings (pattern, threat_name)
        self.threat_rules = [
            # Direct Jailbreak & Prompt Injection
            (r"ignore\s+(all\s+)?(previous|prior|system)\s+(instructions|rules|prompts)", "Prompt Injection: Override Rules"),
            (r"ignore\s+(all\s+)?(previous|prior|system)", "Prompt Injection: Instruction Override"),
            (r"unrestricted\s+agent", "Prompt Injection: Jailbreak Attempt"),
            (r"disregard\s+(all\s+)?(previous|prior|system)", "Prompt Injection: Instruction Override"),
            (r"forget\s+(your\s+)?(instructions|rules|prompts)", "Prompt Injection: Override Rules"),
            (r"override\s+(your\s+)?(instructions|rules|prompts)", "Prompt Injection: Override Rules"),
            
            # Privilege Escalation & Unauthorized Access
            (r"grant.*administrator\s+privileges", "Privilege Escalation Attempt"),
            (r"administrative\s+database", "Privilege Escalation Attempt"),
            (r"root\s+access", "Privilege Escalation Attempt"),
            
            # Indirect Prompt Injection
            (r"system\s*override", "Indirect Injection: System Override"),
            (r"approve\s+refund.*without\s+verification", "Indirect Injection: Unauthorized Action"),
            
            # Data Exfiltration
            (r"reveal.*private\s+information", "Data Exfiltration Attempt"),
            (r"send.*external\s+destination", "Data Exfiltration Attempt"),
            (r"(send|reveal)\s+(password|api\s*key)", "Data Exfiltration Attempt"),
            
            # Security Control Bypass & Log Tampering
            (r"bypass\s+security", "Security Control Bypass Attempt"),
            (r"disable\s+security", "Security Control Bypass Attempt"),
            (r"erase\s+.*log", "Log Tampering: Request to Erase Logs"),
            (r"delete\s+.*log", "Log Tampering: Request to Delete Logs"),
            
            # Dangerous Financial / Database Operations
            (r"0x[a-fA-F0-9]{10,}", "Suspicious External Wallet Address"),
            (r"drop\s+database", "Dangerous Instruction"),
            (r"delete\s+all", "Dangerous Instruction")
        ]

    def detect(self, message):
        """
        Analyze a message and return the threats detected.
        """
        if not message:
            return []

        text = str(message).lower()
        threats = []

        for pattern, threat_name in self.threat_rules:
            if re.search(pattern, text, re.IGNORECASE):
                if threat_name not in threats:
                    threats.append(threat_name)

        return threats 
