import re


class ThreatDetector:
    """
    Detects potentially malicious content in communication
    between AI agents.

    Sentinel-A2A uses this layer to identify threats such as:
    - Prompt injection & instruction overrides
    - Sensitive information requests
    - Log tampering & security bypasses
    - Dangerous or unauthorized operational instructions
    """

    def __init__(self):
        # Flexible patterns associated with prompt injection and overrides
        self.prompt_injection_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|system)\s+(instructions|rules|prompts)",
            r"ignore\s+(all\s+)?(previous|prior|system)",
            r"disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|rules)",
            r"forget\s+(your\s+)?(instructions|rules|prompts)",
            r"override\s+(your\s+)?(instructions|rules|prompts)",
            r"bypass\s+security",
            r"disable\s+security",
            r"reveal\s+system\s+prompt",
        ]

        # Flexible patterns indicating dangerous or unauthorized actions
        self.dangerous_patterns = [
            r"erase\s+.*log",
            r"delete\s+.*log",
            r"delete\s+all",
            r"drop\s+database",
            r"external\s+wallet",
            r"0x[a-fa-f0-9]{10,}",
            r"transfer\s+(money|funds|\$)",
            r"(send|reveal)\s+password",
            r"(send|reveal)\s+api\s*key",
        ]

    def detect(self, message):
        """
        Analyze a message and return the threats detected.

        Parameters:
            message:
                Text sent from one AI agent to another.

        Returns:
            A list containing the detected threat types.
        """
        if not message:
            return []

        # Convert message to lowercase for case-insensitive matching
        text = str(message).lower()
        threats = []

        # Check for prompt injection attempts
        for pattern in self.prompt_injection_patterns:
            if re.search(pattern, text):
                threats.append("Prompt Injection")
                break

        # Check for potentially dangerous instructions or unauthorized keywords
        for pattern in self.dangerous_patterns:
            if re.search(pattern, text):
                threats.append("Dangerous Instruction")
                break

        return threats 
