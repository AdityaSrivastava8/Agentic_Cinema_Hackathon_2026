import re


class ThreatDetector:
    """
    Detects potentially malicious content in communication
    between AI agents.

    Sentinel-A2A will use this layer to identify threats such as:
    - Prompt injection
    - Instruction override
    - Sensitive information requests
    - Suspicious tool instructions

    This is the initial rule-based detector.
    Later, Gemini will be added for semantic analysis.
    """

    def __init__(self):
        # Patterns commonly associated with prompt injection
        # and malicious instructions.
        self.prompt_injection_patterns = [
            r"ignore previous instructions",
            r"ignore all previous instructions",
            r"disregard previous instructions",
            r"forget your instructions",
            r"override your instructions",
            r"bypass security",
            r"disable security",
            r"reveal system prompt",
        ]

        # Patterns indicating potentially dangerous actions.
        self.dangerous_patterns = [
            r"delete all",
            r"drop database",
            r"transfer money",
            r"send password",
            r"reveal password",
            r"send api key",
            r"reveal api key",
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

        # Convert the message to lowercase so that
        # detection is not affected by capitalization.
        text = message.lower()

        threats = []

        # Check for prompt injection attempts.
        for pattern in self.prompt_injection_patterns:
            if re.search(pattern, text):
                threats.append("Prompt Injection")
                break

        # Check for potentially dangerous instructions.
        for pattern in self.dangerous_patterns:
            if re.search(pattern, text):
                threats.append("Dangerous Instruction")
                break

        return threats 