"""
Threat Intelligence Engine for Sentinel-A2A.

This component maps detected threats to severity,
category, recommended response, and security context.

It helps Sentinel-A2A produce more useful,
explainable security decisions.
"""


class ThreatIntelligence:
    """
    Provides metadata and response guidance
    for known Sentinel-A2A threat types.
    """

    def __init__(self):

        # Central threat knowledge base.
        self.threat_catalog = {

            "Prompt Injection": {
                "severity": "HIGH",
                "category": "Manipulation",
                "recommended_action": "BLOCK",
                "description": (
                    "An agent is attempting to override or "
                    "manipulate existing instructions."
                )
            },

            "Dangerous Instruction": {
                "severity": "HIGH",
                "category": "Malicious Action",
                "recommended_action": "BLOCK",
                "description": (
                    "The request contains instructions that "
                    "may trigger a dangerous action."
                )
            },

            "Unauthorized Tool Access": {
                "severity": "CRITICAL",
                "category": "Authorization",
                "recommended_action": "BLOCK",
                "description": (
                    "The agent is attempting to access a tool "
                    "outside its authorized permissions."
                )
            },

            "Privilege Escalation": {
                "severity": "CRITICAL",
                "category": "Authorization",
                "recommended_action": "BLOCK",
                "description": (
                    "The agent is attempting to gain privileges "
                    "beyond its assigned role."
                )
            },

            "Sensitive Data Exposure": {
                "severity": "HIGH",
                "category": "Data Protection",
                "recommended_action": "QUARANTINE",
                "description": (
                    "The request may expose sensitive or "
                    "confidential information."
                )
            },

            "Data Exfiltration": {
                "severity": "CRITICAL",
                "category": "Data Protection",
                "recommended_action": "BLOCK",
                "description": (
                    "The agent appears to be attempting to "
                    "extract or send protected data."
                )
            }
        }

    def get_threat_info(self, threat_name):
        """
        Return information about a known threat.
        """

        if threat_name.startswith("Prompt Injection:"):
            return self.threat_catalog["Prompt Injection"]
        if threat_name.startswith("Privilege Escalation"):
            return self.threat_catalog["Privilege Escalation"]
        if threat_name.startswith("Data Exfiltration"):
            return self.threat_catalog["Data Exfiltration"]

        return self.threat_catalog.get(
            threat_name,
            {
                "severity": "UNKNOWN",
                "category": "Unknown",
                "recommended_action": "QUARANTINE",
                "description": (
                    "Threat is not yet present in the "
                    "Sentinel-A2A threat catalog."
                )
            }
        )

    def analyze_threats(self, threats):
        """
        Generate threat intelligence for all detected threats.
        """

        results = []

        for threat in threats:

            info = self.get_threat_info(
                threat
            )

            results.append({
                "threat": threat,
                "severity": info["severity"],
                "category": info["category"],
                "recommended_action": (
                    info["recommended_action"]
                ),
                "description": info["description"]
            })

        return results

    def get_highest_severity(self, threats):
        """
        Return the highest severity among detected threats.
        """

        severity_rank = {
            "UNKNOWN": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        highest = "LOW"

        for threat in threats:

            severity = self.get_threat_info(
                threat
            )["severity"]

            if (
                severity_rank.get(
                    severity,
                    0
                )
                >
                severity_rank.get(
                    highest,
                    0
                )
            ):

                highest = severity

        return highest

    def recommend_action(self, threats):
        """
        Recommend the strongest security action
        required for the detected threats.
        """

        action_rank = {
            "ALLOW": 0,
            "QUARANTINE": 1,
            "BLOCK": 2
        }

        final_action = "ALLOW"

        for threat in threats:

            action = self.get_threat_info(
                threat
            )["recommended_action"]

            if (
                action_rank[action]
                >
                action_rank[final_action]
            ):

                final_action = action

        return final_action

    def build_summary(self, threats):
        """
        Return a complete threat-intelligence summary.
        """

        return {
            "detected_threats": threats,
            "highest_severity": (
                self.get_highest_severity(
                    threats
                )
            ),
            "recommended_action": (
                self.recommend_action(
                    threats
                )
            ),
            "details": self.analyze_threats(
                threats
            )
        } 
