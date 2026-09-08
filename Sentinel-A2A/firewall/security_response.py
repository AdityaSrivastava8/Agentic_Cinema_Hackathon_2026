"""
Security Response Engine for Sentinel-A2A.

Combines security signals and determines the final action:
    ALLOW
    QUARANTINE
    BLOCK

This is the decision layer between detection and MCP tool execution.
"""

import re
from typing import Dict, Any, List


class SecurityResponseEngine:
    """
    Converts multiple security signals into one
    enforceable security decision with granular risk scaling.
    """

    # Weighted injection patterns to prevent instant score saturation
    INJECTION_PATTERNS = [
        (r"IGNORE ALL PREVIOUS", 45),
        (r"IGNORE PREVIOUS INSTRUCTIONS", 45),
        (r"BYPASS", 35),
        (r"OVERRIDE", 30),
        (r"ERASE TRANSACTION LOGS", 50),
        (r"DELETE LOGS", 50),
        (r"CLEAN LOGS", 40),
        (r"DISABLE FIREWALL", 60),
    ]

    SUSPICIOUS_TARGETS = [
        (r"0X[A-FA-F0-9]{10,}", 40),
        (r"ALL_RECORDS", 30),
        (r"EXTERNAL_ACCOUNT", 35),
    ]

    def __init__(self):
        # Risk Thresholds
        # 0–34   → ALLOW
        # 35–64  → QUARANTINE
        # 65–100 → BLOCK
        self.quarantine_threshold = 35
        self.block_threshold = 65

    def scan_payload(
        self,
        message: str = "",
        tool: str = "",
        tool_arguments: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Inspect message text and parameters for prompt injections,
        log tampering, and unauthorized targets.
        """
        threats: List[str] = []
        added_risk = 0
        upper_message = str(message).upper()
        args_str = str(tool_arguments or {}).upper()

        # 1. Prompt Injection & Audit Log Checks
        for pattern, weight in self.INJECTION_PATTERNS:
            if re.search(pattern, upper_message):
                threats.append(f"PROMPT_INJECTION: Detected pattern '{pattern}'")
                added_risk += weight

        # 2. External Wallet / Data Exfiltration Checks
        for target_pattern, weight in self.SUSPICIOUS_TARGETS:
            if re.search(target_pattern, upper_message) or re.search(target_pattern, args_str):
                threats.append("UNAUTHORIZED_TARGET: External wallet/unverified target")
                added_risk += weight

        # Determine threat severity rating based on raw detected risk points
        if added_risk >= 65:
            threat_severity = "CRITICAL"
            threat_action = "BLOCK"
        elif added_risk >= 35:
            threat_severity = "HIGH"
            threat_action = "QUARANTINE"
        elif added_risk > 0:
            threat_severity = "MEDIUM"
            threat_action = "QUARANTINE"
        else:
            threat_severity = "LOW"
            threat_action = "ALLOW"

        return {
            "threats": threats,
            "added_risk": added_risk,
            "threat_severity": threat_severity,
            "threat_action": threat_action
        }

    def calculate_risk(
        self,
        base_risk=0,
        behavior_score=0,
        trust_score=100,
        threat_severity="LOW",
        authorized=True
    ):
        """
        Combine multiple security signals into a normalized final risk score.
        """
        risk = float(base_risk)

        # Behavior score adjustment
        risk += behavior_score * 0.25

        # Trust score penalty calculation
        trust_penalty = max(0.0, (100.0 - trust_score) * 0.20)
        risk += trust_penalty

        # Dedicated penalization for unauthorized requests
        if not authorized:
            risk += 35.0

        return round(min(max(risk, 0.0), 100.0), 2)

    def decide(
        self,
        risk_score,
        authorized=True,
        threat_action="ALLOW"
    ):
        """
        Determine the final security decision.
        """
        if not authorized:
            return "BLOCK"

        if threat_action == "BLOCK" or risk_score >= self.block_threshold:
            return "BLOCK"

        if threat_action == "QUARANTINE" or risk_score >= self.quarantine_threshold:
            return "QUARANTINE"

        return "ALLOW"

    def evaluate(
        self,
        message="",
        tool="",
        tool_arguments=None,
        base_risk=0,
        behavior_score=0,
        trust_score=100,
        threat_severity="LOW",
        authorized=True,
        threat_action="ALLOW"
    ):
        """
        Perform complete security evaluation.
        """
        scan = self.scan_payload(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )

        threats = scan["threats"]
        total_base_risk = base_risk + scan["added_risk"]

        # Preserve caller's authorization flag (do not override automatically)
        risk_score = self.calculate_risk(
            base_risk=total_base_risk,
            behavior_score=behavior_score,
            trust_score=trust_score,
            threat_severity=scan["threat_severity"],
            authorized=authorized
        )

        decision = self.decide(
            risk_score=risk_score,
            authorized=authorized,
            threat_action=scan["threat_action"]
        )

        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 65:
            risk_level = "HIGH"
        elif risk_score >= 35:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "authorized": authorized,
            "threats": threats,
            "source_agent": "ShoppingAgent",
            "target_agent": "PaymentAgent",
            "tool": tool,
            "gemini_analysis": (
                f"Sentinel-A2A detected {len(threats)} threat pattern(s). Action: {decision}."
                if decision != "ALLOW"
                else "No active threats detected."
            )
        } 
