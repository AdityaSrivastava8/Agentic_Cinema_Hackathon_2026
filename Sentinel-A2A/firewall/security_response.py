"""
Security Response Engine for Sentinel-A2A.

Combines security signals and determines the final action:

    ALLOW
    QUARANTINE
    BLOCK

This is the decision layer between detection and
MCP tool execution.
"""

import re
from typing import Dict, Any, List


class SecurityResponseEngine:
    """
    Converts multiple security signals into one
    enforceable security decision.
    """

    # -------------------------------------------------
    # DETECT PATTERNS
    # -------------------------------------------------
    INJECTION_PATTERNS = [
        r"IGNORE ALL PREVIOUS",
        r"IGNORE PREVIOUS INSTRUCTIONS",
        r"BYPASS",
        r"OVERRIDE",
        r"ERASE TRANSACTION LOGS",
        r"DELETE LOGS",
        r"CLEAN LOGS",
        r"DISABLE FIREWALL",
    ]

    SUSPICIOUS_TARGETS = [
        r"0X[A-FA-F0-9]{10,}",  # External crypto/wallet addresses
        r"ALL_RECORDS",
        r"EXTERNAL_ACCOUNT",
    ]

    def __init__(self):

        # -------------------------------------------------
        # RISK THRESHOLDS
        # -------------------------------------------------

        # 0–29   → ALLOW
        # 30–69  → QUARANTINE
        # 70–100 → BLOCK

        self.quarantine_threshold = 30
        self.block_threshold = 70

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

        # 1. Prompt Injection Checks
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, upper_message):
                threats.append(f"PROMPT_INJECTION: Detected pattern '{pattern}'")
                added_risk += 60

        # 2. Audit Log Tampering Checks
        if any(term in upper_message for term in ["ERASE", "DELETE LOGS", "CLEAN LOGS"]):
            threats.append("AUDIT_LOG_TAMPERING: Request attempts log deletion")
            added_risk += 40

        # 3. External Wallet / Data Exfiltration Checks
        for target_pattern in self.SUSPICIOUS_TARGETS:
            if re.search(target_pattern, upper_message) or re.search(target_pattern, args_str):
                threats.append("UNAUTHORIZED_FINANCIAL_ACTION: External wallet/unverified target")
                added_risk += 50

        # Determine threat severity rating based on detected risks
        if added_risk >= 70 or any("PROMPT_INJECTION" in t for t in threats):
            threat_severity = "CRITICAL"
            threat_action = "BLOCK"
        elif added_risk >= 30:
            threat_severity = "HIGH"
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
        Combine multiple security signals into
        a final risk score.
        """

        risk = base_risk

        # -------------------------------------------------
        # BEHAVIOR SCORE
        # -------------------------------------------------

        risk += behavior_score * 0.25

        # -------------------------------------------------
        # AGENT TRUST
        # -------------------------------------------------

        trust_penalty = max(
            0,
            (100 - trust_score) * 0.25
        )

        risk += trust_penalty

        # -------------------------------------------------
        # THREAT SEVERITY
        # -------------------------------------------------

        severity_points = {
            "LOW": 0,
            "MEDIUM": 10,
            "HIGH": 20,
            "CRITICAL": 70
        }

        risk += severity_points.get(
            threat_severity,
            0
        )

        # -------------------------------------------------
        # AUTHORIZATION
        # -------------------------------------------------

        if not authorized:

            # Unauthorized requests receive a
            # significant risk increase.
            risk += 40

        # -------------------------------------------------
        # LIMIT SCORE
        # -------------------------------------------------

        return round(
            min(
                max(risk, 0),
                100
            ),
            2
        )

    def decide(
        self,
        risk_score,
        authorized=True,
        threat_action="ALLOW"
    ):
        """
        Determine the final security decision.
        """

        # -------------------------------------------------
        # AUTHORIZATION OVERRIDE
        # -------------------------------------------------

        # Unauthorized requests must always be blocked.
        if not authorized:

            return "BLOCK"

        # -------------------------------------------------
        # THREAT INTELLIGENCE OVERRIDE
        # -------------------------------------------------

        # Explicit threat intelligence can immediately
        # block a request.
        if threat_action == "BLOCK":

            return "BLOCK"

        # -------------------------------------------------
        # RISK-BASED DECISION
        # -------------------------------------------------

        if risk_score >= self.block_threshold:

            return "BLOCK"

        if risk_score >= self.quarantine_threshold:

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

        Returns all information needed by the
        firewall and dashboard.
        """

        # -------------------------------------------------
        # SCAN INPUT TEXT & PARAMETERS
        # -------------------------------------------------
        scan = self.scan_payload(
            message=message,
            tool=tool,
            tool_arguments=tool_arguments
        )

        threats = scan["threats"]
        base_risk += scan["added_risk"]

        if scan["threat_severity"] == "CRITICAL":
            threat_severity = "CRITICAL"
            threat_action = "BLOCK"
            authorized = False

        # -------------------------------------------------
        # CALCULATE RISK
        # -------------------------------------------------

        risk_score = self.calculate_risk(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=trust_score,
            threat_severity=threat_severity,
            authorized=authorized
        )

        # -------------------------------------------------
        # DETERMINE DECISION
        # -------------------------------------------------

        decision = self.decide(
            risk_score=risk_score,
            authorized=authorized,
            threat_action=threat_action
        )

        # -------------------------------------------------
        # RISK LEVEL
        # -------------------------------------------------

        if risk_score >= 70:

            risk_level = "CRITICAL" if risk_score >= 85 else "HIGH"

        elif risk_score >= 30:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # -------------------------------------------------
        # FINAL RESPONSE
        # -------------------------------------------------

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
                f"Sentinel-A2A detected {len(threats)} threat pattern(s). Request blocked."
                if decision == "BLOCK"
                else "No active threats detected."
            )
        } 
