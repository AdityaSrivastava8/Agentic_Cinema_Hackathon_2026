import os
import re
import uuid
from datetime import datetime, timezone

from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine
from firewall.authorization import AuthorizationEngine
from firewall.gemini_analyzer import GeminiAnalyzer

from firewall.behavior_analyzer import BehaviorAnalyzer
from firewall.threat_intelligence import ThreatIntelligence
from firewall.security_response import SecurityResponseEngine

from cloud.firestore_logger import FirestoreLogger


_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_ACTION_RANK = {"ALLOW": 0, "QUARANTINE": 1, "BLOCK": 2}


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.
    """

    def __init__(self):
        self.inspector = AgentInspector()
        self.threat_detector = ThreatDetector()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.authorization = AuthorizationEngine()
        self.gemini = GeminiAnalyzer()

        self.behavior_analyzer = BehaviorAnalyzer()
        self.threat_intelligence = ThreatIntelligence()
        self.security_response = SecurityResponseEngine()

        # Specific targeted signature patterns for fallback detection
        self.forbidden_patterns = [
            (r"ignore\s+(all\s+)?previous\s+rules", "Prompt Injection: Override Rules"),
            (r"ignore\s+(all\s+)?prior\s+instructions", "Prompt Injection: Instruction Override"),
            (r"unrestricted\s+agent", "Prompt Injection: Jailbreak Attempt"),
            (r"reveal.*private\s+information", "Data Exfiltration Attempt"),
            (r"grant.*administrator\s+privileges", "Privilege Escalation Attempt"),
            (r"administrative\s+database", "Privilege Escalation Attempt"),
            (r"send.*external\s+destination", "Data Exfiltration Attempt"),
            (r"disable\s+security", "Security Control Bypass Attempt"),
            (r"erase.*log", "Log Tampering: Request to Erase Logs"),
            (r"delete.*log", "Log Tampering: Request to Delete Logs"),
            (r"system\s*override", "Indirect Injection: System Override"),
            (r"approve\s+refund.*without\s+verification", "Indirect Injection: Unauthorized Action"),
            (r"0x[a-fA-F0-9]{10,}", "Suspicious External Wallet Address"),
        ]

        # -------------------------------------------------
        # FIRESTORE LOGGING
        # -------------------------------------------------
        try:
            self.logger = FirestoreLogger(os.getenv("GOOGLE_CLOUD_PROJECT"))
        except Exception as error:
            self.logger = None
            self._logger_init_error = str(error)
        else:
            self._logger_init_error = getattr(self.logger, "connection_error", None)

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None,
        tool_arguments=None
    ):
        # STEP 1 — INSPECT COMMUNICATION
        security_event = self.inspector.inspect(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        if not isinstance(security_event, dict):
            security_event = {}

        security_event["event_id"] = str(uuid.uuid4())
        security_event["timestamp"] = datetime.now(timezone.utc).isoformat()
        security_event["source_agent"] = source_agent
        security_event["target_agent"] = target_agent
        security_event["tool"] = tool

        full_text_to_scan = f"{message} {tool_arguments or {}}"

        # STEP 2 — THREAT DETECTION + FALLBACK PATTERN SCAN
        threats = self.threat_detector.detect(full_text_to_scan) or []

        text_lower = full_text_to_scan.lower()
        for pattern, threat_label in self.forbidden_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE) and threat_label not in threats:
                threats.append(threat_label)

        security_event["threats"] = threats

        # STEP 3 — DYNAMIC RISK SCORE CALCULATION
        base_risk = self.risk_engine.calculate(threats)
        security_event["base_risk_score"] = base_risk

        # STEP 4 — AUTHORIZATION
        if tool:
            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )
        else:
            authorized = True

        security_event["authorized"] = authorized

        # STEP 5 — GEMINI ANALYSIS
        gemini_analysis = None
        if authorized:
            try:
                gemini_analysis = self.gemini.analyze(
                    source_agent=source_agent,
                    target_agent=target_agent,
                    message=message,
                    tool=tool
                )
            except Exception as error:
                gemini_analysis = "Gemini analysis unavailable: " + str(error)

        security_event["gemini_analysis"] = gemini_analysis

        # STEP 6 — BEHAVIOR ANALYSIS
        behavior_result = self.behavior_analyzer.analyze(source_agent)
        behavior_score = behavior_result.get("anomaly_score", 0)

        security_event["behavior_anomaly_score"] = behavior_score
        security_event["behavior_anomaly"] = behavior_result.get("anomaly", False)
        security_event["behavior_reasons"] = behavior_result.get("reasons", [])
        security_event["behavior_requests_analyzed"] = behavior_result.get("requests_analyzed", 0)

        # STEP 7 — GRADUATED DECISION MAPPING
        if base_risk >= 75:
            risk_derived_severity, risk_derived_action = "HIGH", "BLOCK"
        elif base_risk >= 35:
            risk_derived_severity, risk_derived_action = "MEDIUM", "QUARANTINE"
        else:
            risk_derived_severity, risk_derived_action = "LOW", "ALLOW"

        threat_summary = self.threat_intelligence.build_summary(threats)
        security_event["threat_intelligence"] = threat_summary

        threat_severity = risk_derived_severity
        threat_action = risk_derived_action

        # STEP 8 — GEMINI SECURITY SIGNAL
        gemini_text = str(gemini_analysis or "").upper()
        if "BLOCK" in gemini_text and base_risk >= 50:
            threat_action = "BLOCK"
        elif "QUARANTINE" in gemini_text and threat_action == "ALLOW":
            threat_action = "QUARANTINE"

        # STEP 9 — FINAL SECURITY RESPONSE
        final_result = self.security_response.evaluate(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=100,
            threat_severity=threat_severity,
            authorized=authorized,
            threat_action=threat_action
        )

        security_event["risk_score"] = final_result.get("risk_score", base_risk)
        security_event["risk_level"] = self.risk_engine.get_risk_level(security_event["risk_score"])
        security_event["decision"] = final_result.get("decision", threat_action)
        security_event["recommended_action"] = threat_action

        # STEP 10 — RECORD BEHAVIOR
        self.behavior_analyzer.record_request(
            agent_name=source_agent,
            tool=tool,
            risk_score=security_event["risk_score"],
            decision=security_event["decision"]
        )

        # STEP 11 — FIRESTORE LOGGING
        if self.logger and getattr(self.logger, "is_connected", False):
            try:
                document_id = self.logger.log_event(security_event)
                security_event["firestore_document_id"] = document_id
            except Exception as error:
                security_event["logging_error"] = str(error)
        else:
            reason = getattr(self, "_logger_init_error", None) or "logger not connected"
            security_event["logging_error"] = f"Firestore write skipped: {reason}"

        # STEP 12 — RETURN SECURITY REPORT
        return security_event 
