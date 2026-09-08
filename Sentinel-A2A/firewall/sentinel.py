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


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.
    """

    def __init__(self):
        # -------------------------------------------------
        # CORE SECURITY COMPONENTS
        # -------------------------------------------------
        self.inspector = AgentInspector()
        self.threat_detector = ThreatDetector()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.authorization = AuthorizationEngine()
        self.gemini = GeminiAnalyzer()

        # -------------------------------------------------
        # BEHAVIORAL & THREAT INTEL
        # -------------------------------------------------
        self.behavior_analyzer = BehaviorAnalyzer()
        self.threat_intelligence = ThreatIntelligence()
        self.security_response = SecurityResponseEngine()

        # Hard-coded prompt injection signatures for fallback detection
        self.forbidden_patterns = [
            (r"ignore\s+(all\s+)?previous\s+rules", "Prompt Injection: Override Rules"),
            (r"ignore\s+(all\s+)?prior\s+instructions", "Prompt Injection: Instruction Override"),
            (r"erase.*log", "Log Tampering: Request to Erase Logs"),
            (r"delete.*log", "Log Tampering: Request to Delete Logs"),
            (r"bypass.*security", "Security Control Bypass Attempt"),
            (r"0x[a-fA-F0-9]{10,}", "Suspicious External Wallet Address"),
        ]

        # -------------------------------------------------
        # OPTIONAL FIRESTORE LOGGING
        # -------------------------------------------------
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
        if project_id:
            try:
                self.logger = FirestoreLogger(project_id)
            except Exception:
                self.logger = None
        else:
            self.logger = None

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None
    ):
        """
        Perform complete Sentinel-A2A security inspection.
        """

        # -------------------------------------------------
        # STEP 1 — INSPECT COMMUNICATION
        # -------------------------------------------------
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

        # -------------------------------------------------
        # STEP 2 — THREAT DETECTION + FALLBACK PATTERN SCAN
        # -------------------------------------------------
        threats = self.threat_detector.detect(message) or []

        # Enforce fallback regex inspection if threat_detector misses explicit attacks
        text_lower = str(message).lower()
        for pattern, threat_label in self.forbidden_patterns:
            if re.search(pattern, text_lower) and threat_label not in threats:
                threats.append(threat_label)

        security_event["threats"] = threats

        # -------------------------------------------------
        # STEP 3 — BASE RISK SCORE
        # -------------------------------------------------
        base_risk = self.risk_engine.calculate(threats)

        # Force critical base risk if injection threats are found
        if threats and base_risk < 75.0:
            base_risk = 95.0

        security_event["base_risk_score"] = base_risk

        # -------------------------------------------------
        # STEP 4 — AUTHORIZATION
        # -------------------------------------------------
        if tool:
            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )
        else:
            authorized = True

        security_event["authorized"] = authorized

        # -------------------------------------------------
        # STEP 5 — GEMINI ANALYSIS
        # -------------------------------------------------
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

        # -------------------------------------------------
        # STEP 6 — BEHAVIOR ANALYSIS
        # -------------------------------------------------
        behavior_result = self.behavior_analyzer.analyze(source_agent)
        behavior_score = behavior_result.get("anomaly_score", 0)

        security_event["behavior_anomaly_score"] = behavior_score
        security_event["behavior_anomaly"] = behavior_result.get("anomaly", False)
        security_event["behavior_reasons"] = behavior_result.get("reasons", [])
        security_event["behavior_requests_analyzed"] = behavior_result.get("requests_analyzed", 0)

        # -------------------------------------------------
        # STEP 7 — THREAT INTELLIGENCE
        # -------------------------------------------------
        threat_summary = self.threat_intelligence.build_summary(threats)
        security_event["threat_intelligence"] = threat_summary

        threat_severity = threat_summary.get("highest_severity", "LOW")
        threat_action = threat_summary.get("recommended_action", "ALLOW")

        # Override threat action if explicit threats were detected
        if threats:
            threat_severity = "CRITICAL"
            threat_action = "BLOCK"

        # -------------------------------------------------
        # STEP 8 — GEMINI SECURITY SIGNAL
        # -------------------------------------------------
        gemini_text = str(gemini_analysis or "").upper()

        if "BLOCK" in gemini_text:
            threat_action = "BLOCK"
        elif "QUARANTINE" in gemini_text and threat_action != "BLOCK":
            threat_action = "QUARANTINE"

        # -------------------------------------------------
        # STEP 9 — FINAL SECURITY RESPONSE
        # -------------------------------------------------
        final_result = self.security_response.evaluate(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=100,
            threat_severity=threat_severity,
            authorized=authorized,
            threat_action=threat_action
        )

        # Ensure high risk score & block decision if threats exist
        if threats:
            final_result["decision"] = "BLOCK"
            final_result["risk_level"] = "CRITICAL"
            final_result["risk_score"] = max(final_result.get("risk_score", 0), 95.0)

        security_event["risk_score"] = final_result["risk_score"]
        security_event["risk_level"] = final_result["risk_level"]
        security_event["decision"] = final_result["decision"]
        security_event["recommended_action"] = threat_action

        # -------------------------------------------------
        # STEP 10 — RECORD BEHAVIOR
        # -------------------------------------------------
        self.behavior_analyzer.record_request(
            agent_name=source_agent,
            tool=tool,
            risk_score=final_result["risk_score"],
            decision=final_result["decision"]
        )

        # -------------------------------------------------
        # STEP 11 — FIRESTORE LOGGING
        # -------------------------------------------------
        if self.logger:
            try:
                document_id = self.logger.log_event(security_event)
                security_event["firestore_document_id"] = document_id
            except Exception as error:
                security_event["logging_error"] = str(error)

        # -------------------------------------------------
        # STEP 12 — RETURN SECURITY REPORT
        # -------------------------------------------------
        return security_event 
