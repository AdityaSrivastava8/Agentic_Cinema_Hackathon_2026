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
    Main security controller for Sentinel-A2A with authentic dynamic risk scoring.
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

        try:
            self.logger = FirestoreLogger(os.getenv("GOOGLE_CLOUD_PROJECT"))
        except Exception:
            self.logger = FirestoreLogger()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None,
        tool_arguments=None,
        allowed_tools=None
    ):
        # 1. INSPECT COMMUNICATION
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

        full_text_to_scan = f"{message} {tool_arguments or {}} {tool or ''}"

        # 2. THREAT DETECTION
        threats = self.threat_detector.detect(full_text_to_scan) or []

        # 3. AUTHORIZATION CHECK
        if tool:
            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )
            if allowed_tools is not None and tool not in allowed_tools:
                authorized = False
        else:
            authorized = True

        if not authorized:
            unauth_msg = "Unauthorized Tool Access"
            if unauth_msg not in threats:
                threats.append(unauth_msg)

        security_event["threats"] = threats
        security_event["authorized"] = authorized

        # 4. DYNAMIC RISK SCORE CALCULATION
        calculated_risk = self.risk_engine.calculate(threats)

        # 5. GEMINI & BEHAVIOR ANALYSIS
        gemini_analysis = None
        try:
            gemini_analysis = self.gemini.analyze(
                source_agent=source_agent,
                target_agent=target_agent,
                message=message,
                tool=tool
            )
        except Exception as error:
            gemini_analysis = f"Gemini analysis unavailable: {error}"

        security_event["gemini_analysis"] = gemini_analysis

        behavior_result = self.behavior_analyzer.analyze(source_agent)
        behavior_score = behavior_result.get("anomaly_score", 0)

        security_event["behavior_anomaly_score"] = behavior_score
        security_event["behavior_anomaly"] = behavior_result.get("anomaly", False)
        security_event["behavior_reasons"] = behavior_result.get("reasons", [])

        # 6. GRADUATED DECISION EVALUATION
        threat_summary = self.threat_intelligence.build_summary(threats)
        security_event["threat_intelligence"] = threat_summary

        # Assign decision boundaries directly based on calculated dynamic risk
        recommended_actions = [
            item.get("recommended_action")
            for item in threat_summary.get("details", [])
        ]
        if "BLOCK" in recommended_actions or calculated_risk >= 75:
            decision = "BLOCK"
        elif calculated_risk >= 35:
            decision = "QUARANTINE" if calculated_risk < 60 else "BLOCK"
        else:
            decision = "ALLOW"

        # Explicitly preserve calculated risk score without forced overrides
        security_event["base_risk_score"] = calculated_risk
        security_event["risk_score"] = calculated_risk
        security_event["risk_level"] = self.risk_engine.get_risk_level(calculated_risk)
        security_event["decision"] = decision

        # 7. LOG EVENT TO FIRESTORE
        if self.logger:
            try:
                doc_id = self.logger.log_event(security_event)
                security_event["firestore_document_id"] = doc_id
            except Exception:
                pass

        return security_event 
