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

        # Specific signature patterns for threat classification
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

        try:
            self.logger = FirestoreLogger(os.getenv("GOOGLE_CLOUD_PROJECT"))
        except Exception as error:
            self.logger = FirestoreLogger()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None,
        tool_arguments=None
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

        # 2. THREAT DETECTION & PATTERN MATCHING
        threats = self.threat_detector.detect(full_text_to_scan) or []

        text_lower = full_text_to_scan.lower()
        for pattern, threat_label in self.forbidden_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE) and threat_label not in threats:
                threats.append(threat_label)

        # 3. AUTHORIZATION CHECK
        if tool:
            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )
        else:
            authorized = True

        if not authorized:
            unauth_msg = f"Unauthorized Tool Access Attempt: '{tool}'"
            if unauth_msg not in threats:
                threats.append(unauth_msg)

        security_event["threats"] = threats
        security_event["authorized"] = authorized

        # 4. AUTHENTIC DYNAMIC RISK SCORE CALCULATION
        # Calculate calculated base risk dynamically from threats detected
        base_risk = self.risk_engine.calculate(threats)

        # Add proportionate risk weight for authorization failure without hardcoding a forced 100
        if not authorized:
            base_risk = min(100, max(base_risk, 45))  # Tool abuse generates authentic medium/high risk score (~45-75 range)

        security_event["base_risk_score"] = base_risk

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

        # 6. GRADUATED DYNAMIC DECISION EVALUATION
        threat_summary = self.threat_intelligence.build_summary(threats)
        security_event["threat_intelligence"] = threat_summary

        if base_risk >= 75:
            threat_severity, threat_action = "CRITICAL", "BLOCK"
        elif base_risk >= 35:
            threat_severity, threat_action = "HIGH" if base_risk >= 50 else "MEDIUM", "QUARANTINE" if base_risk < 60 else "BLOCK"
        else:
            threat_severity, threat_action = "LOW", "ALLOW"

        # Evaluate final response using multi-factor signals (risk, behavior, trust, authorization)
        final_result = self.security_response.evaluate(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=100 if authorized else 40,
            threat_severity=threat_severity,
            authorized=authorized,
            threat_action=threat_action
        )

        security_event["risk_score"] = final_result.get("risk_score", base_risk)
        security_event["risk_level"] = self.risk_engine.get_risk_level(security_event["risk_score"])
        security_event["decision"] = final_result.get("decision", threat_action)

        # 7. LOG EVENT TO SESSION & FIRESTORE
        if self.logger:
            doc_id = self.logger.log_event(security_event)
            security_event["firestore_document_id"] = doc_id

        return security_event 
