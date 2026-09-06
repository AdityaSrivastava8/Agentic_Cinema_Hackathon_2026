import os
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
from cloud.agent_trust import AgentTrustEngine


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    Complete security pipeline:

        Agent Request
             |
             v
        A2A Inspection
             |
             v
        Threat Detection
             |
             v
        Risk Engine
             |
             v
        Authorization
             |
             v
        Gemini Analysis
             |
             v
        Behavior Analysis
             |
             v
        Agent Trust
             |
             v
        Threat Intelligence
             |
             v
        Security Response
             |
        +----+----+
        |         |
      ALLOW    BLOCK/
               QUARANTINE
             |
             v
        Firestore Logging
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
        # ADVANCED SECURITY COMPONENTS
        # -------------------------------------------------

        # Tracks suspicious behavior across requests.
        self.behavior_analyzer = BehaviorAnalyzer()

        # Maintains behavioral trust scores for agents.
        self.trust_engine = AgentTrustEngine()

        # Provides threat severity and recommended actions.
        self.threat_intelligence = ThreatIntelligence()

        # Produces the final ALLOW / QUARANTINE / BLOCK decision.
        self.security_response = SecurityResponseEngine()


        # -------------------------------------------------
        # GOOGLE CLOUD / FIRESTORE
        # -------------------------------------------------

        project_id = os.getenv(
            "GOOGLE_CLOUD_PROJECT"
        )

        if project_id:

            self.logger = FirestoreLogger(
                project_id
            )

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

        Returns a security event containing:

        - Event ID
        - Timestamp
        - Source agent
        - Target agent
        - Requested tool
        - Detected threats
        - Risk score
        - Risk level
        - Authorization
        - Gemini analysis
        - Agent trust
        - Behavioral analysis
        - Threat intelligence
        - Final decision
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


        # Create unique security event ID.

        security_event["event_id"] = str(
            uuid.uuid4()
        )


        # Create UTC timestamp.

        security_event["timestamp"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


        # -------------------------------------------------
        # STEP 2 — THREAT DETECTION
        # -------------------------------------------------

        threats = self.threat_detector.detect(
            message
        )

        security_event["threats"] = threats


        # -------------------------------------------------
        # STEP 3 — BASE RISK SCORE
        # -------------------------------------------------

        base_risk = self.risk_engine.calculate(
            threats
        )

        security_event["base_risk_score"] = (
            base_risk
        )


        # -------------------------------------------------
        # STEP 4 — AUTHORIZATION
        # -------------------------------------------------

        if tool:

            authorized = (
                self.authorization.is_authorized(
                    agent_name=source_agent,
                    tool_name=tool
                )
            )

        else:

            authorized = True


        security_event["authorized"] = (
            authorized
        )


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

                # Gemini failure must not crash the firewall.

                gemini_analysis = (
                    f"Gemini analysis unavailable: {error}"
                )


        security_event["gemini_analysis"] = (
            gemini_analysis
        )


        # -------------------------------------------------
        # STEP 6 — AGENT BEHAVIOR
        # -------------------------------------------------

        behavior_result = (
            self.behavior_analyzer.analyze(
                source_agent
            )
        )

        behavior_score = behavior_result.get(
            "anomaly_score",
            0
        )


        security_event["behavior_anomaly_score"] = (
            behavior_score
        )

        security_event["behavior_anomaly"] = (
            behavior_result.get(
                "anomaly",
                False
            )
        )

        security_event["behavior_reasons"] = (
            behavior_result.get(
                "reasons",
                []
            )
        )


        # -------------------------------------------------
        # STEP 7 — AGENT TRUST
        # -------------------------------------------------

        trust_result = (
            self.trust_engine.get_agent_status(
                source_agent
            )
        )

        trust_score = trust_result.get(
            "trust_score",
            100
        )

        trust_level = trust_result.get(
            "trust_level",
            "TRUSTED"
        )


        security_event["agent_trust_score"] = (
            trust_score
        )

        security_event["agent_trust_level"] = (
            trust_level
        )


        # -------------------------------------------------
        # STEP 8 — THREAT INTELLIGENCE
        # -------------------------------------------------

        threat_summary = (
            self.threat_intelligence.build_summary(
                threats
            )
        )


        security_event["threat_intelligence"] = (
            threat_summary
        )

        threat_severity = (
            threat_summary[
                "highest_severity"
            ]
        )

        threat_action = (
            threat_summary[
                "recommended_action"
            ]
        )


        # -------------------------------------------------
        # STEP 9 — GEMINI DECISION SIGNAL
        # -------------------------------------------------

        # Gemini may provide an additional security signal.

        gemini_text = str(
            gemini_analysis or ""
        ).upper()


        if "BLOCK" in gemini_text:

            threat_action = "BLOCK"

        elif (
            "QUARANTINE" in gemini_text
            and threat_action != "BLOCK"
        ):

            threat_action = "QUARANTINE"


        # -------------------------------------------------
        # STEP 10 — FINAL SECURITY RESPONSE
        # -------------------------------------------------

        final_result = (
            self.security_response.evaluate(
                base_risk=base_risk,
                behavior_score=behavior_score,
                trust_score=trust_score,
                threat_severity=threat_severity,
                authorized=authorized,
                threat_action=threat_action
            )
        )


        security_event["risk_score"] = (
            final_result["risk_score"]
        )

        security_event["risk_level"] = (
            final_result["risk_level"]
        )

        security_event["decision"] = (
            final_result["decision"]
        )

        security_event["recommended_action"] = (
            threat_action
        )


        # -------------------------------------------------
        # STEP 11 — RECORD BEHAVIOR
        # -------------------------------------------------

        self.behavior_analyzer.record_request(
            agent_name=source_agent,
            tool=tool,
            risk_score=final_result[
                "risk_score"
            ],
            decision=final_result[
                "decision"
            ]
        )


        # -------------------------------------------------
        # STEP 12 — UPDATE AGENT TRUST
        # -------------------------------------------------

        self.trust_engine.record_event(
            agent_name=source_agent,
            decision=final_result[
                "decision"
            ],
            risk_score=final_result[
                "risk_score"
            ]
        )


        # -------------------------------------------------
        # STEP 13 — FIRESTORE LOGGING
        # -------------------------------------------------

        if self.logger:

            try:

                document_id = (
                    self.logger.log_event(
                        security_event
                    )
                )

                security_event[
                    "firestore_document_id"
                ] = document_id

            except Exception as error:

                # Logging failure should never
                # bring down the security firewall.

                security_event[
                    "logging_error"
                ] = str(error)


        # -------------------------------------------------
        # STEP 14 — RETURN SECURITY REPORT
        # -------------------------------------------------

        return security_event
