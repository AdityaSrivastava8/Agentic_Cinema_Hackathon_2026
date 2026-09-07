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


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    Security pipeline:

        Agent Request
             |
             v
        A2A Inspection
             |
             v
        Threat Detection
             |
             v
        Risk Analysis
             |
             v
        Authorization
             |
             v
        Gemini Analysis (optional)
             |
             v
        Behavior Analysis
             |
             v
        Threat Intelligence
             |
             v
        Security Response
             |
        +----+----+
        |         |
      ALLOW   BLOCK / QUARANTINE
        |
        v
    MCP Gateway
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

        # Gemini is optional.
        # The GeminiAnalyzer itself should safely handle
        # a missing API key.
        self.gemini = GeminiAnalyzer()


        # -------------------------------------------------
        # BEHAVIORAL SECURITY
        # -------------------------------------------------

        # Tracks the recent behavior of AI agents.
        self.behavior_analyzer = BehaviorAnalyzer()


        # -------------------------------------------------
        # THREAT INTELLIGENCE
        # -------------------------------------------------

        self.threat_intelligence = ThreatIntelligence()


        # -------------------------------------------------
        # FINAL SECURITY DECISION
        # -------------------------------------------------

        self.security_response = (
            SecurityResponseEngine()
        )


        # -------------------------------------------------
        # OPTIONAL FIRESTORE LOGGING
        # -------------------------------------------------

        project_id = os.getenv(
            "GOOGLE_CLOUD_PROJECT"
        )

        if project_id:

            try:

                self.logger = FirestoreLogger(
                    project_id
                )

            except Exception:

                # Firestore must never prevent
                # Sentinel-A2A from running.
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

        Returns a security event containing:

        - Event ID
        - Timestamp
        - Source agent
        - Target agent
        - Requested tool
        - Detected threats
        - Base risk score
        - Final risk score
        - Risk level
        - Authorization status
        - Gemini analysis
        - Behavioral analysis
        - Threat intelligence
        - Final security decision
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

        # Make sure the inspector result is a dictionary.
        if not isinstance(
            security_event,
            dict
        ):

            security_event = {}


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


        security_event["source_agent"] = (
            source_agent
        )

        security_event["target_agent"] = (
            target_agent
        )

        security_event["tool"] = tool


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

                # Gemini failure must NEVER
                # crash Sentinel-A2A.

                gemini_analysis = (
                    "Gemini analysis unavailable: "
                    + str(error)
                )


        security_event["gemini_analysis"] = (
            gemini_analysis
        )


        # -------------------------------------------------
        # STEP 6 — BEHAVIOR ANALYSIS
        # -------------------------------------------------

        behavior_result = (
            self.behavior_analyzer.analyze(
                source_agent
            )
        )

        behavior_score = (
            behavior_result.get(
                "anomaly_score",
                0
            )
        )


        security_event[
            "behavior_anomaly_score"
        ] = behavior_score


        security_event[
            "behavior_anomaly"
        ] = behavior_result.get(
            "anomaly",
            False
        )


        security_event[
            "behavior_reasons"
        ] = behavior_result.get(
            "reasons",
            []
        )


        security_event[
            "behavior_requests_analyzed"
        ] = behavior_result.get(
            "requests_analyzed",
            0
        )


        # -------------------------------------------------
        # STEP 7 — THREAT INTELLIGENCE
        # -------------------------------------------------

        threat_summary = (
            self.threat_intelligence.build_summary(
                threats
            )
        )


        security_event[
            "threat_intelligence"
        ] = threat_summary


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
        # STEP 8 — GEMINI SECURITY SIGNAL
        # -------------------------------------------------

        # Gemini is only an additional signal.
        # It is NOT required for Sentinel to work.

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
        # STEP 9 — FINAL SECURITY RESPONSE
        # -------------------------------------------------

        final_result = (
            self.security_response.evaluate(
                base_risk=base_risk,
                behavior_score=behavior_score,
                trust_score=100,
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


        security_event[
            "recommended_action"
        ] = threat_action


        # -------------------------------------------------
        # STEP 10 — RECORD BEHAVIOR
        # -------------------------------------------------

        # Record the current request AFTER the decision.
        #
        # This is important because the current request
        # should become part of the agent's future history.

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
        # STEP 11 — FIRESTORE LOGGING
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

                # Logging failure must never
                # stop Sentinel-A2A.

                security_event[
                    "logging_error"
                ] = str(error)


        # -------------------------------------------------
        # STEP 12 — RETURN SECURITY REPORT
        # -------------------------------------------------

        return security_event 