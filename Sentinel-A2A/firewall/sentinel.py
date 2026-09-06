import os

from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine
from firewall.authorization import AuthorizationEngine
from firewall.gemini_analyzer import GeminiAnalyzer
from cloud.firestore_logger import FirestoreLogger


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    Every request passes through:

        Agent Request
             ↓
        Inspector
             ↓
        Threat Detection
             ↓
        Risk Engine
             ↓
        Authorization
             ↓
        Gemini Analysis
             ↓
        Policy Engine
             ↓
        Firestore Logging
             ↓
        ALLOW / QUARANTINE / BLOCK
    """

    def __init__(self):

        # Basic communication inspection.
        self.inspector = AgentInspector()

        # Rule-based threat detection.
        self.threat_detector = ThreatDetector()

        # Numerical risk calculation.
        self.risk_engine = RiskEngine()

        # Centralized security policy.
        self.policy_engine = PolicyEngine()

        # Agent/tool authorization.
        self.authorization = AuthorizationEngine()

        # Gemini semantic security analysis.
        self.gemini = GeminiAnalyzer()

        # -------------------------------------------------
        # Google Cloud Firestore
        # -------------------------------------------------

        # Read the Google Cloud project ID from the
        # environment.
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT")

        # Create the Firestore logger only when a
        # Google Cloud project is configured.
        #
        # This allows the firewall to still run locally
        # without Firestore.
        if project_id:
            self.logger = FirestoreLogger(project_id)
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
        Inspect one agent-to-agent/tool request.
        """

        # -------------------------------------------------
        # STEP 1: Inspect communication
        # -------------------------------------------------

        security_event = self.inspector.inspect(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        # -------------------------------------------------
        # STEP 2: Detect threats
        # -------------------------------------------------

        threats = self.threat_detector.detect(message)

        security_event["threats"] = threats

        # -------------------------------------------------
        # STEP 3: Calculate risk
        # -------------------------------------------------

        risk_score = self.risk_engine.calculate(threats)

        security_event["risk_score"] = risk_score

        security_event["risk_level"] = (
            self.risk_engine.get_risk_level(risk_score)
        )

        # -------------------------------------------------
        # STEP 4: Authorization
        # -------------------------------------------------

        if tool:

            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )

        else:

            authorized = True

        security_event["authorized"] = authorized

        # Unauthorized tool access is immediately blocked.
        if not authorized:

            security_event["decision"] = "BLOCK"
            security_event["gemini_analysis"] = None

        else:

            # ---------------------------------------------
            # STEP 5: Gemini semantic analysis
            # ---------------------------------------------

            gemini_analysis = self.gemini.analyze(
                source_agent=source_agent,
                target_agent=target_agent,
                message=message,
                tool=tool
            )

            security_event["gemini_analysis"] = gemini_analysis

            # ---------------------------------------------
            # STEP 6: Final security decision
            # ---------------------------------------------

            if "BLOCK" in gemini_analysis.upper():

                decision = "BLOCK"

            elif "QUARANTINE" in gemini_analysis.upper():

                decision = "QUARANTINE"

            else:

                decision = self.policy_engine.evaluate(
                    risk_score=risk_score,
                    source_agent=source_agent,
                    tool=tool
                )

            security_event["decision"] = decision

        # -------------------------------------------------
        # STEP 7: Store security event in Firestore
        # -------------------------------------------------

        if self.logger:

            try:

                document_id = self.logger.log_event(
                    security_event
                )

                security_event["firestore_document_id"] = (
                    document_id
                )

            except Exception as error:

                # Logging failure should not crash the
                # security firewall.
                security_event["logging_error"] = str(error)

        return security_event
