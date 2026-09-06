import os
import uuid
from datetime import datetime, timezone

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

    Security pipeline:

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

        # Inspect and record incoming agent communication.
        self.inspector = AgentInspector()

        # Detect known malicious patterns.
        self.threat_detector = ThreatDetector()

        # Calculate numerical risk score.
        self.risk_engine = RiskEngine()

        # Apply centralized security policies.
        self.policy_engine = PolicyEngine()

        # Check whether the agent can use the requested tool.
        self.authorization = AuthorizationEngine()

        # Analyze the semantic meaning of the request using Gemini.
        self.gemini = GeminiAnalyzer()

        # Read the Google Cloud project ID.
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT")

        # Enable Firestore logging when Google Cloud is configured.
        #
        # This also allows local testing without Firestore.
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
        - Authorization status
        - Gemini analysis
        - Final decision
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

        # Generate a unique ID for this security event.
        security_event["event_id"] = str(uuid.uuid4())

        # Record the exact UTC time of the inspection.
        security_event["timestamp"] = datetime.now(
            timezone.utc
        ).isoformat()

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

        # -------------------------------------------------
        # STEP 5: Handle unauthorized requests
        # -------------------------------------------------

        if not authorized:

            # Unauthorized tool access is immediately blocked.
            security_event["decision"] = "BLOCK"

            # Gemini does not need to analyze an already
            # unauthorized tool request.
            security_event["gemini_analysis"] = None

        else:

            # -------------------------------------------------
            # STEP 6: Gemini semantic analysis
            # -------------------------------------------------

            gemini_analysis = self.gemini.analyze(
                source_agent=source_agent,
                target_agent=target_agent,
                message=message,
                tool=tool
            )

            security_event["gemini_analysis"] = gemini_analysis

            # -------------------------------------------------
            # STEP 7: Final security decision
            # -------------------------------------------------

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
        # STEP 8: Store event in Firestore
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

                # Logging failure should never crash the firewall.
                security_event["logging_error"] = str(error)

        # -------------------------------------------------
        # STEP 9: Return security report
        # -------------------------------------------------

        return security_event 
