from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine
from firewall.authorization import AuthorizationEngine
from firewall.gemini_analyzer import GeminiAnalyzer


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    Security pipeline:

        Agent Request
             ↓
        Inspector
             ↓
        Rule-Based Threat Detection
             ↓
        Risk Engine
             ↓
        Authorization
             ↓
        Gemini Semantic Analysis
             ↓
        Policy Engine
             ↓
        ALLOW / QUARANTINE / BLOCK
    """

    def __init__(self):

        # Capture information about agent communication.
        self.inspector = AgentInspector()

        # Detect known threats using deterministic rules.
        self.threat_detector = ThreatDetector()

        # Calculate the initial numerical risk score.
        self.risk_engine = RiskEngine()

        # Apply the centralized security policies.
        self.policy_engine = PolicyEngine()

        # Check agent/tool permissions.
        self.authorization = AuthorizationEngine()

        # Use Gemini for semantic security analysis.
        self.gemini = GeminiAnalyzer()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None
    ):
        """
        Perform complete Sentinel-A2A analysis.

        The request is analyzed using both:
        - deterministic security rules
        - Gemini semantic reasoning
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
        # STEP 2: Rule-based threat detection
        # -------------------------------------------------

        threats = self.threat_detector.detect(message)

        security_event["threats"] = threats

        # -------------------------------------------------
        # STEP 3: Calculate initial risk
        # -------------------------------------------------

        risk_score = self.risk_engine.calculate(threats)

        security_event["risk_score"] = risk_score

        security_event["risk_level"] = (
            self.risk_engine.get_risk_level(risk_score)
        )

        # -------------------------------------------------
        # STEP 4: Authorization check
        # -------------------------------------------------

        if tool:

            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )

        else:

            authorized = True

        security_event["authorized"] = authorized

        # Unauthorized tools are immediately blocked.
        if not authorized:

            security_event["decision"] = "BLOCK"
            security_event["gemini_analysis"] = None

            return security_event

        # -------------------------------------------------
        # STEP 5: Gemini semantic analysis
        # -------------------------------------------------

        gemini_analysis = self.gemini.analyze(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        # Store Gemini's analysis for the dashboard
        # and future logging.
        security_event["gemini_analysis"] = gemini_analysis

        # -------------------------------------------------
        # STEP 6: Combine security signals
        # -------------------------------------------------

        # Gemini's recommendation is used as an additional
        # security signal rather than blindly trusting it.
        if "BLOCK" in gemini_analysis.upper():

            decision = "BLOCK"

        elif "QUARANTINE" in gemini_analysis.upper():

            decision = "QUARANTINE"

        else:

            # Fall back to our deterministic policy engine.
            decision = self.policy_engine.evaluate(
                risk_score=risk_score,
                source_agent=source_agent,
                tool=tool
            )

        # -------------------------------------------------
        # STEP 7: Store final decision
        # -------------------------------------------------

        security_event["decision"] = decision

        return security_event 
