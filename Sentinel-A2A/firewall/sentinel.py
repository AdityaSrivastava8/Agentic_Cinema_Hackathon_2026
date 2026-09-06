from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine
from firewall.authorization import AuthorizationEngine


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    Every agent-to-agent or agent-to-tool request
    passes through this security pipeline:

        Agent Request
             ↓
        Inspector
             ↓
        Threat Detector
             ↓
        Risk Engine
             ↓
        Authorization Engine
             ↓
        Policy Engine
             ↓
        ALLOW / QUARANTINE / BLOCK
    """

    def __init__(self):

        # Capture and record incoming agent communication.
        self.inspector = AgentInspector()

        # Detect suspicious or malicious instructions.
        self.threat_detector = ThreatDetector()

        # Convert detected threats into a 0–100 risk score.
        self.risk_engine = RiskEngine()

        # Apply the centralized security policies.
        self.policy_engine = PolicyEngine()

        # Check whether an agent is authorized to
        # access the requested tool.
        self.authorization = AuthorizationEngine()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None
    ):
        """
        Perform a complete security inspection.

        Returns a security report containing:
        - Source and target agents
        - Requested tool
        - Detected threats
        - Risk score
        - Risk level
        - Authorization result
        - Final decision
        """

        # -------------------------------------------------
        # STEP 1: Record the communication
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
        # STEP 4: Check agent authorization
        # -------------------------------------------------

        # If no tool is requested, authorization is not needed.
        if tool:

            authorized = self.authorization.is_authorized(
                agent_name=source_agent,
                tool_name=tool
            )

        else:

            authorized = True

        # Store the authorization result in the security report.
        security_event["authorized"] = authorized

        # -------------------------------------------------
        # STEP 5: Enforce the security policy
        # -------------------------------------------------

        # Immediately block unauthorized tool access.
        if not authorized:

            decision = "BLOCK"

        else:

            decision = self.policy_engine.evaluate(
                risk_score=risk_score,
                source_agent=source_agent,
                tool=tool
            )

        # Store the final decision.
        security_event["decision"] = decision

        # -------------------------------------------------
        # STEP 6: Return security report
        # -------------------------------------------------

        return security_event 
