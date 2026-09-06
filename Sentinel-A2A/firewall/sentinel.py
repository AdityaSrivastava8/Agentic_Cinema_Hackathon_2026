from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    This class connects all security components and
    processes agent-to-agent communication.

    Security pipeline:

        Agent Message
             ↓
        Inspector
             ↓
        Threat Detector
             ↓
        Risk Engine
             ↓
        Policy Engine
             ↓
        ALLOW / QUARANTINE / BLOCK
    """

    def __init__(self):

        # Initialize the message inspection layer.
        self.inspector = AgentInspector()

        # Initialize the threat detection layer.
        self.threat_detector = ThreatDetector()

        # Initialize the risk calculation layer.
        self.risk_engine = RiskEngine()

        # Initialize the centralized policy engine.
        #
        # PolicyEngine automatically loads:
        # config/policies.json
        self.policy_engine = PolicyEngine()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None
    ):
        """
        Perform a complete Sentinel-A2A security inspection.

        Parameters:
            source_agent:
                Agent sending the request.

            target_agent:
                Agent receiving the request.

            message:
                Actual message being transmitted.

            tool:
                Optional MCP/API tool being requested.

        Returns:
            Complete security analysis.
        """

        # -------------------------------------------------
        # STEP 1: Capture the communication
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

        # Store detected threats in the security event.
        security_event["threats"] = threats

        # -------------------------------------------------
        # STEP 3: Calculate risk
        # -------------------------------------------------

        risk_score = self.risk_engine.calculate(threats)

        # Store the numerical risk score.
        security_event["risk_score"] = risk_score

        # Convert the score into:
        # LOW / MEDIUM / HIGH
        security_event["risk_level"] = (
            self.risk_engine.get_risk_level(risk_score)
        )

        # -------------------------------------------------
        # STEP 4: Enforce security policy
        # -------------------------------------------------

        decision = self.policy_engine.evaluate(
            risk_score=risk_score,
            source_agent=source_agent,
            tool=tool
        )

        # Store the final security decision.
        security_event["decision"] = decision

        # -------------------------------------------------
        # STEP 5: Return complete security report
        # -------------------------------------------------

        return security_event 
