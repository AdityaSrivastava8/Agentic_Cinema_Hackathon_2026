from firewall.inspector import AgentInspector
from firewall.threat_detector import ThreatDetector
from firewall.risk_engine import RiskEngine
from firewall.policy_engine import PolicyEngine


class SentinelA2A:
    """
    Main security controller for Sentinel-A2A.

    This class connects all firewall components and
    processes an agent-to-agent communication from
    beginning to end.

    Flow:

        Message
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

    def _init_(self):

        # Create the four security components.
        self.inspector = AgentInspector()
        self.threat_detector = ThreatDetector()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()

    def inspect_message(
        self,
        source_agent,
        target_agent,
        message,
        tool=None,
        allowed_tools=None
    ):
        """
        Run a complete security inspection.

        Parameters:
            source_agent:
                Agent sending the message.

            target_agent:
                Agent receiving the message.

            message:
                Message being transmitted.

            tool:
                Optional MCP/API tool being requested.

            allowed_tools:
                Tools that the source agent is authorized to use.

        Returns:
            Complete security analysis.
        """

        # ---------------------------------------------
        # STEP 1: Capture the communication
        # ---------------------------------------------

        security_event = self.inspector.inspect(
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            tool=tool
        )

        # ---------------------------------------------
        # STEP 2: Detect threats
        # ---------------------------------------------

        threats = self.threat_detector.detect(message)

        # Add detected threats to the security event.
        security_event["threats"] = threats

        # ---------------------------------------------
        # STEP 3: Calculate risk
        # ---------------------------------------------

        risk_score = self.risk_engine.calculate(threats)

        # Store the calculated risk score.
        security_event["risk_score"] = risk_score

        # Convert numerical score into LOW/MEDIUM/HIGH.
        security_event["risk_level"] = (
            self.risk_engine.get_risk_level(risk_score)
        )

        # ---------------------------------------------
        # STEP 4: Make the security decision
        # ---------------------------------------------

        decision = self.policy_engine.evaluate(
            risk_score=risk_score,
            threats=threats,
            tool=tool,
            allowed_tools=allowed_tools
        )

        # Store the final decision.
        security_event["decision"] = decision

        # ---------------------------------------------
        # STEP 5: Return complete security report
        # ---------------------------------------------

        return security_event
