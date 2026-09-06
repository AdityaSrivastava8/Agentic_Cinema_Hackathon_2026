from agents.shopping_agent import ShoppingAgent
from agents.payment_agent import PaymentAgent

from firewall.sentinel import SentinelA2A
from firewall.behavior_analyzer import BehaviorAnalyzer
from firewall.threat_intelligence import ThreatIntelligence
from firewall.security_response import SecurityResponseEngine

from mcp.mcp_gateway import MCPGateway

from protocol.a2a_message import A2AMessage

from cloud.agent_trust import AgentTrustEngine


class AgentRouter:
    """
    Central communication router for Sentinel-A2A.

    Complete security flow:

        ShoppingAgent
              |
              v
        A2A Message
              |
              v
        Sentinel-A2A
              |
       +------+------+
       |             |
       v             v
    Behavior       Trust
    Analysis       Analysis
       |             |
       +------+------+
              |
              v
       Threat Intelligence
              |
              v
       Security Response
              |
        +-----+-----+
        |     |     |
      ALLOW QUAR. BLOCK
        |     |     |
        v     X     X
    PaymentAgent
        |
        v
    MCP Gateway
        |
        v
      MCP Tool
    """

    def __init__(self):

        # -------------------------------------------------
        # AI AGENTS
        # -------------------------------------------------

        self.shopping_agent = ShoppingAgent()
        self.payment_agent = PaymentAgent()


        # -------------------------------------------------
        # CORE SENTINEL FIREWALL
        # -------------------------------------------------

        self.sentinel = SentinelA2A()


        # -------------------------------------------------
        # MCP GATEWAY
        # -------------------------------------------------

        self.mcp_gateway = MCPGateway()


        # -------------------------------------------------
        # BEHAVIOR ANALYZER
        # -------------------------------------------------

        self.behavior_analyzer = BehaviorAnalyzer()


        # -------------------------------------------------
        # AGENT TRUST ENGINE
        # -------------------------------------------------

        self.trust_engine = AgentTrustEngine()


        # -------------------------------------------------
        # THREAT INTELLIGENCE
        # -------------------------------------------------

        self.threat_intelligence = ThreatIntelligence()


        # -------------------------------------------------
        # SECURITY RESPONSE ENGINE
        # -------------------------------------------------

        self.security_response = SecurityResponseEngine()


    def send_to_payment_agent(
        self,
        message,
        tool=None,
        tool_arguments=None
    ):
        """
        Send a request from ShoppingAgent to PaymentAgent.

        Every request passes through the Sentinel-A2A
        security pipeline before the PaymentAgent or
        MCP tool can execute.

        Returns:

            {
                "security": {...},
                "payment": {...} or None,
                "mcp_result": {...} or None
            }
        """

        # -------------------------------------------------
        # INITIALIZE TOOL ARGUMENTS
        # -------------------------------------------------

        if tool_arguments is None:
            tool_arguments = {}


        # -------------------------------------------------
        # STEP 1 — CREATE AGENT REQUEST
        # -------------------------------------------------

        request = self.shopping_agent.create_request(
            message=message,
            tool=tool
        )


        # -------------------------------------------------
        # STEP 2 — CREATE STANDARD A2A MESSAGE
        # -------------------------------------------------

        a2a_message = A2AMessage(
            source_agent=request["source_agent"],
            target_agent=self.payment_agent.name,
            message=request["message"],
            tool=request["tool"],
            tool_arguments=tool_arguments
        )


        # -------------------------------------------------
        # STEP 3 — VALIDATE A2A MESSAGE
        # -------------------------------------------------

        valid, validation_message = (
            a2a_message.validate()
        )

        if not valid:

            return {
                "security": {
                    "decision": "BLOCK",
                    "risk_score": 100,
                    "risk_level": "CRITICAL",
                    "authorized": False,
                    "threats": [
                        validation_message
                    ],
                    "event_id": a2a_message.message_id,
                    "timestamp": a2a_message.timestamp,
                    "source_agent": (
                        a2a_message.source_agent
                    ),
                    "target_agent": (
                        a2a_message.target_agent
                    ),
                    "tool": a2a_message.tool
                },
                "payment": None,
                "mcp_result": None
            }


        # -------------------------------------------------
        # STEP 4 — CORE SENTINEL INSPECTION
        # -------------------------------------------------

        security_result = self.sentinel.inspect_message(
            source_agent=a2a_message.source_agent,
            target_agent=a2a_message.target_agent,
            message=a2a_message.message,
            tool=a2a_message.tool
        )


        # -------------------------------------------------
        # STEP 5 — GET BASE SECURITY INFORMATION
        # -------------------------------------------------

        base_risk = security_result.get(
            "risk_score",
            0
        )

        threats = security_result.get(
            "threats",
            []
        )

        authorized = security_result.get(
            "authorized",
            True
        )


        # -------------------------------------------------
        # STEP 6 — AGENT BEHAVIOR ANALYSIS
        # -------------------------------------------------

        behavior_result = (
            self.behavior_analyzer.analyze(
                a2a_message.source_agent
            )
        )

        behavior_score = behavior_result.get(
            "anomaly_score",
            0
        )


        # -------------------------------------------------
        # STEP 7 — AGENT TRUST SCORE
        # -------------------------------------------------

        trust_result = (
            self.trust_engine.get_agent_status(
                a2a_message.source_agent
            )
        )

        trust_score = trust_result.get(
            "trust_score",
            100
        )


        # -------------------------------------------------
        # STEP 8 — THREAT INTELLIGENCE
        # -------------------------------------------------

        threat_summary = (
            self.threat_intelligence.build_summary(
                threats
            )
        )

        threat_severity = (
            threat_summary["highest_severity"]
        )

        threat_action = (
            threat_summary["recommended_action"]
        )


        # -------------------------------------------------
        # STEP 9 — FINAL SECURITY DECISION
        # -------------------------------------------------

        response = self.security_response.evaluate(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=trust_score,
            threat_severity=threat_severity,
            authorized=authorized,
            threat_action=threat_action
        )


        # -------------------------------------------------
        # STEP 10 — UPDATE SECURITY RESULT
        # -------------------------------------------------

        security_result.update({

            "risk_score": response[
                "risk_score"
            ],

            "risk_level": response[
                "risk_level"
            ],

            "decision": response[
                "decision"
            ],

            "authorized": response[
                "authorized"
            ],

            "agent_trust_score": trust_score,

            "agent_trust_level": (
                trust_result["trust_level"]
            ),

            "behavior_anomaly_score": (
                behavior_score
            ),

            "behavior_anomaly": (
                behavior_result["anomaly"]
            ),

            "threat_severity": (
                threat_severity
            ),

            "recommended_action": (
                threat_action
            ),

            "threat_intelligence": (
                threat_summary
            ),

            "message_id": (
                a2a_message.message_id
            ),

            "timestamp": (
                a2a_message.timestamp
            )
        })


        # -------------------------------------------------
        # STEP 11 — RECORD BEHAVIOR
        # -------------------------------------------------

        self.behavior_analyzer.record_request(
            agent_name=a2a_message.source_agent,
            tool=a2a_message.tool,
            risk_score=response["risk_score"],
            decision=response["decision"]
        )


        # -------------------------------------------------
        # STEP 12 — UPDATE AGENT TRUST
        # -------------------------------------------------

        self.trust_engine.record_event(
            agent_name=a2a_message.source_agent,
            decision=response["decision"],
            risk_score=response["risk_score"]
        )


        # -------------------------------------------------
        # STEP 13 — SECURITY ENFORCEMENT
        # -------------------------------------------------

        if response["decision"] != "ALLOW":

            # BLOCK and QUARANTINE requests stop here.

            security_result[
                "mcp_execution"
            ] = False

            return {
                "security": security_result,
                "payment": None,
                "mcp_result": None
            }


        # -------------------------------------------------
        # STEP 14 — PAYMENT AGENT
        # -------------------------------------------------

        payment_result = (
            self.payment_agent.process_payment(
                message
            )
        )


        # -------------------------------------------------
        # STEP 15 — MCP TOOL
        # -------------------------------------------------

        mcp_result = None

        if tool:

            # Preserve your existing MCPGateway interface.
            #
            # The request only reaches this point after
            # Sentinel-A2A has returned ALLOW.

            mcp_result = self.mcp_gateway.execute(
                tool,
                **tool_arguments
            )


        # -------------------------------------------------
        # STEP 16 — FINAL RESULT
        # -------------------------------------------------

        security_result[
            "mcp_execution"
        ] = True

        return {
            "security": security_result,
            "payment": payment_result,
            "mcp_result": mcp_result
        } 
