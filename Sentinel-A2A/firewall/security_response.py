"""
Security Response Engine for Sentinel-A2A.

Combines security signals and determines the final action:

    ALLOW
    QUARANTINE
    BLOCK

This is the decision layer between detection and
MCP tool execution.
"""


class SecurityResponseEngine:
    """
    Converts multiple security signals into one
    enforceable security decision.
    """

    def __init__(self):

        # Risk thresholds.
        self.block_threshold = 80
        self.quarantine_threshold = 50

    def calculate_risk(
        self,
        base_risk=0,
        behavior_score=0,
        trust_score=100,
        threat_severity="LOW",
        authorized=True
    ):
        """
        Combine multiple security signals into
        a final risk score.
        """

        risk = base_risk

        # -------------------------------------------------
        # BEHAVIOR SCORE
        # -------------------------------------------------

        # Suspicious historical behavior increases risk.
        risk += behavior_score * 0.25


        # -------------------------------------------------
        # AGENT TRUST
        # -------------------------------------------------

        # Low trust increases risk.
        trust_penalty = max(
            0,
            (100 - trust_score) * 0.25
        )

        risk += trust_penalty


        # -------------------------------------------------
        # THREAT SEVERITY
        # -------------------------------------------------

        severity_points = {
            "LOW": 0,
            "MEDIUM": 10,
            "HIGH": 20,
            "CRITICAL": 35
        }

        risk += severity_points.get(
            threat_severity,
            0
        )


        # -------------------------------------------------
        # AUTHORIZATION
        # -------------------------------------------------

        if not authorized:

            # Unauthorized requests receive a large
            # risk increase.
            risk += 40


        # Keep score between 0 and 100.

        return round(
            min(
                max(risk, 0),
                100
            ),
            2
        )

    def decide(
        self,
        risk_score,
        authorized=True,
        threat_action="ALLOW"
    ):
        """
        Determine the final security decision.
        """

        # -------------------------------------------------
        # AUTHORIZATION OVERRIDE
        # -------------------------------------------------

        # An unauthorized request must never be allowed.
        if not authorized:

            return "BLOCK"


        # -------------------------------------------------
        # THREAT INTELLIGENCE OVERRIDE
        # -------------------------------------------------

        if threat_action == "BLOCK":

            return "BLOCK"


        # -------------------------------------------------
        # RISK-BASED DECISION
        # -------------------------------------------------

        if risk_score >= self.block_threshold:

            return "BLOCK"

        if risk_score >= self.quarantine_threshold:

            return "QUARANTINE"


        return "ALLOW"

    def evaluate(
        self,
        base_risk=0,
        behavior_score=0,
        trust_score=100,
        threat_severity="LOW",
        authorized=True,
        threat_action="ALLOW"
    ):
        """
        Perform complete security evaluation.

        Returns all information needed by the
        firewall and dashboard.
        """

        risk_score = self.calculate_risk(
            base_risk=base_risk,
            behavior_score=behavior_score,
            trust_score=trust_score,
            threat_severity=threat_severity,
            authorized=authorized
        )

        decision = self.decide(
            risk_score=risk_score,
            authorized=authorized,
            threat_action=threat_action
        )


        # Determine human-readable risk level.

        if risk_score >= 80:

            risk_level = "CRITICAL"

        elif risk_score >= 50:

            risk_level = "HIGH"

        elif risk_score >= 25:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"


        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "decision": decision,
            "authorized": authorized
        } 
