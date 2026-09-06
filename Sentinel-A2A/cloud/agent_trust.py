from collections import defaultdict


class AgentTrustEngine:
    """
    Calculates a behavioral trust score for AI agents.

    The score starts at 100 and changes based on the
    agent's previous security behavior.

    Higher score = more trusted
    Lower score = less trusted
    """

    def __init__(self):
        # Store security history for each agent.
        self.agent_history = defaultdict(list)

    def record_event(self, agent_name, decision, risk_score):
        """
        Record one security event for an agent.
        """

        self.agent_history[agent_name].append({
            "decision": decision,
            "risk_score": risk_score
        })

    def calculate_trust_score(self, agent_name):
        """
        Calculate the current trust score of an agent.
        """

        events = self.agent_history.get(
            agent_name,
            []
        )

        # New agents start with maximum trust.
        if not events:
            return 100

        score = 100

        for event in events:

            decision = event.get(
                "decision",
                "ALLOW"
            )

            risk_score = event.get(
                "risk_score",
                0
            )

            # Blocked requests significantly reduce trust.
            if decision == "BLOCK":
                score -= 20

            # Quarantined requests moderately reduce trust.
            elif decision == "QUARANTINE":
                score -= 10

            # High-risk behavior reduces trust.
            if risk_score >= 80:
                score -= 10

            elif risk_score >= 50:
                score -= 5

        # Keep score between 0 and 100.
        return max(
            0,
            min(100, score)
        )

    def get_trust_level(self, score):
        """
        Convert numerical trust score into a
        human-readable trust level.
        """

        if score >= 80:
            return "TRUSTED"

        elif score >= 50:
            return "SUSPICIOUS"

        else:
            return "UNTRUSTED"

    def get_agent_status(self, agent_name):
        """
        Return complete trust information for an agent.
        """

        score = self.calculate_trust_score(
            agent_name
        )

        return {
            "agent": agent_name,
            "trust_score": score,
            "trust_level": self.get_trust_level(
                score
            ),
            "events": len(
                self.agent_history.get(
                    agent_name,
                    []
                )
            )
        } 
