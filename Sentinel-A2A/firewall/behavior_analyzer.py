"""
Behavioral Anomaly Detector for Sentinel-A2A.

Instead of examining only one request, this component
looks at an agent's recent behavior and identifies
suspicious patterns.
"""


from collections import defaultdict


class BehaviorAnalyzer:
    """
    Tracks agent behavior and detects anomalies.
    """

    def __init__(self):

        # Store recent activity for every agent.
        self.agent_activity = defaultdict(list)

    def record_request(
        self,
        agent_name,
        tool,
        risk_score,
        decision
    ):
        """
        Record a request made by an AI agent.
        """

        self.agent_activity[agent_name].append({
            "tool": tool,
            "risk_score": risk_score,
            "decision": decision
        })

    def analyze(self, agent_name):
        """
        Analyze the recent behavior of an agent.
        """

        history = self.agent_activity.get(
            agent_name,
            []
        )

        # No previous behavior means there is
        # nothing suspicious to analyze.
        if not history:

            return {
                "agent": agent_name,
                "anomaly": False,
                "anomaly_score": 0,
                "reasons": []
            }

        reasons = []
        anomaly_score = 0


        # =================================================
        # RULE 1 — REPEATED BLOCKED REQUESTS
        # =================================================

        blocked_requests = sum(
            1
            for event in history
            if event["decision"] == "BLOCK"
        )

        if blocked_requests >= 3:

            anomaly_score += 30

            reasons.append(
                "Repeated blocked requests detected."
            )


        # =================================================
        # RULE 2 — HIGH RISK BEHAVIOR
        # =================================================

        high_risk_requests = sum(
            1
            for event in history
            if event["risk_score"] >= 80
        )

        if high_risk_requests >= 2:

            anomaly_score += 25

            reasons.append(
                "Repeated high-risk requests detected."
            )


        # =================================================
        # RULE 3 — TOOL SWITCHING
        # =================================================

        tools = {
            event["tool"]
            for event in history
            if event.get("tool")
        }

        # Rapidly requesting many different tools can
        # indicate unusual agent behavior.

        if len(tools) >= 4:

            anomaly_score += 20

            reasons.append(
                "Agent accessed an unusually large "
                "number of different tools."
            )


        # =================================================
        # RULE 4 — SUSPICIOUS ESCALATION
        # =================================================

        if len(history) >= 3:

            recent_events = history[-3:]

            recent_scores = [
                event["risk_score"]
                for event in recent_events
            ]

            if (
                recent_scores[0]
                < recent_scores[1]
                < recent_scores[2]
            ):

                anomaly_score += 20

                reasons.append(
                    "Risk level is continuously increasing."
                )


        # =================================================
        # RULE 5 — EXCESSIVE REQUESTS
        # =================================================

        if len(history) >= 10:

            anomaly_score += 15

            reasons.append(
                "Agent generated an unusually high "
                "number of requests."
            )


        # Keep the score within 0–100.

        anomaly_score = min(
            anomaly_score,
            100
        )


        return {
            "agent": agent_name,
            "anomaly": anomaly_score >= 40,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "requests_analyzed": len(history)
        }

    def get_agent_behavior(self, agent_name):
        """
        Return the complete behavioral history
        of an agent.
        """

        return self.agent_activity.get(
            agent_name,
            []
        )

    def get_all_agents(self):
        """
        Return all agents currently being monitored.
        """

        return list(
            self.agent_activity.keys()
        ) 
