from collections import Counter


class SecurityAnalytics:
    """
    Calculates security statistics from Sentinel-A2A
    Firestore security events.
    """

    def __init__(self, events):
        # Store the security events received from Firestore.
        self.events = events or []

    def total_events(self):
        """
        Return the total number of inspected events.
        """
        return len(self.events)

    def decision_counts(self):
        """
        Count ALLOW, QUARANTINE and BLOCK decisions.
        """

        decisions = [
            event.get("decision", "UNKNOWN")
            for event in self.events
        ]

        return dict(Counter(decisions))

    def risk_level_counts(self):
        """
        Count events by risk level.
        """

        risk_levels = [
            event.get("risk_level", "UNKNOWN")
            for event in self.events
        ]

        return dict(Counter(risk_levels))

    def blocked_count(self):
        """
        Return the number of blocked requests.
        """

        return sum(
            1
            for event in self.events
            if event.get("decision") == "BLOCK"
        )

    def quarantined_count(self):
        """
        Return the number of quarantined requests.
        """

        return sum(
            1
            for event in self.events
            if event.get("decision") == "QUARANTINE"
        )

    def allowed_count(self):
        """
        Return the number of allowed requests.
        """

        return sum(
            1
            for event in self.events
            if event.get("decision") == "ALLOW"
        )

    def high_risk_count(self):
        """
        Count HIGH-risk security events.
        """

        return sum(
            1
            for event in self.events
            if event.get("risk_level") == "HIGH"
        )

    def tool_activity(self):
        """
        Find which MCP tools are being requested most often.
        """

        tools = [
            event.get("tool", "Unknown")
            for event in self.events
        ]

        return dict(
            Counter(tools).most_common()
        )

    def agent_activity(self):
        """
        Find which source agents generate the most traffic.
        """

        agents = [
            event.get("source_agent", "Unknown")
            for event in self.events
        ]

        return dict(
            Counter(agents).most_common()
        )

    def average_risk_score(self):
        """
        Calculate the average risk score.
        """

        scores = [
            event.get("risk_score", 0)
            for event in self.events
            if isinstance(
                event.get("risk_score"),
                (int, float)
            )
        ]

        if not scores:
            return 0

        return round(
            sum(scores) / len(scores),
            2
        )

    def summary(self):
        """
        Return a complete security analytics summary.
        """

        return {
            "total_events": self.total_events(),
            "allowed": self.allowed_count(),
            "quarantined": self.quarantined_count(),
            "blocked": self.blocked_count(),
            "high_risk": self.high_risk_count(),
            "average_risk_score": self.average_risk_score(),
            "risk_levels": self.risk_level_counts(),
            "tools": self.tool_activity(),
            "agents": self.agent_activity()
        } 
