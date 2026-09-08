from collections import Counter


class SecurityAnalytics:
    """
    Calculates security statistics from Sentinel-A2A
    Firestore or local in-memory security events.
    """

    def __init__(self, events):
        self.events = events or []

    def total_events(self):
        return len(self.events)

    def decision_counts(self):
        decisions = [
            event.get("decision", "UNKNOWN") if isinstance(event, dict) else "UNKNOWN"
            for event in self.events
        ]
        return dict(Counter(decisions))

    def risk_level_counts(self):
        risk_levels = [
            event.get("risk_level", "UNKNOWN") if isinstance(event, dict) else "UNKNOWN"
            for event in self.events
        ]
        return dict(Counter(risk_levels))

    def blocked_count(self):
        return sum(
            1
            for event in self.events
            if isinstance(event, dict) and event.get("decision") == "BLOCK"
        )

    def quarantined_count(self):
        return sum(
            1
            for event in self.events
            if isinstance(event, dict) and event.get("decision") == "QUARANTINE"
        )

    def allowed_count(self):
        return sum(
            1
            for event in self.events
            if isinstance(event, dict) and event.get("decision") == "ALLOW"
        )

    def high_risk_count(self):
        return sum(
            1
            for event in self.events
            if isinstance(event, dict) and event.get("risk_level") in ["HIGH", "CRITICAL"]
        )

    def tool_activity(self):
        tools = [
            event.get("tool") or "Unknown"
            for event in self.events
            if isinstance(event, dict)
        ]
        return dict(Counter(tools).most_common())

    def agent_activity(self):
        agents = [
            event.get("source_agent") or "Unknown"
            for event in self.events
            if isinstance(event, dict)
        ]
        return dict(Counter(agents).most_common())

    def average_risk_score(self):
        scores = [
            event.get("risk_score", 0)
            for event in self.events
            if isinstance(event, dict)
            and isinstance(event.get("risk_score"), (int, float))
        ]

        if not scores:
            return 0.0

        return round(sum(scores) / len(scores), 2)

    def summary(self):
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
