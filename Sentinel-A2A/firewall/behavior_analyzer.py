"""
Behavioral Anomaly Detector for Sentinel-A2A.

Instead of examining only one request, this component
looks at an agent's recent behavior and identifies
suspicious patterns.
"""

import time
from collections import defaultdict


class BehaviorAnalyzer:
    """
    Tracks agent behavior, enforces rate limits, and detects anomalies.
    """

    def __init__(self, time_window_seconds=60, max_requests_per_window=10):
        # Store recent activity for every agent.
        self.agent_activity = defaultdict(list)
        self.time_window = time_window_seconds
        self.max_requests = max_requests_per_window

    def record_request(
        self,
        agent_name,
        tool=None,
        risk_score=0,
        decision="ALLOW"
    ):
        """
        Record a request made by an AI agent with a timestamp.
        """
        self.agent_activity[agent_name].append({
            "timestamp": time.time(),
            "tool": tool,
            "risk_score": risk_score,
            "decision": decision
        })

    def analyze(self, agent_name):
        """
        Analyze the recent behavior of an agent within the active time window.
        """
        current_time = time.time()
        raw_history = self.agent_activity.get(agent_name, [])

        if not raw_history:
            return {
                "agent": agent_name,
                "anomaly": False,
                "anomaly_score": 0,
                "reasons": [],
                "requests_analyzed": 0
            }

        # Filter events to keep only those within the rolling time window
        history = [
            event for event in raw_history
            if current_time - event.get("timestamp", current_time) <= self.time_window
        ]
        self.agent_activity[agent_name] = history

        reasons = []
        anomaly_score = 0

        # =================================================
        # RULE 1 — REPEATED BLOCKED REQUESTS
        # =================================================
        blocked_requests = sum(
            1 for event in history if event.get("decision") == "BLOCK"
        )
        if blocked_requests >= 3:
            anomaly_score += 30
            reasons.append("Repeated blocked requests detected.")

        # =================================================
        # RULE 2 — HIGH RISK BEHAVIOR
        # =================================================
        high_risk_requests = sum(
            1 for event in history if event.get("risk_score", 0) >= 80
        )
        if high_risk_requests >= 2:
            anomaly_score += 25
            reasons.append("Repeated high-risk requests detected.")

        # =================================================
        # RULE 3 — TOOL SWITCHING
        # =================================================
        tools = {
            event["tool"] for event in history if event.get("tool")
        }
        if len(tools) >= 4:
            anomaly_score += 20
            reasons.append(
                "Agent accessed an unusually large number of different tools."
            )

        # =================================================
        # RULE 4 — SUSPICIOUS ESCALATION
        # =================================================
        if len(history) >= 3:
            recent_events = history[-3:]
            recent_scores = [event.get("risk_score", 0) for event in recent_events]
            if recent_scores[0] < recent_scores[1] < recent_scores[2]:
                anomaly_score += 20
                reasons.append("Risk level is continuously increasing.")

        # =================================================
        # RULE 5 — TIME-WINDOWED RATE LIMITING / EXCESSIVE REQUESTS
        # =================================================
        request_count = len(history)
        if request_count > self.max_requests:
            excess = request_count - self.max_requests
            anomaly_score += min(50, 15 + (excess * 5))
            reasons.append(
                f"Rate limit exceeded: {request_count} requests in last "
                f"{self.time_window}s (max allowed: {self.max_requests})."
            )
        elif request_count >= 10:
            anomaly_score += 15
            reasons.append("Agent generated an unusually high number of requests.")

        # Cap score between 0 and 100
        anomaly_score = min(anomaly_score, 100)

        return {
            "agent": agent_name,
            "anomaly": anomaly_score >= 40,
            "anomaly_score": anomaly_score,
            "reasons": reasons,
            "requests_analyzed": request_count
        }

    def get_agent_behavior(self, agent_name):
        """
        Return the complete behavioral history of an agent.
        """
        return self.agent_activity.get(agent_name, [])

    def get_all_agents(self):
        """
        Return all agents currently being monitored.
        """
        return list(self.agent_activity.keys()) 
