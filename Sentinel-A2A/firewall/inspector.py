from datetime import datetime


class AgentInspector:
    """
    Sentinel-A2A's core inspection layer.

    This class sits between two AI agents and intercepts
    the message being sent from one agent to another.

    Later, this inspector will connect to:
    - Threat detection
    - Policy checking
    - Risk scoring
    - Data-loss prevention
    """

    def inspect(self, source_agent, target_agent, message, tool=None):
        """
        Inspect a communication between two AI agents.

        Parameters:
            source_agent:
                The AI agent sending the message.

            target_agent:
                The AI agent receiving the message.

            message:
                The actual text/instruction being sent.

            tool:
                Optional MCP/API tool that the receiving agent
                is being asked to use.

        Returns:
            A dictionary containing the security information
            about this communication.
        """

        # Create a security event for this communication.
        # This event will later be stored in our database/logs.
        result = {

            # Record exactly when Sentinel-A2A inspected the message.
            "timestamp": datetime.utcnow().isoformat(),

            # Identify the agent that initiated the communication.
            "source_agent": source_agent,

            # Identify the agent that is supposed to receive it.
            "target_agent": target_agent,

            # Store the message so our security system can analyze it.
            "message": message,

            # Store the requested tool, if the agent is trying
            # to call an MCP tool or external API.
            "tool": tool,

            # The message hasn't been approved or rejected yet.
            # The later security modules will change this to
            # "ALLOWED", "BLOCKED", or "QUARANTINED".
            "decision": "PENDING",

            # Initial risk score.
            # Later, our risk engine will calculate a score from 0–100.
            "risk_score": 0,

            # List of threats discovered in the communication.
            # For example:
            # ["Prompt Injection", "Unauthorized Tool Access"]
            "threats": []
        }

        # Return the complete security event.
        return result
