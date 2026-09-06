"""
Sentinel-A2A Agent-to-Agent Message Protocol.

This module defines a standard structure for communication
between AI agents before the message enters the firewall.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass
class A2AMessage:
    """
    Secure representation of an AI-agent-to-agent message.
    """

    source_agent: str
    target_agent: str
    message: str

    # Optional MCP tool requested by the source agent.
    tool: Optional[str] = None

    # Arguments that will eventually be passed to the tool.
    tool_arguments: Dict[str, Any] = field(
        default_factory=dict
    )

    # Unique identifier for tracing this message.
    message_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    # Timestamp created automatically in UTC.
    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    def to_dict(self):
        """
        Convert the A2A message into a dictionary.

        This format can be passed to the firewall,
        logged in Firestore, or sent through an API.
        """

        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "message": self.message,
            "tool": self.tool,
            "tool_arguments": self.tool_arguments
        }

    @classmethod
    def from_dict(cls, data):
        """
        Reconstruct an A2A message from a dictionary.
        """

        return cls(
            source_agent=data["source_agent"],
            target_agent=data["target_agent"],
            message=data["message"],
            tool=data.get("tool"),
            tool_arguments=data.get(
                "tool_arguments",
                {}
            ),
            message_id=data.get(
                "message_id",
                str(uuid.uuid4())
            ),
            timestamp=data.get(
                "timestamp",
                datetime.now(
                    timezone.utc
                ).isoformat()
            )
        )

    def validate(self):
        """
        Perform basic protocol validation.

        Returns:
            tuple:
                (True, "VALID") when valid
                (False, "reason") when invalid
        """

        if not self.source_agent:
            return False, "Source agent is missing."

        if not self.target_agent:
            return False, "Target agent is missing."

        if not self.message:
            return False, "Message is empty."

        if self.source_agent == self.target_agent:
            return (
                False,
                "Source and target agents cannot be identical."
            )

        if not isinstance(
            self.tool_arguments,
            dict
        ):
            return (
                False,
                "Tool arguments must be a dictionary."
            )

        return True, "VALID" 
