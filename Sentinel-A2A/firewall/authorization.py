import json
import os


class AuthorizationEngine:
    """
    Controls which AI agents are allowed to access
    which MCP tools.

    This implements a basic least-privilege model:

        Agent Identity
              ↓
        Permission Check
              ↓
        ALLOWED / DENIED
    """

    def __init__(self):
        # Find the root directory of Sentinel-A2A.
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        # Locate the central security policy file.
        policy_path = os.path.join(
            project_root,
            "config",
            "policies.json"
        )

        # Load the policies.
        with open(policy_path, "r", encoding="utf-8") as file:
            self.policies = json.load(file)

    def is_authorized(self, agent_name, tool_name):
        """
        Check whether an agent is authorized to use a tool.

        Parameters:
            agent_name:
                Identity of the requesting AI agent.

            tool_name:
                MCP/API tool the agent wants to use.

        Returns:
            True  → authorized
            False → denied
        """

        # Find the policy associated with this agent.
        agent_policy = self.policies["agents"].get(agent_name)

        # Unknown agents are not trusted.
        if agent_policy is None:
            return False

        # Explicitly blocked tools always remain blocked.
        if tool_name in agent_policy["blocked_tools"]:
            return False

        # The tool must be explicitly listed as allowed.
        if tool_name not in agent_policy["allowed_tools"]:
            return False

        return True
