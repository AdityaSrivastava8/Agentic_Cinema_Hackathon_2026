import json
import os


class PolicyEngine:
    """
    Sentinel-A2A policy enforcement layer.

    This component loads agent permissions from
    config/policies.json and decides whether a request
    should be:

        ALLOW
        QUARANTINE
        BLOCK
    """

    def __init__(self):
        # Find the project root directory.
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        # Build the path to the central security policy.
        policy_path = os.path.join(
            project_root,
            "config",
            "policies.json"
        )

        # Load the security policies.
        with open(policy_path, "r", encoding="utf-8") as file:
            self.policies = json.load(file)

        # Read risk thresholds from the policy file.
        risk_policy = self.policies["risk_policy"]

        self.quarantine_threshold = risk_policy["low_risk_max"] + 1
        self.block_threshold = risk_policy["high_risk_min"]

    def evaluate(
        self,
        risk_score,
        source_agent,
        tool=None
    ):
        """
        Evaluate an agent request against the security policy.

        Parameters:
            risk_score:
                Risk score from RiskEngine.

            source_agent:
                Agent requesting the action.

            tool:
                MCP/API tool being requested.

        Returns:
            ALLOW, QUARANTINE, or BLOCK.
        """

        # Get the security policy for this agent.
        agent_policy = self.policies["agents"].get(source_agent)

        # If the agent does not have a registered policy,
        # do not trust it by default.
        if agent_policy is None:
            return "BLOCK"

        # Check whether the requested tool is explicitly blocked.
        if tool in agent_policy["blocked_tools"]:
            return "BLOCK"

        # Check whether the tool is authorized.
        if tool and tool not in agent_policy["allowed_tools"]:
            return "BLOCK"

        # High-risk requests are blocked.
        if risk_score >= self.block_threshold:
            return "BLOCK"

        # Medium-risk requests require additional verification.
        if risk_score >= self.quarantine_threshold:
            return "QUARANTINE"

        # Everything else is allowed.
        return "ALLOW"
