from mcp.tools import MCPTools


class MCPGateway:
    """
    Gateway between Sentinel-A2A and the MCP tools.

    Sentinel-A2A decides whether a tool request is safe.
    Only approved requests should reach this gateway.
    """

    def __init__(self):
        # Initialize our simulated MCP tool server.
        self.tools = MCPTools()

    def execute(self, tool_name, **arguments):
        """
        Execute an MCP tool after Sentinel-A2A has approved it.

        Parameters:
            tool_name:
                Name of the requested MCP tool.

            arguments:
                Parameters required by that tool.

        Returns:
            Result returned by the MCP tool.
        """

        # Make sure the requested tool actually exists.
        tool = getattr(self.tools, tool_name, None)

        if tool is None:
            return {
                "status": "ERROR",
                "message": f"Unknown MCP tool: {tool_name}"
            }

        # Execute the requested MCP tool.
        return tool(**arguments) 