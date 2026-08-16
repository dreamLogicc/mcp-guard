"""A minimal stdio MCP server, spawned by the end-to-end test as a real subprocess.

Kept deliberately dull: the point of the test is the gateway in front of it.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("stub")


@server.tool()
def read_file(path: str) -> str:
    """Return the contents of a file."""
    return f"contents of {path}"


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write a file."""
    return f"wrote {len(content)} bytes to {path}"


@server.tool()
def ping() -> str:
    """Answer with pong."""
    return "pong"


if __name__ == "__main__":
    server.run()
