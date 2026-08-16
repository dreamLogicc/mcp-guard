"""The MCP server the client talks to; every request is proxied by the gateway."""

from __future__ import annotations

import logging

import mcp_types as types
import uvicorn
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server

from mcp_guard.gateway import MCPGateway

logger = logging.getLogger(__name__)

SERVER_NAME = "mcp-guard"
SERVER_VERSION = "0.1.0"
INSTRUCTIONS = (
    "Gateway over several MCP servers. Tool names carry their upstream as a prefix. "
    "Calls are checked against the gateway policy before being forwarded."
)


def build_server(gateway: MCPGateway) -> Server[None]:
    """Wire a lowlevel MCP server whose tools are the gateway's tools."""

    async def on_list_tools(
        ctx: ServerRequestContext[None, types.PaginatedRequestParams | None],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        # The full union is held in memory, so it is returned unpaginated.
        return types.ListToolsResult(tools=gateway.list_tools())

    async def on_call_tool(
        ctx: ServerRequestContext[None, types.CallToolRequestParams],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        return await gateway.call_tool(params.name, params.arguments)

    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _announce(gateway: MCPGateway, how: str) -> None:
    logger.info(
        "serving %d upstream(s), %d tool(s) over %s",
        len(gateway.upstreams),
        len(gateway.list_tools()),
        how,
    )


async def serve_stdio(gateway: MCPGateway) -> None:
    """Connect the upstreams, then serve over stdio until the client leaves.

    The client owns this process: it spawns the gateway and kills it on exit.
    """
    async with gateway:
        server = build_server(gateway)
        _announce(gateway, "stdio")
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(NotificationOptions(tools_changed=True)),
            )


async def serve_http(gateway: MCPGateway, host: str, port: int, path: str = "/mcp") -> None:
    """Serve over streamable HTTP as a long-lived process of its own.

    Unlike stdio, this outlives any one client and several may connect at once —
    which also means they share one verification state, so a taint raised by one
    client constrains the others.
    """
    async with gateway:
        server = build_server(gateway)
        app = server.streamable_http_app(streamable_http_path=path, host=host)
        _announce(gateway, f"http://{host}:{port}{path}")
        if host not in ("127.0.0.1", "localhost", "::1"):
            logger.warning("bound to %s: anyone who can reach this port can call every upstream tool", host)
        # log_config=None keeps uvicorn from replacing the audit formatter.
        config = uvicorn.Config(app, host=host, port=port, log_config=None, access_log=False)
        await uvicorn.Server(config).serve()
