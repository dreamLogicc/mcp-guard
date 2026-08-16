"""The gateway: one object holding every upstream MCP and its tools."""

from __future__ import annotations

import logging
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import anyio
import mcp_types as types
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.exceptions import MCPError

from mcp_guard import audit
from mcp_guard.auth import UpstreamAuth
from mcp_guard.policy import Policy, PolicyDecision, ToolCall

logger = logging.getLogger(__name__)

PREFIX_SEPARATOR = "__"
"""Separator between the upstream name and the upstream's own tool name."""

_ALLOWED_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


class GatewayError(Exception):
    """Configuration or routing error raised by the gateway."""


@dataclass(slots=True)
class Upstream:
    """One upstream: remote over streamable HTTP (`url`), or a local stdio subprocess."""

    name: str
    """Prefix this upstream's tools are exposed under."""

    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    """Extra environment for `command`, merged over the inherited one."""

    cwd: str | None = None

    auth: UpstreamAuth = field(default_factory=UpstreamAuth)
    """HTTP credentials. A stdio upstream takes secrets via `env`."""

    client: Client | None = field(default=None, repr=False)
    """`None` until `MCPGateway.connect` runs."""

    tools: dict[str, types.Tool] = field(default_factory=dict, repr=False)
    """Upstream tool definitions, keyed by their unprefixed name."""

    def __post_init__(self) -> None:
        if bool(self.url) == bool(self.command):
            raise GatewayError(f"upstream {self.name or '<unnamed>'}: give exactly one of 'url' or 'command'")
        if self.command and not self.auth.is_empty:
            raise GatewayError(
                f"upstream {self.name or '<unnamed>'}: a stdio upstream has no HTTP headers; "
                "pass its credentials through 'env' instead"
            )

    @property
    def is_stdio(self) -> bool:
        return self.command is not None

    @property
    def target(self) -> str:
        """How this upstream is reached, for logs."""
        if self.url is not None:
            return self.url
        return " ".join([self.command or "", *self.args]).strip()

    @property
    def connected(self) -> bool:
        return self.client is not None


class MCPGateway:
    """Aggregates the tools of several upstream MCP servers behind one interface.

    Usage:
        ```python
        gateway = MCPGateway(load_upstreams(), policy=EPCAPolicy(spec))
        async with gateway:
            result = await gateway.call_tool("fs__read_file", {"path": "notes.md"})
        ```
    """

    def __init__(
        self,
        upstreams: list[Upstream] | None = None,
        *,
        policy: Policy | None = None,
        separator: str = PREFIX_SEPARATOR,
        log_arguments: str = "redacted",
    ) -> None:
        self._upstreams: dict[str, Upstream] = {}
        self._policy = policy or Policy()
        self._separator = separator
        self._log_arguments = log_arguments
        self._exit_stack: AsyncExitStack | None = None
        self._refresh_lock = anyio.Lock()

        for upstream in upstreams or []:
            self.add_upstream(upstream)

    @classmethod
    def from_urls(
        cls,
        urls: list[str],
        *,
        policy: Policy | None = None,
        separator: str = PREFIX_SEPARATOR,
    ) -> MCPGateway:
        """Build an unauthenticated gateway from `URL` or `name=URL` strings.

        For tests and embedding; the CLI goes through `mcp_guard.config` instead.
        """
        gateway = cls(policy=policy, separator=separator)
        for spec in urls:
            name, url = parse_upstream_spec(spec)
            gateway.add_upstream(Upstream(name=name or "", url=url))
        return gateway

    def add_upstream(self, upstream: Upstream) -> Upstream:
        """Register an upstream, naming it after its target if it has no name."""
        if self._exit_stack is not None:
            raise GatewayError("cannot add an upstream to a connected gateway")
        if not upstream.name:
            upstream.name = self._unique_name(default_name(upstream.target))
        if upstream.name in self._upstreams:
            raise GatewayError(f"duplicate upstream name: {upstream.name!r}")
        if not set(upstream.name) <= _ALLOWED_NAME_CHARS:
            raise GatewayError(
                f"invalid upstream name {upstream.name!r}: only letters, digits, '_' and '-' are allowed"
            )
        self._upstreams[upstream.name] = upstream
        return upstream

    @property
    def upstreams(self) -> list[Upstream]:
        return list(self._upstreams.values())

    @property
    def policy(self) -> Policy:
        return self._policy

    def _unique_name(self, candidate: str) -> str:
        if candidate not in self._upstreams:
            return candidate
        for suffix in range(2, 1000):
            name = f"{candidate}_{suffix}"
            if name not in self._upstreams:
                return name
        raise GatewayError(f"cannot derive a unique name from {candidate!r}")

    async def __aenter__(self) -> MCPGateway:
        await self.connect()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    async def connect(self) -> None:
        """Connect to every upstream and load its tool list."""
        if self._exit_stack is not None:
            raise GatewayError("gateway is already connected")

        stack = AsyncExitStack()
        await stack.__aenter__()
        self._exit_stack = stack
        try:
            for upstream in self._upstreams.values():
                try:
                    upstream.client = await self._open_client(upstream, stack)
                except Exception as exc:
                    # One unreachable upstream must not take the whole gateway down.
                    logger.error(
                        "upstream %s (%s): connection failed: %s",
                        upstream.name,
                        upstream.target,
                        explain(exc),
                    )
                    logger.debug("upstream %s: connection traceback", upstream.name, exc_info=True)
                    upstream.client = None
            await self.refresh_tools()
        except BaseException:
            self._exit_stack = None
            await stack.aclose()
            raise

    async def _open_client(self, upstream: Upstream, stack: AsyncExitStack) -> Client:
        """Connect one upstream, carrying its credentials if it has any."""
        if upstream.is_stdio:
            logger.info("upstream %s: spawning %s", upstream.name, upstream.target)
            parameters = StdioServerParameters(
                command=upstream.command or "",
                args=list(upstream.args),
                env=dict(upstream.env) or None,
                cwd=upstream.cwd,
            )
            # errlog defaults to our stderr, keeping the child's logs off the transport.
            return await stack.enter_async_context(Client(stdio_client(parameters)))

        headers = upstream.auth.resolve_headers(upstream.name)
        auth_flow = upstream.auth.httpx_auth
        if not headers and auth_flow is None:
            logger.info("upstream %s: connecting unauthenticated", upstream.name)
            return await stack.enter_async_context(Client(upstream.url))

        logger.info("upstream %s: connecting with %s", upstream.name, upstream.auth.describe(upstream.name))
        # The transport does not own a caller-provided http client, so the gateway keeps it.
        http_client = await stack.enter_async_context(
            create_mcp_http_client(headers=headers or None, auth=auth_flow)
        )
        transport = streamable_http_client(upstream.url, http_client=http_client)
        return await stack.enter_async_context(Client(transport))

    async def aclose(self) -> None:
        """Disconnect every upstream."""
        stack, self._exit_stack = self._exit_stack, None
        for upstream in self._upstreams.values():
            upstream.client = None
            upstream.tools.clear()
        if stack is not None:
            await stack.aclose()

    async def refresh_tools(self) -> None:
        """Re-fetch `tools/list` from every connected upstream, in parallel."""
        async with self._refresh_lock, anyio.create_task_group() as tg:
            for upstream in self._upstreams.values():
                if upstream.connected:
                    tg.start_soon(self._load_tools, upstream)

    async def _load_tools(self, upstream: Upstream) -> None:
        assert upstream.client is not None
        tools: dict[str, types.Tool] = {}
        cursor: str | None = None
        try:
            while True:
                page = await upstream.client.list_tools(cursor=cursor)
                for tool in page.tools:
                    tools[tool.name] = tool
                cursor = page.next_cursor
                if cursor is None:
                    break
        except Exception as exc:
            logger.error("upstream %s: tools/list failed: %s", upstream.name, explain(exc))
            logger.debug("upstream %s: tools/list traceback", upstream.name, exc_info=True)
            return
        upstream.tools = tools
        logger.info("upstream %s: %d tool(s)", upstream.name, len(tools))

    def list_tools(self) -> list[types.Tool]:
        """The union of all upstream tools, renamed to their prefixed names."""
        listing: list[types.Tool] = []
        for upstream in self._upstreams.values():
            for tool in upstream.tools.values():
                listing.append(tool.model_copy(update={"name": self.public_name(upstream.name, tool.name)}))
        return listing

    def public_name(self, upstream: str, tool: str) -> str:
        return f"{upstream}{self._separator}{tool}"

    def resolve(self, public_name: str) -> tuple[Upstream, types.Tool]:
        """Map a prefixed tool name back to its upstream and definition."""
        upstream_name, separator, tool_name = public_name.partition(self._separator)
        if not separator:
            raise GatewayError(f"unknown tool: {public_name!r}")
        upstream = self._upstreams.get(upstream_name)
        if upstream is None:
            raise GatewayError(f"unknown upstream {upstream_name!r} for tool {public_name!r}")
        tool = upstream.tools.get(tool_name)
        if tool is None:
            raise GatewayError(f"upstream {upstream_name!r} has no tool {tool_name!r}")
        return upstream, tool

    async def call_tool(
        self, public_name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        """Check the policy, then forward the call to the owning upstream.

        Denials and failures come back as `is_error` results rather than exceptions,
        so the model can see the reason and react.
        """
        try:
            upstream, tool = self.resolve(public_name)
        except GatewayError as exc:
            return _error_result(str(exc))

        call = ToolCall(
            upstream=upstream.name,
            tool=tool.name,
            public_name=public_name,
            arguments=arguments or {},
            definition=tool,
        )
        shown = audit.render_arguments(call.arguments, mode=self._log_arguments)
        decision = self._policy.check_tool_call(call)
        if not decision.allowed:
            audit.call(
                verdict="DENY",
                tool=public_name,
                arguments=shown,
                detail=decision.reason or "denied by policy",
                level=logging.WARNING,
            )
            return _denied_result(call, decision)

        if upstream.client is None:
            audit.call(verdict="ERROR", tool=public_name, arguments=shown, detail="upstream not connected")
            return _error_result(f"upstream {upstream.name!r} is not connected")

        started = time.perf_counter()
        try:
            result = await upstream.client.call_tool(tool.name, arguments)
        except Exception as exc:
            audit.call(
                verdict="ERROR",
                tool=public_name,
                arguments=shown,
                detail=explain(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                level=logging.WARNING if isinstance(exc, MCPError) else logging.ERROR,
            )
            logger.debug("upstream %s: tools/call traceback", upstream.name, exc_info=True)
            if isinstance(exc, MCPError):
                return _error_result(f"upstream {upstream.name!r} returned an error: {exc}")
            return _error_result(f"calling {public_name!r} failed: {explain(exc)}")

        audit.call(
            verdict="ALLOW" if decision.verified else "PASS",
            tool=public_name,
            arguments=shown,
            detail=decision.detail or "",
            elapsed_ms=(time.perf_counter() - started) * 1000,
            level=logging.INFO if decision.verified else logging.WARNING,
        )
        return result


def explain(exc: BaseException) -> str:
    """Flatten an exception into one log line.

    Transports run inside task groups, so failures arrive as an `ExceptionGroup`
    whose own message says nothing; the leaves are what matter.
    """
    if isinstance(exc, BaseExceptionGroup):
        leaves = [explain(inner) for inner in exc.exceptions]
        return "; ".join(dict.fromkeys(leaves))
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _error_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def _denied_result(call: ToolCall, decision: PolicyDecision) -> types.CallToolResult:
    reason = decision.reason or "denied by policy"
    return _error_result(f"mcp-guard blocked {call.public_name!r}: {reason}")


def parse_upstream_spec(spec: str) -> tuple[str | None, str]:
    """Split a `name=URL` spec into its parts; a bare URL yields no name."""
    name, separator, url = spec.partition("=")
    if separator and "://" not in name:
        return name.strip(), url.strip()
    return None, spec.strip()


def default_name(target: str) -> str:
    """Derive a name from a target, e.g. `mcp.github.com` -> `mcp_github_com`."""
    parts = urlsplit(target)
    source = parts.hostname or (target.split()[0] if target.split() else target)
    sanitized = "".join(char if char in _ALLOWED_NAME_CHARS else "_" for char in source).strip("_")
    return sanitized or "mcp"
