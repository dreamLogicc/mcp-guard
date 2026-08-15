"""The policy interface the gateway consults before forwarding a tool call."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import mcp_types as types


@dataclass(frozen=True, slots=True)
class ToolCall:
    """Everything a policy gets to look at for a single call."""

    upstream: str
    tool: str
    """Tool name as the upstream knows it, without the gateway prefix."""

    public_name: str
    """Prefixed name the MCP client used, e.g. `github__create_issue`."""

    arguments: dict[str, Any] = field(default_factory=dict)
    definition: types.Tool | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Verdict for one `ToolCall`."""

    allowed: bool
    reason: str | None = None

    @classmethod
    def allow(cls) -> PolicyDecision:
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: str) -> PolicyDecision:
        return cls(allowed=False, reason=reason)


class Policy:
    """Base policy: forwards everything. See `mcp_guard.epca.EPCAPolicy`."""

    def check_tool_call(self, call: ToolCall) -> PolicyDecision:
        """Whether `call` may be forwarded to its upstream."""
        return PolicyDecision.allow()
