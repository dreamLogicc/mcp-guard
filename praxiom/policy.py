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
    """Why it was denied; shown to the model and written to the audit line."""

    detail: str | None = None
    """What the policy wants on the audit line either way, e.g. the resulting state."""

    verified: bool = True
    """False when the policy had no rule for this call and let it through by default."""

    @classmethod
    def allow(cls, detail: str | None = None, *, verified: bool = True) -> PolicyDecision:
        return cls(allowed=True, detail=detail, verified=verified)

    @classmethod
    def deny(cls, reason: str, detail: str | None = None) -> PolicyDecision:
        return cls(allowed=False, reason=reason, detail=detail)


class Policy:
    """Base policy: forwards everything. See `praxiom.epca.EPCAPolicy`."""

    def check_tool_call(self, call: ToolCall) -> PolicyDecision:
        """Whether `call` may be forwarded to its upstream."""
        return PolicyDecision.allow()
