"""Plugging the reference monitor into the gateway's policy interface."""

from __future__ import annotations

from mcp_guard.epca.monitor import ReferenceMonitor
from mcp_guard.epca.spec import PolicySpec
from mcp_guard.policy import Policy, PolicyDecision, ToolCall


class EPCAPolicy(Policy):
    """Decides tool calls by SMT satisfiability against a `PolicySpec`.

    The transition is committed at authorization time, before the upstream runs: a
    call that fails or times out may still have had its effect, so an error must not
    wash away a taint.
    """

    def __init__(self, spec: PolicySpec) -> None:
        self._monitor = ReferenceMonitor(spec)

    @property
    def monitor(self) -> ReferenceMonitor:
        return self._monitor

    def check_tool_call(self, call: ToolCall) -> PolicyDecision:
        verdict = self._monitor.check(call.public_name, call.upstream, call.arguments)
        if not verdict.allowed:
            return PolicyDecision.deny(verdict.reason or "denied by policy")
        if not verdict.actions:
            return PolicyDecision.allow("no policy action covers this tool", verified=False)
        return PolicyDecision.allow(f"[{', '.join(verdict.actions)}] {self._monitor.describe_state()}")
