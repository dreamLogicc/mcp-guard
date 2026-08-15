"""mcp-guard: an MCP gateway fronting several upstream MCP servers.

Speaks stdio to one MCP client, exposes the union of the upstream tools under
per-upstream prefixes, and routes `tools/call` back to the owning upstream after a
policy check. Configured by `mcp-guard.yaml` and `mcp-guard-policy.yaml`.
"""

from mcp_guard.auth import AuthError, UpstreamAuth
from mcp_guard.config import ConfigError, load_policy_spec, load_upstreams
from mcp_guard.epca import EPCAPolicy, PolicySpec, ReferenceMonitor, SpecError, Verdict
from mcp_guard.gateway import GatewayError, MCPGateway, Upstream
from mcp_guard.policy import Policy, PolicyDecision, ToolCall

__all__ = [
    "AuthError",
    "ConfigError",
    "EPCAPolicy",
    "GatewayError",
    "MCPGateway",
    "Policy",
    "PolicyDecision",
    "PolicySpec",
    "ReferenceMonitor",
    "SpecError",
    "ToolCall",
    "Upstream",
    "UpstreamAuth",
    "Verdict",
    "load_policy_spec",
    "load_upstreams",
]
