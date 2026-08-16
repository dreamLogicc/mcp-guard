"""praxiom: an MCP gateway fronting several upstream MCP servers.

Speaks stdio to one MCP client, exposes the union of the upstream tools under
per-upstream prefixes, and routes `tools/call` back to the owning upstream after a
policy check. Configured by `praxiom.yaml` and `praxiom-policy.yaml`.
"""

from praxiom.auth import AuthError, UpstreamAuth
from praxiom.config import ConfigError, load_policy_spec, load_upstreams
from praxiom.epca import EPCAPolicy, PolicySpec, ReferenceMonitor, SpecError, Verdict
from praxiom.gateway import GatewayError, MCPGateway, Upstream
from praxiom.policy import Policy, PolicyDecision, ToolCall

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
