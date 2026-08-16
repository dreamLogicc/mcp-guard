"""The gateway itself, against a real stdio upstream spawned as a subprocess."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_guard.config import load_policy_spec
from mcp_guard.epca import EPCAPolicy
from mcp_guard.gateway import GatewayError, MCPGateway, Upstream, explain
from tests.conftest import TAINT_POLICY

STUB = Path(__file__).with_name("upstream_stub.py")


def stub_upstream(name: str = "fs") -> Upstream:
    return Upstream(name=name, command=sys.executable, args=(str(STUB),))


@pytest.fixture
def gateway(write_policy):
    def build(policy_body: str = TAINT_POLICY, *, name: str = "fs") -> MCPGateway:
        spec = load_policy_spec(write_policy(policy_body))
        return MCPGateway([stub_upstream(name)], policy=EPCAPolicy(spec))

    return build


@pytest.mark.anyio
async def test_tools_are_exposed_under_their_prefix(gateway):
    async with gateway() as guard:
        names = sorted(tool.name for tool in guard.list_tools())
    assert names == ["fs__ping", "fs__read_file", "fs__write_file"]


@pytest.mark.anyio
async def test_an_allowed_call_reaches_the_upstream(gateway):
    async with gateway() as guard:
        result = await guard.call_tool("fs__read_file", {"path": "/w/notes.md"})
    assert not result.is_error
    assert "contents of /w/notes.md" in result.content[0].text


@pytest.mark.anyio
async def test_a_refused_call_never_reaches_the_upstream(gateway):
    async with gateway() as guard:
        await guard.call_tool("fs__read_file", {"path": "/w/.env"})
        result = await guard.call_tool("fs__write_file", {"path": "/w/copy", "content": "x"})

    assert result.is_error
    text = result.content[0].text
    assert "mcp-guard blocked 'fs__write_file'" in text
    assert "no_writes_after_secret_read" in text
    assert "wrote" not in text, "the upstream must not have run"


@pytest.mark.anyio
async def test_the_same_call_is_allowed_before_the_secret(gateway):
    async with gateway() as guard:
        before = await guard.call_tool("fs__write_file", {"path": "/w/copy", "content": "x"})
        await guard.call_tool("fs__read_file", {"path": "/w/.env"})
        after = await guard.call_tool("fs__write_file", {"path": "/w/copy", "content": "x"})

    assert not before.is_error and after.is_error


@pytest.mark.anyio
async def test_an_unknown_tool_is_reported_not_raised(gateway):
    async with gateway() as guard:
        result = await guard.call_tool("fs__nope", {})
        unprefixed = await guard.call_tool("bare_name", {})
    assert result.is_error and "has no tool 'nope'" in result.content[0].text
    assert unprefixed.is_error and "unknown tool" in unprefixed.content[0].text


@pytest.mark.anyio
async def test_a_dead_upstream_does_not_take_the_gateway_down(write_policy):
    spec = load_policy_spec(write_policy(TAINT_POLICY))
    guard = MCPGateway(
        [stub_upstream("alive"), Upstream(name="dead", command="/nonexistent-binary")],
        policy=EPCAPolicy(spec),
    )
    async with guard:
        names = {tool.name.split("__")[0] for tool in guard.list_tools()}
    assert names == {"alive"}


class TestUpstreamValidation:
    def test_exactly_one_transport(self):
        with pytest.raises(GatewayError, match="exactly one"):
            Upstream(name="a")
        with pytest.raises(GatewayError, match="exactly one"):
            Upstream(name="a", url="http://x/mcp", command="npx")

    def test_headers_are_meaningless_over_stdio(self):
        from mcp_guard.auth import UpstreamAuth

        with pytest.raises(GatewayError, match="no HTTP headers"):
            Upstream(name="a", command="npx", auth=UpstreamAuth(token="t"))

    def test_duplicate_names_are_refused(self):
        guard = MCPGateway([Upstream(name="a", url="http://x/mcp")])
        with pytest.raises(GatewayError, match="duplicate upstream name"):
            guard.add_upstream(Upstream(name="a", url="http://y/mcp"))

    def test_a_name_is_derived_when_missing(self):
        guard = MCPGateway([Upstream(name="", url="https://mcp.github.com/mcp")])
        assert guard.upstreams[0].name == "mcp_github_com"


def test_explain_flattens_exception_groups():
    inner = ExceptionGroup("outer", [ValueError("first"), OSError("second")])
    flattened = explain(inner)
    assert "ValueError: first" in flattened and "OSError: second" in flattened
    assert "unhandled errors" not in flattened
