"""The shipped examples must stay loadable — they are the documentation people copy."""

from __future__ import annotations

import pytest

from praxiom.config import load_policy_spec, load_upstreams
from praxiom.epca import ReferenceMonitor
from tests.conftest import REPO

EXAMPLES = sorted(p for p in (REPO / "examples").iterdir() if p.is_dir())
# The example configs name real credentials; the values are irrelevant to loading.
PLACEHOLDER_VARS = ["GITHUB_MCP_TOKEN", "ETHERSCAN_API_KEY", "INTERNAL_API_KEY", "CONTEXT7_API_KEY"]


@pytest.fixture(autouse=True)
def _placeholder_credentials(monkeypatch):
    for name in PLACEHOLDER_VARS:
        monkeypatch.setenv(name, "placeholder")


@pytest.mark.parametrize("directory", EXAMPLES, ids=lambda p: p.name)
def test_example_config_loads(directory):
    upstreams = load_upstreams(directory / "praxiom.yaml")
    assert upstreams
    for upstream in upstreams:
        assert upstream.url or upstream.command


@pytest.mark.parametrize("directory", EXAMPLES, ids=lambda p: p.name)
def test_example_policy_compiles_and_starts(directory):
    spec = load_policy_spec(directory / "praxiom-policy.yaml")
    assert spec.actions, "an example policy with no actions teaches nothing"
    ReferenceMonitor(spec)  # also checks s₀ against the invariants


def test_the_filesystem_example_blocks_the_two_step_leak():
    spec = load_policy_spec(REPO / "examples/filesystem/praxiom-policy.yaml")
    monitor = ReferenceMonitor(spec)

    assert monitor.check("fs__write_file", "fs", {"path": "/w/a.txt", "content": "x"}).allowed
    assert monitor.check("fs__read_text_file", "fs", {"path": "/w/.env"}).allowed
    assert not monitor.check("fs__write_file", "fs", {"path": "/w/a.txt", "content": "x"}).allowed


def test_the_mixed_example_carries_the_taint_between_servers():
    spec = load_policy_spec(REPO / "examples/mixed/praxiom-policy.yaml")
    monitor = ReferenceMonitor(spec)

    assert monitor.check("github__create_pull_request", "github", {"title": "t"}).allowed
    assert monitor.check("fs__read_text_file", "fs", {"path": "/w/.env"}).allowed

    for tool in ("github__create_pull_request", "docs__query-docs", "fs__write_file"):
        verdict = monitor.check(tool, tool.split("__")[0], {"q": "x"})
        assert not verdict.allowed, f"{tool} should be closed once the session is tainted"


def test_the_etherscan_example_only_counts():
    spec = load_policy_spec(REPO / "examples/etherscan/praxiom-policy.yaml")
    monitor = ReferenceMonitor(spec)
    assert monitor.check("etherscan__get_gas_oracle", "etherscan", {"chainid": "1"}).allowed
    assert monitor.state["calls"] == 1
