"""The command line: the wiring that a `NameError` would break before anything runs."""

from __future__ import annotations

import textwrap

import pytest

from mcp_guard.cli import build_parser, main
from mcp_guard.gateway import MCPGateway
from mcp_guard.server import SERVER_NAME, build_server

POLICY = """
state:
  n: {type: int, init: 0}
invariants:
  - name: ok
    expr: n >= 0
actions:
  - name: nothing
    match: ["never__matches"]
    requires: "false"
"""
CONFIG = 'servers: {a: "https://example.invalid/mcp"}\n'


@pytest.fixture(autouse=True)
def _no_ambient_configuration(monkeypatch):
    for name in ("MCP_GUARD_CONFIG", "MCP_GUARD_POLICY", "MCP_GUARD_ENV_FILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def files(tmp_path):
    (tmp_path / "policy.yaml").write_text(textwrap.dedent(POLICY).lstrip(), encoding="utf-8")
    (tmp_path / "servers.yaml").write_text(CONFIG, encoding="utf-8")
    return tmp_path


def test_every_documented_flag_exists():
    options = {action.option_strings[0] for action in build_parser()._actions if action.option_strings}
    assert {
        "--config",
        "--policy",
        "--env-file",
        "--http",
        "--log-arguments",
        "--log-level",
        "--color",
    } <= options


def test_the_parser_builds_without_a_missing_name():
    # `--env-file` reads its default from the environment at parser-build time;
    # a stale import here used to raise NameError before argparse ever ran.
    assert build_parser().parse_args([]).config is None


def test_no_policy_is_an_error_not_a_silent_pass(capsys):
    assert main([]) == 2
    assert "no policy given" in capsys.readouterr().err


def test_no_config_is_an_error(files, capsys):
    assert main(["--policy", str(files / "policy.yaml")]) == 2
    assert "no config given" in capsys.readouterr().err


def test_a_missing_file_is_reported(files, capsys):
    assert main(["--policy", str(files / "nope.yaml")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_a_malformed_policy_is_reported(tmp_path, capsys):
    (tmp_path / "bad.yaml").write_text("state: {x: {type: nope, init: 0}}\n", encoding="utf-8")
    assert main(["--policy", str(tmp_path / "bad.yaml")]) == 2
    assert "state.x.type" in capsys.readouterr().err


def test_an_unresolvable_credential_stops_startup(files, tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    (tmp_path / "servers.yaml").write_text(
        'servers: {a: {url: "https://example.invalid/mcp", token_env: MISSING_TOKEN}}\n', encoding="utf-8"
    )
    assert main(["--policy", str(files / "policy.yaml"), "--config", str(tmp_path / "servers.yaml")]) == 2
    assert "MISSING_TOKEN" in capsys.readouterr().err


def test_the_env_file_supplies_the_token(files, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SUPPLIED_TOKEN", raising=False)
    (tmp_path / ".env").write_text("SUPPLIED_TOKEN=value\n", encoding="utf-8")
    (tmp_path / "servers.yaml").write_text(
        'servers: {a: {url: "https://example.invalid/mcp", token_env: SUPPLIED_TOKEN}}\n', encoding="utf-8"
    )
    # Serving is not reached: a bad --http value fails after the config is accepted.
    code = main(
        [
            "--policy",
            str(files / "policy.yaml"),
            "--config",
            str(tmp_path / "servers.yaml"),
            "--env-file",
            str(tmp_path / ".env"),
            "--http",
            "not-a-port",
        ]
    )
    assert code == 2
    assert "--http expects" in capsys.readouterr().err, "the credential resolved; only --http failed"


def test_the_mcp_server_is_wired_to_the_gateway():
    server = build_server(MCPGateway())
    assert server.name == SERVER_NAME
    options = server.create_initialization_options()
    assert options.capabilities.tools is not None, "the gateway must advertise tools"
