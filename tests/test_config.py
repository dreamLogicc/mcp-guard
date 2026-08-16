"""The server config, credentials, and the env file."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_guard.auth import AuthError, UpstreamAuth
from mcp_guard.config import ConfigError, load_env_file, load_upstreams, resolve_path


@pytest.fixture
def write_config(tmp_path: Path):
    def write(body: str) -> Path:
        path = tmp_path / "servers.yaml"
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return path

    return write


def test_remote_and_local_servers_load(write_config, monkeypatch):
    monkeypatch.setenv("TOK", "s3cret")
    upstreams = load_upstreams(
        write_config("""
        servers:
          short: https://short.example/mcp
          remote:
            url: https://remote.example/mcp
            token_env: TOK
          headered:
            url: https://headered.example/mcp
            headers: {X-Api-Key: "${TOK}"}
          local:
            command: npx
            args: ["-y", "pkg", "/work"]
            env: {EXTRA: "1"}
            cwd: /tmp
    """)
    )
    by_name = {u.name: u for u in upstreams}
    assert by_name["short"].url == "https://short.example/mcp"
    assert by_name["remote"].auth.resolve_headers("remote") == {"Authorization": "Bearer s3cret"}
    assert by_name["headered"].auth.headers == {"X-Api-Key": "s3cret"}
    assert by_name["local"].is_stdio
    assert by_name["local"].args == ("-y", "pkg", "/work")
    assert by_name["local"].target.startswith("npx -y pkg")


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ('servers: {a: {url: "http://x/mcp", header: {A: b}}}', "servers.a.header: Extra inputs"),
        ('servers: {a: {url: "http://x/mcp", tokenEnv: T}}', "tokenEnv: Extra inputs"),
        ("servers: {a: {}}", "exactly one of 'url'"),
        ('servers: {a: {url: "http://x/mcp", command: npx}}', "exactly one of 'url'"),
        ("servers: {a: {command: npx, headers: {A: b}}}", "no HTTP headers"),
        ('servers: {a: {url: "http://x/mcp", args: ["-y"]}}', "belong to a 'command' server"),
        ("servers: {a: {url: 8080}}", "url: Input should be a valid string"),
        ('servers: {a: {command: npx, args: "-y"}}', "args: Input should be a valid list"),
        ("servers: {}", "'servers' is empty"),
        ("servers: [a]", "servers: Input should be a valid dictionary"),
        ('servers: {a: "http://x/mcp"}\nextra: 1', "extra: Extra inputs"),
    ],
)
def test_malformed_configs_are_rejected(write_config, body, fragment):
    with pytest.raises(ConfigError) as excinfo:
        load_upstreams(write_config(body))
    assert fragment in str(excinfo.value)


def test_a_policy_in_the_server_file_is_pointed_elsewhere(write_config):
    with pytest.raises(ConfigError, match="its own file"):
        load_upstreams(write_config('servers: {a: "http://x/mcp"}\npolicy: {default: deny}'))


def test_an_unset_variable_stops_startup(write_config, monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    with pytest.raises(AuthError, match="is unset"):
        load_upstreams(write_config('servers: {a: {url: "http://x/mcp", headers: {A: "${NOPE}"}}}'))


def test_resolve_path_requires_a_source(monkeypatch):
    monkeypatch.delenv("MCP_GUARD_CONFIG", raising=False)
    with pytest.raises(ConfigError, match=r"pass --config PATH or set \$MCP_GUARD_CONFIG"):
        resolve_path(None, env_var="MCP_GUARD_CONFIG", flag="--config", kind="config")


def test_resolve_path_reports_a_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        resolve_path(tmp_path / "nope.yaml", env_var="X", flag="--config", kind="config")


def test_env_file_loads_without_overriding_the_environment(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(
        '# comment\nexport FROM_FILE=one\nQUOTED="two"\nALREADY=from-file\n\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ALREADY", "from-environment")
    monkeypatch.delenv("FROM_FILE", raising=False)

    loaded = load_env_file(path)

    assert "FROM_FILE" in loaded and "ALREADY" not in loaded
    import os

    assert os.environ["FROM_FILE"] == "one"
    assert os.environ["QUOTED"] == "two"
    assert os.environ["ALREADY"] == "from-environment", "the real environment wins"


def test_env_file_reports_a_bad_line(tmp_path):
    path = tmp_path / ".env"
    path.write_text("GOOD=1\nnonsense line\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="line 2: expected KEY=value"):
        load_env_file(path)


class TestCredentialPrecedence:
    def test_headers_win_over_a_token(self):
        auth = UpstreamAuth(headers={"Authorization": "Bearer explicit"}, token="ignored")
        assert auth.resolve_headers("x")["Authorization"] == "Bearer explicit"

    def test_token_env_is_read(self, monkeypatch):
        monkeypatch.setenv("T", "from-env")
        assert UpstreamAuth(token_env="T").resolve_headers("x") == {"Authorization": "Bearer from-env"}

    def test_a_missing_token_env_is_an_error(self, monkeypatch):
        monkeypatch.delenv("T", raising=False)
        with pytest.raises(AuthError, match="unset or empty"):
            UpstreamAuth(token_env="T").resolve_headers("x")

    def test_the_naming_convention_is_the_last_resort(self, monkeypatch):
        monkeypatch.setenv("MCP_GUARD_TOKEN_GITHUB", "conventional")
        assert UpstreamAuth().resolve_headers("github") == {"Authorization": "Bearer conventional"}

    def test_no_credentials_means_no_headers(self, monkeypatch):
        monkeypatch.delenv("MCP_GUARD_TOKEN_PLAIN", raising=False)
        assert UpstreamAuth().resolve_headers("plain") == {}

    def test_describe_never_shows_a_value(self, monkeypatch):
        monkeypatch.setenv("T", "super-secret-value")
        described = UpstreamAuth(token_env="T").describe("x")
        assert "super-secret-value" not in described
        assert "Authorization" in described
