"""Local YAML files: the upstream servers, and — separately — the ePCA policy."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mcp_guard.auth import UpstreamAuth, expand_env
from mcp_guard.epca.spec import PolicySpec, SpecError, load_policy
from mcp_guard.gateway import GatewayError, Upstream
from mcp_guard.schema import ConfigFile, ServerEntry, describe_errors

CONFIG_ENV_VAR = "MCP_GUARD_CONFIG"
POLICY_ENV_VAR = "MCP_GUARD_POLICY"


class ConfigError(Exception):
    """A config file is missing, malformed, or has the wrong shape."""


def resolve_path(path: str | Path | None, *, env_var: str, flag: str, kind: str) -> Path:
    """Locate a config file: the explicit path, else the env var. No implicit defaults.

    Raises:
        ConfigError: Neither was given, or the file does not exist.
    """
    source = path if path is not None else os.environ.get(env_var)
    if not source:
        raise ConfigError(f"no {kind} given: pass {flag} PATH or set ${env_var}")
    resolved = Path(source).expanduser()
    if not resolved.is_file():
        raise ConfigError(f"{kind} {resolved} does not exist")
    return resolved


def _read_yaml(path: Path, kind: str) -> Any:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {kind} {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{kind} {path} is not valid YAML: {exc}") from exc
    if raw is None:
        raise ConfigError(f"{kind} {path} is empty")
    if not isinstance(raw, dict):
        raise ConfigError(f"{kind} {path}: expected a mapping at the top level")
    return raw


def load_policy_spec(path: str | Path | None = None) -> PolicySpec:
    """Read the ePCA policy from its own file.

    Raises:
        ConfigError: No path given, the file is missing, or the policy is malformed.
    """
    path = resolve_path(path, env_var=POLICY_ENV_VAR, flag="--policy", kind="policy")
    raw = _read_yaml(path, "policy")
    try:
        return load_policy(raw, context=f"policy {path}")
    except SpecError as exc:
        raise ConfigError(str(exc)) from exc


def load_upstreams(path: str | Path | None = None) -> list[Upstream]:
    """Read the server config and build the upstream list.

    Each key under `servers` becomes that server's tool-name prefix; `${VAR}` in any
    string is expanded from the environment. See examples/ for working files.

    Raises:
        ConfigError: Missing, not valid YAML, or the wrong shape.
        AuthError: A `${VAR}` reference is unset.
    """
    path = resolve_path(path, env_var=CONFIG_ENV_VAR, flag="--config", kind="config")
    raw = _read_yaml(path, "config")
    context = f"config {path}"

    if isinstance(raw, dict) and "policy" in raw:
        raise ConfigError(f"{context}: the policy lives in its own file; pass it with --policy PATH")

    try:
        parsed = ConfigFile.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(describe_errors(exc, context=context)) from exc

    return [_build_upstream(name, entry, context) for name, entry in parsed.servers.items()]


def _build_upstream(name: str, entry: ServerEntry, context: str) -> Upstream:
    where = f"{context}, servers.{name}"

    def expand(value: str) -> str:
        return expand_env(value, context=where)

    auth = UpstreamAuth(
        headers={key: expand(value) for key, value in entry.headers.items()},
        token=expand(entry.token) if entry.token else None,
        token_env=entry.token_env,
    )
    try:
        if entry.url:
            return Upstream(name=name, url=expand(entry.url), auth=auth)
        return Upstream(
            name=name,
            command=expand(entry.command or ""),
            args=tuple(expand(arg) for arg in entry.args),
            env={key: expand(value) for key, value in entry.env.items()},
            cwd=expand(entry.cwd) if entry.cwd else None,
            auth=auth,
        )
    except GatewayError as exc:
        raise ConfigError(f"{where}: {exc}") from exc
