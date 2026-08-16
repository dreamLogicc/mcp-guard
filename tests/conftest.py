"""Shared fixtures. Nothing here reaches the network or needs credentials."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_guard.config import load_policy_spec
from mcp_guard.epca import ReferenceMonitor

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def write_policy(tmp_path: Path):
    """Write a policy file from inline YAML and return its path."""

    def write(body: str, name: str = "policy.yaml") -> Path:
        path = tmp_path / name
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return path

    return write


@pytest.fixture
def monitor(write_policy):
    """Build a reference monitor from inline policy YAML."""

    def build(body: str) -> ReferenceMonitor:
        return ReferenceMonitor(load_policy_spec(write_policy(body)))

    return build


TAINT_POLICY = """
    default: allow
    patterns:
      secret_paths: ["/.ssh", "/.env", "id_rsa"]
    state:
      tainted: {type: bool, init: false}
      secret_reads: {type: int, init: 0}
    invariants:
      - name: secret_read_budget
        expr: secret_reads <= 2
    actions:
      - name: read_files
        match: ["fs__read*"]
        effect:
          tainted: tainted or matches(payload, secret_paths)
          secret_reads: secret_reads + ite(matches(payload, secret_paths), 1, 0)
      - name: no_writes_after_secret_read
        match: ["fs__write*", "net__post"]
        requires: not tainted
      - name: never
        match: ["fs__delete*"]
        requires: "false"
"""
