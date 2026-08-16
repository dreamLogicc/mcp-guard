"""Redaction and shortening — the audit line must not become the leak."""

from __future__ import annotations

import pytest

from praxiom import audit


@pytest.mark.parametrize(
    "key",
    ["token", "api_key", "apiKey", "password", "AUTHORIZATION", "secret", "cookie", "credentials"],
)
def test_credential_shaped_keys_are_blanked(key):
    rendered = audit.render_arguments({key: "sk-live-real-value"}, mode="redacted")
    assert "sk-live-real-value" not in rendered
    assert "***" in rendered


def test_ordinary_values_survive():
    rendered = audit.render_arguments({"path": "/w/notes.md"}, mode="redacted")
    assert "/w/notes.md" in rendered


def test_nested_and_listed_credentials_are_blanked():
    rendered = audit.render_arguments(
        {"config": {"token": "leak-me"}, "tokens": ["leak-me-too"]}, mode="redacted"
    )
    assert "leak-me" not in rendered


def test_none_mode_writes_nothing():
    assert audit.render_arguments({"token": "x"}, mode="none") == ""


def test_full_mode_is_verbatim():
    rendered = audit.render_arguments({"token": "sk-live"}, mode="full")
    assert "sk-live" in rendered, "full mode is opt-in and documented as unsafe"


def test_long_values_lose_the_middle_not_the_tail():
    path = "/home/gondin02/py_projects/deeply/nested/directory/tree/.ssh/id_rsa"
    rendered = audit.render_arguments({"path": path}, mode="redacted")
    assert "id_rsa" in rendered, "the tail identifies what was touched"
    assert rendered.startswith('"path"="/home')
    assert "…" in rendered


def test_shorten_keeps_both_ends():
    assert audit.shorten("abcdefghij", 20) == "abcdefghij"
    shortened = audit.shorten("a" * 30 + "TAIL", 20)
    assert len(shortened) == 20
    assert shortened.startswith("aaa") and shortened.endswith("TAIL")


def test_an_audit_line_carries_the_verdict_tool_and_latency(caplog):
    with caplog.at_level("INFO", logger="praxiom.audit"):
        audit.call(
            verdict="DENY",
            tool="fs__write_file",
            arguments='"path"="x"',
            detail="fails guard 'g'",
            elapsed_ms=12.4,
        )
    line = caplog.records[-1].getMessage()
    assert line.startswith("DENY ")
    assert "fs__write_file" in line and "fails guard 'g'" in line and "12ms" in line


def test_colour_is_off_unless_asked_for():
    audit.enable_color(False)
    assert "\033[" not in audit.paint("text", "red")
    audit.enable_color(True)
    try:
        assert "\033[" in audit.paint("text", "red")
    finally:
        audit.enable_color(False)
