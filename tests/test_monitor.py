"""The reference monitor: the decisions themselves."""

from __future__ import annotations

import pytest

from tests.conftest import TAINT_POLICY


def test_allows_an_ordinary_call(monitor):
    verdict = monitor(TAINT_POLICY).check("fs__read_file", "fs", {"path": "/w/notes.md"})
    assert verdict.allowed
    assert verdict.actions == ("read_files",)


def test_the_same_call_is_allowed_before_the_secret_and_refused_after(monitor):
    mon = monitor(TAINT_POLICY)
    write = ("fs__write_file", "fs", {"path": "/w/out.txt"})

    assert mon.check(*write).allowed, "a write with a clean session must pass"
    assert mon.check("fs__read_file", "fs", {"path": "/w/.env"}).allowed
    assert mon.state["tainted"] is True

    refused = mon.check(*write)
    assert not refused.allowed
    assert refused.violated == ("no_writes_after_secret_read",)


def test_taint_crosses_servers(monitor):
    mon = monitor(TAINT_POLICY)
    mon.check("fs__read_file", "fs", {"path": "/w/.ssh/id_rsa"})
    refused = mon.check("net__post", "net", {"url": "https://example.com"})
    assert not refused.allowed, "a taint raised on fs must close the exit on net"


def test_ordinary_reads_do_not_taint(monitor):
    mon = monitor(TAINT_POLICY)
    for _ in range(5):
        mon.check("fs__read_file", "fs", {"path": "/w/README.md"})
    assert mon.state == {"tainted": False, "secret_reads": 0}


def test_invariant_bounds_the_counter(monitor):
    mon = monitor(TAINT_POLICY)
    for index in range(2):
        assert mon.check("fs__read_file", "fs", {"path": f"/w/.env.{index}"}).allowed

    refused = mon.check("fs__read_file", "fs", {"path": "/w/.env.3"})
    assert not refused.allowed
    assert refused.violated == ("secret_read_budget",)
    assert "secret_reads <= 2" in refused.reason


def test_a_refused_call_leaves_the_state_alone(monitor):
    mon = monitor(TAINT_POLICY)
    mon.check("fs__read_file", "fs", {"path": "/w/.env"})
    before = mon.state
    mon.check("fs__write_file", "fs", {"path": "/w/out.txt"})
    assert mon.state == before


def test_a_guard_of_false_never_holds(monitor):
    verdict = monitor(TAINT_POLICY).check("fs__delete_file", "fs", {"path": "/w/x"})
    assert not verdict.allowed
    assert verdict.violated == ("never",)


def test_unmatched_tool_passes_unverified_by_default(monitor):
    verdict = monitor(TAINT_POLICY).check("other__thing", "other", {})
    assert verdict.allowed
    assert verdict.actions == ()


def test_unmatched_tool_is_refused_when_the_default_says_deny(monitor):
    mon = monitor(TAINT_POLICY.replace("default: allow", "default: deny"))
    verdict = mon.check("other__thing", "other", {})
    assert not verdict.allowed
    assert "default is deny" in verdict.reason


DECLARED_ARGS = """
    state:
      spent: {type: int, init: 0}
    invariants:
      - name: budget
        expr: spent <= 100
    actions:
      - name: transfer
        match: ["bank__transfer"]
        args: {amount: int}
        requires: amount > 0
        effect:
          spent: spent + amount
"""


def test_declared_arguments_are_used_in_guards(monitor):
    mon = monitor(DECLARED_ARGS)
    assert mon.check("bank__transfer", "bank", {"amount": 10}).allowed
    assert not mon.check("bank__transfer", "bank", {"amount": -1}).allowed
    assert mon.state["spent"] == 10


def test_a_missing_declared_argument_is_refused(monitor):
    verdict = monitor(DECLARED_ARGS).check("bank__transfer", "bank", {})
    assert not verdict.allowed
    assert "requires argument 'amount'" in verdict.reason


def test_a_mistyped_argument_is_refused(monitor):
    verdict = monitor(DECLARED_ARGS).check("bank__transfer", "bank", {"amount": "10"})
    assert not verdict.allowed
    assert "to be int, got str" in verdict.reason


def test_a_bool_is_not_an_int(monitor):
    verdict = monitor(DECLARED_ARGS).check("bank__transfer", "bank", {"amount": True})
    assert not verdict.allowed, "bool subclasses int in Python; the monitor must not accept it"


def test_split_transfers_are_caught_by_the_cumulative_invariant(monitor):
    mon = monitor(DECLARED_ARGS)
    assert mon.check("bank__transfer", "bank", {"amount": 60}).allowed
    refused = mon.check("bank__transfer", "bank", {"amount": 60})
    assert not refused.allowed, "each half is under the limit; their sum is not"
    assert refused.violated == ("budget",)


def test_the_call_context_is_in_scope(monitor):
    mon = monitor("""
        state:
          seen: {type: int, init: 0}
        invariants:
          - name: sane
            expr: seen >= 0
        actions:
          - name: only_from_trusted
            match: ["*"]
            requires: upstream == "trusted"
    """)
    assert mon.check("trusted__x", "trusted", {}).allowed
    assert not mon.check("other__x", "other", {}).allowed


def test_payload_matching_needs_no_argument_names(monitor):
    mon = monitor(TAINT_POLICY)
    # `paths` is a list, and the policy never mentions it — matching the JSON still works.
    mon.check("fs__read_multiple_files", "fs", {"paths": ["/w/a.md", "/w/.ssh/id_rsa"]})
    assert mon.state["tainted"] is True


@pytest.mark.parametrize("value", [{"path": "/w/.env"}, {"nested": {"path": "/w/.env"}}])
def test_payload_matching_sees_nested_values(monitor, value):
    mon = monitor(TAINT_POLICY)
    mon.check("fs__read_file", "fs", value)
    assert mon.state["tainted"] is True
