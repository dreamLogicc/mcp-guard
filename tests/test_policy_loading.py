"""Loading a policy: the strict schema, and the cross-checks the schema cannot do."""

from __future__ import annotations

import pytest

from praxiom.config import ConfigError, load_policy_spec

VALID = """state:
  n: {type: int, init: 0}
invariants:
  - name: ok
    expr: n >= 0
"""


def test_a_valid_policy_compiles(write_policy):
    spec = load_policy_spec(write_policy(VALID))
    assert spec.default == "allow"
    assert [inv.name for inv in spec.invariants] == ["ok"]


def test_scalars_are_accepted_where_yaml_makes_them(write_policy):
    spec = load_policy_spec(
        write_policy("""
        state:
          flag: {type: bool, init: false}
        invariants:
          - name: ok
            expr: implies(flag, flag)
        actions:
          - name: a
            match: fs__x
            effect: {flag: true}
    """)
    )
    assert spec.actions[0].patterns == ("fs__x",), "a single glob may be written without a list"


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        # schema
        ("state: {x: {type: int, init: 0}}\ninvariant: []", "invariant: Extra inputs"),
        ("state: {x: {type: integer, init: 0}}", "Input should be 'int', 'bool' or 'str'"),
        ("state: {x: {type: int}}", "state.x.init: Field required"),
        ("state: {x: {type: int, init: true}}", "'init' must be int"),
        ("default: alow\nstate: {x: {type: int, init: 0}}", "Input should be 'allow' or 'deny'"),
        (VALID + "actions: [{name: a, matches: '*'}]", "actions.0.match: Field required"),
        (VALID + "actions: [{name: a, match: '*', effekt: {n: 1}}]", "effekt: Extra inputs"),
        (
            "state: {x: {type: int, init: 0}}\n"
            "invariants: [{name: i, expr: 'x >= 0'}, {name: i, expr: 'x <= 9'}]",
            "duplicate invariant name",
        ),
        # cross-checks that need the whole file
        (VALID + "actions: [{name: a, match: '*', effect: {zzz: 1}}]", "unknown state variable 'zzz'"),
        (VALID + "actions: [{name: a, match: '*', effect: {n: 'true'}}]", "must produce int"),
        (VALID + "actions: [{name: a, match: '*', args: {n: str}}]", "shadows a state variable"),
        ("state: {payload: {type: str, init: ''}}", "reserved name"),
        ("state: {x: {type: int, init: 0}}", "nothing can ever be denied"),
        (
            VALID + "actions: [{name: a, match: '*', requires: 'matches(payload, nope)'}]",
            "unknown pattern list",
        ),
    ],
)
def test_malformed_policies_are_rejected(write_policy, body, fragment):
    with pytest.raises(ConfigError) as excinfo:
        load_policy_spec(write_policy(body))
    assert fragment in str(excinfo.value)


def test_an_eval_attempt_is_refused_at_load_time(write_policy):
    with pytest.raises(ConfigError, match="unknown function"):
        load_policy_spec(
            write_policy("""
            state: {x: {type: int, init: 0}}
            invariants:
              - name: i
                expr: '__import__("os").system("id")'
        """)
        )


def test_the_initial_state_must_satisfy_the_invariants(write_policy):
    from praxiom.epca import ReferenceMonitor, SpecError

    spec = load_policy_spec(
        write_policy("""
        state: {x: {type: int, init: 9}}
        invariants: [{name: cap, expr: 'x <= 5'}]
    """)
    )
    with pytest.raises(SpecError, match="initial state violates"):
        ReferenceMonitor(spec)


def test_errors_name_the_file_and_the_key(write_policy):
    path = write_policy("state: {x: {type: nope, init: 0}}")
    with pytest.raises(ConfigError) as excinfo:
        load_policy_spec(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert "state.x.type" in message
