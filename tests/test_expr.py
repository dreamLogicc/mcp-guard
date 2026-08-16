"""The expression grammar: what compiles, and — more importantly — what does not."""

from __future__ import annotations

import pytest
import z3

from praxiom.epca.expr import ExprError, compile_condition, compile_expr

SCOPE = {
    "n": z3.Int("n"),
    "flag": z3.Bool("flag"),
    "path": z3.String("path"),
    "payload": z3.String("payload"),
}
PATTERNS = {"secrets": ("/.ssh", ".env")}


def evaluate(source: str, **values) -> bool:
    """Compile a condition and decide it against concrete values."""
    solver = z3.Solver()
    for name, value in values.items():
        const = SCOPE[name]
        literal = {int: z3.IntVal, bool: z3.BoolVal, str: z3.StringVal}[type(value)](value)
        solver.add(const == literal)
    solver.add(compile_condition(source, SCOPE, patterns=PATTERNS, where="test"))
    return solver.check() == z3.sat


@pytest.mark.parametrize(
    ("source", "values", "expected"),
    [
        ("n > 3", {"n": 4}, True),
        ("n > 3", {"n": 3}, False),
        ("0 < n <= 5", {"n": 5}, True),
        ("0 < n <= 5", {"n": 6}, False),
        ("n + 2 * 3 == 8", {"n": 2}, True),
        ("not flag", {"flag": False}, True),
        ("flag and n > 0", {"flag": True, "n": 1}, True),
        ("flag or n > 0", {"flag": False, "n": -1}, False),
        ("implies(flag, n > 0)", {"flag": False, "n": -5}, True),
        ("implies(flag, n > 0)", {"flag": True, "n": -5}, False),
        ("ite(flag, n, 0) == 7", {"flag": True, "n": 7}, True),
        ('startswith(path, "/home")', {"path": "/home/u/x"}, True),
        ('endswith(path, ".py")', {"path": "main.py"}, True),
        ('contains(path, "src")', {"path": "a/src/b"}, True),
        ("matches(path, secrets)", {"path": "/home/u/.ssh/id_rsa"}, True),
        ("matches(path, secrets)", {"path": "/home/u/notes.md"}, False),
        ('member(path, ["a", "b"])', {"path": "b"}, True),
        ('member(path, ["a", "b"])', {"path": "c"}, False),
        ("true", {}, True),
        ("false", {}, False),
    ],
)
def test_grammar_evaluates(source, values, expected):
    assert evaluate(source, **values) is expected


def test_matches_accepts_an_inline_list():
    assert evaluate('matches(path, ["zzz", ".env"])', path="/app/.env.local") is True


@pytest.mark.parametrize(
    ("source", "fragment"),
    [
        ('__import__("os").system("id")', "unknown function"),
        ("path.__class__", "Attribute"),
        ("[1, 2]", "List"),
        ("{1: 2}", "Dict"),
        ("lambda: 1", "Lambda"),
        ("n if flag else 0", "IfExp"),
        ("f(n)", "unknown function"),
        ("unknown_name > 1", "unknown name"),
        ("matches(path, nope)", "unknown pattern list"),
        ("implies(flag)", "takes exactly 2"),
        ("ite(flag, 1)", "takes exactly 3"),
        ("ite(n, 1, 2)", "first argument of ite"),
        ("", "non-empty string"),
        ("n >", "cannot parse"),
        ("n << 2", "operator LShift"),
    ],
)
def test_grammar_rejects(source, fragment):
    with pytest.raises(ExprError) as excinfo:
        compile_expr(source, SCOPE, patterns=PATTERNS, where="test")
    assert fragment in str(excinfo.value)


def test_type_errors_are_reported():
    with pytest.raises(ExprError, match="ill-typed"):
        compile_expr('n > "text"', SCOPE, patterns=PATTERNS, where="test")


def test_condition_must_be_boolean():
    with pytest.raises(ExprError, match="expected a boolean condition"):
        compile_condition("n + 1", SCOPE, patterns=PATTERNS, where="test")


def test_error_message_names_the_location_and_scope():
    with pytest.raises(ExprError) as excinfo:
        compile_expr("zzz", SCOPE, where="policy p.yaml, invariant 'i'")
    message = str(excinfo.value)
    assert "policy p.yaml, invariant 'i'" in message
    assert "flag, n, path, payload" in message
