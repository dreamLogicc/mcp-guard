"""Layer 2 of ePCA: the deterministic translation `⟦·⟧_SMT`.

Expressions are parsed with Python's own parser, then walked into Z3 terms through
a strict node whitelist. Nothing is ever evaluated: a construct outside the grammar
is a load-time error, not something that runs.

Grammar:
    literals        1, -2, true, false, "text"
    names           state variables, declared arguments, and `payload` / `tool` / `upstream`
    arithmetic      + - * // %
    comparison      < <= > >= == !=          (chaining allowed: 0 < x <= limit)
    boolean         and, or, not
    functions       implies(a, b)
                    ite(cond, then, else)    -- if/then/else, e.g. counting a flag
                    startswith(s, prefix), endswith(s, suffix), contains(s, sub)
                    matches(s, patterns)     -- true if s contains any of the patterns
                    member(x, [a, b, c])
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from typing import Any

import z3


class ExprError(Exception):
    """A policy expression is outside the grammar, unknown, or ill-typed."""


_BOOL_OPS: dict[type, Any] = {ast.And: z3.And, ast.Or: z3.Or}
_BIN_OPS: dict[type, Any] = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a / b,  # Z3's integer division
    ast.Mod: lambda a, b: a % b,
}
_COMPARE_OPS: dict[type, Any] = {
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
}
_FUNCTIONS = ("implies", "ite", "startswith", "endswith", "contains", "matches", "member")


def compile_expr(
    source: str,
    scope: Mapping[str, z3.ExprRef],
    *,
    patterns: Mapping[str, Sequence[str]] | None = None,
    where: str,
) -> z3.ExprRef:
    """Translate one policy expression into a Z3 term.

    `scope` maps usable names to their Z3 constants, `patterns` are the named lists
    `matches()` may refer to, and `where` locates errors for the reader.

    Raises:
        ExprError: Outside the grammar, unknown name, or ill-typed.
    """
    if not isinstance(source, str) or not source.strip():
        raise ExprError(f"{where}: expression must be a non-empty string")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise ExprError(f"{where}: cannot parse {source!r}: {exc.msg}") from exc

    try:
        return _Translator(scope, patterns or {}, where).visit(tree.body)
    except z3.Z3Exception as exc:
        raise ExprError(f"{where}: ill-typed expression {source!r}: {exc}") from exc


def compile_condition(
    source: str,
    scope: Mapping[str, z3.ExprRef],
    *,
    patterns: Mapping[str, Sequence[str]] | None = None,
    where: str,
) -> z3.BoolRef:
    """`compile_expr`, rejecting anything that is not a boolean condition."""
    term = compile_expr(source, scope, patterns=patterns, where=where)
    if not z3.is_bool(term):
        raise ExprError(f"{where}: expected a boolean condition, got {source!r}")
    return term


class _Translator:
    """Walks the whitelisted AST subset, emitting Z3 terms."""

    def __init__(
        self,
        scope: Mapping[str, z3.ExprRef],
        patterns: Mapping[str, Sequence[str]],
        where: str,
    ) -> None:
        self._scope = scope
        self._patterns = patterns
        self._where = where

    def visit(self, node: ast.AST) -> Any:
        method = getattr(self, f"_on_{type(node).__name__}", None)
        if method is None:
            raise self._reject(type(node).__name__)
        return method(node)

    def _reject(self, what: str) -> ExprError:
        return ExprError(f"{self._where}: {what} is not allowed in policy expressions")

    def _on_Constant(self, node: ast.Constant) -> z3.ExprRef:
        value = node.value
        if isinstance(value, bool):
            return z3.BoolVal(value)
        if isinstance(value, int):
            return z3.IntVal(value)
        if isinstance(value, str):
            return z3.StringVal(value)
        raise self._reject(f"literal of type {type(value).__name__}")

    def _on_Name(self, node: ast.Name) -> z3.ExprRef:
        # YAML writers reach for lowercase true/false.
        if node.id in ("true", "false"):
            return z3.BoolVal(node.id == "true")
        try:
            return self._scope[node.id]
        except KeyError:
            known = ", ".join(sorted(self._scope)) or "<nothing>"
            raise ExprError(f"{self._where}: unknown name {node.id!r}; in scope: {known}") from None

    def _on_BoolOp(self, node: ast.BoolOp) -> z3.ExprRef:
        return _BOOL_OPS[type(node.op)](*[self.visit(value) for value in node.values])

    def _on_UnaryOp(self, node: ast.UnaryOp) -> z3.ExprRef:
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return z3.Not(operand)
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return operand
        raise self._reject(type(node.op).__name__)

    def _on_BinOp(self, node: ast.BinOp) -> z3.ExprRef:
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise self._reject(f"operator {type(node.op).__name__}")
        return op(self.visit(node.left), self.visit(node.right))

    def _on_Compare(self, node: ast.Compare) -> z3.ExprRef:
        terms = [self.visit(node.left)] + [self.visit(other) for other in node.comparators]
        parts = []
        for index, op_node in enumerate(node.ops):
            op = _COMPARE_OPS.get(type(op_node))
            if op is None:
                raise self._reject(f"comparison {type(op_node).__name__}")
            parts.append(op(terms[index], terms[index + 1]))
        return parts[0] if len(parts) == 1 else z3.And(*parts)

    def _on_Call(self, node: ast.Call) -> z3.ExprRef:
        if not isinstance(node.func, ast.Name) or node.func.id not in _FUNCTIONS:
            name = getattr(node.func, "id", "<expression>")
            raise ExprError(f"{self._where}: unknown function {name!r}; available: {', '.join(_FUNCTIONS)}")
        if node.keywords:
            raise self._reject("keyword arguments")

        name = node.func.id
        if name in ("matches", "member"):
            return self._on_list_call(name, node)

        if name == "ite":
            if len(node.args) != 3:
                raise ExprError(f"{self._where}: ite() takes exactly 3 arguments, got {len(node.args)}")
            condition, then_term, else_term = (self.visit(arg) for arg in node.args)
            if not z3.is_bool(condition):
                raise ExprError(f"{self._where}: the first argument of ite() must be a condition")
            return z3.If(condition, then_term, else_term)

        args = [self.visit(arg) for arg in node.args]
        if len(args) != 2:
            raise ExprError(f"{self._where}: {name}() takes exactly 2 arguments, got {len(args)}")
        if name == "implies":
            return z3.Implies(args[0], args[1])
        if name == "startswith":
            return z3.PrefixOf(args[1], args[0])
        if name == "endswith":
            return z3.SuffixOf(args[1], args[0])
        return z3.Contains(args[0], args[1])

    def _on_list_call(self, name: str, node: ast.Call) -> z3.ExprRef:
        if len(node.args) != 2:
            raise ExprError(f"{self._where}: {name}() takes exactly 2 arguments, got {len(node.args)}")
        subject = self.visit(node.args[0])
        options = self._resolve_list(name, node.args[1])
        if name == "member":
            return z3.Or(*[subject == z3.StringVal(option) for option in options])
        return z3.Or(*[z3.Contains(subject, z3.StringVal(option)) for option in options])

    def _resolve_list(self, name: str, node: ast.expr) -> list[str]:
        """A named pattern list, or a literal one."""
        if isinstance(node, ast.Name):
            try:
                options = list(self._patterns[node.id])
            except KeyError:
                known = ", ".join(sorted(self._patterns)) or "<none defined>"
                raise ExprError(
                    f"{self._where}: unknown pattern list {node.id!r}; defined: {known}"
                ) from None
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            options = []
            for element in node.elts:
                if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                    raise ExprError(f"{self._where}: {name}() list must hold string literals")
                options.append(element.value)
        else:
            raise ExprError(f"{self._where}: {name}() needs a pattern list name or a literal list")

        if not options:
            raise ExprError(f"{self._where}: {name}() needs a non-empty list")
        return options
