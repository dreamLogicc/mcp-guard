"""The policy spec `Σ = ⟨S_ver, A, δ, s₀, Φ_safe⟩`, compiled from a validated file.

The file's shape is `praxiom.schema.PolicyFile`; what is left here is turning it
into Z3 terms and cross-checking references between sections. Both happen at load
time, so a broken axiom is a startup error rather than a surprise on the first call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

import z3
from pydantic import ValidationError

from praxiom.epca.expr import ExprError, compile_condition, compile_expr
from praxiom.schema import ActionEntry, PolicyFile, VarType, describe_errors

_TYPES: dict[VarType, Any] = {"int": z3.Int, "bool": z3.Bool, "str": z3.String}
_LITERALS: dict[VarType, Any] = {"int": z3.IntVal, "bool": z3.BoolVal, "str": z3.StringVal}

CONTEXT_NAMES = ("payload", "tool", "upstream")
"""Always in scope for guards and effects."""


class SpecError(Exception):
    """The policy file is malformed."""


@dataclass(frozen=True, slots=True)
class StateVar:
    """One dimension of the verification state `s = ⟨α₁, …, α_k⟩`."""

    name: str
    type: VarType
    init: Any

    def const(self, suffix: str) -> z3.ExprRef:
        return _TYPES[self.type](f"{self.name}{suffix}")

    def literal(self, value: Any) -> z3.ExprRef:
        return _LITERALS[self.type](value)


@dataclass(frozen=True, slots=True)
class Invariant:
    """One member of `Φ_safe`; must hold in every reachable state."""

    name: str
    source: str
    term: z3.BoolRef = field(repr=False)


@dataclass(frozen=True, slots=True)
class Action:
    """An element of `A`: which calls it covers, its guards, and its transition `δ`."""

    name: str
    patterns: tuple[str, ...]
    """Globs over the prefixed tool name, e.g. `fs__read*`."""

    args: dict[str, VarType]
    """Security-relevant arguments. Absent or ill-typed on a call means denial."""

    requires: tuple[tuple[str, z3.BoolRef], ...] = field(repr=False, default=())
    """Guards, as (label, term) over the pre-state."""

    effect: dict[str, z3.ExprRef] = field(repr=False, default_factory=dict)
    """`δ`: state variable -> next value, over the pre-state."""

    def covers(self, tool_name: str) -> bool:
        return any(fnmatchcase(tool_name, pattern) for pattern in self.patterns)


@dataclass(frozen=True, slots=True)
class PolicySpec:
    """A compiled policy file."""

    state: dict[str, StateVar]
    invariants: tuple[Invariant, ...]
    actions: tuple[Action, ...]
    default: str
    patterns: dict[str, tuple[str, ...]]

    def actions_for(self, tool_name: str) -> list[Action]:
        """Every action covering `tool_name`, in declaration order."""
        return [action for action in self.actions if action.covers(tool_name)]


def load_policy(raw: Any, *, context: str) -> PolicySpec:
    """Validate a policy file and compile it to Z3.

    Raises:
        SpecError: Malformed, or an expression outside the grammar.
    """
    try:
        parsed = PolicyFile.model_validate(raw)
    except ValidationError as exc:
        raise SpecError(describe_errors(exc, context=context)) from exc

    patterns = {name: tuple(values) for name, values in parsed.patterns.items()}
    state = _build_state(parsed, context)

    # Invariants speak only about the state; a payload belongs in a guard.
    invariant_scope = {name: var.const("") for name, var in state.items()}
    invariants = tuple(
        Invariant(
            name=entry.name,
            source=entry.expr,
            term=_condition(entry.expr, invariant_scope, patterns, f"{context}, invariant {entry.name!r}"),
        )
        for entry in parsed.invariants
    )
    actions = tuple(_build_action(entry, state, patterns, context) for entry in parsed.actions)

    if not invariants and not any(action.requires for action in actions):
        raise SpecError(f"{context}: no invariants and no guards, so nothing can ever be denied")

    return PolicySpec(
        state=state,
        invariants=invariants,
        actions=actions,
        default=parsed.default,
        patterns=patterns,
    )


def _build_state(parsed: PolicyFile, context: str) -> dict[str, StateVar]:
    state: dict[str, StateVar] = {}
    for name, entry in parsed.state.items():
        if name in CONTEXT_NAMES:
            raise SpecError(f"{context}: state.{name}: {name!r} is a reserved name")
        state[name] = StateVar(name=name, type=entry.type, init=entry.init)
    return state


def _build_action(
    entry: ActionEntry,
    state: dict[str, StateVar],
    patterns: dict[str, tuple[str, ...]],
    context: str,
) -> Action:
    where = f"{context}, action {entry.name!r}"

    # Guards and effects see the pre-state, declared arguments, and call context.
    scope: dict[str, z3.ExprRef] = {name: var.const("") for name, var in state.items()}
    for arg_name, arg_type in entry.args.items():
        if arg_name in scope:
            raise SpecError(f"{where}: argument {arg_name!r} shadows a state variable")
        scope[arg_name] = _TYPES[arg_type](f"arg.{arg_name}")
    for reserved in CONTEXT_NAMES:
        scope[reserved] = z3.String(reserved)

    requires = tuple(
        (
            entry.name if len(entry.requires) == 1 else f"{entry.name}#{index + 1}",
            _condition(source, scope, patterns, f"{where}, requires"),
        )
        for index, source in enumerate(entry.requires)
    )

    effect: dict[str, z3.ExprRef] = {}
    for var_name, source in entry.effect.items():
        var = state.get(var_name)
        if var is None:
            known = ", ".join(sorted(state)) or "<none declared>"
            raise SpecError(f"{where}: effect on unknown state variable {var_name!r}; declared: {known}")
        try:
            term = compile_expr(source, scope, patterns=patterns, where=f"{where}, effect on {var_name!r}")
        except ExprError as exc:
            raise SpecError(str(exc)) from exc
        if term.sort() != var.const("").sort():
            raise SpecError(
                f"{where}: effect on {var_name!r} must produce {var.type}, got {term.sort()} from {source!r}"
            )
        effect[var_name] = term

    return Action(
        name=entry.name,
        patterns=tuple(entry.match),
        args=dict(entry.args),
        requires=requires,
        effect=effect,
    )


def _condition(
    source: str,
    scope: dict[str, z3.ExprRef],
    patterns: dict[str, tuple[str, ...]],
    where: str,
) -> z3.BoolRef:
    try:
        return compile_condition(source, scope, patterns=patterns, where=where)
    except ExprError as exc:
        raise SpecError(str(exc)) from exc


def has_type(value: Any, var_type: VarType) -> bool:
    """Whether a concrete call argument matches a declared policy type."""
    if var_type == "int":
        # bool subclasses int in Python; an int slot must not accept True.
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, {"bool": bool, "str": str}[var_type])
