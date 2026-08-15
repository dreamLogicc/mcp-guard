"""The ePCA reference monitor: layers 1, 3 and 4.

Every call is decided by the joint formula `C = s ∧ ⟦j⟧_SMT ∧ Φ_safe(s')`: the state
pinned to its concrete values, the call's guards and transition, and the invariants
asserted over the *induced* state. SAT executes and the model yields the next state;
UNSAT is the paper's algebraic deadlock — blocked, state unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import z3

from mcp_guard.epca.spec import Action, PolicySpec, SpecError, has_type

GUARD_PREFIX = "guard:"
INVARIANT_PREFIX = "invariant:"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Outcome of one verification."""

    allowed: bool
    reason: str | None = None
    violated: tuple[str, ...] = ()
    """Names of the guards/invariants in the unsat core."""

    actions: tuple[str, ...] = ()
    """Policy actions that covered the call."""

    next_state: dict[str, Any] = field(default_factory=dict)


class ReferenceMonitor:
    """Holds the verification state and decides one call at a time.

    Deciding is synchronous, so under the gateway's single event loop a check and
    its commit cannot interleave with another call.
    """

    def __init__(self, spec: PolicySpec) -> None:
        self._spec = spec
        self._state: dict[str, Any] = {name: var.init for name, var in spec.state.items()}
        self._pre = {name: var.const("") for name, var in spec.state.items()}
        self._post = {name: var.const("_next") for name, var in spec.state.items()}
        self._check_initial_state()

    @property
    def spec(self) -> PolicySpec:
        return self._spec

    @property
    def state(self) -> dict[str, Any]:
        """A copy of the current verification state."""
        return dict(self._state)

    def _check_initial_state(self) -> None:
        """Theorem 1's base case: refuse to start from a state that already violates Φ_safe."""
        solver = z3.Solver()
        for name, var in self._spec.state.items():
            solver.add(self._pre[name] == var.literal(self._state[name]))
        for invariant in self._spec.invariants:
            solver.assert_and_track(invariant.term, f"{INVARIANT_PREFIX}{invariant.name}")
        if solver.check() != z3.sat:
            broken = sorted(str(name).removeprefix(INVARIANT_PREFIX) for name in solver.unsat_core())
            raise SpecError(f"the initial state violates Φ_safe: {', '.join(broken)}")

    def check(self, tool: str, upstream: str, arguments: dict[str, Any]) -> Verdict:
        """Decide whether `tool` may run, and commit `δ(s, a)` when it may."""
        actions = self._spec.actions_for(tool)
        if not actions:
            if self._spec.default == "deny":
                return Verdict(
                    allowed=False,
                    reason=f"no policy action covers {tool!r} and the policy default is deny",
                )
            return Verdict(allowed=True)

        # Layer 1: strict payload validation. What cannot be typed cannot be verified.
        rejection = self._validate_arguments(actions, arguments)
        if rejection is not None:
            return Verdict(allowed=False, reason=rejection, actions=tuple(a.name for a in actions))

        solver = z3.Solver()
        self._assert_current_state(solver)
        self._assert_payload(solver, tool, upstream, arguments, actions)
        for action in actions:
            for label, guard in action.requires:
                solver.assert_and_track(guard, f"{GUARD_PREFIX}{label}")
        self._assert_transition(solver, actions)
        for invariant in self._spec.invariants:
            solver.assert_and_track(self._at_next_state(invariant.term), f"{INVARIANT_PREFIX}{invariant.name}")

        names = tuple(action.name for action in actions)
        if solver.check() == z3.sat:
            next_state = self._read_state(solver.model())
            self._state = next_state
            return Verdict(allowed=True, actions=names, next_state=dict(next_state))

        violated = tuple(str(name) for name in solver.unsat_core())
        return Verdict(
            allowed=False,
            reason=self._explain(violated),
            violated=tuple(_strip_prefix(name) for name in violated),
            actions=names,
        )

    def _validate_arguments(self, actions: list[Action], arguments: dict[str, Any]) -> str | None:
        for action in actions:
            for arg_name, arg_type in action.args.items():
                if arg_name not in arguments:
                    return f"action {action.name!r} requires argument {arg_name!r}, which the call omits"
                if not has_type(arguments[arg_name], arg_type):
                    got = type(arguments[arg_name]).__name__
                    return f"action {action.name!r} requires {arg_name!r} to be {arg_type}, got {got}"
        return None

    def _assert_current_state(self, solver: z3.Solver) -> None:
        """Pin `s` to its concrete values — the paper's rigid truth injection."""
        for name, var in self._spec.state.items():
            solver.add(self._pre[name] == var.literal(self._state[name]))

    def _assert_payload(
        self,
        solver: z3.Solver,
        tool: str,
        upstream: str,
        arguments: dict[str, Any],
        actions: list[Action],
    ) -> None:
        """Bind the call's parameters as immutable algebraic constants."""
        solver.add(z3.String("tool") == z3.StringVal(tool))
        solver.add(z3.String("upstream") == z3.StringVal(upstream))
        solver.add(z3.String("payload") == z3.StringVal(serialize_payload(arguments)))
        for action in actions:
            for arg_name, arg_type in action.args.items():
                solver.add(_arg_const(arg_name, arg_type) == _arg_literal(arguments[arg_name], arg_type))

    def _assert_transition(self, solver: z3.Solver, actions: list[Action]) -> None:
        """`s' = δ(s, a)`, including the frame: whatever no action assigns stays put."""
        assigned: dict[str, z3.ExprRef] = {}
        for action in actions:
            # Later declarations win, so overlapping actions have a defined meaning.
            assigned.update(action.effect)
        for name in self._spec.state:
            solver.add(self._post[name] == assigned.get(name, self._pre[name]))

    def _at_next_state(self, term: z3.BoolRef) -> z3.BoolRef:
        """Re-express an invariant over `s'`, since Φ_safe constrains the induced state."""
        return z3.substitute(term, *[(self._pre[name], self._post[name]) for name in self._spec.state])

    def _read_state(self, model: z3.ModelRef) -> dict[str, Any]:
        state: dict[str, Any] = {}
        for name, var in self._spec.state.items():
            value = model.eval(self._post[name], model_completion=True)
            if var.type == "int":
                state[name] = value.as_long()
            elif var.type == "bool":
                state[name] = z3.is_true(value)
            else:
                state[name] = value.as_string()
        return state

    def _explain(self, tracked: tuple[str, ...]) -> str:
        invariants = [_strip_prefix(n) for n in tracked if n.startswith(INVARIANT_PREFIX)]
        guards = [_strip_prefix(n) for n in tracked if n.startswith(GUARD_PREFIX)]
        parts = []
        if invariants:
            sources = {inv.name: inv.source for inv in self._spec.invariants}
            parts.append(
                "violates " + ", ".join(f"invariant {name!r} ({sources.get(name, '?')})" for name in invariants)
            )
        if guards:
            parts.append("fails guard " + ", ".join(repr(name) for name in guards))
        if not parts:  # pragma: no cover - the core always holds a tracked assertion
            parts.append("the action is unsatisfiable against the current state")
        return "; ".join(parts) + f" [state: {self.describe_state()}]"

    def describe_state(self) -> str:
        return ", ".join(f"{name}={value!r}" for name, value in self._state.items()) or "<no state>"


def serialize_payload(arguments: dict[str, Any]) -> str:
    """Deterministic rendering of the arguments, so a rule can match on content
    without knowing a tool's argument names."""
    return json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)


def _arg_const(name: str, arg_type: str) -> z3.ExprRef:
    return {"int": z3.Int, "bool": z3.Bool, "str": z3.String}[arg_type](f"arg.{name}")


def _arg_literal(value: Any, arg_type: str) -> z3.ExprRef:
    return {"int": z3.IntVal, "bool": z3.BoolVal, "str": z3.StringVal}[arg_type](value)


def _strip_prefix(name: str) -> str:
    return str(name).removeprefix(INVARIANT_PREFIX).removeprefix(GUARD_PREFIX)
