"""ePCA — Executable Proof-Constrained Action.

Decides tool calls by satisfiability rather than judgement, after Wu et al.,
*Provably Secure Agent Guardrail* (arXiv:2605.29251). Each call becomes a typed
payload, is translated into first-order logic by a fixed table, and is checked
against human-authored axioms by Z3.
"""

from mcp_guard.epca.expr import ExprError
from mcp_guard.epca.monitor import ReferenceMonitor, Verdict
from mcp_guard.epca.policy import EPCAPolicy
from mcp_guard.epca.spec import Action, Invariant, PolicySpec, SpecError, StateVar, load_policy

__all__ = [
    "Action",
    "EPCAPolicy",
    "ExprError",
    "Invariant",
    "PolicySpec",
    "ReferenceMonitor",
    "SpecError",
    "StateVar",
    "Verdict",
    "load_policy",
]
