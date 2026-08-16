"""The exact shape of both YAML files, in one place.

Every model forbids unknown fields: a misspelled key is an error the user must fix,
never a silently ignored line. That matters more here than in most config — a typo
in `headers` would mean an unauthenticated upstream, and a typo in a policy key
would mean an unenforced restriction, both without a word of warning.

These models describe the files. Turning a validated policy into Z3 terms is
`mcp_guard.epca.spec`; building upstreams is `mcp_guard.config`.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)

VarType = Literal["int", "bool", "str"]
Decision = Literal["allow", "deny"]


def describe_errors(exc: ValidationError, *, context: str) -> str:
    """Render a `ValidationError` as one line per problem, naming the offending key."""
    lines = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<top level>"
        message = error["msg"].removeprefix("Value error, ")
        lines.append(f"{context}: {location}: {message}")
    return "\n".join(dict.fromkeys(lines))


def _as_text(value: Any) -> Any:
    """Accept the scalars YAML produces where an expression or string is meant.

    `port: 8080` and `tainted: true` are natural things to write; only containers
    are a real mistake.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return value


Text = Annotated[StrictStr, BeforeValidator(_as_text)]
"""A string field that tolerates a YAML scalar."""

Expression = Text
"""A policy expression, compiled later by `mcp_guard.epca.expr`."""


class Model(BaseModel):
    """Base: unknown fields are rejected, strings are not silently trimmed away."""

    model_config = ConfigDict(extra="forbid")


class ServerEntry(Model):
    """One entry under `servers:`. Exactly one of `url` or `command`."""

    url: StrictStr | None = None

    command: StrictStr | None = None
    args: list[Text] = []
    env: dict[StrictStr, Text] = {}
    cwd: StrictStr | None = None

    headers: dict[StrictStr, Text] = {}
    token: StrictStr | None = None
    token_env: StrictStr | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_bare_url(cls, value: Any) -> Any:
        # Shorthand: `github: https://api.example.com/mcp`
        return {"url": value} if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check_transport(self) -> ServerEntry:
        if bool(self.url) == bool(self.command):
            raise ValueError("give exactly one of 'url' (remote) or 'command' (local stdio server)")
        if self.command and (self.headers or self.token or self.token_env):
            raise ValueError("a stdio server has no HTTP headers; pass its credentials through 'env' instead")
        if self.url and (self.args or self.env or self.cwd):
            raise ValueError("'args', 'env' and 'cwd' belong to a 'command' server, not a 'url' one")
        return self


class ConfigFile(Model):
    """The whole server config file."""

    servers: dict[StrictStr, ServerEntry]

    @model_validator(mode="after")
    def _check_not_empty(self) -> ConfigFile:
        if not self.servers:
            raise ValueError("'servers' is empty")
        return self


class StateVarEntry(Model):
    """One entry under `state:`: a verification variable and its initial value."""

    type: VarType
    init: StrictBool | StrictInt | StrictStr

    @model_validator(mode="after")
    def _check_init_type(self) -> StateVarEntry:
        # bool subclasses int in Python, so an int slot must not accept True.
        expected: dict[str, type | tuple[type, ...]] = {"int": int, "bool": bool, "str": str}
        if isinstance(self.init, bool) != (self.type == "bool") or not isinstance(
            self.init, expected[self.type]
        ):
            raise ValueError(f"'init' must be {self.type}, got {self.init!r}")
        return self


class InvariantEntry(Model):
    """One member of `Φ_safe`."""

    name: StrictStr
    expr: Expression


class ActionEntry(Model):
    """One element of `A`: the calls it covers, its guards, and its transition."""

    name: StrictStr
    match: list[Text]
    args: dict[StrictStr, VarType] = {}
    requires: list[Expression] = []
    effect: dict[StrictStr, Expression] = {}

    @model_validator(mode="before")
    @classmethod
    def _accept_scalars(cls, value: Any) -> Any:
        """`match` and `requires` each accept one item or a list."""
        if isinstance(value, dict):
            value = dict(value)
            for key in ("match", "requires"):
                if key in value and not isinstance(value[key], list):
                    value[key] = [value[key]]
        return value

    @model_validator(mode="after")
    def _check_not_empty(self) -> ActionEntry:
        if not self.match:
            raise ValueError("'match' needs at least one tool-name glob")
        return self


class PolicyFile(Model):
    """The whole policy file."""

    default: Decision = "allow"
    patterns: dict[StrictStr, list[Text]] = {}
    state: dict[StrictStr, StateVarEntry] = {}
    invariants: list[InvariantEntry] = []
    actions: list[ActionEntry] = []

    @model_validator(mode="after")
    def _check_names(self) -> PolicyFile:
        for label, names in (
            ("invariant", [item.name for item in self.invariants]),
            ("action", [item.name for item in self.actions]),
        ):
            duplicates = sorted({name for name in names if names.count(name) > 1})
            if duplicates:
                raise ValueError(f"duplicate {label} name(s): {', '.join(duplicates)}")
        for name, values in self.patterns.items():
            if not values:
                raise ValueError(f"pattern list {name!r} is empty")
        return self
