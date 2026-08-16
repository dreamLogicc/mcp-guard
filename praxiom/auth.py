"""Credentials for HTTP upstreams, resolved into request headers."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx2

TOKEN_ENV_PREFIX = "PRAXIOM_TOKEN_"
"""Per-upstream fallback env var: `PRAXIOM_TOKEN_GITHUB` for upstream `github`."""


class AuthError(Exception):
    """A credential was configured but could not be resolved."""


def token_env_var(upstream_name: str) -> str:
    return TOKEN_ENV_PREFIX + upstream_name.upper().replace("-", "_")


@dataclass(slots=True)
class UpstreamAuth:
    """How to authenticate against one upstream.

    Tried in order: explicit `headers`, `token`, `token_env`, then the
    `PRAXIOM_TOKEN_<NAME>` convention. `httpx_auth` is orthogonal and always applied.
    """

    headers: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    """Bearer token, sent as `Authorization: Bearer <token>`."""

    token_env: str | None = None
    """Env var holding the bearer token. Missing or empty is an error."""

    httpx_auth: httpx2.Auth | None = field(default=None, repr=False)
    """An `httpx2.Auth` flow, e.g. `mcp.client.auth.OAuthClientProvider`."""

    @property
    def is_empty(self) -> bool:
        return not self.headers and self.token is None and self.token_env is None and self.httpx_auth is None

    def resolve_headers(self, upstream_name: str) -> dict[str, str]:
        """Build the header set for `upstream_name`.

        Raises:
            AuthError: `token_env` names a variable that is unset or empty.
        """
        headers = dict(self.headers)
        if any(key.lower() == "authorization" for key in headers):
            return headers

        token = self.token
        if token is None and self.token_env is not None:
            token = os.environ.get(self.token_env)
            if not token:
                raise AuthError(f"upstream {upstream_name!r}: env var {self.token_env!r} is unset or empty")
        if token is None:
            # Convention fallback; absence just means "no auth".
            token = os.environ.get(token_env_var(upstream_name)) or None

        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def validate(self, upstream_name: str) -> None:
        """Fail at startup if a configured credential cannot be resolved."""
        self.resolve_headers(upstream_name)

    def describe(self, upstream_name: str) -> str:
        """Header names and auth flow, never their values — this goes into logs."""
        names = sorted(self.resolve_headers(upstream_name))
        parts = [f"headers={names}" if names else "headers=[]"]
        if self.httpx_auth is not None:
            parts.append(f"auth={type(self.httpx_auth).__name__}")
        return " ".join(parts)


def expand_env(value: str, *, context: str) -> str:
    """Expand `${VAR}` references, so a config can point at secrets instead of holding them.

    Raises:
        AuthError: A referenced variable is unset.
    """
    out: list[str] = []
    rest = value
    while True:
        start = rest.find("${")
        if start == -1:
            out.append(rest)
            return "".join(out)
        end = rest.find("}", start)
        if end == -1:
            out.append(rest)
            return "".join(out)
        name = rest[start + 2 : end]
        resolved = os.environ.get(name)
        if resolved is None:
            raise AuthError(f"{context}: env var {name!r} referenced by '${{{name}}}' is unset")
        out.append(rest[:start])
        out.append(resolved)
        rest = rest[end + 1 :]
