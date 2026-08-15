"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import os
import sys

import anyio

from mcp_guard import audit
from mcp_guard.auth import AuthError
from mcp_guard.config import (
    CONFIG_ENV_VAR,
    ENV_FILE_ENV_VAR,
    POLICY_ENV_VAR,
    ConfigError,
    load_env_file,
    load_policy_spec,
    load_upstreams,
)
from mcp_guard.epca import EPCAPolicy, SpecError
from mcp_guard.gateway import GatewayError, MCPGateway
from mcp_guard.server import serve_http, serve_stdio

logger = logging.getLogger("mcp_guard.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="MCP gateway: fronts several upstream MCP servers over one stdio connection.",
        epilog=(
            f"Both files are required, each from its flag or its env var "
            f"(${CONFIG_ENV_VAR}, ${POLICY_ENV_VAR}). There are no default locations: running "
            "unverified must be something you asked for, not something you got by omission."
        ),
    )
    parser.add_argument("--config", metavar="PATH", help=f"Server list (YAML). Defaults to ${CONFIG_ENV_VAR}.")
    parser.add_argument("--policy", metavar="PATH", help=f"ePCA policy (YAML). Defaults to ${POLICY_ENV_VAR}.")
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        default=os.environ.get(ENV_FILE_ENV_VAR),
        help=(
            f"Load KEY=value lines into the environment before reading the config, for the "
            f"tokens named by 'token_env' and '${{VAR}}'. Defaults to ${ENV_FILE_ENV_VAR}. "
            "Existing variables win."
        ),
    )
    parser.add_argument(
        "--http",
        metavar="[HOST:]PORT",
        help=(
            "Serve over streamable HTTP as a standalone process instead of stdio, so the "
            "gateway outlives its clients and keeps its own console. Host defaults to 127.0.0.1."
        ),
    )
    parser.add_argument(
        "--log-arguments",
        default="redacted",
        choices=list(audit.ARGUMENT_MODES),
        help=(
            "How much of each call's arguments to log. 'redacted' (default) blanks "
            "credential-looking keys and truncates; 'full' writes them verbatim, secrets included."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (logs go to stderr; stdout is the MCP transport).",
    )
    parser.add_argument(
        "--color",
        default="auto",
        choices=["auto", "always", "never"],
        help="Colourise the log. 'auto' colours only when stderr is a terminal.",
    )
    return parser


def _setup_logging(level: str, color: str) -> None:
    # stdout belongs to the MCP transport, so logs must go to stderr.
    if color == "auto":
        enabled = sys.stderr.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
    else:
        enabled = color == "always"
    audit.enable_color(enabled)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(audit.Formatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.log_level, args.color)

    try:
        if args.env_file:
            names = load_env_file(args.env_file)
            logger.info("env file %s: set %s", args.env_file, ", ".join(names) or "nothing new")

        spec = load_policy_spec(args.policy)
        gateway = MCPGateway(policy=EPCAPolicy(spec), log_arguments=args.log_arguments)
        logger.info(
            "policy: %d invariant(s), %d action(s), unmatched tools are %s",
            len(spec.invariants),
            len(spec.actions),
            "denied" if spec.default == "deny" else "ALLOWED UNVERIFIED",
        )

        for upstream in load_upstreams(args.config):
            registered = gateway.add_upstream(upstream)
            # Up front, so a bad token_env is a config error, not a later connection failure.
            registered.auth.validate(registered.name)
            logger.info("upstream %s -> %s", registered.name, registered.target)
    except (AuthError, ConfigError, GatewayError, SpecError) as exc:
        print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2

    if args.log_arguments == "full":
        logger.warning("--log-arguments full: tool arguments are logged verbatim, secrets included")

    try:
        if args.http:
            host, _, port = args.http.rpartition(":")
            anyio.run(serve_http, gateway, host or "127.0.0.1", int(port))
        else:
            anyio.run(serve_stdio, gateway)
    except ValueError:
        print(f"mcp-guard: --http expects [HOST:]PORT, got {args.http!r}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
