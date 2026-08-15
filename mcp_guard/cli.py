"""Command line entry point: `mcp-guard` reads its upstreams from the YAML config."""

from __future__ import annotations

import argparse
import logging
import sys

import anyio

from mcp_guard.auth import AuthError
from mcp_guard.config import CONFIG_ENV_VAR, POLICY_ENV_VAR, ConfigError, load_policy_spec, load_upstreams
from mcp_guard.epca import EPCAPolicy, SpecError
from mcp_guard.gateway import GatewayError, MCPGateway
from mcp_guard.server import serve_stdio

logger = logging.getLogger(__name__)


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
    parser.add_argument(
        "--config",
        metavar="PATH",
        help=f"Server list (YAML). Defaults to ${CONFIG_ENV_VAR}.",
    )
    parser.add_argument(
        "--policy",
        metavar="PATH",
        help=f"ePCA policy (YAML). Defaults to ${POLICY_ENV_VAR}.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity (logs go to stderr; stdout is the MCP transport).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # stdout belongs to the MCP transport, so logs must go to stderr.
    logging.basicConfig(
        level=args.log_level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    try:
        spec = load_policy_spec(args.policy)
        logger.info(
            "policy: %d invariant(s), %d action(s), default=%s",
            len(spec.invariants),
            len(spec.actions),
            spec.default,
        )
        gateway = MCPGateway(policy=EPCAPolicy(spec))

        for upstream in load_upstreams(args.config):
            registered = gateway.add_upstream(upstream)
            # Up front, so a bad token_env is a config error, not a later connection failure.
            registered.auth.validate(registered.name)
            logger.info(
                "upstream %s -> %s (%s)",
                registered.name,
                registered.target,
                registered.auth.describe(registered.name),
            )
    except (AuthError, ConfigError, GatewayError, SpecError) as exc:
        print(f"mcp-guard: {exc}", file=sys.stderr)
        return 2

    try:
        anyio.run(serve_stdio, gateway)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
