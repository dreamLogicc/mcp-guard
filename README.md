# praxiom

An MCP gateway that fronts several MCP servers behind one connection and checks
every tool call against a formal policy before forwarding it.

![praxiom proxying an agent's tool calls: reading a secret through one server
closes the exits on the others](assets/demo.svg)

The client sees one server. Tools keep their upstream as a prefix — `github`'s
`create_issue` arrives as `github__create_issue`.

The policy is not a list of forbidden tools. It is a state machine checked by an
SMT solver, so it can forbid a *sequence* whose steps are each unremarkable:

```
ALLOW fs__read_file                "path"="…/README.md"   tainted=False
ALLOW github__create_pull_request                         writes=1
ALLOW fs__read_file                "path"="…/.env"        tainted=True
DENY  github__create_pull_request  fails guard 'publish_to_github'
DENY  docs__query-docs             fails guard 'query_third_party_docs'
```

The secret was read through one server and the exits closed on two others. No
per-server config can express that — no single server sees both halves.

Implements **ePCA** (Executable Proof-Constrained Action) from
[Wu et al., *Provably Secure Agent Guardrail*](https://arxiv.org/abs/2605.29251).
A policy file is a deterministic transition system

$$\Sigma = \langle S_{ver},\ A,\ \delta,\ s_0,\ \Phi_{safe} \rangle$$

— a state space of security-relevant attributes, a finite set of actions, a
transition $\delta : S_{ver} \times A \to S_{ver}$, an initial state, and the
invariants. Each call becomes a typed payload $j$, is translated into
first-order logic by a fixed table, and Z3 decides the joint formula

$$C = s \ \wedge\ [[j]]_{SMT} \ \wedge\ \Phi_{safe}(s') \qquad s' = \delta(s, a)$$

against the state the call *would* produce. SAT forwards it and commits the
transition; UNSAT is the paper's algebraic deadlock — blocked, state unchanged.
No language model takes part in the decision.

## Install

```bash
uv tool install praxiom      # or: pip install praxiom
```

Python 3.12+.

## Run

Two files, both required, each from its flag or its environment variable. There
are no default locations: running unverified should be something you asked for.

```bash
praxiom --config praxiom.yaml --policy praxiom-policy.yaml
```

| Flag | Environment | |
| --- | --- | --- |
| `--config PATH` | `PRAXIOM_CONFIG` | Upstream servers |
| `--policy PATH` | `PRAXIOM_POLICY` | ePCA policy |
| `--env-file PATH` | `PRAXIOM_ENV_FILE` | `KEY=value` lines loaded before the config |
| `--http [HOST:]PORT` | | Serve over streamable HTTP instead of stdio |
| `--log-arguments` | | `none`, `redacted` (default), `full` |
| `--log-level` | | Default `INFO`; logs go to stderr |
| `--color` | | `auto` (default), `always`, `never` |

You do not start it yourself: the client spawns it, and it spawns its own local
upstreams in turn.

## Server config

Each key under `servers` is that server's tool-name prefix. A server is either a
local subprocess (`command`) or a remote endpoint (`url`) — exactly one.

```yaml
servers:
  fs:                                    # local, stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "${HOME}/work"]
    # env: {TOKEN: "${TOKEN}"}, cwd: /some/dir

  github:                                # remote, bearer token
    url: https://api.githubcopilot.com/mcp/
    token_env: GITHUB_MCP_TOKEN

  internal:                              # remote, other headers
    url: https://mcp.internal.example.com/mcp
    headers:
      X-Api-Key: ${INTERNAL_API_KEY}

  docs: https://mcp.context7.com/mcp     # no credentials
```

Credentials in order: `headers`, `token` (a literal — prefer the others),
`token_env`, then `PRAXIOM_TOKEN_<NAME>`. `${VAR}` expands from the
environment anywhere in the file and is strict — an unset variable stops startup
rather than connecting without the credential. Header values never reach the
log, only their names. Unknown keys are rejected, because a misspelled `headers`
would otherwise mean a silently unauthenticated upstream.

## Policy

```yaml
default: allow          # unmatched tools are forwarded, logged as PASS

patterns:               # named substring lists for matches()
  secret_paths: ["/.ssh", "/.env", "id_rsa", ".pem", ".aws/"]

state:                  # S_ver and the initial state s₀
  tainted: {type: bool, init: false}
  secret_reads: {type: int, init: 0}

invariants:             # Φ_safe — must hold in every reachable state
  - name: secret_read_budget
    expr: secret_reads <= 5

actions:                # A and δ; `match` globs the prefixed tool name
  - name: read_files
    match: [fs__read_file, fs__read_text_file]
    effect:
      tainted: tainted or matches(payload, secret_paths)
      secret_reads: secret_reads + ite(matches(payload, secret_paths), 1, 0)

  - name: no_writes_after_secret_read
    match: [fs__write_file, fs__edit_file, fs__move_file]
    requires: not tainted
```

Invariants are checked against the state a call *would produce*, and that state
persists between calls — that is what catches the split attack. Every action
whose glob matches contributes; guards are conjoined, effects merged.

In scope for `requires` and `effect`: state variables, arguments declared under
`args`, and always `payload` (the arguments as JSON), `tool`, `upstream`.
Matching `payload` makes a rule work without knowing a server's argument names.
Invariants see only the state. A guard of `"false"` never holds — that is how
you refuse a tool outright.

| | |
| --- | --- |
| literals | `1`, `-2`, `true`, `false`, `"text"` |
| arithmetic | `+ - * // %` |
| comparison | `< <= > >= == !=`, chainable |
| boolean | `and`, `or`, `not` |
| functions | `implies(a,b)`, `ite(c,a,b)`, `startswith`, `endswith`, `contains`, `matches(s, patterns)`, `member(x, [..])` |

Expressions are parsed by Python's parser and walked into Z3 through a strict
node whitelist — **`eval` is never used**, and anything outside the grammar
fails at startup. Denials name the axiom from Z3's unsat core and reach the
client as `is_error=True`, so the model can adapt:

```
praxiom blocked 'fs__write_file': fails guard 'no_writes_after_secret_read'
  [state: tainted=True, secret_reads=1]
```

## Claude Code

```bash
claude mcp add praxiom \
  --env PRAXIOM_CONFIG=/path/to/praxiom.yaml \
  --env PRAXIOM_POLICY=/path/to/praxiom-policy.yaml \
  -- uv run --directory /path/to/praxiom praxiom
```

Remove the direct entries for any server you put behind the gateway — two paths
to the same data means the policy is decoration. The same applies to the
built-in `Bash`, `Read` and `Write` tools: they bypass the gateway, and asking
the model to prefer the MCP tools is a request, not a control. Close them with
`permissions.deny` or a `PreToolUse` hook if the guarantee is meant to be real.

## Pydantic AI

```python
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset, StdioTransport

praxiom = MCPToolset(
    StdioTransport(
        command="uv",
        args=["run", "--directory", "/path/to/praxiom", "praxiom"],
        env={"PRAXIOM_CONFIG": "…", "PRAXIOM_POLICY": "…"},
    ),
    tool_error_behavior="failed",
)

agent = Agent("anthropic:claude-sonnet-4-6", toolsets=[praxiom])
async with agent:
    result = await agent.run("read the config and open a PR")
```

`tool_error_behavior="failed"` matters: the default retries a denied call until
the run dies instead of letting the model see the refusal. An agent you build
yourself is where mediation is actually complete — its tool list is whatever you
give it, so don't hand it a shell alongside.

## Audit log

One line per call: verdict, tool, arguments, the rule that fired, the state
after, upstream latency. Logs go to stderr; stdout belongs to the MCP transport.

```
ALLOW fs__read_file       "path"="…/notes.md"                 [read_files] tainted=False         7ms
ALLOW fs__write_file      "path"="…/api.txt", "token"="***"   [never_write_secret_paths]         8ms
DENY  fs__write_file      "path"="…/copy.txt"                 fails guard 'no_writes_after_secret_read'
PASS  fs__list_directory                                      no policy action covers this tool  5ms
```

`--log-arguments redacted` (default) blanks credential-shaped keys and shortens
long values from the middle, keeping both ends. `full` writes them verbatim.

## Transports

stdio is the right answer almost always: it works for local and remote upstreams
alike, gives each client its own state, and opens no port. `--http` makes the
gateway a standalone shared process — but all clients then share one verification
state, there is no authentication, and path-based tools break, since a path is a
string interpreted on the far side.

## Examples

Tool names in these were taken from live connections, not documentation — the
two differ.

| | |
| --- | --- |
| [examples/filesystem](examples/filesystem) | Local `npx` server. Reading a secret taints; writes close after it. |
| [examples/github](examples/github) | Remote, 44 tools. Read-here-publish-there, review comments included. |
| [examples/etherscan](examples/etherscan) | Remote, all 20 tools read-only — a policy with little to forbid, so budgets and an audit trail. |
| [examples/mixed](examples/mixed) | All of the above plus a public server, 80 tools. Cross-server taint. |


