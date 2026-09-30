# PF5 design record — the MCP server (2026-09-30 design session)

**Position**: the ROADMAP H series "no-revision group", second item =
**PF5: MCP server (a thin wrapper of `maruhi schema`, distributes no values)**
(order VH → PF5 → PF4 → PF6 — 2026-09-14 owner ruling; the 2026-08-30 "after
demand measurement" was retracted and the item pulled forward). This record
carries the overall picture, the option enumeration and rulings for every
point the ROADMAP entry left open, and the implementation.

**Approval (2026-09-30)**: the owner delegated every open point ("for each
point to rule, keep searching for a strictly-better or structurally-better
option until none is left, lay the options out, and pick the one you
recommend") and ruled that backward compatibility is to be ignored entirely
(there are zero users). The rulings below (M1–M9) are the designer's picks
under that delegation.

**Premises (not relitigated)**: value-free-schema-design.md §1-1 (`maruhi
schema` is keyless, the agent gate does not apply — the permit side) and §4
("MCP delivery: a thin wrapper that returns `maruhi schema`'s output —
verified-store-derived, already neutralized"); rulings CK / CW (description
neutralization via `escapeText`, the "data, not instructions" framing on
agent-facing output — session-46); CRYPTO_SPEC §14.3 (a type is shown as a
declaration, never "verified"); AUTH_SPEC §12-7 (the metadata-only pull
carries no value or DEK and records no `var.read`); ADR-0014 (agent
isolation — "never serve values"); ADR-0016 decision 7 (the value-display
gate) and decision 9 (stdout carries only the command's output).

---

## 1. Overall picture

### 1-1. Problem

A coding agent with a shell can already read the environment's contract with
`maruhi schema` plus one line in AGENTS.md. Agents whose host speaks MCP but
that are not steered by AGENTS.md — or hosts that expose no shell at all —
have no way to learn which variables a project needs. Competitors fill that
gap with MCP servers that **return plaintext secrets to the model**
(competitive-analysis.md: Infisical, Doppler, Keyway). maruhi's answer is the
same channel with the opposite content: the contract, never the values.

### 1-2. Mechanism sketch

```
agent host (Claude Code, Cursor, …)
  │  spawns: maruhi mcp --project <id> --env dev        (stdio, newline-delimited JSON-RPC)
  ▼
maruhi mcp  ── one process, the user's own CLI session (keychain token / MARUHI_TOKEN / maruhi agent)
  │  tools/call get_schema {environment?}
  │  resources/read maruhi://schema  |  maruhi://schema/{environment}
  │     └─ exactly one `maruhi schema` per call:
  │        config → session → chain sync → §6.3 verification → floor
  │        → metadata-only pull (no value, no DEK, no var.read) → schemaRows()
  ▼
{ notice, projectId, environment, environments[], variables[{name, declaredType,
  required, status, description}], warnings[] }
```

Nothing on the server side changes: no endpoint, no acceptance rule, no audit
event, no spec text (the ROADMAP's "no spec revision" holds).

## 2. Ruling M1 — where the server runs

| # | Shape | Verdict |
|---|---|---|
| 1-A | **`maruhi mcp`, a subcommand of the existing CLI binary, stdio transport** (the host spawns it) | **Adopted** |
| 1-B | A separate package (`@maruhi/mcp`), the competitors' shape | Rejected: a second release artifact and a second copy of the §6.3 verification pipeline that can drift from the CLI's (version skew between the two would make "the schema the agent sees" and "the schema `maruhi run` enforces" disagree) |
| 1-C | A remote MCP endpoint on the maruhi server (Worker, Streamable HTTP) | Rejected: under E2EE the server is not trusted — what it served would be an unverified server claim, inverting "verified-store-derived". It would also make the server speak directly to an LLM (a server-originated injection surface no client verified) and need an MCP OAuth surface |
| 1-D | Local HTTP (the CLI listens on localhost) | Rejected: a listening socket (other local users and processes, DNS rebinding, browser-origin requests) needing its own auth token. stdio has none of that and every major host supports it |
| 1-E | No MCP; guidance only (SKILL.md / AGENTS.md) | Rejected as the answer (PF5 is an MCP server by owner ruling). Kept as a complement: the docs page gives the AGENTS.md line for shell-having agents |

**Why 1-A is strictly better**: the verification path is the CLI's, byte for
byte (one implementation of §6.3); there is no new artifact to release or
sign; the process inherits exactly the user's session (OS keychain,
`MARUHI_TOKEN`, a `maruhi agent` socket) with no new credential to provision.

## 3. Ruling M2 — the protocol implementation

| # | Shape | Verdict |
|---|---|---|
| 2-A | **`effect/unstable/ai`'s `McpServer`** (already inside the pinned `effect@4.0.0-rc.117`) | **Adopted** |
| 2-B | `@modelcontextprotocol/sdk` | Rejected: a new dependency tree (zod and friends) for the CLI's supply chain, and a second schema system beside Effect Schema |
| 2-C | Hand-rolled JSON-RPC over ndjson | Rejected: re-implementing version negotiation, capability advertisement, and error mapping — the "do not invent" spirit, and more code to review |

**Measured before ruling (prototype under Bun 1.4.2)**: `initialize`,
`tools/list`, `tools/call` (success, declared failure, parameter
validation), `resources/list`, `resources/templates/list`, `resources/read`
all work over the stdio layer. Offering the stateless `2026-07-28` revision
over stdio negotiates down to `2025-11-25` (stdio is a stateful session), so
the server offers the stateful revisions `2025-11-25`, `2025-06-18`,
`2025-03-26`, `2024-11-05` (every one carries the two primitives used). The
module is `unstable/`, which the exact pin already governs (ADR-0011): an
Effect upgrade PR re-runs the end-to-end stdio tests (`test/mcp.test.ts`) and
fails loud on a break. **Zero new dependencies.**

## 4. Ruling M3 — the capability surface

| # | Shape | Verdict |
|---|---|---|
| 3-A | Resource only (the wording of value-free-schema-design.md §4) | Rejected alone: resources are application-controlled (the human attaches them); the model cannot fetch one on its own in most hosts |
| 3-B | Tool only | Rejected alone: loses the host-native "attach this as context" path (`@maruhi:…` mentions) |
| 3-C | Tools **and** resources over **one** projection | **Adopted** |
| 3-D | Write tools (`schema set`, declare a variable) | Rejected: a model-initiated signature on the human's key with no ceremony. A shell-having agent already has `maruhi schema set`, which carries its own fail-closed entropy gate; duplicating the surface adds nothing |
| 3-E | Any value-bearing tool (get, masked get, `run` with captured output) | **Rejected permanently** — ADR-0014's line. A `run` tool that returned the child's output would leak whatever the child prints; value brokering is PF4's (`maruhi proxy run`), which never hands a value to the model either |
| 3-F | Other metadata reads (`var history`, audit, members, `env diff`) | Rejected for PF5: history / audit / members carry actors (user ids, key fingerprints) — data minimization toward the model; `env diff` is two `get_schema` calls |
| 3-G | MCP prompts | Rejected: nothing to template |

**The strictly-better round on 3-C**: the first draft had two tools,
`list_environments` and `get_schema`. Every schema read already verifies the
whole chain, which knows every environment — so `get_schema` returns the
environment list alongside the rows at zero cost, and the separate tool (and
its round trip) disappears. **Final surface**: one tool `get_schema
{ environment? }`; one listed resource `maruhi://schema` (the default
environment) and one template `maruhi://schema/{environment}`. All three are
the same function.

Tool annotations: `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, `openWorldHint: false` (a closed domain — the
project's own maruhi server). Parameters are **strict**: an unknown key is a
`-32602` refusal, not ignored.

## 5. Ruling M4 — scope binding

| # | Shape | Verdict |
|---|---|---|
| 4-A | Project and environment both tool parameters | Rejected: the model could roam every project the user's token reaches. The host configuration is where a human states the scope |
| 4-B | Both fixed at launch | Rejected: "is X required in prod?" is the primary question, and it needs another environment |
| 4-C | **Project fixed at launch; environment a tool parameter defaulting to the launch-time `--env` (or `defaultEnvironment`)** | **Adopted** |
| 4-D | 4-C plus a launch-time environment allow-list | Rejected: metadata is scope-agnostic for members by design (AUTH_SPEC §12-7), and the agent's shell can run `maruhi schema --env X` anyway — a restriction with no guarantee behind it |

The flags are `maruhi schema`'s (`--server`, `--project`, `--env`), so a host
entry mirrors a command line the human already knows.

## 6. Ruling M5 — lifecycle

| # | Shape | Verdict |
|---|---|---|
| 5-A | Open the project once at startup and cache the view | Rejected: a long agent session reads a stale schema; the floor stops advancing; a startup failure (not logged in) kills the server with nothing the agent can relay |
| 5-B | **Every call is one `maruhi schema`**: config, session, chain sync, §6.3 verification, floor check / commit, metadata-only pull — nothing cached across calls | **Adopted** |
| 5-C | A TTL cache or incremental re-sync | Rejected: state to get wrong for a read that happens a few times per session |

Two consequences: (i) a failure (not logged in, unknown environment, a
verification refusal) is a **tool error carrying the CLI's own message** —
maruhi wording, identifiers neutralized, never a value (errors.ts) — and the
server keeps running; (ii) calls are **serialized** (a one-permit semaphore):
one call at a time is one `maruhi schema` at a time, the shape the prologue's
floor writes and attestation submission were built for.

## 7. Ruling M6 — output shape and the adversarial surface

| # | Shape | Verdict |
|---|---|---|
| 6-A | The CLI table text (with its framing header) | Rejected: a tab-separated table is a parsing exercise for the model and gives the host no schema |
| 6-B | **Structured JSON** (`outputSchema` + `structuredContent`) from **the same projection as the CLI table** (`schemaRows` — schema.ts) | **Adopted** |
| 6-C | The `schema export` snapshot (JSON Schema subset) | Rejected: it deliberately omits `set` / `declared` (a committed artifact must not churn), which is the agent's main question |

- **One projection, two renderers**: `schemaRows` produces the neutralized
  rows; the CLI table and the MCP result both render from it, so the two
  surfaces cannot drift in content or neutralization. Names go through
  `displayText`, descriptions through `escapeText` — exactly `maruhi schema`
  (rulings CK / CW apply at every display point; JSON encoding alone escapes
  C0 controls but passes bidi overrides and invisible characters through,
  which matters to the human reading the transcript)
- **Honest field names**: `declaredType` (CRYPTO_SPEC §14.3 — a declaration,
  never "verified"), `required: null` / `declaredType: null` /
  `description: null` for a v1 statement (nothing fabricated), `status: set |
  declared`
- **The framing in three places** (ruling CW): the server `instructions` at
  `initialize`, the tool description, and a `notice` field in every result
  (the framing stays adjacent to the data, as the CLI's non-TTY header does)
- **Warnings are returned** as well as written to stderr: a human rarely sees
  an MCP server's stderr, and a warning such as "a name that is not
  NFC-normalized — visually identical names may coexist" is about exactly the
  data the agent is reading
- **The instructions steer to the diskless path**: "to run a program with the
  secrets, run `maruhi run -- <command>`", so the natural next step of an
  agent that needs a value is the one that never shows it

## 8. Ruling M7 — the structural "no values" guarantee

| # | Shape | Verdict |
|---|---|---|
| 7-A | Convention: the MCP module only calls metadata functions | Kept, but not sufficient alone |
| 7-B | **Capability narrowing**: the server runs with a Keychain that answers **API-token entries only** — a master-key read is refused with a typed error and nothing is ever written | **Adopted** (with 7-A and the tests below) |
| 7-C | A separate process with no keychain access at all (token passed in the environment) | Rejected: it pushes a long-lived token into the host's config file — for `.mcp.json`, a file committed to the repository. Strictly worse |

A future code path that tried to load the master key inside the MCP server
fails closed instead of decrypting. Pinned by tests: the narrowed Keychain
refuses master-key reads and all writes; an end-to-end call hits only the
chain and `…/pull/metadata` (never `…/pull`, `…/deks`, or a version range).
The agent gate does not apply (the permit side, like `maruhi schema`) — the
MCP server is the agent-facing surface by construction and has nothing to
gate; a test runs it under a detected agent.

## 9. Ruling M8 — stdio discipline

stdout is the protocol channel and stdin is the client's. For the server's
lifetime:

- `CliIo.log` is routed to stderr (defensive — no MCP path uses it; a test
  asserts nothing reached it); `promptLine` / `readStdin` fail with a typed
  error (never read the protocol stream as user input); `openBrowser` is off
- **Effect's own logging is routed to stderr**: the default logger writes
  through `console.log` = stdout, which would corrupt the protocol stream (a
  finding of the design session's own review — below)
- **stdin EOF is a clean shutdown (exit 0)**: the stdio protocol interrupts
  the fiber that built it when stdin ends, so the server runs in a child
  fiber and an interrupt-only exit reads as "the host went away"
- Launched in a terminal (stdin is a TTY), it prints one `Note:` pointing at
  the setup page, then serves as usual (Ctrl-D exits)

## 10. Ruling M9 — audit

No audit event. The metadata-only pull records no `var.read` (AUDIT_SPEC §3.3
— do not record as read what was not read), unchanged. A "via MCP" marker was
considered and rejected: it would be an AUDIT_SPEC change for a client-declared
fact the server cannot verify, with no detection gain (the same reads are
already possible through `maruhi schema`).

## 11. What does not change

- CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC: nothing. Test vectors untouched
- The server: nothing (no endpoint, no acceptance rule)
- `maruhi schema`'s output: byte-identical (it now renders from `schemaRows`)
- The value-display gate (ADR-0016 decision 7): unchanged; `pull --show` is
  still refused under an agent

## 12. Residuals (explicit)

- **Signed ≠ benign**: a malicious member can still write a description that
  reads like an instruction. Neutralization and framing reduce, not remove,
  that surface (the same residual as `maruhi schema` — ruling CW)
- **Non-ASCII descriptions reach the agent as `\u{…}` escapes** (the CLI's
  `escapeText` allow-list). Relaxing that for MCP would be a ruling-CW
  revision, not a PF5 decision; the model reads the escapes fine
- **The environment list comes from the chain**: an environment deleted on
  the server (a tombstone the chain does not observe — CRYPTO_SPEC §6.4) still
  appears; reading it returns the server's refusal as a tool error
- **The unstable Effect module**: governed by the exact pin and the
  end-to-end tests; an upstream break is handled by reverting the upgrade PR
- The host's own behavior (whether it shows stderr, how it renders
  `structuredContent`) is outside maruhi's control

## 13. Re-check round (self review before the PR)

Each ruling was re-attacked against the running implementation:

- **R-1 (M8 — stdout pollution)**: Effect's default logger writes
  `console.log` (stdout). An internal tool defect (logged by `McpServer`)
  would have injected a non-JSON line into the protocol stream. Fixed: the
  server runs with a stderr `Console`
- **R-2 (M8 — EOF)**: the prototype exited with "All fibers interrupted" on
  stdin EOF. Fixed with the child-fiber shape; pinned (`exitCode 0` after
  every session in the tests)
- **R-3 (M5 — concurrency)**: hosts may issue calls concurrently; two
  interleaved prologues in one process is a shape the CLI never produced.
  Fixed with the one-permit semaphore
- **R-4 (M3 — resource media type)**: a string body loses `mimeType`; the
  resource now returns the full `ReadResourceResult` with
  `application/json`. Pinned by a test
- **R-5 (M6 — input echo)**: parameter-validation errors from the protocol
  layer must not echo the input; verified that they name the constraint, not
  the value. Pinned by a test
- **R-6 (M1 — terminal launch)**: a human running `maruhi mcp` saw a silent,
  apparently hung process. Added the one-line `Note:`
- Checked and unchanged: the metadata prologue reads only the `token::` entry
  (session.ts `resolveSession`), so the narrowed Keychain does not break
  `MARUHI_TOKEN`, OS-keychain, or `maruhi agent` sessions

## 14. Implementation

- `apps/cli/src/schema.ts`: `schemaRows` (the shared neutralized projection)
  and the CLI table rendering from it
- `apps/cli/src/mcp.ts`: the server (`mcpServeOp`), the tool / resource
  definitions, the narrowed Keychain, the stdio discipline
- `apps/cli/src/effect-cli.ts`: the `maruhi mcp` command (`commonFlags`)
- `apps/cli/src/keychain.ts`: `isTokenEntryName`
- Tests: `apps/cli/test/mcp.test.ts` (end-to-end over the stdio framing);
  the `Stdio` stdin / stdout hooks in `test/support/env.ts`
- Public docs: `/docs/ai-agents` (host setup, what the agent sees, what it
  never sees)
