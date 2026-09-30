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
fails loud on a break. **Zero new dependencies.** **Declared fallback
(ADR-0011)**: 2-C — the surface used is small (`initialize`, `tools/list`,
`tools/call`, `resources/list`, `resources/templates/list`,
`resources/read` over ndjson), so if the module breaks or disappears, a
hand-written JSON-RPC loop over the same `Stdio` service replaces it without
touching `readSchema` or the result shape.

## 4. Ruling M3 — the capability surface

| # | Shape | Verdict |
|---|---|---|
| 3-A | Resource only (the wording of value-free-schema-design.md §4) | Rejected alone: resources are application-controlled (the human attaches them); the model cannot fetch one on its own in most hosts |
| 3-B | Tool only | Rejected alone: loses the host-native "attach this as context" path (`@maruhi:…` mentions) |
| 3-C | Tools **and** resources over **one** projection | **Adopted** |
| 3-D | Write tools (`schema set`, declare a variable) | Rejected: a model-initiated signature on the human's key with no ceremony. A shell-having agent already has `maruhi schema set`, which carries its own fail-closed entropy gate; duplicating the surface adds nothing |
| 3-E | Any value-bearing tool (get, masked get, `run` with captured output) | **Out of PF5's scope** — PF5 is value-free by definition. Whether any value-bearing agent read should ever exist (the Phase-3 "scoped, short-lived, audited reads", DO leases) is an ADR-0014 matter for its own owner ruling, not a PF5 decision (§16 D-5). A `run` tool that returned the child's output would leak whatever the child prints; value brokering is PF4's (`maruhi proxy run`), which never hands a value to the model either |
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
| 4-D | 4-C plus a launch-time environment allow-list | Rejected: metadata is readable regardless of environment scope by design (AUTH_SPEC §12-7) — any member can read every environment's schema, so an allow-list below that would restrict nothing the user's own credential could not already read |

The flags are `maruhi schema`'s (`--server`, `--project`, `--env`), so a host
entry mirrors a command line the human already knows. They are checked at
startup (an invalid ID is a usage error, exit 2); config is still read per
call (M5). **Who states the scope** (§16 D-10): a host entry committed to the
repository (`.mcp.json`) is written by whoever can commit, not by the human
running the agent. `--server` cannot capture the token (tokens are stored and
sent per origin — session.ts), but `--project` can point the agent at another
project the user belongs to — the same exposure as an `AGENTS.md` line, and
the docs say to review the file like code.

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
floor and pin writes were built for (the keyless prologue submits no head
attestation — it holds no signing key).

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
- **Every warning of the call is returned** as well as written to stderr: a
  human rarely sees an MCP server's stderr. The read observes each warning
  notice it emits through the `NoticeObserver` hook (notice.ts — by kind and
  text, §17 B) — the prologue's (a corrupt local floor or invite pin that
  switches a check off, a token near expiry, unconverged rotation mandates) as
  well as the pull's — so the agent can relay exactly what the CLI would have
  shown (§16 D-2 / D-9: the first version returned the pull's warnings only)
- **The instructions steer to the diskless path, honestly** (§16 D-1′):
  `maruhi run -- <command>` injects values into that process in memory, and
  they never pass through this server — but whatever that program prints
  reaches whoever reads its output, the agent included. The instructions and
  the docs say so and tell the agent never to run commands that print the
  environment. That is guidance, not a guarantee; keeping values away from an
  agent that reads a program's output is PF4's job (`maruhi proxy run`, with
  run-output redaction), not the schema's

## 8. Ruling M7 — the structural "no values" guarantee

| # | Shape | Verdict |
|---|---|---|
| 7-A | Convention: the MCP module only calls metadata functions | Kept, but not sufficient alone |
| 7-B | **Capability narrowing**: the server runs with a Keychain that answers **API-token entries only** — a master-key read is refused with a typed error and nothing is ever written | **Adopted** (with 7-A and the tests below) |
| 7-C | A separate process with no keychain access at all (token passed in the environment) | Rejected: it pushes a long-lived token into the host's config file — for `.mcp.json`, a file committed to the repository. Strictly worse |

**How the narrowing is wired** (§16 D-1 — the first version was broken):
`narrowedContext` builds **one** service context in which Keychain, CliIo,
and Console are replaced by their narrowed forms (`Context.add`), and both
the server layer and every read run in it. Layering `provideService` over a
captured context does not work — an inner `provideContext(captured)` puts the
real services back on top — and that is exactly how the first version ran
every read with the real Keychain and CliIo.

A code path that tried to load the master key inside the MCP server fails
instead of decrypting. The guarantee is as strong as the service boundary:
the Keychain service is the only way the CLI reaches the OS keychain, but
code that bypassed the service (calling `Bun.secrets` directly) would not be
stopped — the compile-time split (7-E) and a read-scoped token (§16 D-11) are
the recorded follow-ups. Pinned by tests: the context every read runs in
refuses master-key reads and routes `CliIo.log` to stderr; an end-to-end
call with an unverified invite anchor (whose prologue prints a stdout line)
keeps the protocol stream JSON-only (this test fails on the first version's
wiring — checked by mutation); an end-to-end call hits only the chain and
`…/pull/metadata` (never `…/pull`, `…/deks`, or a version range).
The agent gate does not apply (the permit side, like `maruhi schema`) — the
MCP server is the agent-facing surface by construction and has nothing to
gate; a test runs it under a detected agent.

## 9. Ruling M8 — stdio discipline

stdout is the protocol channel and stdin is the client's. For the server's
lifetime:

- `CliIo.log` is routed to stderr (defensive — no MCP path uses it; a test
  asserts nothing reached it); `promptLine` / `readStdin` fail with a typed
  error (never read the protocol stream as user input); `openBrowser` is off
- **Effect's own logging is routed to stderr, live**: the default logger
  writes through the `Console` service. Inside a command that is
  `runEffectCli`'s collecting console, which buffers every line until the
  process exits — unbounded for a long-lived server, and lost on a kill. The
  narrowed context supplies a Console that writes to stderr immediately
- **Defects are reported by type name only** (the CLI's rule — failure.ts):
  a read turns a defect into `internal error (<TypeName>)` before McpServer
  sees it (otherwise McpServer would pass the defect's message to the model
  as a resource error, and log the full cause)
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
  end-to-end tests; an upstream break is handled by reverting the upgrade PR,
  and a disappearance by the declared fallback (M2 — 2-C)
- **Names are an injection carrier too**: names are member-written plaintext
  (AUTH_SPEC §12-1), neutralized with `displayText` like the CLI's listings,
  which lets non-ASCII and look-alike characters through (the known open hole
  display.ts records)
- **What `maruhi run` prints is unprotected** (§16 D-1′): the MCP server never
  hands a value over, but an agent that runs a program under `maruhi run`
  reads that program's output. Guidance only until PF4
- **Comparisons across calls are not atomic**: two `get_schema` calls verify
  two views, and a push can land between them. The same class as `maruhi env
  diff`'s documented specimen skew (it too reads the two environments in two
  sequential pulls); get_schema reports no comparison of its own (§16 D-3)
- **EOF drops in-flight responses**: the stdio protocol interrupts the server
  as soon as stdin ends, so a client that writes requests and closes stdin at
  once gets no answers. Hosts keep stdin open for the session; hand tests must
  too (upstream behavior)
- **`resources.subscribe` is advertised** (McpServer's default capability) but
  no update notification is ever sent — a subscriber simply never hears back
- The host's own behavior (whether it shows stderr, how it renders
  `structuredContent`) is outside maruhi's control

## 13. Re-check round (self review before the PR)

Each ruling was re-attacked against the running implementation:

- **R-1 (M8 — Effect logging)**: Effect's default logger writes through the
  `Console` service. The first draft of this record said that meant stdout;
  inside a command it is `runEffectCli`'s collecting console, so the lines
  would have been buffered until exit (unbounded, lost on a kill), then sent
  to stderr — not injected into stdout (corrected by §16 D-9). Fixed either
  way: the server runs with a live stderr `Console`
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
  definitions, `narrowedContext` (Keychain / CliIo / Console), the per-read
  warning capture, the stdio discipline
- `apps/cli/src/notice.ts`: `NoticeObserver` (an optional hook observing
  notices by kind and text; absent outside `maruhi mcp`)
- `apps/cli/src/effect-cli.ts`: the `maruhi mcp` command (`commonFlags`)
- `apps/cli/src/keychain.ts`: `isTokenEntryName`
- Tests: `apps/cli/test/mcp.test.ts` (end-to-end over the stdio framing);
  the `Stdio` stdin / stdout hooks in `test/support/env.ts`
- Public docs: `/docs/ai-agents` (host setup, what the agent sees, what it
  never sees)

## 15. Exhaustion loop (owner-requested, 2026-09-30 — a self-review)

**Read with §16**: this loop was run by the designer, in the same session.
The independent review that followed found options and errors this loop did
not (one adoption here, 3-I, was withdrawn). A self-run loop is not evidence
of exhaustion on its own; the "converged" below is this loop's result, not a
claim that no better option exists.

The owner's delegation required the strictly-better search to continue **until
no new option appears**. The first pass (§§2–10) enumerated each point once,
and only M3 recorded a second round; this section runs the loop explicitly for
every ruling. Each round asks: is there an option not yet in the table (a new
axis, a combination, a relocation of the responsibility) that dominates the
adopted one? A ruling is closed when a round produces nothing new.

| Ruling | Round 2 — new candidates | Round 3 | Outcome |
|---|---|---|---|
| M1 where | 1-F WebMCP in the dashboard: the dashboard holds no keys and does not run the CLI's §6.3 verification, and it is the TCB (ADR-0018) — an agent-facing surface there widens the one place an XSS leaks everything. Rejected. 1-G serve MCP from the `maruhi agent` daemon (KL2): puts the agent-facing surface inside the process whose job is holding key material — the inverse of M7. Rejected. 1-H naming: `maruhi schema mcp` / `maruhi schema --mcp` (honest about today's scope) vs `maruhi mcp` (the host convention; a server, not a display; future value-free agent reads would join the same server without a rename). `maruhi mcp` kept | nothing new | **unchanged** |
| M2 library | 2-D a lighter third-party MCP framework: dominated by 2-B (a dependency either way, and less scrutiny). 2-E offer only the newest revision: no security gain (the same two primitives exist in every revision), fewer hosts. Rejected | nothing new | **unchanged** |
| M3 surface | 3-H a two-environment compare parameter: two calls already give it. Rejected. **3-I a derived `missingRequired`** — the names `maruhi run` would refuse on. Derivable by the model from `required` + `status`, but only approximately: `maruhi run` applies a fail-closed conversion (a declared without a schema counts as required) the model would have to know. Computing it with **the same function** `maruhi run` calls makes the agent's answer and the CLI's behavior one rule. ~~Adopted~~ **Withdrawn by §16 D-4**: its premise was false (a verified `declared` is layout v2 and always carries a schema, so the fail-closed branch is unreachable and the field equals `required && status = declared`), and it overclaimed (`maruhi run` also refuses an environment outside the caller's scope, which the keyless read cannot fully judge). 3-J write tools confirmed through MCP elicitation (the host asks the human): the confirmation UI would be the host's, not a maruhi-controlled trusted surface, and the entropy gate's interactive path would move into it. Rejected. 3-K resource subscriptions / change notifications: needs polling (server-side change notification is demand-driven — SY6). Rejected. 3-L value-derived metadata (length, "looks like a URL"): value-derived information is a value leak. Rejected with 3-E | 3-I's placement: a separate tool vs a field in `get_schema`. A field — same verification pass, no round trip (the M3 folding argument again). Nothing further | ~~3-I adopted~~ (withdrawn — §16) |
| M4 scope | 4-E infer the project from the working directory (a repository file): the CLI has no cwd-based project resolution today (`--project` → `defaultProject`); adding one is a CLI-wide feature, not PF5's. Out of scope. 4-F an environment variable for the project: the same | nothing new | **unchanged** |
| M5 lifecycle | 5-D verify at startup, re-pull metadata per call: the per-call chain sync is what keeps the view fresh; skipping it re-creates 5-A's staleness. Rejected. 5-F exit after idle (the ROADMAP's old "short-lived"): that word was about value leases. The server holds no key and does not retain the token between calls (read per call through the narrowed Keychain), so an idle process holds nothing to expire. Rejected | nothing new | **unchanged** |
| M6 output | 6-D table text in `content` + JSON in `structuredContent`: the MCP convention is the JSON serialization in `content` (what Effect emits); two renderings invite divergence. Rejected. 6-E drop `notice` since `instructions` carry the framing: hosts are not required to show instructions to the model. Rejected. 6-G add variableId / metaVersion / author: actors and internals — data minimization. Rejected. (3-I lands here as a field) | nothing new | **unchanged** |
| M7 guarantee | 7-D narrow to the token of the launch-time origin only: which server is M4's concern, and pinning it would break M5's per-call config reading; every token entry is equally the user's. Rejected. 7-E split `Keychain` into a token store and a key store project-wide (a compile-time guarantee instead of a runtime refusal): strictly stronger in kind, but a CLI-wide refactor of every keychain user for a property the runtime refusal plus tests already make fail-closed. Not adopted in PF5 — **recorded as a follow-up candidate** for a later refactor. 7-F an HTTP allow-list (the MCP process may only reach chain / metadata paths): redundant with 7-B for confidentiality (ciphertext without a key reveals nothing), and brittle — every future change to the metadata prologue's traffic would break the server. Rejected | nothing new | **unchanged** (7-E noted) |
| M8 stdio | 8-B write protocol frames to a dedicated file descriptor: MCP stdio is defined on stdin/stdout; hosts do not support another channel | nothing new | **unchanged** |
| M9 audit | 9-B a `maruhi-mcp` User-Agent on requests: no consumer on the server, no detection gain (client-declared). Rejected | nothing new | **unchanged** |

**This loop's result**: round 3 produced no candidate for any ruling. One
adoption (3-I, later withdrawn), one follow-up candidate outside PF5's scope
(7-E the token/key store split).

## 16. Independent review round (2026-09-30 — owner-requested)

Two independent reviewer agents attacked the branch: one on code
correctness and security, one on design, spec consistency, and docs. Each
finding was verified before acting. Dispositions:

| # | Finding (severity) | Verified | Disposition |
|---|---|---|---|
| D-1 | **The narrowing never reached the read path** (critical, code). In a `pipe` the inner `provideContext(captured)` shadowed the outer `provideService(Keychain / CliIo)`: every read ran with the real Keychain and CliIo; right after accepting an invite, the prologue's "anchor check passed" line went to stdout and corrupted the protocol stream. The tests missed it (the Keychain test was a unit test of `narrowKeychain`) | Yes — reproduced (a precedence probe prints `REAL`; the end-to-end anchor case writes to stdout) | **Fixed**: `narrowedContext` (M7). Pinned end to end; the new test fails on the old wiring (mutation-checked) |
| D-1′ | **"Values never pass through the agent" is false for `maruhi run`** (high, design). An agent that runs a program under `maruhi run` reads its output; the instructions and the docs overclaimed, against this record's own 3-E reasoning | Yes | **Fixed**: instructions, docs, and M6 now say what is and is not protected; residual added; PF4 named as the real answer |
| D-2 | Prologue warnings reached stderr only (medium, both reviews) | Yes | **Fixed**: every `Warning:` of the call is captured and returned (M6) |
| D-3 | `get_schema { environments: [...] }` over one prologue would dominate two calls (medium, design — `env diff`'s single-view rule) | Partly: `env diff` aligns the verification view but itself reads the two environments in two sequential pulls and documents the resulting specimen skew | **Not adopted**: the multi-environment shape would remove only the view difference, not the skew, at the cost of a second result shape; get_schema produces no comparison report of its own. Residual recorded |
| D-4 | `missingRequired` overclaims (out-of-scope environments) and its adoption premise was false (medium, design) | Yes (pull.ts: a verified declared always carries a schema) | **Withdrawn** (3-I) — the field, its code, and its docs are removed; `status` + `required` carry the same fact, and the docs no longer present it as the whole answer to "why won't it start" |
| D-5 | "Value-bearing MCP reads rejected permanently" exceeds the PF5 delegation (medium, design) | Yes — it would close an ADR-0014 Phase-3 item | **Fixed**: reworded to "out of PF5's scope; its own owner ruling under ADR-0014" (3-E, ROADMAP) |
| D-6 | "Even a bug could not decrypt" overstates M7 (medium, design) | Yes — the guarantee holds at the service boundary only | **Fixed**: docs and M7 state the boundary; 7-E and D-11 recorded as follow-ups |
| D-7 | The §15 "converged" claim is not credible for a same-session self-review (medium, design) | Yes — this round found more | **Fixed**: §15 is labelled a self-review |
| D-8 | Stale text (ROADMAP Phase 3, competitive analysis), README docs list, ADR-0011's declared fallback, docs details (`--scope project` placement, `MARUHI_TOKEN` + `MARUHI_TOKEN_ORIGIN` in the host environment, `maruhi agent` only for hosts started from that shell), a raw U+202E in a test file, the 4-D reason relying on a shell (low / nit, design) | Yes | **Fixed**. ADR-0014's own text is left untouched (its revisions are owner rulings; the pull-forward is recorded in the ROADMAP) |
| D-9 | Record inaccuracies: R-1's "stdout" (it was a buffered console), M5's "attestation submission", M6's NFC example (that warning names a variableId the result does not carry) (low, design) | Yes | **Fixed** (R-1, M5, M6 rewritten) |
| D-10 | A committed `.mcp.json` lets committers choose the scope (low, design) | Yes; `--server` cannot capture the token (per-origin tokens) | **Documented** (M4, docs) |
| D-11 | A read-scoped API token for `maruhi mcp` would be least privilege on the server-authority axis (low, design) | Token scopes exist server-side (`TokenScope` — read / write / admin) but the CLI cannot issue one | **Follow-up** (CLI-wide, beside 7-E) |
| D-12 | The default resource reused one notice ledger for the process (low, code): its effect is built once, and the ledger was created at construction | Yes | **Fixed**: the ledger and the warning capture are created per execution |
| D-13 | Defect messages reached the model through McpServer's resource error path, and the full cause reached the log (low, code) | Yes (McpServer maps a resource defect to `InternalError(message)`) | **Fixed**: a read maps defects to `internal error (<TypeName>)`; the stop message uses the same rule |
| D-14 | Launch flags unvalidated; the raw `--env` went into the resource description (nit, both) | Yes | **Fixed**: startup validation (usage error) and `displayText` |
| D-15 | `schemaRows` relabelled any non-active status as `declared` (nit, code) | Yes (unreachable today — the pull refuses deleted statements) | **Fixed**: exhaustive — a deleted statement is left out |
| D-16 | EOF drops in-flight responses; `resources.subscribe` advertised with no updates; test-driver deadline above the test timeout; the stdout decoder without `stream` (low / nit, code) | Yes | Residuals recorded for the upstream behaviors; the test driver fixed |

Checked by the reviewers and found correct: the table output is
byte-identical after the `schemaRows` refactor; neutralization of every
field; strict parameters and non-echoing validation errors; freshness (every
call re-runs the prologue); EOF exits 0 and a real failure exits 1; the
metadata-only path fetches no value or DEK and records no `var.read`; no spec
revision is needed; no telemetry; the docs' JSON example, anchors, and host
configuration shapes.


## 17. Exhaustion loop on the decisions made after the review (2026-09-30 — owner-requested)

The review round (§16) and the CI audit failure on the PR produced new
decisions that were first made directly, without the loop. The owner asked
whether they were looped; they were not, so this section runs the loop on
each (a self-review again — §15's caveat applies).

| # | Decision | Round 2 — candidates | Round 3 | Outcome |
|---|---|---|---|---|
| A | How the narrowing is wired (D-1) | (a) one narrowed context via `Context.add` (adopted). (b) reorder the provides (narrowing innermost): correct today, but one refactor away from the same bug. (c) run the whole command body under the narrowed services so `Effect.context` captures them: equivalent to (a) but implicit. (d) a type-level split (7-E): CLI-wide. (e) process isolation — spawn `maruhi schema` per call: the child is the unnarrowed CLI, so strictly weaker | nothing new | **(a) unchanged** |
| B | How a read's warnings are captured (D-2) | (a) wrap `CliIo.logError`, match the rendered `Warning:` prefix, and force colour off so the prefix matches (first fix). (b) **an optional `NoticeObserver` service in notice.ts that `logNotice` calls with (kind, text) before rendering** — the same shape as the existing optional `NoticeLedger`. No string parsing, no coupling to the prefix format or to colour, no behaviour change anywhere it is absent. (c) have the prologue functions return their warnings: CLI-wide refactor. (d) return the pull's warnings only: the reviewed gap | nothing new | **(b) adopted — replaces (a)** (dominates: same data, typed, no hidden coupling) |
| C | Two environments, one view (D-3) | (a) residual (adopted). (b) `environments[]` parameter over one prologue: removes the view difference, not `env diff`'s documented specimen skew; a second result shape. (c) a separate compare tool: `env diff` exists for shells; for MCP it duplicates (b). (d) add the verified chain head seq to each result so an agent can tell whether two results share a view: detects only half the inconsistency, and no agent is likely to use it | nothing new | **(a) unchanged** |
| D | `missingRequired` (D-4) | (a) withdraw (adopted). (b) keep with an honest description ("required with no value — not the only reason `maruhi run` refuses"): redundant with `required` + `status`. (c) add scope awareness: the keyless read can judge the person's scope but not the device cap (DK), so a partial answer would mislead | nothing new | **(a) unchanged** |
| E | Launch flags (D-14) | (a) validate at startup (usage error, exit 2) and `displayText` (adopted). (b) neutralize only: the host log would show a server that starts and fails every call | nothing new | **(a) unchanged** |
| F | Defects (D-13) | (a) map a defect to its type name inside the read (adopted). (b) rely on McpServer: passes the message to the model on the resource path. (c) disable the upstream log: not configurable, and (a) already removes the content | nothing new | **(a) unchanged** |
| G | The CI audit failure (not PF5's — commit 1f5c93b) | (a) `bun audit fix` + a `miniflare>undici` → 7.29.1 override (adopted in this PR). (b) add the undici advisories to CI's ignore list: leaves the vulnerable version where an override fixes it (tests pass on 7.29.1). (c) **upgrade wrangler 4.136.1 → 4.144.0 and `@cloudflare/vitest-plugin` 1.2.1 → 1.3.3**, whose miniflare (5.20260926.1-alpha) already pins undici 7.29.1 — the proper end state, but a toolchain upgrade (workerd moves too) belongs in its own deliberate PR (CLAUDE.md), not in PF5. (d) put (a) in a separate PR merged first: the repo convention, but this session may push only to the PR's branch | nothing new | **(a) here; (c) recorded as the follow-up that removes the override** |

**Round results**: one replacement (B). A, C–F unchanged. G keeps the
override in this PR, with the toolchain upgrade (c) as a separate follow-up.

**G follow-up (done 2026-09-30, its own PR)**: wrangler 4.144.0,
`@cloudflare/vitest-plugin` 1.3.3 (which pins exactly that wrangler, so one
wrangler / miniflare 5.20260926.1-alpha / workerd 1.20260926.1 remains), and
`@cloudflare/workers-types` 5.20260926.1; the `miniflare>undici` override is
gone. The same PR removes three stale CI audit ignores (image-size and
sharp@0.35.2 — neither is in the tree any more). Its decisions were looped in
the PR description.
