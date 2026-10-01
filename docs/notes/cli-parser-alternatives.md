# Re-selecting the CLI argument parser (gunshi alternative survey)

**Date**: 2026-08-16 / **Status**: decided (→ **ADR-0016**). This memo records the measurements; the decision itself lives in the ADR as the source of truth

## 0. Background

gunshi 0.37.1 has several shapes where it silently accepts input that disagrees with the declaration and **produces the opposite of what was written**.
maruhi has been closing those holes from the outside with `apps/cli/src/args.ts` (911 lines) + per-command tests,
but new escapes kept appearing through review rounds 7–10 (commits 08b8a98 / 0ea3a34 / ef7cba1).
The ef7cba1 shape in particular (`maruhi pull --no-show $FLAGS` **prints all secrets to the terminal**)
turns the parser's silence directly into a secret leak. Since the iteration cost of fixes was high, we compared alternatives by measurement.

## 1. How we measured

We fed each candidate the same argv for the 12 shapes actually hit with gunshi and recorded the behavior (measured 2026-08-16).
The compared command definitions are all isomorphic: `pull` (boolean `--show` / string `--env` (alias `-e`) / integer `--limit`),
`run` (variadic positional), `env create <environment-id>`.

- Environment: Bun 1.3.14 / effect 4.0.0-beta.107 and **rc.109 both** (see §5) / @stricli/core 1.3.0 / gunshi 0.37.1
- Verdict: "reject" = typed error at parse time; "silence" = **a value different from what was written** passes with no error
- effect behaves **identically on all 12 shapes** under beta.107 and rc.109. The probe sources also ran unmodified

## 2. Results

| # | Shape | gunshi 0.37.1 | effect/unstable/cli | @stricli/core | util.parseArgs (Bun built-in) |
|---|---|---|---|---|---|
| 1 | Undeclared option `pull --shwo` | silently ignored (rejects with `strict: true`) | rejects `UnrecognizedOption` | rejects + suggests candidates | rejects |
| 2 | `--show=false` | **read as true without reading** | interpreted as `false` | interpreted as `false` | rejects (takes no value) |
| 3 | `--show false` | flag true + extra positional | consumed as `false` | **rejects** | true + positional "false" |
| 4 | Duplicate option `--env prod -e dev` | **silent last-wins** | **silent first-wins** | **rejects** | silent last-wins |
| 5 | Empty string after `--` | dropped from rest | preserved | preserved | preserved |
| 6 | Leading empty positional `"" pull` | skipped + remains in positionals | rejects `UnknownSubcommand` | rejects + suggests candidates | preserved (resolution is manual) |
| 7 | Command resolution of `-- run printenv` | **resolves across `--`** | does not cross, `UnexpectedArgument` | does not cross | no such mechanism |
| 8 | Missing required positional | optional ones not verified | rejects `MissingArgument` | rejects | manual |
| 9 | Number option with no value | **bare TypeError** | rejects `InvalidValue` (typed) | rejects (typed) | rejects (with error code) |
| 10 | Writing a positional name as an option | discards the value | rejects `UnrecognizedOption` | rejects | rejects |
| 11 | Empty string to an option | collapses to undefined | preserves `""` | preserves `""` | preserves `""` |
| 12 | stdout pollution | header goes to stdout (stopped by `renderHeader: null`) | help goes to stdout (**measured 0B** with Console swapped) | stderr only by default (**measured 0B**) | no output mechanism |

Notes (measured values):

- effect/unstable/cli wraps failures in `ShowHelp`, which carries **typed errors as an array** on `ShowHelp.errors`.
  Unlike gunshi's one-at-a-time reporting, it can return multiple usage mistakes at once.
  exit code is 1 when errors is non-empty (maruhi's usage=2 is expressed by giving the error type `Runtime.errorExitCode` — §7)
- effect/unstable/cli's `DuplicateOption` refers to **declaration conflicts** (same-named flags on parent/child commands);
  it does not fire when the user types the same option twice. #4 remains "silent first-wins"
- Help goes through `Console.log`, so swapping the `Console` service keeps stdout clean
  (measured 0 bytes on stdout for both `pull --shwo` and `pull --help`; only command output remains on stdout)

### Dependencies, size, maintenance

| Candidate | Runtime deps | Minimal CLI bundle | Last update |
|---|---|---|---|
| gunshi 0.37.1 | **0** (all bundled) | 31 KB | 2026-07-19 |
| effect/unstable/cli | shipped with effect + the 2 packages `@effect/platform-bun` (→ `@effect/platform-node-shared`) | 274 KB (of which effect foundation 86 KB = already paid; effective delta ≈ 190 KB) | same release as effect |
| @stricli/core 1.3.0 | **0** | 36 KB | 2026-07-16 |
| util.parseArgs | **0** (Bun built-in) | — | — |

`@effect/platform-bun` is released with the same version number as effect (both beta.107 / rc.109 exist),
and supplies `FileSystem` / `Path` / `Stdio` / `Terminal` / `ChildProcessSpawner` via `BunServices.layer`.

### Agent detection is not a gunshi lock-in (→ redesigned in §8)

`gunshi/agent` is actually **a thin wrapper over std-env 4.1.0's `agentInfo`** (`lib/agent.js` inlines std-env).
Detection is just a scan of an environment-variable table (`CLAUDECODE` / `CLAUDE_CODE` / `CURSOR_AGENT` / `CODEX_SANDBOX` / `GEMINI_CLI` /
`OPENCODE` / `AUGMENT_AGENT` / `GOOSE_PROVIDER` / `REPL_ID` / `AI_AGENT` and others).

So when migrating, the choices are "add std-env as a direct dependency" or "keep an equivalent table in-house (~30 lines)".
The latter has the advantage that **detection rules no longer silently change on upstream updates** (today the security boundary's definition depends on upstream).
The cost is tracking new agents ourselves. Since this is the implementation of the diskless invariant,
which to adopt is a human ruling.

## 3. Evaluation

### Front-runner: `effect/unstable/cli` (bundled with effect v4)

- Of the 12 gunshi-derived shapes, **10 disappear structurally**. What remains is #4 (silent duplicates) and #12 (needs a Console swap)
- **Effect-native**: the `Execute` bridge on the current `runCli`, the `Effect.runPromise` round-trip,
  and the guard that keeps defects from turning into usage errors (`Effect.catchDefect`) become almost unnecessary.
  Errors are `Schema.TaggedError`, so they map cleanly onto `failure.ts`
- The only added dependency is `@effect/platform-bun`, versioned in lockstep with effect. The real binary delta is noise-level in size
- Risk: **unstable module** (that is its status in effect v4). API changes can happen across beta → rc → stable.
  However, maruhi already takes the same risk with `effect/unstable/http` / `effect/unstable/httpapi`

### Contender: `@stricli/core`

- **The only measured candidate where the parser itself rejects #4 (duplicates) and #3 (space-separated boolean)**.
  Diagnostics go to stderr only by default; stdout is 0 bytes on all shapes. Zero deps, 36 KB
- Weakness: wiring to Effect stays in-house as today (an `execute`-equivalent bridge remains).
  Errors are not Effect typed errors, so they must be hand-mapped into `failure.ts`
- Looking only at "parser strength" this is the best. On "overall code simplicity" effect/unstable/cli wins

### Passed over

- **util.parseArgs** (Bun built-in): decent pedigree — it rejects #2 — but subcommands, help, and completion are all in-house.
  Too thin a foundation for maruhi's 14 subcommands. That said, checking #4 is easy with tokens,
  which corroborates that "duplicate checking can be written in-house under any candidate"
- **clipanion**: rc.4 last updated **2024-09**. Stagnation is heavy for a dependency sitting on the security boundary
- **commander / cac / citty**: actively maintained, but no stronger than gunshi on #2–#4 above — no reason to switch

## 4. Recommendation

1. **Migrate to `effect/unstable/cli` as the first choice**. Beyond "10/12 gunshi holes disappear",
   the argument layer unifies on Effect typed errors, and most of `args.ts` plus the `runCli` bridge become unnecessary
2. Put **all checks on Effect declarations** (measured in §6 round 2). What stays in-house is only
   diagnostic re-wording (to avoid printing values) and the `--` requirement on `maruhi run` (policy)
3. **Keep `@stricli/core` as the counter-proposal** for "prioritize argument strictness over Effect wiring"
4. Replace the primary boundary of agent detection **with TTY** (§8). The env name table drops to a secondary layer,
   and library choice is no longer a decision that defines the security boundary

### Estimate and staging (proposal)

1. **Upgrade effect to rc.109** (§5; already done alongside this memo). Pin the migration target to the rc API before writing
2. In a spike PR porting only `pull` / `run` / `env create` (= the 3 commands where dangerous shapes concentrate),
   measure how much of args.ts disappears. Migrating all 14 subcommands at once is too large a review unit
3. Write the ADR after that measurement (envisioned as an addition under ADR-0011 "unstable dependencies" as the CLI argument-layer decision)

## 5. effect 4.0.0-beta.107 → rc.109 (measured)

effect v4 entered rc in 2026-08 (`rc.108` / `rc.109`; the last beta is `beta.107` = this repo's pin).
To decide whether to upgrade before writing the CLI migration, we swapped `effect` to rc.109 in every workspace and ran the quality gate.

| Check | Result |
|---|---|
| `tsc --noEmit` (all 7 workspaces) | pass (**zero source changes**) |
| `vitest run` (whole suite) | 48 files / **all 1488 pass** (including server / DO tests in real workerd) |
| oxlint / ImportLint / fallow audit | pass |
| `effect/unstable/cli` 12-shape probe | **completely identical** to beta.107 |

Notably, the **drift detector in `apps/server/test/data-policy.test.ts` stayed green**.
It checks "for all 14 endpoints × every error kind, do `Schema.is` / `endpoint.error`-derived fail/die verdicts match the declaration exactly" —
an automated re-run of the contract derivation manually verified against beta.107 in PR #49.
In other words **the HttpApi error contract semantics are unchanged on rc.109** (no manual re-verification needed).

Judgment: **upgrade to rc, then migrate the CLI**. Migrating on beta means re-applying the rc-followup diff
to the same file set right after migrating — duplicated effort. The measured cost of upgrading was zero.

## 6. Migration spike (pull / run / env create) — measured

We built the 3 commands on effect/unstable/cli in `apps/cli/test/support/effect-cli-spike.ts`,
and pinned whether maruhi's discipline holds in `apps/cli/test/effect-cli-spike.test.ts` (32 cases).
Production `src/cli.ts` stays on gunshi (the spike is for measurement; promoted to src on adoption).

### What we learned

1. **All 12 shapes produced the expected exit codes and diagnostics** (32/32 green).
   `--show=false` / `--show false` are read as `false` as written,
   empty strings after `--` are preserved, and `--no-show --show` fails
2. **`env` becomes a true subcommand**. Since gunshi only nests one level, maruhi made
   create / rotate / diff **positional arguments**, so one argument table held the flags for
   every operation. The machinery that became necessary as a result — rejecting "options not applicable
   to that operation" (`cli.ts`'s `ENV_ACTION_FLAGS` / `optionRestrictedTo` / `actionFlagRejection` /
   `envActionFlagRejection` / `withoutPositionals`; the same shape exists for server / invite / member)
   — becomes **unnecessary as a mechanism** once subcommands nest
3. **Default English text must not be emitted as-is** (important). `UnexpectedArgument.arguments` and
   `InvalidValue.value` carry **the typed-in value itself**. The extra positional of `maruhi push API_KEY "$SECRET"`
   is plaintext, so with `renderErrors: false` we must rebuild diagnostics **only from safe structured fields**
   (declaration names, candidates, counts). The spike pins this in a test
   (a check that values never reach stderr)
4. Swapping `Console` keeps help/diagnostics off stdout (0 stdout lines even with `--help`)
5. `ShowHelp.errors` returns **multiple mistakes as an array**. Not one at a time like gunshi
6. **`Flag.atMost(1)` is needed even for booleans** (found in review): a bare `Flag.boolean`
   resolves duplicates silently and **the result changes with the order typed** (measured: `--show --no-show` is
   `true` first-wins, `--no-show --show` is `false`). The `maruhi pull --no-show $FLAGS` shape must not be
   order-dependent, so attach `atMost(1)` as with value-taking flags
7. **"stdout carries only command output" can only be checked by separating 3 paths** (review point):
   a test that only watches `Console` output misses the mark, while building the positive control by
   hitting `process.stdout.write` directly breaks the very discipline the spike is meant to prove (output goes through
   Effect services too). The current spike splits three ways —
   **command output** = `Stdio`'s stdout Sink (the harness captures it with `Stdio.layerTest({ stdout })`),
   **help & diagnostics** = `Console` (every method routed to stderr),
   **bypassed writes** = `process.stdout.write` replaced (`SpikeOutcome.bypassed`).
   Cross the wires and a test fails (measured: removing the positive control fails 1 case)
8. **`InvalidValue.expected` can also contain the value** (review point): upstream `Param.filter`
   builds `expected: onNone(a)` (effect's own JSDoc example is `Expected even number, got ${n}`).
   The dangerous fields are **3**, not the 2 of `UnexpectedArgument.arguments` / `InvalidValue.value`.
   The Formatter only emits expected values **matching wording we wrote**
9. **Exit codes break in production unless put on teardown** (review point): upstream declares
   `ShowHelp[Runtime.errorExitCode] = errors.length ? 1 : 0`, so by default
   **a usage mistake exits 1**. `makeRunMain({ teardown })` is upstream's only hook
   (`CliConfig` only holds builtIns), so that's where we remap to 2.
   Computing it by hand in the harness can't check the real boot path
10. **Built-in global flags appear by default** (measured): on top of `--help` / `--version`,
   `--wizard` / `--completions` / `--log-level` attach to every command, and **`maruhi pull --wizard`
   actually launches an interactive wizard**. Narrowing via `CliConfig.layer({ builtIns: [Help, Version] })`
   was confirmed to make them `UnrecognizedOption`, and the spike sets it that way (ADR-0016 decision 5)

### Remaining in-house checks → **nearly all replaced by Effect declarations** (round-2 measurement)

In round 1 of the spike, duplicates / blank values / required rest were written as an in-house `preflight`,
but once we learned they can be declared in Effect's mechanisms we **deleted all of it** (32 cases green).

| maruhi discipline | Round 1 (in-house) | Round 2 (Effect declaration) |
|---|---|---|
| Duplicate same option | scan counting by declaration name | `Flag.atMost(1)` |
| Empty / whitespace-only value | `isBlank` scan | `Flag.withSchema(NonBlank)` (Schema) |
| `run` with nothing to execute | in-house rest check | `Argument.atLeast(1)` |
| Empty-string execution target (`run -- "$CMD"` unset form) | same as above | `Argument.filter` (empty strings from the second one on are kept as child-process args) |
| usage=2 / failure=1 | mapping inside the runner | error type carries `Runtime.errorExitCode` (read by `runMain`'s default teardown) |

**Diagnostics and the `--` requirement also went onto Effect mechanisms** (round 3):

| Remaining in-house | Effect mechanism | Location |
|---|---|---|
| Diagnostic re-wording (render loop in the runner) | implement **`CliOutput.Formatter`** and inject via `CliOutput.layer` | `test/support/cli-formatter.ts` |
| `--` required for `maruhi run` (runner pre-scan) | Effect reading **`Stdio.args`** + typed error carrying `Runtime.errorExitCode = 2` | `TerminatorRequired` (`yield*` at the head of the command body) |

The benefit of a Formatter is "swap only the wording, **leave the rendering call upstream**".
An if-statement added to the runner leaves a hole when upstream adds rendering paths.
`formatHelpDoc` emits the full default formatter text when `--help` was explicit,
and only the one-line usage when attached to a usage error.

**What remains in-house is only "the wording itself"** (the no-values vocabulary is a maruhi-specific
requirement no library covers).

### Attribution of args.ts's 911 lines (per-function estimate)

| Category | Functions | Lines |
|---|---|---|
| **Unneeded** — the parser blocks structurally (boolean values, rest reconstruction, positional recounting, candidate generation, gunshi error mapping) | 27 | **525** |
| **Stay** as maruhi policy (duplicates, blank values, blank positionals, required rest, no-value diagnostics) | 12 | 222 |

`restArguments` (workaround for gunshi dropping empty strings after `--`), `editDistance` / `nearest` /
`suggestionText` (candidate generation — effect returns structured `suggestions`),
the `booleanSpellings` family of 5 functions (detecting values on booleans), and the `usageErrorMessages` family of 3 functions
(unpacking gunshi's `AggregateError`) all disappear together.
This is a **per-function attribution estimate**, not a number measured by actually deleting.

## 7. Inventory of what Effect mechanisms cover (whole CLI)

We also listed things beyond the argument layer. All verified to exist (effect rc.109 / `@effect/platform-bun`).

| Current in-house implementation | Effect mechanism | Effect |
|---|---|---|
| Tokens, master key, decrypted values held as bare `string` / `Uint8Array` | **`Redacted`** (`toString` / `toJSON` return redactions; `Redacted.value` retrieves explicitly; `wipeUnsafe` can also discard) | "no plaintext in logs/errors" is **type-guaranteed**. Today it relies on manual review and tests. `Flag.redacted` also exists, so value-taking flags can be wrapped from the start |
| `live.ts`'s hand-rolled `stdin.setRawMode(true)` no-echo input (recovery code) | **`Prompt.password` / `Prompt.hidden`** | No terminal control needed |
| `run.ts`'s `Bun.spawn` wrapper (`ProcessRunner` service) | **`effect/unstable/process`** (`ChildProcess` + `BunChildProcessSpawner`). `env` / `extendEnv: false` / `stdio: "inherit"` are declarations | Child-process env injection rides Effect's API. `extendEnv: false` is isomorphic to maruhi's denylist thinking |
| Direct `node:fs/promises` calls in `config.ts` / `floor.ts` / `pins.ts` | **`FileSystem` / `Path`** (+ `BunFileSystem`) | Tests no longer need temp dirs (`FileSystem.layerNoop`) |
| `io.ts`'s `envVar` (reading env like `MARUHI_TOKEN`) | **`Config` / `ConfigProvider`** | Config has a single source |
| `io.ts`'s direct `stdin.isTTY` read | **`Stdio.stdinIsTerminal` / `stdoutIsTerminal`** | Terminal detection becomes a service, fakeable in tests (§8's primary boundary) |
| `device-flow.ts` polling interval (fixed floor) | **`Schedule`** | Interval, cap, and jitter become declarations |
| `config.json` parsing | **`Schema`** | Aligns vocabulary with api-schema |

**What does not get replaced** (recorded honestly):

- `retry.ts`'s `retryOnConflict` — CAS conflicts go "classify → recover (re-sync, re-sign material prep) → retry",
  and recovery is domain-specific. Doesn't fit `Effect.retry` + `Schedule`. **Keep**
- Diagnostic re-wording (§6 item 3)
- `keychain.ts` (`Bun.secrets`) — Effect has no key-store abstraction

## 8. Agent-detection redesign (result of the deep dive)

### 8-1. What we learned

- **Effect does not have it**. Across all of effect rc.109's source, `CLAUDECODE` / `isAgent` etc. occur 0 times,
  and the CLI module has no such feature. It is not a general CLI-library feature either
- **Bun's `isAIAgent()` is an internal implementation (Zig), not a public JS API**.
  It's `Output.isAIAgent()` in `src/output.zig`, used to **reduce `bun test` output**
  (PR #21135, merged 2025-07-18; checks `CLAUDECODE=1` / `REPL_ID=1` / `IS_CODE_AGENT=1`,
  later adding `AGENT=1`). `Bun.isAIAgent` is `undefined` on 1.3.14 (measured), with no official docs mention.
  **No public info on Bun 1.4 was found as of 2026-08-16** (npm latest is 1.3.14 / 2026-05-13,
  canary is 1.3.13-canary; no 1.4 announcement on the blog).
  Worth checking "did it get exposed to JS" when released,
  but even if exposed **its detection range is narrower than std-env** (Bun checks 4 variables, std-env 12 kinds).
  Either way it's a secondary layer, so the design doesn't depend on it
- **Several dedicated packages exist** (all zero-dep):
  `@vercel/detect-agent` 1.2.5 (cursor / claude / cowork / devin / replit / gemini / codex / antigravity /
  augment-cli / opencode / github-copilot / v0), `std-env` 4.2.0 (`agentInfo`), `ai-agent-detect`, `is-ai-agent`
- **Env-var standardization is in progress but unsettled**. A proposal pushing `AGENT` (agentsmd/agents.md #136; Goose / Amp already implement)
  coexists with `AI_AGENT` (read by std-env / @vercel/detect-agent), while Claude Code uses `CLAUDECODE=1`,
  Cursor `CURSOR_AGENT=1`, Gemini CLI `GEMINI_CLI=1` — each vendor has its own.
  VS Code / Copilot **oppose** it on the grounds that "agents should run in the same environment as the user"
- The libraries' detection ranges are **not subsets of each other** (std-env has kiro / pi / auggie,
  vercel has cowork / antigravity / v0 / github-copilot). `@vercel/detect-agent` is
  **async** because it also checks file existence like `/opt/.devin` — heavy for a security check

### 8-2. Core: a deny-list is fail-open

The current `gunshi/agent` is a deny-list that "rejects when it matches a **known** agent's env var",
so **the boundary's definition depends on upstream's list**. New agents not on the list, custom harnesses,
CI, log-collection paths **all pass through**. As the survey above shows, standardization is unsettled
and vendor-specific variables are multiplying — the premise "the list is always right" doesn't hold.

### 8-3. Redesign: make the primary boundary "is it a human interactive terminal" (fail-closed)

maruhi's requirement was always "**values may only be seen when a human runs it on an interactive terminal**".
Make that the check itself:

1. **Primary boundary = TTY**: are **both** `stdin` and `stdout` terminals (`Stdio.stdinIsTerminal` /
   `stdoutIsTerminal`; Effect services, so fakeable in tests).
   Agents, CI, pipes, redirects are all **rejected by default**
2. **Secondary layer = known-agent env**: knowing the name makes diagnostics friendlier,
   and it also catches agents that allocate a PTY to run

**Measured (this session = actually inside Claude Code)**: `isTTY` is false for all of stdin/stdout/stderr.
Meanwhile both `CLAUDECODE` and `AI_AGENT` env vars were set.
So **either signal catches it**, but **only the TTY side can stop an unknown agent**.

As a side effect, `maruhi pull --show > secrets.txt` is also rejected.
That operation writes plaintext to disk, and under the diskless invariant **rejecting is correct**.

The spike implements this design in `apps/cli/test/support/agent-gate.ts`,
and pins in a test that "even an unknown agent (`isAgent: false`) is rejected if stdout isn't a terminal".

### 8-4. Library choice drops a rank

Once the primary boundary is TTY, the env name table drops to a **secondary layer**. So
"which library to use" no longer decides the security boundary, and can be treated thinly, in this order:

1. **`@vercel/detect-agent`** (zero deps, wide detection, Vercel-maintained). However
   `determineAgent()` is async and also checks file existence
2. **`std-env`** (zero deps, synchronous, same entity as the current `gunshi/agent` = behavior unchanged)
3. Replace with zero-dep `Bun.isAIAgent()` if it ever ships

**Recommendation: 2 (std-env, synchronous, identical behavior to today) as a strictly-pinned direct dependency**. As a secondary layer,
a detection miss doesn't immediately become a boundary hole. Plus a snapshot test of the detection table
lets CI notice when upstream shrinks it.

## 9. Reproduction steps

```bash
mkdir probe && cd probe && bun init -y
bun add effect@rc.109 @effect/platform-bun@rc.109 gunshi@0.37.1 @stricli/core@1.3.0
# Feed each candidate the same argv (the 12 shapes above) and record values, errors, stdout byte counts
```

The scripts used for measurement aren't in the repo (throwaway, for survey only).
If re-measurement is needed, rebuild from the argv list in the table above.
