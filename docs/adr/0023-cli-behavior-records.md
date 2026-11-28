# ADR-0023: CLI behavior decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 1408 comments on the CLI were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/agent-gate.ts`

- L1: Fail-closed two-layer display gate: TTY allow-list is primary because an agent env-var deny-list fails open; env detection is only a secondary diagnostic layer (ADR-0016 d7)
- L50: AgentProfileRef holds only the detection value so the implementation can be swapped; it is a secondary layer, not the boundary
- L59: Sensitive gate checks 3 channels, one stricter than the value-display gate, because a path also writes to stderr
- L83: describeNonTerminal names which side failed the TTY boundary so the user knows what to fix; check semantics unchanged (DP5 G)
- L102: Agent-refusal message order is fixed: what was refused, why, what to do (DP5 ruling G); semantics unchanged
- L114: Value-display gate has two call sites for defense in depth: pull entry (pre-decryption) and showValues (post-decryption)
- L132: Gate principle: do not stop what is known, let only a human terminal through (fail-closed)
- L143: Ceremony gate shares ADR-0016 d7 two-layer evidence; refusal text is supplied per ceremony
- L171: Device approval is a human FP-comparison act, so it cannot hold in agent/non-interactive runs; registry match never substitutes for a person's yes
- L187: Plain run with a proxy config is gated like value display: injecting real values while the repo brokers them hands agents plaintext (ADR-0016 d7 rev2)

### `apps/cli/src/agent.ts`

- L1: Agent holds keys only in process memory as a Keychain service substitution; no disk writes, no new crypto, lifetime = child lifespan, no TTL or display gate added
- L71: Protocol version mismatch is refused, never reinterpreted
- L74: Message size cap exists so a broken peer cannot exhaust memory; keychain records are orders of magnitude smaller
- L81: IO timeout cap so an unresponsive agent cannot hang the CLI
- L103: Response union order matters: first-match-wins decoding, same reading the hand-written parser had
- L138: Request handling is factored out as a pure function so its semantics are testable apart from socket split-arrival/disconnect concerns
- L157: The list operation carries names only, never values — the wire contract for agent status
- L162: Only master-key entries expire on the TTL (token stays, no re-login); the deadline extends on every set
- L245: A silent peer is cut off at IO_TIMEOUT_MS, otherwise server.close() never returns and the agent outlives the child, skipping cleanup and its exit code
- L284: Socket errors are not reported by the agent: the peer reports its own side, and the agent's stderr shares the child's terminal so writing would dirty the screen
- L295: startAgentServer requires a pre-existing user-private (0700) dir and serves the socket at mode 0600 — the trust precondition of the agent socket
- L305: Open connections are tracked because close must sever them first: server.close only waits for natural close and never severs
- L320: Socket mode is tightened right after listen, independent of umask; the 0700 directory means there is no window for another user to connect
- L328: Held records are discarded before close; JS strings cannot be zeroed, so dropping references is the most that can be done
- L335: Connections are severed without waiting: termination is decided by the child's exit and in-flight requests need not complete (the peer reports its own failure)
- L375: The env-var socket path is distrusted before connecting: anyone can plant MARUHI_AGENT_SOCK, so socket/owner/0600 checks gate use; same-user attack is out of scope like the OS keychain
- L394: Pre-connect lstat failures reuse the connect side's classification so the same state cannot become a different story by path
- L415: Uid comes from process.getuid, not os.userInfo (passwd read throws for numeric-only uids in containers — this feature's target); process.* here is owner identity, not decision input
- L431: sendAgentRequest settles only on the first resume and destroys the socket first, so a late close/error cannot mask the outcome; Effect.callback cleanup covers interruption/timeout
- L497: The timeout clock covers only the conversation; the preceding lstat was never inside the timer either.
- L516: Only the two shared socket-error cases live in the shared handlers; AgentGone differs per caller (the probe treats it as safe to start a new session)
- L531: A stale socket from an ended session is fine to replace; untrusted destination or version mismatch surfaces its reason to the user
- L558: Invariant: a request this implementation sends can only be refused by a version-mismatched agent
- L564: Agent keychain is selected by the production layer only when MARUHI_AGENT_SOCK is set (live.ts)
- L574: A names-shaped response to a value request implies a version-mismatched agent
- L594: XDG_RUNTIME_DIR preferred (per-user tmpfs, 0700); os.tmpdir() fallback is safe because the created directory itself is 0700
- L605: Private runtime dir removal failure is a warning naming the path, never fatal, since the directory holds no values; shared with proxy run
- L648: An empty first argument is a usage error too: 'there is one argument' and 'there is something to run' are different things (same as run)
- L659: Agent nesting is refused, but only a live agent counts: a leftover env var from a dead parent may be replaced, else reparented shells would dead-end
- L679: Removal failure must not discard the session result (child exit code); the directory holds no values, and the failure is warned, not swallowed
- L699: The session notice goes to stderr so it does not dirty or interleave with the child's stdout
- L719: agent status shows held entry names only: values are neither carried over the protocol nor printed
- L743: Socket path arrives via an env var, so it is display-neutralized before printing despite being self-created
- L754: Entry names are rendered readable, and server-supplied origin/userId free strings are neutralized on output
- L764: The master entry separator is the last '::' because an origin such as http://[::1]:8787 can itself contain '::'; userId never does

### `apps/cli/src/approval.package/command.ts`

- L70: Approval commands carry zero values, so the agent-gate is not applied to them (K6-E).
- L256: The fulfilled-sweep report is ordered preamble, then sweep, then the completion line.
- L342: Approve signs, then fulfils if the proposal completed (K6-B / approval item 22).
- L351: The completion-time sweep report carries the unconverged duties, so the always-on mandate warning is suppressed, as for a convergent command.

### `apps/cli/src/approval.package/index.ts`

- L1: approval-rules.ts stays at the src root because the command startup path imports it; routing it through this index would also load approval.ts and chain-sync.ts.

### `apps/cli/src/audit.package/audit-d1.ts`

- L1: audit invites/self read D1 rows (invite.* events and the user's own events) rather than the project DO, which list reads.
- L92: The §3.1 implication note for to-be-monitored events is attached once, at the self listing.

### `apps/cli/src/audit.package/audit-list.ts`

- L1: Visibility classes are server-enforced and this side only renders; each chain.* row is reconciled against the verified chain and names come from verified statements only.
- L52: expandReads expands an aggregated var.read row into one line per variable; the default is a count-only summary (§3.3).
- L84: Name resolution covers environments of rows carrying a variableId and, when expanding, an aggregated var.read's environment, since the expanded lines draw names.
- L128: Expanded read lines take display names only from verified statements — the same TCB discipline as the var= label.
- L158: With --var, the matched item is the variable in the row's enumeration; the server returns rows whose enumeration contains that variable, and a row is one kind so at most one matches.
- L185: chain.* rows are reconciled against the verified chain and any mismatch (tampering evidence) exits 1; readability and soundness are not conflated.

### `apps/cli/src/audit.package/audit-mirror.ts`

- L109: The mirror mapping never sets api_token_id (§3.4's actor copies the chain entry's), but the check stays explicit to block a fake "via token" display.
- L121: Unreachable on a verified chain, but verify (reports a problem) and list (unverified label) share the same missing-proposal predicate.
- L150: Rows newer than the local chain can be an honest race (chain grew after sync), not evidence on their own; verify distinguishes forgery by contiguity from just after the head.
- L178: A row carrying chain_seq with an event name outside chain.* claims forged provenance: the only writer that sets chainSeq is chainMirrorEvents, so it gets an explicit distrust label.
- L200: Provenance is judged by the presence of chainSeq before looking at the event name.
- L215: The D1 path (invites / self) stores no chain provenance; if chainSeq is present it is forgery or corruption.
- L228: An empty warning list means unverified but not tamper-decidable on its own.

### `apps/cli/src/audit.package/audit-page.ts`

- L30: Unspecified paging keys are omitted from the query so the server defaults apply.
- L38: Aggregated var.read rows enumerate variables in the payload (no variableId column) and are interpreted with the same shared implementation as the server (§3.3).
- L52: Aggregated read counts count distinct variables; several versions of one variable (the §12-7 version range) are counted as such.
- L64: Aggregated rotation.recommended rows carry one row per environment per chunk with no variableId column (§3.3 Sc-5); the flagged variables come from the payload via the shared @maruhi/core reader.
- L78: serverTs is a server-claimed unbounded number, so it is displayed with the total shared formatter to avoid RangeError on out-of-Date-range values.
- L113: An aggregated row's line shows only the read=/flags= count; the enumeration (tens to ~100 KiB) is never dumped on the line and rides --expand-reads instead.
- L150: A rotation.recommended row's epoch is its exposure bound, not a value's epoch (AUDIT_SPEC §3.3 / §4.1-5).
- L168: Even if a caller forgets the trust computation, chain_seq is never displayed label-less like a verified coordinate — the last line of defense.
- L178: The recorded= prefix marks server-claimed content; it may carry a name snapshot but is never promoted to the verified display-name position (TCB discipline).
- L186: For an aggregated var.read only the payload remainder after dropping the variable enumeration is printed, since the enumeration can reach tens of KB and is carried by the summary/--var/--expand-reads paths.
- L196: Aggregated rows drop their variables enumeration from recorded= because the read=/flags= summary and --var's match already surface it.
- L207: Display names (resolvedName) come only from verified statements.
- L216: seq rides only on an admin-visible response; a non-admin never sees the ordinal (§7).

### `apps/cli/src/audit.package/audit-reconcile.ts`

- L57: Fetch progress is shown every 50 pages so unresponsiveness and non-termination on huge logs become visible.
- L116: Integrity strategy (ruling AJ): the paging cursor is a row id and duplicate ids or non-strictly-decreasing seq abort as a self-contradicting response; the fetched set closes as a snapshot of the first page's point in time.
- L141: No static page bound: strictly decreasing positive seq bounds the total row count by the first page's maximum seq and carries termination.
- L202: The stored TEXT is reconstructed per the header comment's round-trip premise; no payload maps to NULL.
- L213: The recomputation failure's whole payload is the seq and the crypto-side kind — identifiers only, no secrets.
- L232: The cumulative hash column is recomputed per §5.1; the canonical implementation is @maruhi/crypto and the audit-head.json vectors pin the same h_n as the server.
- L250: A stray duplicate head keeps the first (earliest position) even though SHA-256 collisions do not occur in practice.
- L257: The recomputation error carries only a seq and reason code, but per discipline it is still mapped to a fixed wording of identifiers only.
- L266: A gap in seq is the trace of a deletion (§6).
- L313: Position floor (c): a checkpoint's position must be at or above the mirror row of the immediately preceding checkpoint itself; a missing or duplicated mirror row is a broken §3.4 bijection reported as tampering evidence.
- L351: Runs membership (a) plus position (b)(c) checks of the notarizing checkpoints (AUDIT_SPEC §6).
- L373: A notarized cumulative hash not appearing in the recomputed column means some row inside the notarized prefix was altered or deleted afterwards (§6).
- L401: Declared-head membership detects a false head declaration without waiting for notarization (ruling AK).
- L425: Reconcile pipeline: pre-judge effective admin, fetch declared head, fetch all rows, gap check, recompute the column, then checkpoint membership/position checks; any violation exits 1 (§6).
- L437: The head declaration is taken before fetching all rows (ruling AK) so the membership check's population is always covered by the fetched snapshot.
- L446: With a gap, downstream checks would misleadingly report every notarization as a violation, so only the strongest evidence (the deletion trace) is reported and checking stops fail-closed.
- L473: Success wording stays faithful to what was proved: with zero notarizations (a)(b)(c) are vacuously true, so no unconditional "checks passed" is printed.
- L486: Rows after the last notarization are outside the notarized prefix and uncovered until the next notarization (§6 residual).

### `apps/cli/src/audit.package/audit-verify.ts`

- L46: Verify paging is hard-capped (100 pages) so a server whose cursor does not advance cannot loop forever; the cap is a single total across namespaces.
- L54: Paging contract: with a null bound, termination is carried by the caller's row check (reconcile bounds total rows via the strictly decreasing admin-visible seq).
- L71: The type annotation breaks self-referential inference inside the paging generator (before -> rows -> before).
- L139: Verify's mirror candidate set is the union of every chain.* row and every row carrying chain_seq, deduped by id; changed content for one id means the server contradicts itself.
- L181: Rows newer than head must run contiguously from head+1 with at most 2 rows per chain_seq (§3.4/§5.1); non-contiguity or 3+ rows is evidence of forged rows claiming nonexistent entries.
- L221: chain_seq's presence is the trust boundary ahead of the event name: its only genuine writer is chainMirrorEvents, so an out-of-namespace row is a forged provenance claim no real op can reconcile.
- L231: Inside the namespace, an event name missing from the mapping is itself forgery evidence, since a real op's mirror always lands in chainMirrorEvents' image.
- L273: serverTs is out of comparison scope: the observed row's value is copied onto the expected row before comparing.
- L279: Expected rows pair to observed rows by event name: none observed is missing, 2+ is duplicate, an out-of-set name is excess; any field mismatch including viaProposalSeq is listed (§3.4).
- L295: A propose missing from the index is a contradiction in the index's construction, reported as a verification failure with the chain_seq rather than dropped as a defect.
- L324: Verify checks the full chain-to-mirror bijection and every field, detecting missing/forged/altered rows — including the missing case per-row list labels cannot see; it reads only class 1 so every member can run it.
- L355: Never say OK while unverified rows remain: a successful exit must not paper over forged rows sitting permanently inside the unverified allowance.

### `apps/cli/src/audit.package/command.ts`

- L77: audit self takes no project account-wide: with no --project on the declaration, passing one is an Unknown flag error.
- L107: The cursor is a row id (AUDIT_SPEC §5.1, format shared with api-schema); the value the previous page's guidance showed is passed as-is.
- L147: List's filter flag format is checked before any network access.
- L153: --env / --var arrive already decoded because their declarations check the format, so no re-check here.
- L165: Audit list needs no master key (audit rows are non-secret metadata, the same keyless class as rotation list); the visibility class and invite.* authority axis are enforced server-side.
- L284: Bare `maruhi audit` = list (stage 3 ruling): the parent itself carries list's declaration and handler, which measured behavior of a handler-carrying parent plus withSubcommands makes work.

### `apps/cli/src/bin.ts`

- L4: Runtime check runs as the leading side-effect import so it takes effect before import hoisting
- L11: Explicit process.exit over exitCode assignment: a pending Bun.secrets call interrupted by the keychain timeout was observed to keep the event loop alive

### `apps/cli/src/byte-replace.ts`

- L1: Byte-level (not text) replacement so invalid UTF-8 is never corrupted by U+FFFD re-encoding; carry-over holds only bytes that could still begin a match; longest pattern first
- L105: Scan invariants: longest match wins, replacement output is never rescanned, and a shorter match is never taken while a longer one is still possible (pf4-design 19 C-2/C-11)
- L143: replaceBytes contract: longest pattern wins at each position; patterns with an empty from are ignored
- L164: Stream replacer correctness: scan runs over source bytes only and stops exactly where a longer match could begin; hold is at most longest pattern minus 1 bytes
- L196: 8-byte scrub floor: shorter fragments are ordinary text rewritten everywhere and carry no secret worth the corruption (pf4-design 21 R-1)
- L206: Scrub patterns cover each secret whole, per line, and JSON-escaped, sharing the maruhi sync fragment rule; sub-floor fragments are dropped entirely
- L228: Dedupe key is the fragment's byte list as a short string to avoid re-encoding the whole fragment as text
- L241: Non-UTF-8 fragments are skipped for line/escaped derivation: only the raw bytes can be matched

### `apps/cli/src/checkpoint.package/checkpoint.ts`

- L348: AuditHeadNotReady retries share one budget across runs via counts.notReady, and the attempt cap lives in the while predicate, not the schedule's times, which would still run the predicate on the final step and emit a spurious retry line.
- L396: AuditHeadNotReady (503, lazy materialization incomplete) is absorbed by a dedicated bounded retry because server-side progress is saved per call and always advances; on exhaustion the message guides re-running instead of dropping to a generic error.
- L608: The type annotation cuts the generator's self-referential inference (built -> subset -> built).

### `apps/cli/src/checkpoint.package/index.ts`

- L1: checkpoint-integrity.ts stays at the src root: values.ts imports it, and through this index it would load checkpoint.ts, which imports values.ts.

### `apps/cli/src/ci.package/ci-lease.ts`

- L81: A lease 404 is a uniform existence-concealment response (§14-1), so the member-oriented shared guidance is replaced with lease-specific guidance pointing at policy mismatch.
- L175: The anchor file is read before any network call or key generation so a broken anchor fails fast instead of hiding behind a round trip.
- L245: Verification success goes to stderr (decision 9): stdout stays free for the child process's output; stderr is the destination for diagnostics and info.

### `apps/cli/src/ci.package/ci-rotate.ts`

- L103: The primary's value shape is shown locally only and never becomes a proposal fact (D-8).
- L666: The mint report lines never include values, only names, counts and dates.

### `apps/cli/src/ci.package/command.ts`

- L143: ci run's required flags never fall back to the config file: a CI runner has no persistent config, and pinning the genesis belongs to the workflow YAML's review; diagnostics say "write the flag", not "set it in config".
- L157: ci sync has no --env (the sync config's target decides the environment), so the missing-flag fix is stated per command.
- L173: CI read fallback (PF2 — AUTH_SPEC §11-7 ruling E): only when the server is unreachable and --mirror names a replica, lease there with a token for the mirror's audience; never on a server answer (404/401 is not retried).
- L223: Every format check precedes network and key generation (the existing commands' discipline): the ids at the declaration, the origin here.
- L259: Format checks and the config read precede network and key generation (as ci run); there is no --env because the sync config's target decides the environment.
- L282: Every format check for ci rotate's coordinates runs before the config read and the network.
- L332: The rotate config is read before any network or key generation (the same discipline as ci run).
- L363: Terminator handling drops a malformed command before any communication or key generation, the same -- discipline as run.

### `apps/cli/src/ci.package/index.ts`

- L1: ci.package exposes only the lease surface other files import; ci sync's op lives in sync.package and leases through this index.

### `apps/cli/src/cli-formatter.ts`

- L1: Diagnostics are an Effect CliOutput.Formatter (not runner-side rendering, which upstream render paths would bypass) and show only maruhi-authored wording, because upstream defaults embed typed values that may be plaintext
- L33: CommandSpec contents are derived from the command definitions themselves, no hand-written copy, so new declarations cannot leave diagnostics stale
- L46: strayHint exists because argument contents are withheld from diagnostics, so a mistyped invocation needs a command-specific fix hint
- L58: Only allowlisted expected-wording may be shown as-is; anything else was not written by maruhi and may contain a typed value
- L71: Branded-id refine annotations carry no input, so echoing them in diagnostics is safe; the allowlist stores the authored wording with the render prefix stripped
- L97: Declaration choice prefers the stage upstream reported (error.command), because the argv-inferred dispatch key can resolve a parent-stage flag to the leaf and produce a self-contradictory diagnostic
- L106: An empty error key is built from the root spec too: falling back to the dispatched leaf for a flag written before the command name would refuse a flag while listing it as accepted
- L114: Writing a positional argument's name as an option is a different mistake shape and needs a different fix
- L119: A flag present in the resolved stage's declaration but reported undeclared was written before the subcommand: guide placement only, never say 'does not exist' or list accepted flags
- L137: A nested parent stage usually has no own flags, so an undeclared flag there gets placement guidance, not 'does not exist'; a handler-bearing parent (bare audit = list) lists accepted flags like a leaf
- L147: Runtime-admixed globals (--help/--version) are filled into the accepted-flags list here because they never appear in the declaration table
- L178: InvalidValue is described without showing the value: `expected` is not inherently safe, so only upstream's fixed phrases and repo-written constants are trusted
- L200: The Schema machinery's 'Expected <annotation>' render prefix is stripped so the allowlist and echo carry the authored wording alone
- L212: A UserError is shown only when it is the authored userMessage: an empty one falls back to the cause's message, which may contain the typed value; bound now though currently unreachable
- L250: describeError renders errors in maruhi's vocabulary and never echoes typed values; discrimination is by instanceof (direct _tag access is banned by oxlint)
- L272: rc.117: atLeast(1) with 0 arguments is MissingArgument, not InvalidValue; run-shaped commands revert to the 'no command after --' wording
- L290: A ValidationError from maruhi's own Command.validate rule carries fixed repo-written text, so its message may be returned as-is
- L299: Help amount is deliberate: explicit --help gets the full default text; a usage mistake gets only the single usage line so the diagnostic is not buried
- L317: Full help rides upstream's default formatter but with maruhi's color decision: upstream's stdout-based auto-detection also disagrees with the NO_COLOR convention, so it is overridden (stderr-based)
- L324: On a handler-bearing parent (audit = list) upstream's required '<subcommand>' usage is corrected to '[subcommand]'; the decision is declaration-driven so ordinary parents stay untouched
- L334: run requires '--' (ADR-0016 d8) though upstream renders only a variadic positional; the usage substitution touches only the usage line's word and keys off the declaration-derived key
- L348: --version prints the version number only (pinned by version.test.ts), in the shape usable as V=$(maruhi --version)
- L353: When the command name itself did not resolve, flags reconciled against root would line up correctly-spelled flags as unknown; the user is not made to hunt through them
- L358: Flag-error suppression applies only at the root stage: on a deep-stage UnknownSubcommand, placement guidance for parent-stage flags is still needed alongside

### `apps/cli/src/cli-runner.ts`

- L21: Unused Effect environments get dying implementations so undeclared interaction/output paths (Prompt/wizard) have no room to move (decision 5)
- L57: Every Console method is bent to stderr (decision 9): a partial override would let a future upstream render method leak to stdout; lines are collected and flushed after the run
- L92: argv is re-mounted onto Stdio so the argument layer and the terminator judgment read the same array; only the source is unified, the value never changes
- L103: Failure reporting uses only maruhi vocabulary, never an upstream English sentence passed through raw
- L106: ShowHelp needs no re-render here: the effect side already rendered it via the Formatter to stderr
- L113: Defect messages are never shown (they can embed a typed-in value); only the error type name is attached, and the failure is not swallowed silently
- L142: The pre-'--' scan decides only the amount of help, never an argument check; arguments after '--' belong to the child process and are not inspected for help requests
- L149: Bare maruhi with no arguments is treated as a help request (exit 0, to stderr); a bare subcommand stage is a misspelling (exit 2) (ADR-0016 appendix)
- L158: infoRequested is the teardown's discrimination material: without an explicit help/version request, an errors-empty ShowHelp means a bare parent command = usage error
- L181: Only --version output goes to stdout (it is the command's output, legitimately captured by scripts); help and diagnostics stay on stderr
- L206: Production and tests go through the same teardown so the ShowHelp exit-code reinterpretation cannot work on only one side
- L212: maruhi run inherits the child's exit code via a successful run's return value, since Command.runWith discards handler returns and it cannot ride Runtime.errorExitCode

### `apps/cli/src/cli-teardown.ts`

- L1: Exit convention 0/1/2 is expressed as a runMain teardown (ADR-0016 d4) because upstream ShowHelp makes usage errors exit 1 and the teardown is the only reinterpretation hook; tests share the production path
- L22: Usage errors get their own exit code 2 so a script cannot read a typo as an execution failure
- L25: Teardown distinguishes explicit help/version (0) from a bare parent command (2) via launch argv, because upstream's errors-empty ShowHelp carries both meanings
- L49: Errors present, or no explicit help/version request, both mean usage error even when ShowHelp's errors are empty

### `apps/cli/src/cli.ts`

- L1: runCli holds only the pre-dispatch diagnostic, the diagnostic destination resolution, and the final internal-error net; values enter via stdin and display is gated by agent-gate
- L20 (2026-11-28 tree): `CliServices`, the union of every service the entry provides, is declared here and not in context.ts. There it named three services of feature files (`ProcessRunner`, `ProxyAcceptStore`, `SqlRunner`), so context.ts imported types from the layer above it, and attestation.ts imported context.ts for the union. The three functions of attestation.ts that named it now declare the two services they use (`FloorStore`, `CliIo`), so no trust-core file names the union. The command layer, the features and context.ts name the type through a type-only import of this file, the one direction in which a lower layer may see the entry; none imports an entry file by value. The record on `Stdio` as a member of the union stays under `apps/cli/src/context.ts` (L70)
- L24: A dedicated message exists for a command name placed after -- because effect/cli's diagnostic can only say 'extra argument' and cannot say how to fix it
- L34: positionalTokens is dispatch material, not the argument-inspecting scan ADR-0016 d2 forbids; it cannot disagree with effect's resolution because consumers only read the first token and pre-terminator presence
- L71: Diagnostic destination resolves to the deepest known command level drawn from COMMAND_SPECS (no hand-written copy); unknown or empty names resolve to root
- L101: RunCli's exit-code contract (0 success, 1 failure, 2 usage, 3 rotation-due findings) is carried in this doc.
- L119: A command name sitting after '--' is dropped before dispatch is decided, and an empty token is never resolved as a command name
- L129: Layer-build and logError failures surface only the error type name, never the message, which could embed a typed-in value; otherwise bin.ts would show Bun's unhandled rejection

### `apps/cli/src/commands/agent.ts`

- L47: The -- terminator discipline applies to agent too, so a misspelling drops first even though this path touches neither server nor keys.

### `apps/cli/src/commands/config.ts`

- L34: An empty/whitespace-only value is refused by the NonBlank declaration: it blocks the accident where the unset shape of config set overwrites the existing config with an empty value and reports success.
- L44: Config key validation never lets the given value itself appear in the error.
- L60: stdout carries only the command's output (the value), so V=$(maruhi config get server) captures nothing besides the value (decision 9).
- L73: A config key holding a closed-set value is validated at declaration so a typo is never silently stored.
- L79: A broken config is recreatable via set (it holds only non-secrets), but never swallowed silently — a warning is emitted; recreatable is content corruption only, while a read failure (EACCES/EISDIR/EIO) fails as-is so an unreadable existing config is not silently replaced.

### `apps/cli/src/commands/flags.ts`

- L14: NonBlank blocks the accident of an unset $ENV silently writing a secret into the default environment.
- L29: singleValued uses atMost(1) to refuse duplicated flags in the declaration, since effect's default first-wins would silently accept shapes like pull --no-show $FLAGS.
- L64: Booleans also need atMost(1): a raw Flag.Boolean resolves duplicates order-dependently (measured), which would make --show/--no-show outcomes depend on typing order.
- L80: Diagnostics' declarations are derived from the command definition itself because a hand-written copy would go stale when a flag is added.
- L137: Run target rules: atLeast(1) plus a filter drop a missing or empty first target, while a second-or-later empty string is kept as a child argument.
- L179: Flag-combination refusals run after parsing and before the handler, are reported like parse errors (exit 2), cost no network round trip, and use fixed text naming flags, never values.
- L192: --env/--all-envs/--no-envs each set the whole scope, so at most one of them may be given.
- L207: --no-sync combined with --config is refused as a contradiction rather than silently skipping the config that was pointed at.

### `apps/cli/src/commands/index.ts`

- L1: ADR-0016 discipline: all argument checks are declarations (never hand-rolled scans), typed values never surface in diagnostics, exit codes live on error types, global flags are narrowed to help/version.
- L172: GROUP_CONFIGS is the single source from which COMMAND_SPECS is derived; a hand-written copy would leave dispatch and diagnostics stale when a subcommand is added.
- L287: Only audit's parent stage carries a declaration (bare maruhi audit = list), and it feeds COMMAND_SPECS so parent-stage diagnostics assemble from the same declaration.
- L307: ROOT_SPEC_KEY is the empty string because a 1-stage commandPath makes slice(1).join(' ') empty; the root diagnostic key must match that spelling.
- L316: push's stray-argument hint never shows the refused argument (it may be plaintext) and always attaches the stdin guidance instead.
- L358: The root stage spec is the single-stage list the unknown-command diagnostic prints as the possible commands.
- L395: The product's one-liner sits at the top of bare `maruhi` and `maruhi --help` (ruling F).

### `apps/cli/src/commands/lazy.ts`

- L1: Command-layer entry points into context/session are lazy wrappers so parsing, help and version load none of those modules; startup-loads.test.ts pins this (P-6).
- L151: lazyWithMirrorFallback is declared generically in the read's value rather than derived from context.ts's type.

### `apps/cli/src/commands/login-logout.ts`

- L81: Checked before any communication: without the shared bound, a too-long token name surfaces as start's encode failure, a diagnostic confusingly close to a connection failure.
- L87: --show-token's displayability is judged by the same fail-closed two-layer gate as value display (ADR-0016 decision 7), before any communication: on a refused environment a completed browser approval would rotate away the old token and end with no new raw value (ruling CK).
- L104: The default-name judgment uses the resolved actual name: explicitly passing cli:<hostname> also counts as the default name, because the branch keys on a plain re-login becoming a same-name rotation (ruling CM).

### `apps/cli/src/commands/mcp.ts`

- L17: maruhi mcp is keyless and outside the agent-gate: it is the agent-facing surface by construction and serves no values (M3/M7); its op loads lazily (P-6).

### `apps/cli/src/commands/pull-run.ts`

- L48: The shared verified pull fails fast on a required=true variable declared in the verified set before any child starts (rulings CT/CU), while the §14.3-7 type check is advisory — a mismatch warns only.
- L73: Point-of-use nudge (PF7a): one note when a just-pulled value is past the max age its schema declares; it never changes the outcome.
- L84: The brokered run shared by proxy run and run-with-proxy-config: project check, environment, verified pull, presence fail-fast, type advisory, then proxy-run.
- L100: A proxy config is applied only once a person accepted its content on this machine for this project (R-8/R-24: an agent cannot accept its own rules, nor point another project's accepted rules at this one); checked before any network and again against the resolved project.
- L115: The read may be retried against the configured mirror (PF2); the proxy then starts once.
- L125: From the first brokered run on, plain `run` without a config is gated for this project (R-13).
- L148: The value-display refusal is checked at the command entry, before decryption — never build decrypted plaintext and then refuse; the post-decryption check in showValues is a second defense line.
- L156: The read (prologue and pull) may be retried against the configured mirror when the server is unreachable (PF2).
- L172: Filling the missing epochs of my other devices happens on pull only (DK K11-4): it is a registration the mirror would refuse, so it is not done on the fallback read.
- L194: Declared (valueless, §4.2 layout v3) variables are listed as metadata rows since no value or version exists; the schema detail lives in `maruhi schema`.
- L200: Point-of-use nudge (PF7a): one note for values past their declared max age.
- L226: The terminator check drops before any communication or decryption, at the command body's head.
- L228: A present proxy config decides what the child receives (ADR-0016 decision 7 revision 2); --plain keeps the real-value shape only for a person at a terminal; the config is read before any network.
- L255: The read may be retried against the configured mirror when the server is unreachable (PF2); the command then runs once.
- L261: For a project brokered on this machine, real values go only to a person at a terminal: deleting the config or changing directory is not a way around the rules (R-13).
- L269: Environment-variable names go through verified statements (§4.2/§12-7); the execution-control variable-name denylist is a defense layer applied to the verified name.

### `apps/cli/src/commands/rotation.ts`

- L52: The dismiss variable argument is not taken on a --all run; atMost(1) expresses 'omitted under --all' in the declaration.
- L173: A single dismissal names the pair <variableId> --env <environmentId>; --env without a variableId only narrows --all.
- L186: Neither rotation list nor dismiss requires the master key (non-secret metadata, the same keyless class as project verify); dismiss's authority (admin or above × admin scope) is enforced server-side.
- L235: The proposal decides the environment: it is looked up through a keyless project context first, then the environment context (device key) is opened for its environment.

### `apps/cli/src/commands/shared.ts`

- L1: commands/shared.ts is a leaf: of the other commands/ files it imports only lazy.ts, itself a leaf.
- L34: P-6: the heavy implementation graph is imported lazily inside the bodies that use it, so parsing/help/version never pay its module cost; each load reads names off the module in .then (the only shape fallow credits per export), pinned by startup-loads and lazy-imports tests.
- L51: commandAfterTerminator implements ADR-0016 decision 8: only what follows -- runs, and the count after -- must match, derived from the parser-resolved array and argv's position (never a copy of the declaration, which would drift); contents never appear in diagnostics.
- L73: On the no--- branch the variadic arguments stay as extra positionals (a flag's value was already eaten as the flag's value).
- L88: After config set mirror, the member is told now when no keychain session exists for the mirror: a fallback that needs a login while the server is down is no fallback (ruling E revision).
- L185: A value write's sync is decided before the write is sent; a disagreement with an explicitly given config's project is a misspelling (exit 2) and the write is not sent.
- L208: The sync config is read first, before any network, so a broken file or another project's config is never found behind the write (SY2 stage 2 ruling B); the sync is decided before the write is sent.
- L231: After a successful write: trigger (iii) checkpoint proposal, then the decided sync; a failed sync stays a warning and the exit code stays the write's.
- L419: The widenings-outside-scope note is emitted even when no backfill exists within my scope: the main path is a listed admin re-running after someone else's widening.

### `apps/cli/src/config-schema.ts`

- L1: Config files share one Schema step machinery preserving the hand-written validators' step order and exact wording; reasons never contain the offending value or an array position
- L65: Reason rendering rule: a message starting with a separator is a suffix on the field's dotted path (array positions omitted); anything else is already a complete reason
- L102: An optional config value that no union member accepts reports the leaf's own wording instead of the union's default 'Expected X | undefined'
- L168: loadConfig unifies read-failure wording ('cannot read' whichever way it failed) and provides the FileSystem locally so callers never take the service into their environment

### `apps/cli/src/config.ts`

- L1: Config holds only non-secret settings in one JSON file; secrets live only in the OS keychain, and the server URL has no default because self-hosted is the premise
- L35: mirror is the read-only origin run/pull/ci fall back to when the server is unreachable, with the mirror's own session (PF2, AUTH_SPEC 11-7)
- L86: Outside config set, a corrupt config surfaces as a plain CliError: the dedicated tag exists only for the one command allowed to rebuild the file
- L112: Config decoding is a Struct so unknown keys drop out and every key stays optional, keeping an absent key absent
- L125: Config decode is per-key tolerant: one bad value is dropped rather than failing the whole decode and taking down the other settings
- L159: Corrupt-content failure is its own tag so only config set's discard-and-recreate catches it; read failures (EACCES/EISDIR) are not corrupt content and must not trigger replacement
- L172: ConfigFileCorruptError keeps CliError's exit code 1: it is an execution failure, not a usage error
- L184: Only NotFound counts as empty settings (first run); folding read failures into empty would let a later config set silently replace settings that merely failed to read
- L211: Config writes go through temp + rename to prevent torn writes; among concurrent runs the last write wins

### `apps/cli/src/connector.package/connector-aws-iam.ts`

- L1: AWS IAM connector: rotation creates a second key; finalize deactivates the previous only after lineage check + STS proof
- L31: IAM Query API is fixed to us-east-1 whatever the caller's region (external constraint)
- L33: SigV4 signs content-type, so the body must declare the exact value; setting a body rewrites the header from the body's type
- L40: GetCallerIdentity needs no permission; it only proves the credential pair authenticates
- L43: These STS error codes mean the key id/secret are not a pair (or key gone/inactive) — the auth-failure signal
- L54: Companion name every AWS rule carries; the rule's accessKeyIdVariable supplies it
- L63: Signing credentials: the admin pair when named, else the key itself (self-rotation)
- L101: Regex XML extraction is safe because IAM responses are flat and values are never interpolated back
- L117: One SigV4-signed Query API call; an error answer is returned, not thrown — the caller classifies it
- L200: Pair proof: GetCallerIdentity success proves the pair, an auth error refutes it; any other answer is surfaced, never read as not-the-pair
- L292: IAM allows two keys per user; an inactive non-current key is a finalized previous rotation and is reclaimed; an active key is never deleted
- L329: Key ids earlier versions held; ill-formed values are ignored, never matched
- L341: Finalize target is decided against the issuer: deactivated only when lineage-verified and STS proves it authenticates with the previous secret

### `apps/cli/src/connector.package/connector-cloudflare.ts`

- L1: Cloudflare connector: rotation creates a replacement token copying current policies; finalize deletes the previous token
- L26: Cloudflare envelope is {success, errors, result}; other keys are deliberately not read
- L41: Absent/null/misshaped result decodes to none; each step answers with its own wording
- L51: Token definition fields are what the replacement copies; optional ones are checked where copied
- L60: Created token's value is shown only in this answer (secret handling)
- L101: A successful non-envelope answer is now a connector error (was silently an empty envelope); error statuses still own their message

### `apps/cli/src/connector.package/connector-exec.ts`

- L1: Exec connector: script creates the credential; all script output is scrubbed of known secrets before display; finalize reruns with previous
- L35: Stderr shown on failure is the scrubbed tail, capped at this many lines
- L40: Secret representation shaped for the scrubber (what a script could echo)
- L45: Scrubbing follows the sync driver's discipline: remove every known secret, keep the tail
- L50: Script environment contract: credential + companions + admin inputs + control vars; values must be UTF-8 without NUL; refusals name the variable, never the value
- L105: The previous credential's companion (the key id to retire) rides into finalize when known (C-7)
- L151: A rejected capture becomes the connector error: stopped by maruhi (D-6), a leftover's output (D-14), or a launch failure
- L158: Stopped by maruhi after start is not a launch failure (ruling D revision); a started rotate script may already have created the credential (D-17)
- L170: A script's own answer cannot be told from a leftover process's output (D-14); exit 0 on rotate names the recovery
- L185: Runs one script; launch failure or non-zero exit is a connector error naming the script and the scrubbed stderr tail
- L207: New value from stdout: exactly one trailing newline (LF or CRLF) dropped, nothing else touched
- L231: Stdout parsed as a JSON object; anything else is refused with the contract spelled out
- L252: Unknown JSON keys are counted, never echoed — the script's words could carry a credential
- L267: The script's own words never reach an error message (a mistyped key could be a credential); the message names what the rule declares
- L283: Produced values must be non-empty UTF-8 without NUL (injectable by maruhi run later); errors name the value, never carry it
- L295: Produced bytes are checked as UTF-8 without NUL: a value that could not be injected is refused before it is stored
- L330: The rotate script's JSON answer contract: { value, companions?, facts? }
- L374: Script-produced facts are scrubbed of every secret the run knows before reaching the report

### `apps/cli/src/connector.package/connector-shared.ts`

- L1: Shared connector vocabulary anchored to rulings D-7/D-8/D-16/D-18
- L14: Issuer origins: production leaves all unset (issuer's fixed host); tests inject the reference to target a fake issuer
- L32: Finalize invalidates only credentials whose id a lineage-verified ancestor held; server history metadata never picks the target
- L40: Empty inputs map means self-rotation
- L43: RotationSite exists for the exec connector's scripts; other connectors do not need variable/environment
- L59: Plan is decided before anything is sent; the caller confirms an immediate invalidation
- L61: Description must carry no credential (one line shown to the user)
- L63: immediate=true means the old credential stops working within the rotation itself, no grace period
- L70: shape is for the local report only; never a proposal fact
- L74: Line-count mismatch between new and current value is worth a look before pushing (D-16: a leftover's line is the common form)
- L76: facts are non-secret report material (new key id, role in use, token id)
- L80: recovery covers the case where the issuer accepted but storing the new value failed, leaving the credential only in the exiting process
- L86: warnings include a connection test that failed after the issuer accepted the change
- L90: ConnectorOutcome omits shapes because the frame adds the values' shapes
- L98: ConnectorError messages never carry a credential; the caller reports them as-is
- L110: HttpClientError message: the transport's own cause when it has one, the client's wording otherwise
- L141: Shape numbers are formatted at display time and never parsed back (D-19)
- L164: Changed line count earns a warning before the push, never a refusal (D-16/D-18); a token becoming a PEM is legitimate
- L179: Only a script can have printed more than the credential; an API connector's difference is the current value's layout (round 9)

### `apps/cli/src/connector.package/connector-sql.ts`

- L1: SQL connectors: password set via ALTER ROLE/USER on the alternated role or in place, then connection-tested; finalize randomizes/discards the previous
- L28: SqlRunner implementations: production is Bun's SQL client (live.ts); tests use a recorder
- L30: execute contract: statements run in order on one connection, then disconnect
- L32: probe is the connection test of a new credential (trivial query)
- L38: Effect's Random is deliberately not used for password generation — it is not cryptographically secure and the outputs are credentials
- L60: Password generation uses rejection sampling over 62 symbols to avoid modulo bias
- L82: parseDbUrl takes the decoded user and refuses a URL without credentials
- L124: Rotation targets the other role of an alternated pair, or the URL's own role when not alternating
- L167: Driver error messages can echo the connection URL, so only the first line is kept and credential URLs are stripped
- L279: Connection-test failure is a warning, never a refusal — the issuer already accepted the change

### `apps/cli/src/connector.package/connector.ts`

- L1: Connector frame design (PF6/R2): dual-credential grace period like Infisical/Pulumi ESC/AWS SM; old credential valid until --finalize
- L81: ConnectorServices are the command's ambient services; Clock/IssuerEndpoints/ConnectorCrypto come from run context with production defaults
- L90: companionsOf maps companion name to the variable that holds it
- L95: planRotation is decided from the current value alone — nothing is sent
- L218: A missing rotation site is an internal inconsistency, never a user error

### `apps/cli/src/connector.package/index.ts`

- L1: connector.package surface: no command.ts here; rotate flows run through var-rotate/ci-rotate and the frame in connector.ts

### `apps/cli/src/connector.package/rotate-config.ts`

- L1: Rotation config is non-secret and versioned with code (like sync/proxy configs, per CLAUDE.md); it holds no credential
- L63: Connector kinds map to files; postgres and mysql share connector-sql.ts
- L79: Exec control prefix is deliberately outside MARUHI_: that namespace never reaches a child process, and input/companion names may not start with it
- L89: InputRef.environment null means a variable of the target's own environment
- L95: Empty inputs means self-rotation
- L102: accessKeyIdVariable holds the key id pairing with the secret this rule is keyed by
- L104: IAM user is optional: derived from the current key at the issuer when absent
- L110: accountId null means a user-owned token (vs account-owned)
- L116: roles null means the URL's own role changes its password in place (vs alternating pair)
- L123: MySQL host part defaults to % in the 'user'@'host' account form
- L128: Exec connector design (PF8): maruhi interprets nothing about the issuer, so any scriptable issuer works
- L137: Rotate script argv runs with no shell; first element is the executable resolved from cwd
- L139: finalize null means the rotate script must retire the previous credential itself: no grace period, so confirmation is asked
- L145: Scripts' cwd is absolute: the config's directory, or cwd joined onto it
- L147: Rotate script output is the new value alone or a JSON object carrying companions and facts
- L149: companions maps environment variable name to the maruhi variable it carries, pushed next to the credential
- L151: inputs maps environment variable name to the supplying maruhi variable (free-form names for exec)
- L157: projectId is optional and checked against the resolved project when present
- L174: CONNECTOR_INPUTS null means any environment variable name — the exec connector's scripts choose
- L183: DB names outside the safe class are refused rather than escaped: a rotation must never run a statement the author did not mean
- L193: inputs.<input> object form {environment, name} points at another environment's variable
- L212: A bare string input names a variable of the target's own environment
- L221: AWS admin pair is consumed as a set: both keys or neither (self-rotation); a session token rides only with the pair
- L237: Input names: the connector's fixed set, or for exec any name the child can carry; null = acceptable
- L295: Every way the roles list can be wrong reads as the one reason
- L384: Exec env-name refusals: not a POSIX identifier, an execution-control name (run.ts denylist parity), or the connector's control namespace
- L403: Name equality is case-insensitive where env names are — the rule maruhi run applies to its own injection.
- L448: Scripts' cwd is the config's directory or joined onto it; an absolute path would not travel with the repository
- L456: A cwd climbing out of the config's directory would run whatever lives there — refused
- L501: Companion name collisions are judged case-insensitively because the script may run where env var names are case-insensitive (run.ts injection rule)
- L530: The exec rule's own name must be script-carryable and no input may collide with it, judged case-insensitively (run.ts rule)
- L656: A companion belongs to exactly one rule and is not itself a rule — the conflict invariant
- L701: Config is parsed in one pass, header then rules, in the order the reasons ran before (first wins); configDir bases exec cwd
- L733: A broken default config is reported, never skipped

### `apps/cli/src/context.ts`

- L1: Command prologue reads the config exactly once and unifies sync/floor semantics in attachProject; the split is only whether the master key is needed
- L70: Stdio lives in CliServices as the boundary keeping process.argv/process.stdout.isTTY from being read directly; production is platform-bun, tests use layerTest
- L103: --mirror names the read-only replica a read falls back to (PF2, AUTH_SPEC 11-7), defaulting to the mirror setting
- L105: mirrorOf is set by the fallback retry, never a flag: the session opens the mirror's credential, the device key stays the server origin's, and nothing is written to the mirror
- L131: Mirror fallback fires only on unreachable or gateway errors, never on the server's own answers (403/404); the retry is announced on stderr and all verification duties run unchanged (ruling E)
- L206: ID format validation reuses @maruhi/core's isProjectId/isEnvironmentId; no duplicated pattern definitions
- L222: The supplied ID value is never returned in the error (flag values follow ADR-0016 d2 discipline); command-line origin is a usage error (2), config origin an execution failure (1)
- L642: quietMandateWarning is only for converging commands, whose own sweep report conveys the same fact more accurately — the sync-time warning would be double-reporting noise
- L746: §9's server-disclosure Note is emitted on every project open from the verified view and is never quieted — even server revoke states the grant it is about to revoke
- L776: The master key is loaded before sync and floor advance: a write command on a keyless device must fail before any server round-trip
- L800: Own-device observation/registration runs only on keyed prologues (idempotent, non-fatal); a mirror refuses the registration, so the fallback read skips it
- L806: openMetadataProjectWith differs from openProject only by not loading the master key — which also lets MARUHI_TOKEN (keychain-less) sessions run the parity checks
- L838: invite list/revoke use the keyless prologue because every reconciliation input is chain-derived; invite create needs the sig key for the issuance signature, so it stays on openProject

### `apps/cli/src/crypto-error-kind.ts`

- L1: Crypto error kind is recovered by constructor discrimination (same mechanism as internalErrorKind) because reading _tag directly is banned by oxlint
- L63: WrappedCryptoError is a closed union: a non-member is a broken invariant surfaced as a defect, not a guessed kind

### `apps/cli/src/deletion-confirm.ts`

- L1: Terminal deletion is fail-closed and shared: interactive runs retype the identifier, non-interactive runs refuse without --force, and the consequence is always printed
- L32: The retyped confirmation text is compared after trimming and NFC normalization
- L36: Deletion gate contract: --force passes after printing the consequence, an interactive terminal requires retyping, anything else refuses before anything is signed or sent
- L48: --force is explicit risk acceptance, but the deletion fact is still made visible: a deletion is never silent
- L79: A CAS retry that re-resolves the confirmed deletion target under a new name proceeds without a second prompt (the confirmation binds the never-reused ID) — but the name change is always said

### `apps/cli/src/der.ts`

- L1: A minimal DER writer exists only for the two places the CLI must produce ASN.1 (proxy ephemeral certs, PKCS#1-to-PKCS#8 wrapping); encoding only, no parsing, no crypto
- L60: A leading 0x00 keeps a DER INTEGER positive when the high bit is set (X.690 minimal encoding)
- L119: A PKCS#1 private key is wrapped as PKCS#8 PrivateKeyInfo because that is the one form WebCrypto's importKey accepts (RFC 5208)

### `apps/cli/src/device-gaps.ts`

- L174: The gap-fill command always spells --env and --project explicitly: relying on the default environment would pull a different one (K11-5)
- L189: The missing-epochs warning is shared by value pulls and device add's reachability check, and its causes list both the member-side and device backfills (K12-3)
- L216: Failure and success messages name only the epochs this device attempted: naming all gaps would include epochs this device can never fill (pullfrog finding)
- L226: A retry is suggested only where it helps — after the cause is removed (e.g. a read-scope token's 403, K11-7 limit (3))

### `apps/cli/src/device-key.ts`

- L61: Unregistered-key wording routes via device approve only when a pending request exists (a registered key cannot recreate one); a device listed elsewhere is added by syncing from a device listed here (K10-5)
- L72: Revoked-key wording (K13-5): a revoked key never returns, so re-adding uses a new key; cleanup on other projects is stated conditionally because this body sees only this project's chain
- L260: revokedFingerprintsOf is one predicate shared by device-sync's registration exclusion and device add's 'revoked on this project' (K12-6)
- L285: The re-add route always uses a new key: a revoked key is never registered again as the same key (K12-7)

### `apps/cli/src/device-sync.ts`

- L205: Only re-approval clears a record's revocation mark, and a registered key cannot recreate a request (K10-5) — so the note never says 'approve it again', a procedure the user cannot follow
- L308: The registration note reports the added cap from the chain, because this is the only point where the record's cap takes effect (K10-3)
- L324: A registered device's failed backfill is not retried by the next sync (candidates are only records not on the chain); filling is done by a pull from a device whose cap covers it (K11-5)
- L338: Failed-backfill guidance emits copyable commands per environment with the real id; the '<environment>' placeholder is only for when the environment is unknown (Bugbot finding)
- L349: The append path already mapped the typed error onto failure.ts's wording in one place, so here only K4-14's carry-over (the local record is kept) is appended to that wording

### `apps/cli/src/device.package/command.ts`

- Moved 2026-11-28 from `apps/cli/src/commands/device.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L123: The revocation is already on the chain; what remains after a failed sweep is only fulfilling the duty, and the always-on warning keeps displaying it.

### `apps/cli/src/device.package/device-add.ts`

- Moved 2026-11-28 from `apps/cli/src/device-add.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L47: The mid-wait hint fires at TTL/3 from request creation; because docs transcribe it as 'five minutes', the value is pinned by cli-vocabulary.test.ts
- L70: Existing-key branch (DK K13-2/K13-9): a live request resumes the wait, otherwise the chain standing decides; neither path creates a request (the server consumes the 1h/5-attempt window first)
- L87: A registry row for the new key's FP means an FP collision: there is no awaited request, so it is reported by chain standing, never as 'Approved' (K13-3)
- L108: The fingerprint is announced only for a saved key — an unsaved key must never be the one that gets approved (K13-8)
- L145: On expiry the two approver-output branches stay (an approval may not be appended yet — a race), and the chain's facts at this moment are appended with a timestamp (K13-4)
- L157: If the project list cannot be fetched, nothing is counted: '0 projects' would not be a fact (K13-3)
- L170: The completion sentence is emitted once the standing is known; the per-environment key-arrival checks come after (output order stays K12-3's)
- L196: When a project could not be synced the count sentence's range is a lower bound over what was checked — an unqualified '0' would not be a fact (K13-16)
- L212: Existing-key-with-no-request branching follows the §18 table: exit 0 if valid anywhere; with zero valid, stop in the order could-not-sync → revoked somewhere → on nothing
- L244: A failed approver registry PUT (T3, K9-3) is a display note only — the registry never drives branching
- L252: The zero-valid refusal order is could-not-sync → revoked → on-nothing, and every sentence states its assertion's range (no assertion when it could not sync — K13-2)
- L287: Floor projects absent from the server list are informational only (Option B, K13-7): the floor is not separated by server/account, so it supplements the assertion's range but never judges
- L320: Standing report order is key arrival → revoked → could-not-sync → unregistered (K12-3); the approver-side narrative is stated only when it follows the awaited request's signal (K13-3)
- L339: For a revoked key the revocation fact and re-add procedure are stated on this chain — not the approver-side narrative (K12-6)
- L347: Never say 'none' about a project that could not be synced (K13-3)
- L357: The registry signal is PUT after the approver's project loop, so its work is done by signal time; a registration deficit is fixed by a keyed command targeting that project, not by the approver re-syncing (K10-5/K7-2)
- L372: On the existing-key path no approval happened, so the approver-side narrative is deliberately not stated.
- L378: New-key start order is generate → create request → guarded save/replace (K13-8): if request creation fails, the keychain changes nothing and the old key stays
- L477: Key-reach checks reuse the value pull's fetch path (environmentKeysFor, §5.1/§5.2) and absence judgment (missingEpochsOf); failures fold into facts and never change device add's outcome (K12-2/K12-4)
- L568: A live request for the same key means resume the wait (K4-5); a lookup failure is reported, never swallowed — a 409 is proof of life, never grounds for 'it was revoked' guidance
- L591: The registry wait polls to the TTL; the one-time hint (elapsed derived as expiry − TTL) states only the missing signal and leaves the cause to the approver's screen (K7-3)

### `apps/cli/src/device.package/device-approve.ts`

- Moved 2026-11-28 from `apps/cli/src/device-approve.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L31: Approve references accept only the full 32 hex chars or 12 words (K4-6) — prefixes are not accepted
- L61: The matching request row is picked by recomputed FP: the response's claimed FP is never used (K4-6)
- L104: Multiple requests for the same key stop the approval with them shown: silently picking one would grant chain authority on a guess (server is supposed to dedupe by FP)
- L133: The ceremony gate precedes fetching the request list (K4-6 counterexample 3)
- L147: FP-provenance discipline (K7-7): only an admin-token path can place a request, so approval instructs comparing against the screen of the machine being added, never a conveyed fingerprint
- L156: Approval is 2-phase (K10-4): every project is opened and judged first, because judging while appending would notice a cap disagreement only after this run's cap was already added somewhere
- L188: If approval landed on no project, record/registry/cancel do not run: recording would repeat the failure at first sync, the registry row would send a false signal, and cancelling erases the re-run's material
- L215: The registry PUT (the signal) is done last and its result is the cancellation condition (K9-1): cancelling after a failed signal leaves a re-run unable to find the request or resend the signal
- L232: On signal failure the request is left until expiry: a re-run converges via all-projects-already → PUT → cancellation; past expiry no path writes the registry row (K9-3 T3)
- L256: Phase-1 plan carries chainCap — this key's cap if already on the chain — as a chain fact regardless of whether a signing device exists (K10-2 round 3)
- L303: A registered key cannot re-approve without a request (K10-5): registration happens via this project's own-device sync, whose prologue opens only via a keyed command targeting the project
- L334: The re-run command's flag spellings are transcribed from the help golden (--cap/--env/--all-envs/--no-envs/--project)
- L356: Cap discipline (K10-1/K10-2): a device's cap is fixed at first approval, so a re-run is only a continuation; comparison is against the chain (the truth) only — local records are never read
- L448: Landing nowhere (all skipped/failed, with no record or cancellation) ends the approval as a failure — not exit 0 even when everything was only skipped
- L482: 'already' does not backfill, so re-running approval fills no gap (K11): a sibling device's pull fills it — and this route also avoids K10-12's cap refusal

### `apps/cli/src/device.package/device-list.ts`

- Moved 2026-11-28 from `apps/cli/src/device-list.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L69: On-chain appearance lines judge standing with keyStandingIn — the same predicate as device add (K13-6)
- L130: Even when the project list cannot be fetched, the registry and local records are still shown rather than dropping the whole list (K13-6)
- L144: This device's own key is printed even when absent from every chain, registry, and valid record — it is the place a revoked device's error defers to (K13-6)
- L183: On-chain appearance reporting never says 'none' about a project that could not be synced (K13-6/K13-16)

### `apps/cli/src/device.package/device-revoke.ts`

- Moved 2026-11-28 from `apps/cli/src/device-revoke.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L48: Revoke references are an FP prefix of 8+ chars or the registry's display name, your own devices only (K4-7)
- L144: Marking the revoked device in the local record prevents re-registering it (K4-3 counterexample 1)
- L300: Revocation confirmation is skipped by --yes: a revocation is not a ceremony (K4-7)
- L484: After the append is accepted the revocation is on the chain: a resync/sweep failure is reported as a sweep failure, never folded into 'revocation failed', and the local-record/registry aftermath is never skipped
- L514: The sweep is derived on the post-acceptance resynced view (the pre-append view has no revocation duty); the server's claim is never the source of truth
- L527: When this device revoked itself, the sweep cannot be fulfilled from this device (K4-7 counterexample 5)
- L541: Token-revocation proposal (K4-13): candidate is the registry tokenId else 'cli:<label>'; --revoke-token revokes, interactive asks, --yes only proposes; a 403 on the list reports only the fact

### `apps/cli/src/device.package/device.ts`

- Moved 2026-11-28 from `apps/cli/src/device.ts`, the path at the audit base commit `0f036bef` that the L numbers below refer to
- L1: Device group overview: per-command design — add branches on chain standing without a gate, approve recomputes the FP and stops on cap mismatch, the registry PUT precedes request cancellation (K9-1)
- L76: A malformed stored key materializes as a non-matching fingerprint (null, treated as 'no such key'); any other failure is an invariant break and dies
- L85: The registry is used only for display and the approval signal, so an unreadable registry yields null and never fails the command

### `apps/cli/src/device.package/index.ts`

- Added 2026-11-28 (after the audit; no base line): `device.package` holds the `device` command group (`command.ts`, which was `commands/device.ts`) and five files of the group: `device-add.ts`, `device-approve.ts`, `device-list.ts`, `device-revoke.ts` and `device.ts`. The index re-exports `describeBackfill` and `reportRegisteredDevice` of `device-approve.ts`, with which `key recover` reports the device it registers. `device-standing.ts` stays at the src root: `ledger-open.ts` reads a ledger key's standing from it, and through this index `ledger-open.ts` would also load `device-approve.ts` and `device.ts`, which `guardian add` and `key seal passkey` do not load. `device-gaps.ts`, `device-ops.ts` and `device-sync.ts` (the open pipeline) and `device-key.ts` (the trust core) stay at the src root too, where their zones in `.fallowrc.json` name them.

### `apps/cli/src/display.ts`

- L86: Server-declared unix ms display is total: out-of-Date-range values degrade to an 'invalid timestamp' string instead of crashing the whole command with a RangeError
- L100: Only the standard ISO form is accepted: a year outside 0..9999 makes toISOString return the expanded-year form, and a fixed-offset slice would silently cut a different position
- L139: countNoun exists because ADR-0017's English switch multiplied count-embedding wording; writing plurals inline yields '1 variables'
- L157: describeListed phrases the range of 'the N projects the server listed' for none-exists sentences, shared by device add and the ledger-key decision (K13-2/K15-3)
- L235: formatPulledLine unwraps the value for its byte length only: the row is emitted regardless of --show, before the value-display gate, so the value itself must not enter the output here
- L255: Value decoding is fatal on both display and run paths: letting only display pass with replacement characters would create a 'shows under --show, fails under run' asymmetry and silent copy corruption
- L280: showValues re-checks the gate post-decryption as a defensive line, aligned to the same TTY-primary gate — leaving one check on the old deny-list would let an unknown agent slip through that side
- L287: Every value is decoded before any output (all-or-nothing): one invalid UTF-8 value fails the whole display rather than leaving partial output on screen
- L295: The value is unwrapped only after ensureValueDisplayAllowed passes: unwrapping before the gate would assemble plaintext in memory even in an environment that refuses display
- L318: Neutralization is never silent: when it alters a display, stderr names that the original differs and gives the means to pass the actual value, so a copy cannot silently paste a corrupted value
- L346: A trailing newline is stated in the heading rather than dropped: it is part of the value, and a naive split would invent an empty extra line and shift the declared line count
- L362: warnAlteredDisplay does not present `maruhi run` as universal: a value containing NUL cannot ride an env var and run itself refuses it

### `apps/cli/src/entropy.ts`

- L1: Entropy check design (ruling CW, fail-closed): thresholds lean toward detection because a false positive costs one confirmation while a miss puts a real value in plaintext meta; findings never carry the input
- L60: Mixed-charset judging: random secrets almost always mix digits with mixed case or base64 symbols, while identifier-like legitimate input (DATABASE_URL, camelCase, prose) satisfies neither
- L78: Base64 padding only lowers the token's entropy, so it is stripped before judging.
- L94: A finding never carries the matched text — only length and kind — so callers can build messages without echoing a possible secret (ruling CW)

### `apps/cli/src/env.package/command.ts`

- L35: Environment ID format is checked before the network, and the refusal never shows the given value
- L50: Config key is the spelling typed; specOf uses it as-is as the diagnostic name
- L65: No implicit discovery of the sync config default path: rotate can run outside a repository and the config is cwd-dependent
- L79: other-environment-id is declared required because env diff is diff-only (missing = MissingArgument)
- L171: Sync config is read before any network: a broken file must never sit behind the epoch advance
- L176: Opened as an environment context for the floor (6.3); as a convergent command the unconverged-duties warning is suppressed
- L193: Undefined and empty --reason are distinct: an empty one is dropped by the declaration with exit 2
- L205: Whether a new epoch was requested is fixed by the launch-time flags (--new-epoch or a reason selecting the rotate path)
- L223: Cleanup advances the receipt only for accepted re-encryptions; failure stays a warning; the same floor handle is reused for the rotated env
- L235: Cleanup starts from the resynced verified view (an extension of the opened view); a resync failure folds into a warning
- L308: env list is keyless and zero-value: no agent gate, no master key; a device key only narrows the scope column, else member scope with a Note
- L332: A missing or unusable key is not an error for list: the listing states which scope it judged against
- L362: env diff leaves exit 0 on a difference: a difference is report content, not a run failure (else indistinguishable from evidence)
- L382: Diff prologue runs exactly once; no master key is required (nothing is decrypted)
- L392: No env-level meta floor (no values read), but the chain floor's head advances per pull as in pull/push
- L426: --new-epoch validation runs before the session: an unsatisfiable check must not leave per-variable var.read audit entries
- L447: Comparing an environment with itself is refused as a misspelling; the given values are never shown (a positional could carry a value)
- L500: Nested subcommands remove the need to hand-write refusals of inapplicable options

### `apps/cli/src/env.package/env-diff.ts`

- L1: env diff compares variable-name sets and schema contracts only, never values — detects forgot-to-put-in-prod without decrypting
- L92: DiffSideEntry deliberately does not carry description (2)
- L95: declared boolean: true means declared with no value
- L115: contractMismatches judged only from both environments' verified statements (the required axis of 1-5)
- L121: shared count does not imply values match — values are never decrypted
- L125: Name ordering is UTF-16 code-unit ascending; localeCompare rejected because locale-dependent order would make the diff output itself undiffable
- L151: declared counts as an existing variable name (S3 ruling: declared is first-class, 4.2); same-name collisions are already refused by 6.3 verification, so map folding loses no fact
- L166: Warnings are emitted immediately per pull so the first pull's warnings are not dropped when the second pull fails
- L195: The second pull reuses the view the first returned — otherwise the two environments would be compared against separate histories
- L211: commitHead is called per pull: calling it only at the end would drop the first pull's head advancement when the second pull fails
- L271: Diff display shows name, state, required only — description is not shown (2 consumption discipline; 14.3 display discipline)
- L296: Diff listing goes to stdout and warnings to stderr; every emitted string is neutralized here (names may carry ANSI/BEL)
- L322: The count line is printed even at 0 names — the output's shape does not vary between runs
- L328: The required axis (1-5) is shown even for shared names; the count line prints even at 0 (output shape invariant)
- L343: The specimen-skew caveat is always printed to stderr; going silent at zero differences would hide skew's most dangerous direction

### `apps/cli/src/env.package/env-list.ts`

- L1: env list is a zero-value metadata read (no agent gate, no master key); the environment set comes from the verified chain, which never forgets one
- L64: name is null for a deleted environment — none is distributed (12-7)
- L69: inScope is never true for a deleted environment: a deletion leaves no permission in it
- L79: rows include deleted environments, ID ascending
- L82: memberBasisReason is null when the basis is the device's effective scope
- L88: ListWire is the decoded success body; the client method's Success also carries response-mode results
- L93: JoinedEnvironment.statement is null when the environment is deleted on the chain
- L100: Join invariants: a live environment must be listed with a verifying statement; a deleted one must not be listed (listing one is a resurrection refusal)
- L111: resynced=false on the first pass because an omitted live environment may be a deletion the view has not seen yet
- L143: An environment ID listed twice is an inconsistent response
- L161: A live environment must be listed and verify; a listed deleted one is refused as a resurrection
- L177: The list carries no head: a deletion accepted after the view's sync legitimately drops the environment, so the first omission resyncs once
- L222: env list op: facts come from the verified chain (module header); a null device fingerprint means a keyless run
- L308: List row shows ID, name, status, epoch, scope, disclosure; the name is neutralized and a deleted environment shows no name.

### `apps/cli/src/env.package/env-rename.ts`

- L51: resolveRenameTarget refuses a rename that would change nothing
- L95: The meta set is unchanged (4.3); the 3-F intent is persisted before sending

### `apps/cli/src/env.package/env-rm.ts`

- L136: Deletion confirmation is fail-closed: retype the environment ID, or --force
- L233: An intent left open is the safe direction: the next run's reconciliation redoes the same decision

### `apps/cli/src/env.package/env-rotate-decrypt.ts`

- L69: The nothing-can-be-opened wording is pinned to one place: split wording would defeat dedupeWarnings and print lookalike lines
- L79: The undecryptable warning text is pinned to one place: per-path wording variants would pass dedupeWarnings as distinct

### `apps/cli/src/env.package/env-rotate.ts`

- L53: Rotation modes: rotated = new epoch, resumed = unfinished re-encryption, up-to-date = check only
- L67: remainingExact: only the unmeasured shape is labeled includes-unverified on display
- L97: Reason validation: null means --reason was not given; a given-but-empty reason is dropped here so a rotation request cannot slip into the check path
- L119: A malformed reason spelling is a usage error (2); only whitespace-only or too-long shapes reach here
- L141: The rotate_epoch path always has a reason by construction (validate rule / rotatePathOf / sweep) — a missing one is a defect, not usage error
- L157: env rotate: the 12-4 composite then re-encryption as ordinary pushes (7/4.1); a re-run resumes instead of rotating again (12-7)
- L172: Bounded retry on the values_digest 422 (12-4): redo from a verified pull, doubling as omission prevention
- L184: Warnings flush even on failure paths, and the receptacle is created inside the Effect so a second run never inherits the first run's warnings
- L201: A concurrent push invalidated this attempt (epoch did not advance): the generated DEK/wrap set may be discarded; redo from a verified pull
- L212: On exhaustion the tag is dropped and the error surfaces as a plain CliError with the same message
- L221: Resume cleans up the epoch-advanced state without advancing the epoch (12-7); no chain entry, so --reason is neither recorded nor required
- L233: Reason null means --reason was not given; it affects only the warning's wording.
- L235: anyDecryptable judges whether --new-epoch may be suggested when a resume is impossible (whether re-encryption material exists)
- L246: The rotatability guard is re-applied on the advanced view: a role change or deletion between checks must not slip through on the resume path
- L259: The --new-epoch escape is suggested only when fulfillable — an unfulfillable suggestion would bounce the user between contradictory errors
- L273: Wording differs by whether a request was made: a reason-less run requested nothing, so saying it switched would be a lie
- L283: Unopenable values do not stop a resume (the epoch already advanced); the policy is shared with decryptForRotation so the paths cannot diverge
- L300: With nothing pushable the passes are never entered — an empty pass plus full re-verify would only return to an already-known cause
- L328: Issuance trigger (i) (6.3): a resume-path completion is the same milestone as the normal path's — issued on full completion only
- L351: Situation warnings are placed right after the pull warnings, before any subsequent failure
- L365: Path selection: --new-epoch always sends the composite; otherwise rotate / resume / check-only by stale count and reason
- L384: Manifest material is assembled from the verified pull — never sign server-claimed values as-is (16-2 posture)
- L409: Declared (valueless) statements are manifest-digest targets too (4.3); dropping them gives a digest mismatch and a 422
- L444: Without a floor an omitted variable cannot be detected; a rotation is a revocation, so the floorless leftover is made explicit (14.3-3)
- L454: The verified pull (6.3/12-7): per-variable epochs can differ between rotation and re-encryption completion — also the resume detection material
- L466: Pull warnings enter the sink before any subsequent failure, else they would vanish exactly on failure
- L499: A check-only run requires no --reason: requiring one would turn the guided re-run into a second rotation
- L520: The normal path always has its reason set (requireReason) before signing
- L530: Plaintext is gathered before advancing the epoch: never create the state where only the epoch advanced and re-encryption can never complete
- L547: The DEK is wrapped right after generation; from then on it flows only as a Redacted
- L579: The new epoch's DEK is held by its generator; the chain commitment match was already done by appendRotation (5.2)
- L585: Write attribution is the member row at acceptance time (updated if re-signed under CAS retry)
- L616: Computing the new-epoch DEK commitment (CRYPTO_SPEC 5.2); failures are CliError
- L631: Unwrap justified: the commitment computation's input at the encryption boundary; the product is a hash
- L637: Issuance trigger (i) (6.3 SHOULD): the periodic checkpoint is issued after completion only — never on partial completion or failure

### `apps/cli/src/env.package/index.ts`

- L1: env.package surface: command pieces live in command.ts per the package-entry convention; sweep/sync consumers named

### `apps/cli/src/errors.ts`

- L1: Diskless invariant for CLI errors: messages must never contain plaintext secret values, key material, or raw tokens — context is identifiers only
- L15: The evidence flag exists so rotate's per-leg classification can read it and avoid downgrading a cryptographic contradiction to 're-run to fix' guidance
- L32: The exit code is carried by the error type itself (ADR-0016 d4), keeping a usage=2/failure=1 mapping table off the runner; runMain's default teardown reads it
- L57: Usage errors (exit 2) are distinguished from execution failures (1) so a script does not treat a typo as an execution failure
- L69: Cleanup-outcome sorting: evidence keeps failing; everything else returns as a value so the caller can warn without changing the exit code of work already reported

### `apps/cli/src/failure.ts`

- L1: failure.ts discipline: messages consist only of identifiers and never carry values/key material/tokens; _tag access is banned by oxlint, so discrimination is by instanceof
- L77: Schema-failure wording asserts neither side's fault (the same channel carries request encodes and response decodes), and message pass-through is safe only because upstream shows type/location, never the value — pinned by a negative test
- L116: Missing-manifest detection walks only non-Pointer nodes to the first Pointer, so only a missing top-level 'manifest' key matches; an encode-side match is unreachable by construction
- L188: DataLimitExceeded names per-resource next steps (§12-8): the DO storage guard is dominated by the never-pruned audit log (deleting frees little); an environment's ciphertext is freed by deleting/shrinking its values
- L261: ProblemDetails (400 decode / 500 encode) wording asserts neither side's fault, like the schema-failure renderer, and the problem's own fields are never passed through
- L289: The error schema's ID/field columns are unconstrained strings the server can fill freely (unlike Literal reason/op/resource), so they are neutralized before display
- L424: recipientUserId is a free-form string in the server response, so it is neutralized before being emitted to the terminal
- L479: The project-count cap (§11-3) applies only to new inits: a repair re-init of an existing project passes regardless of the cap
- L533: isServerRejection is an allow-list: only a server-processed rejection settles acceptance; unknown failures default to 'unknown whether accepted'
- L583: Internal failures are named by type only: a defect's message can embed the typed value, and silently swallowing is also banned — the type name is code-derived vocabulary that survives in the binary
- L619: Beyond the exhausted typed-client declaration, an unknown failure's message is never passed through (it may carry response fragments or typed values); the type name is kept as the only clue

### `apps/cli/src/fingerprint-flag.ts`

- L10: Fingerprint-flag errors are reported under the flag name as typed — shared across grant/revoke/invite/member — never pointing at a flag name that does not exist

### `apps/cli/src/floor-evidence.ts`

- L77: user_id is a free-form wire string with only a length constraint, so it is neutralized before being emitted to the terminal
- L103: user_id is a free-form wire string with only a length constraint, so it is neutralized before being emitted to the terminal
- L130: user_id is a free-form wire string with only a length constraint, so it is neutralized before being emitted to the terminal
- L274: user_id is a free-form wire string with only a length constraint, so it is neutralized before being emitted to the terminal

### `apps/cli/src/index.ts`

- L1: @maruhi/cli — the `maruhi` / `mh` CLI on effect/cli + Effect. Diskless invariant: never write plaintext secrets to disk. Do not build

### `apps/cli/src/invite.package/invite-accept.ts`

- L1: invite accept pipeline: link interpretation, issue-signature check, inviter confirmation, key generation when absent, joint acceptance signature, accept, then the anchor pin.

### `apps/cli/src/invite.package/invite-create.ts`

- L1: invite create pipeline: pre-issuance role/scope checks, issue signature, link assembly, issuance pin, one-time link display.

### `apps/cli/src/invite.package/invite-list.ts`

- L1: invite list/revoke pipeline: per-row issuance and acceptance verification with fingerprint-word display and the issuance-pin cross-check.

### `apps/cli/src/invite.package/invite.ts`

- L271: Post-issuance guidance routes the link to stdout and the explanations to stderr.
- L299: Server-declared createdAtMs/expiresAtMs are unbounded numbers (B4), so they are displayed via the total shared formatter — an out-of-Date-range value must not end invite create/list in an untyped RangeError crash.

### `apps/cli/src/io.ts`

- L1: The CLI's I/O boundary (an Effect service). Concentrates direct access to process globals (console / process.stdin / environment variables)
- L18: Agent-detection profile. The substance lives in agent-gate.ts (detection is done by live.ts via std-env). The **primary boundary** for
- L33: Reads stdin to EOF (push values arrive here, never via argv).
- L35: Reads one interactive line (recovery-code entry / save confirmation). `secret` requests no-echo input on a TTY; off-TTY input falls back to
- L46: Recovery code uses stderr; this keeps redirect detection behind the I/O service boundary.
- L48: Whether stderr notices may use ANSI colors (notice.ts). In production, `shouldUseColor` (whether stderr is a terminal + NO_COLOR /
- L55: Opens `url` in the default browser (best effort; returns whether the attempt was started). Solely for the UX branch of the CLI login's

### `apps/cli/src/json-record-pure.ts`

- L1: Dependency-free JSON-record helpers: the pure string/object checks that the rest of the CLI shares. This module imports nothing (no node
- L10: Parses `content` as a JSON object; returns the reason when it is not one. The reason is one of two fixed English strings. Neither the
- L36: The keys of `record` outside `allowed` (a typo is reported, never silently ignored).

### `apps/cli/src/json-record.ts`

- L1: Shared entry point for non-secret JSON documents (repository anchor, sync config, proxy config, sync receipt): does it parse as JSON, and
- L25: The header every repository config shares (sync-config.ts / proxy-config.ts): only the accepted top-level keys, `version: 1`, and an
- L49: A config the CLI applies without being told (`maruhi push` → the sync config, `maruhi run` → the proxy config): null when the file is
- L60: `exists` = access(F_OK): a PlatformError whose reason is NotFound is false; every other read failure is `unreadable` (the same discipline
- L71: A per-user ledger file as read (`corrupt` is distinguishable from `missing` — a person deals with it).
- L93: A scope's environment-id list (CRYPTO_SPEC §6.2 — AUTH_SPEC §12-1 id format, at most 256, no duplicates).
- L105: A record-level filter enforcing a map-key format (invite ids, fingerprints, book keys). A checked Record **key** schema only *selects* keys
- L120: Reads `path` and decodes its JSON content by `schema`. Only a `PlatformError` whose reason is `NotFound` (not created yet) is `missing`; a
- L145: Reading one user-named file's content: any read failure becomes the caller's `unreadable` error ("cannot read" is the same whichever way it
- L164: Writes `value` to `path` encoded by `schema`, atomically: the directory is created (mode 0o700), the JSON goes to a temp sibling (mode

### `apps/cli/src/key.package/command.ts`

- L291: --passkey opens the ledger and --replace presumes never opening it, so they cannot combine; with a passkey, opening and reissuing keeps the same reserve key.

### `apps/cli/src/key.package/handoff.ts`

- L218: The handoff code is a public key (not secret) but goes to the same stderr as the guidance.

### `apps/cli/src/key.package/key-publish.ts`

- L60: gh failure output is formatted and attached to the error because the output contains only the public key.
- L75: A public key is not secret, but exec's stdin contract takes Redacted (run.ts), so it is wrapped anyway.
- L112: stdout carries only the key line, so it stays usable via redirection or pbcopy.

### `apps/cli/src/key.package/keygen.ts`

- L146: userId is a server-derived free-form string, so it is sanitized like the other output paths before display.

### `apps/cli/src/lease.package/index.ts`

- L1: lease.package has no command.ts: ci.package's ci-lease requests/verifies the workload lease, and consumers take VerifiedLeaseMaterial through this index like any other outside file.

### `apps/cli/src/max-age.ts`

- L1: Expiring values (PF6 R9 — CRYPTO_SPEC §4.2 layout v3 `max_age_days`) and the PF7a nudges built on them (docs/notes/pf7-pf8-design.md §2)
- L28: How far ahead `rotation list`'s "due soon" looks (also the `--due-within` default).
- L30: The server's bound on a proposal's lifetime (AUTH_SPEC §14-5 — 30 days).
- L33: A variable whose verified statement declares a max age (the only kind this module looks at).
- L50: The rows due inside the window plus the variables whose age could not be judged (history read failed).
- L53: The names of the candidates whose history could not be read (noted on stderr already).
- L55: The environments whose verified metadata could not be read at all (their candidates are unknown — noted on stderr already).
- L59: The bound on one history read (an advisory lookup never holds the command — B-7).
- L62: The due rows of one environment: each candidate's latest push time is read from the history (concurrently — one round-trip time in all)
- L91: A stalled read is bounded like a failed one: the note must never hold `maruhi run` (B-7), and a check cannot wait forever
- L95: A failed read is noted and counted: the listing goes on, but a check (`--fail-on-due`) cannot pass on an unknown age
- L127: Every read at once: a handful of metadata GETs to one DO, so the note costs one round-trip time whatever the count (and one bound)
- L145 (2026-11-28 tree): notePastDueValues takes the three fields it reads (variable id, name, max age) and not pull.ts's `DecryptedVariable`, which made this module import a feature file for a type; a decrypted variable still fits the parameter
- L147: The push time of the **plaintext** the current version holds (B-9): a re-encryption (`sameValueAs = version − 1` — the mandated one after a
- L173: "expired 14 days ago" / "due in 8 days". The day count rounds the way the `--due-within` filter counts: a value due in any part of a day is
- L188: The one-line note of `maruhi run` / `maruhi pull` (S-E): only values **past** their max age, each with the interval, the push date, and how
- L208: The point-of-use nudge (PF7a S-E): after `maruhi run` / `maruhi pull` decrypted an environment, one note names the values past their max

### `apps/cli/src/mcp.ts`

- L1: `maruhi mcp` — the MCP server (PF5 — design record docs/notes/pf5-design.md). A thin wrapper of `maruhi schema` spoken over MCP's stdio
- L65: The untrusted-data framing without the CLI table's `# ` comment marker (ruling CW).
- L68: The server-level instructions (sent once at `initialize`). Steers the agent to the diskless path for values instead of asking for them.
- L103: The one result shape (the tool's structuredContent and every resource's JSON body).
- L120: A tool failure the agent should see verbatim (not logged in, unknown environment, verification refused, …). The message is a CliError's
- L151: A closed domain: the project's own maruhi server, nothing else
- L153: Unknown input keys are refused, not ignored (fail-closed)
- L158: The resource URIs (ruling M3 — the default environment is listed; the rest via the `maruhi://schema/{environment` template).
- L172: The Keychain the MCP server runs with (ruling M7): API-token reads only. A master-key read — anything that is not a token entry — is
- L186: CliIo for the server's lifetime: stdout and stdin belong to the protocol (ruling M8).
- L202: The service context the whole server runs in — every read included (rulings M7 / M8): the command's services with Keychain, CliIo and
- L224: Effect's own logging (the default logger writes to console.log = stdout) → stderr.
- L256: One schema read = one `maruhi schema` (ruling M5): the keyless prologue (fresh config, session, sync, §6.3 verification, floor) and the
- L273: Created per execution: a resource whose effect is built once still gets a fresh ledger and capture on every read
- L305: "An identical notice at most once" is per command run; here a run is one call
- L315: The stateful protocol revisions, newest first. stdio negotiates a stateful session (measured: offering the stateless 2026-07-28 revision
- L328: The registration layer: the schema toolkit (one `get_schema` tool) and the two schema resources. Effect 4.1 builds registrations through
- L347: A resource read failure surfaces as the JSON-RPC error's message (McpServer maps it)
- L384: A failure's user-facing text: a CliError's message, anything else by type name only (failure.ts).
- L391: `maruhi mcp`: serves until stdin reaches EOF (the host closed the session), then returns normally (exit 0).
- L405: Calls are serialized: one call at a time = one `maruhi schema` at a time, the shape the prologue (floor and pin writes) was built for
- L412: A defect's message is never shown (the CLI's rule — failure.ts): the agent and the host log get its type name only
- L417: The stdio protocol interrupts the fiber that built it on stdin EOF, so the server runs in a child fiber and its interruption reads as a

### `apps/cli/src/member-list.ts`

- L1: `maruhi member list`: verified-chain-derived member rows (user id, role, scope, devices — zero values. The group's overview lives in
- L17: One member row (verified-chain-derived — zero values. Design record ruling M / K4-E; the devices column is DK K4-20).
- L22: The member's device keys (fingerprint ascending — 2026-09-19 DK: a member can have multiple devices).
- L26: The verified chain's member list (user_id ascending).
- L38: One `--json` document (machine-readable — for agents / scripts. Zero values).
- L46: The devices list (K4-20): FP and cap emitted structured. The concatenated `keyFingerprintHex` was removed in K4 (never make consumers
- L69: The human-readable row (user id, role, scope, device count, device FPs (cap). The id is neutralized).

### `apps/cli/src/member.package/command.ts`

- L64: Since member add's declaration is add-only, "omittable when exactly one accepted row exists" is expressed by atMost(1).
- L176: member remove is a convergent command, so the always-on unconverged-duties warning is suppressed — its own sweep report carries it.
- L260: A convergent command: the always-on unconverged-duties warning is suppressed because the demotion/narrowing sweep report carries it.

### `apps/cli/src/member.package/member-add-ceremony.ts`

- L1: member add's confirmation flow: choose the accepted row, then the FP ceremony behind the interactive-terminal + non-agent gate (ADR-0016 decision 7), then GitHub-signing-keys verification when possible.

### `apps/cli/src/member.package/member-add.ts`

- L1: member add pipeline: §6.5 independent verification + issuance-pin cross-check, invitee confirmation, add_member append (CAS retry), backfill of every environment × every epoch.

### `apps/cli/src/member.package/member-change-role.ts`

- L1: member change-role pipeline: the full (role, scope) replacement append, then widening backfill + demotion/narrowing sweep (§7).

### `apps/cli/src/member.package/member-remove.ts`

- L1: member remove pipeline: pre-append checks, remove_member append, forced rotation of every environment (§7).

### `apps/cli/src/mirror.package/mirror-deployment.ts`

- L45: The promote probe bound exists so a black-holed source must not hold a failover.

### `apps/cli/src/mirror.package/mirror-heads.ts`

- L37: A head neither on nor past the verified chain is fork evidence: both are signature-verified, so only an equivocating server produces it (never an honest race); a sync showing it fails after the commit so a cron notices (ruling H revision, round 8).

### `apps/cli/src/mirror.package/mirror-mark.ts`

- L1: mirror mark (AUTH_SPEC §11-7, ruling C revision): the owner marks the project read-only on the mirror as a mirror of the source; a self-source is refused, and a mark no sync could follow is refused unless --force.
- L53: A project whose chain is not part of the source's can never be synced (every replica refused as not an extension, no way out but another promotion), so it is refused here, before the mark (round 3).
- L66: The mark's precondition is that the two chains are one chain in either direction — only a fork is refused; there is no floor check (a mirror behind the local floor is the normal pre-sync state), and when the source cannot be read the mark proceeds with a warning.
- L85: Each of the mark's reads stands alone (round 10): a transient failure of one does not discard the chain or mark already read.
- L101: The source reads run concurrently: a source that does not answer costs one bound, not two (round 12).
- L117: A source frozen for this deployment under another hostname (C-13): the star instruction would be refused as a self-mark, so the way out named is the mark under that name (round 11).
- L124: --force marks anyway but says what it overrides (round 10), without the refusal's own escape clause (round 11).
- L146: A refusal's "pass --force" escape clause is kept apart from the body: it is printed on the refusing path only (round 11).
- L170: The source's own mark decides whether the sync the mark leads to can run at all (round 9): a mirror of a third origin is no source (the star), and a writable source takes no page.
- L182: When the chain could not be read but the mark alone tells the source is frozen for this deployment, the undo note still stands (round 11).
- L204: Equal to or behind a source frozen for this project means two frozen copies and no primary — the undo of a planned failover (round 10).

### `apps/cli/src/mirror.package/mirror-promote.ts`

- L1: mirror promote (AUTH_SPEC §11-7, ruling C revision): unmarking accepts writes again, so the guard first reads what the source holds and, unless --force, refuses a promotion that may leave two writable copies, bury the frozen source's last writes, or hide a fork.
- L31: A source that still answers means two writable copies after promotion, refused unless --force: a split brain is an owner's explicit decision (ruling C revision).
- L66: The promotion guard judges a frozen source behind this mirror on the mirror's chain: a strict prefix holds nothing the mirror lacks; anything else is a fork (round 8).
- L96: --force promotes anyway but says what it abandons (round 9), without the refusal's own escape clause (round 10).
- L109: What stays on the frozen source is counted only when the frozen head is the mirror's and a replication is recorded (positions of one log; a re-point clears the record), else it is said to be uncountable from here (rounds 8–9).
- L129: A source that synced back from this mirror holds this mirror's log followed by its own rows, so its own record counts the left-behind rows exactly; otherwise the mirror's record counts, at the same head only (round 10).
- L146: Promotion refusal kinds: a writable source and an unread mark are split brains, a frozen source whose head the mirror lacks loses its last writes, a source frozen for another origin moved; --force skips all four.
- L192: A frozen source holding entries this mirror lacks makes them unreachable forever on promotion (round 7); a source behind the mirror but not on its chain is a fork no sync repairs (round 8); a source behind on its chain holds nothing the mirror lacks.
- L212: At the mirror's height with another hash, or behind it and not on its chain: a fork (round 10).
- L248: sourceState's kinds (round 3): frozen = already a mirror of this deployment, matched by server key fingerprint so another hostname still counts (round 5) — the honest path, promoted without a probe; movedTo/writable/answers/gone as defined, with any HTTP answer counting for answers.
- L284: A fingerprint match never lifts the guard — it is self-reported and shared by deployments cloned from one secrets set (round 6); it only names the honest way out.
- L302: Post-promotion key follow-ups come from the verified chain and this server's public key — never a guess at a fingerprint (ruling F revision, round 3).
- L346: Any HTTP answer from the source counts, even an error; only no answer at all does not.

### `apps/cli/src/mirror.package/mirror-status.ts`

- L1: mirror status follows mirror-sync's TCB discipline: heads and counts only, and it fails on fork evidence in the mirror's head as the sync does (§11-7).
- L35: mirror status must answer while the server is down — it is the one command for "is my mirror usable" — so an unanswering server leaves the mirror's head alone on the report (announced), while any other server-side failure fails as usual.
- L67: Fork evidence fails the status as it fails the sync (round 11): a cron or a member's "is my mirror usable" must not read it as fine.
- L71: A recorded source that is this server under another hostname is this server; the fingerprints decide, on the failing path only (round 13).
- L92: Fork evidence is attributed to the state it was seen in (round 12): unmarked-and-diverging is two writable copies, marked-for-another-source was judged against the wrong server, marked-for-this-server holds fork evidence against it.

### `apps/cli/src/mirror.package/mirror-sync.ts`

- L1: mirror sync (AUTH_SPEC §11-7 PF2, rulings D/H): pages upload in order and the mirror commits only when the trailer page arrives and the replica extends what it holds; two sessions take part, and the TCB discipline reports heads and counts only — row content never reaches the output.
- L46: The pages client is the mirror under the body bound on its headers — a full page on a slow uplink is not "did not answer"; it is used on the replicating path only (ruling H revision, round 5).
- L54: The mirror's recorded source must be the server the sync exports from, else the sync is refused (force overrides — ruling H revision, round 6).
- L56: A server that is itself a mirror of another origin, or a frozen former primary that already synced back, is no source for this mirror (force overrides — round 8).
- L59: The local floor's head: a source whose reported head is behind it is never "current" — the replicating path's floor check decides, with its evidence (round 5).
- L65: The server's verified view is built only when something is uploaded (round 4): a "current" tick costs the two status reads and no chain download.
- L90: mirrorSyncOp opens the two sessions first and fetches/verifies the server's chain only when something is uploaded — a cron's "current" tick is the two status reads (round 4).
- L106: The pages go through the mirror under the body bound on their headers (H-10); the status reads keep the usual bound (H-12).
- L129: A replica behind the pre-export view, past the post-commit view, or off either's chain is evidence against the server; the sync fails so a cron notices (rounds 8–9).
- L243: A cron left at the former primary after a failover elsewhere would export a frozen copy into a mirror of another source (an equal-head replica commits), so the recorded source must be this server.
- L260: Mirrors sync from the primary — a star (§11-7): a server that is itself a mirror of another origin is refused before anything is exported, because a replica of it would commit once and be refused after its next sync when its rows are renumbered; a server frozen as a mirror of this mirror goes through; force overrides.
- L285: A server frozen for this mirror is a source whatever it replicated from it before (round 9): the pair stays consistent — this mirror's rows travel in the server's log verbatim and its own rows are carried by row id; the renumbering hurts a third mirror of that server only, which the refusal above covers.
- L294: Nothing is uploaded when the source's three marks are the last replication's; a floor below the source's head cannot be checked from the two statuses, so the verdict then waits for the view, whose floor check proves the floor's entry is on the source's chain (H-14).
- L345: The export's own renderer names `project export` in its errors; this is a sync, so the wording is corrected here (round 11).
- L354: A replica past the pre-export view is the one honest race — or a server that serves one chain and exports another: the view is taken again and its floor check proves it extends the first; the replica must be on it (round 9).
- L362: The strongest evidence gets the most specific report (round 10), and a server that merely stopped answering or refused the session is not one that failed verification (round 11).
- L391: A committed replica behind the pre-export view is a server rollback, never a race; past the re-taken view, the server exported entries it no longer serves; off either chain is a fork — only an equivocating server produces any of them, so a cron must see exit 1 (rounds 8–9).
- L420: A source behind this machine's floor (rebuilt from a backup taken at the last synced head) is not current (H-11); a floor below the source's head is checked by the view before the verdict (H-14).

### `apps/cli/src/mirror.package/mirror-target.ts`

- L44: Deployment comparison is by string here, so a cron's "current" tick stays the status reads (H-9); the mark and promotion compare deployments by server key fingerprint (C-13).
- L56: The verified view advances the local floor to the verified head once every check passes (round 7): a sync whose view left the floor behind took the view on every tick, forever.

### `apps/cli/src/notice.ts`

- L1: Vocabulary and rendering of stderr notices (Note / Warning / failure) (DP5 rulings A / B). Vocabulary (distinguish by purpose — never mix)
- L38: The wordings of Notes / Warnings emitted within one command execution (ruling C's rule "an identical notice appears at most once per
- L52: An optional observer of the notices a run emits, by kind and text (before rendering). `maruhi mcp` uses it to return a read's warnings to
- L68: info = cyan (the "information" convention of the terminal 16 colors. No imitation of the vermilion accent — a terminal's red carries the
- L76: Decides whether stderr decorations (ANSI colors) may be used. Precedence: `FORCE_COLOR` (non-empty; `0` disables) > `NO_COLOR` (non-empty
- L103: Renders one notice line: the prefix (optionally colored) and the text. The caller passes a body string already neutralized via
- L117: Where a notice belongs. `run` (default): a run-level fact, printed at most once per command execution. `prompt`: attached to the
- L127: Writes a notice to stderr (dedupe by exact text within one run — `run` scope only).

### `apps/cli/src/oidc-github.ts`

- L40: Guidance shown when the OIDC issuance endpoint is missing states the requirement on the spot.

### `apps/cli/src/origin-book.ts`

- L1: The shared outer frame of the local book files keyed origin → user_id (known-fingerprints.json, own-devices.json): `{ v: version, known: {
- L10: Record-key (origin / user_id) discipline: starts with an alphanumeric (like the invite id in pins.ts, this structurally excludes
- L16: The schema of `{ v: version, known: { origin: { user_id: users `. `users` describes one origin's entry (user_id → contents); origin and

### `apps/cli/src/project.package/command.ts`

- L166: The members display carries the scope column (ruling M) in the same row format as `maruhi member list`.
- L196: verify prints the whole state: "none" is said too for the server grants.
- L445: stdout carries only the anchor JSON (decision 9), so a redirect can commit it into a repository as-is; the content is non-secret (hashes, serials, epoch numbers only).

### `apps/cli/src/project.package/project-init.ts`

- L124: Schema import stays an independent command, not folded into init (design doc §1-3); init's completion output adds just one guidance line.

### `apps/cli/src/project.package/project-list.ts`

- L1: project list's response is a server declaration that went through no verification (§11-5): the display is for discovery only, and verified state is project verify's remit.
- L23: The page-chasing bound sits at a volume an honest server never reaches (10,000 projects): it bounds a runaway or malicious server's infinite nextAfter chain.
- L36: Memberships are server-reported — discovery only; verified state comes from syncing each chain.

### `apps/cli/src/proxy.package/command.ts`

- L27: proxy run config (PF4 credential brokering): run's flags plus the proxy config path and a per-request log switch
- L67: proxy run shares run's prologue; what differs is what the child receives (proxy-run.ts)
- L75: Argument parsing drops before communication or decryption, at the command body's head
- L77: The proxy config is read before any network — a broken file is reported first
- L98: proxy accept (R-8/R-14): a person at a terminal records the config as accepted — the direnv model; no server is contacted
- L108: The project is resolved without network (flag, config project, or default); the acceptance mark it arms is per project (R-18)
- L121: Only the default project setting can be malformed here; it is worded the same way as context.ts's resolveProjectId

### `apps/cli/src/proxy.package/index.ts`

- L1: proxy.package surface: re-exporting command.ts here would close an import cycle, so commands import it directly

### `apps/cli/src/proxy.package/proxy-accept.ts`

- L1: Proxy config acceptance (R-8/R-13/R-14): a config applies only once a person accepted it — an agent can edit, delete or sidestep the file
- L63: One accepted config record: the accepted content, when, and for which projects (R-24)
- L82: A corrupt brokered-project record fails the gate closed (distinguishable from missing)
- L90: The record is keyed by the config's resolved absolute path
- L92: accept is read-merge-write and refuses to overwrite a corrupt file
- L97: brokeredProject: corrupt is reported by the gate, never read as never-brokered
- L99: markBrokered is idempotent and keeps the first mark
- L110: The acceptance record deliberately avoids MARUHI_CONFIG_DIR/XDG: an agent could point it at a directory it writes (R-23); home comes from the user database
- L123: The ledger Schema is strict like pins/fingerprints: one bad entry fails the whole file as corrupt; extra keys tolerated
- L152: Absent = missing; an undecodable or unreadable file is corrupt — reported and never overwritten (R-15)
- L168: Read-merge-write; a corrupt or unreadable file is never overwritten
- L227: The record's key is the resolved absolute path (./x and --config /…/x are one entry)
- L241: howToAccept: who may accept and how — the tail of every unaccepted-config refusal
- L261: Acceptance rule: a content match passes silently; anything else is refused before network or decryption, naming who can accept and how
- L271: The acceptance must name the project whose values the config is about to govern (R-24)
- L283: Accepted for another project does not carry: a permissive file accepted elsewhere must not govern this project's values (R-24)
- L303: proxy accept records the config's content as accepted by a person at a terminal; returns what changed
- L311: The accepted project is marked brokered at acceptance (R-18 — the gate must be armed before any run)
- L340: Changed content restarts the project list: the acceptance is of this content, for these projects
- L344: Brokered marking happens at acceptance, not first run: deleting the file between accepting and running must already be gated (R-18)
- L350: A brokered run marks its project; a mark that cannot be written is an error — the mark gates the plain run later (R-18)
- L366: Plain run of a brokered project without a config is gated like --plain (R-13): deleting the config must not be the shortest way around the rules

### `apps/cli/src/proxy.package/proxy-cert.ts`

- L1: Ephemeral CA (P3): created per run in memory; the private key never touches disk and dies with the process; only the public cert is written out
- L93: SAN: an IPv4 literal is an iPAddress GeneralName, anything else a dNSName
- L105: dNSName length uses the context tag's own length — slicing a 2-byte IA5String length broke hosts of 128+ characters (C-10)
- L119: WebCrypto's raw r||s signature is converted to the DER SEQUENCE TLS expects
- L125: Certificate serials are positive random (RFC 5280: at most 20 octets, non-negative)
- L132: Key identifier is SHA-256 of the SPKI truncated to 20 bytes (any unique octet string is allowed)
- L145: extractable only for a leaf (its key is exported for node:tls); the CA key never leaves WebCrypto
- L161: Certificates stay valid 30 days — a session rarely lasts that long and the key dies with the process anyway
- L163: notBefore is back-dated 5 minutes for clock skew between the proxy and a container's clock
- L192: A leaf certificate for one host with its private key — PEM, in memory only
- L200: certPem is the CA certificate (public — the one thing the child must trust)
- L202: issue returns a certificate for the host signed by this CA, cached per host
- L206: CA_SUBJECT is the subject the child sees when inspecting the certificate chain
- L209: The CA and every leaf read one injected clock (production: the Effect clock's unsafe read; tests: Date.now)
- L226: CA keyUsage bits: keyCertSign (5) and cRLSign (6)
- L243: Leaf keyUsage bit: digitalSignature (0)
- L248: AuthorityKeyIdentifier encoding note (SEQUENCE with [0] keyIdentifier)
- L264: A failed issuance is not remembered: the next CONNECT retries (a cached rejection would keep the host unreachable all run — R-5)

### `apps/cli/src/proxy.package/proxy-config.ts`

- L1: Proxy config (P5): per-variable broker/connector/passthrough/withhold rules; unlisted defaults to withhold — fail closed
- L56: Surfaces use RFC 9110 vocabulary (header/path/query/body)
- L61: Default surfaces are headers only: a token in a stored body could be published by the API; other surfaces opt in per rule
- L64: A rule destination: scheme, exact or *. host or IPv4 literal, and port (scheme default unless written)
- L77: ConnectorKind closed set: the connectors that mint a short-lived credential (proxy-connector.ts)
- L95: Connector inputs map input name to the supplying maruhi variable — consumed by the proxy, never injected
- L125: Placeholder shape: printable ASCII without spaces, 16+ chars so it cannot occur in ordinary traffic by accident (C-12)
- L131: Loopback hosts: localhost, any name under .localhost (RFC 6761), or a 127.0.0.0/8 literal (never a wildcard)
- L143: parseHostPattern reads one host entry; http:// is allowed only toward the loopback
- L201: *.localhost is the one single-label wildcard (RFC 6761); *.com would name the public suffix
- L206: A substituted value in plain HTTP travels in cleartext — only the loopback is acceptable for that
- L225: The surfaces array: non-empty, entries from the RFC 9110 set, deduped on success
- L236: The placeholder string rule (16-256 printable ASCII without spaces — C-12)
- L261: Host entries are read in order; the first bad entry decides the reason
- L341: Rule shorthands: an array means broker toward these hosts; a bare mode word is the mode
- L411: One placeholder inside another would make the longer one's substitution rewrite the shorter — refused like a duplicate
- L430: A variable a connector consumes is never injected, so a rule that would inject it contradicts the connector
- L446: The document is read in one pass, header then rules — the first reason wins

### `apps/cli/src/proxy.package/proxy-connector.ts`

- L1: Proxy connector frame (D3/P8): the credential is minted on the proxy just in time from variables the child never receives — the agent never sees the token
- L44: Connector deps are bound per run (production: ambient HttpClient/Clock; tests substitute the proxy seams)
- L58: A cached credential is re-minted this long (5 min) before expiry
- L63: Connector failures are rephrased by resolve/release as connector <kind> for <name>: <reason>
- L68: An unknown thrown value's message — the reason, never a credential
- L73: transportReason: the transport's own cause when wrapped, the client's wording otherwise
- L88: GitHub accepts at most 10 minutes of JWT life; iat is back-dated for clock skew as GitHub suggests
- L92: TokenResponse reads only token/expires_at/message, each type-checked where read; an unreadable body decodes to an empty record
- L174: access_tokens response to the minted token, with status and message on refusal
- L227: A non-JSON edge answer (HTML on a bad day) decodes to {} and the status wording carries the failure
- L242: The installation token is revoked at teardown (D-14a) so its life is the run's, not GitHub's hour; a refusal is a Note
- L258: Unwrap justified: the token authenticates its own revocation (GitHub's API shape)
- L267: 204 = revoked; 401 = already invalid — nothing left to do
- L300: Connector credential: resolve mints on first use, caches until near expiry, re-mints one flight at a time; failure becomes a 502 to the child
- L317: The pre-re-mint token is still valid for a while and worth scrubbing
- L335: Every held token is revoked even when one revocation fails — a token left alive would outlive the run (R-3)

### `apps/cli/src/proxy.package/proxy-guard.ts`

- L1: Host-local guard (R-12): in sandbox mode the proxy runs in the host's network namespace, so host-local destinations are refused
- L36: Host-local ranges are matched by value (R-16): every textual loopback form counts; BlockList measured identical under Bun and Node
- L51: Shared address space (RFC 6598) is host-local: cloud providers put metadata endpoints there (R-20)
- L55: IETF protocol-assignment block and Azure's wire server are host-local (R-22)
- L89: HostLocalCheck: a refusal with its reason, or clearance with the address that was checked
- L94: checkHostLocal pins the connection to the checked address — never a second resolution a sandbox-controlled resolver could answer differently (R-19)

### `apps/cli/src/proxy.package/proxy-rules.ts`

- L1: Brokering vocabulary: pure functions — the network lives in proxy-server.ts
- L13: Target.resolved is the guard-checked address (R-19): the connection goes to it, never to a second resolution
- L21: A brokered credential: the child holds the placeholder; the proxy swaps in the real value toward hosts, on surfaces only
- L31: resolve is called only when a request toward one of hosts carries the placeholder; a connector failure reason carries no secret
- L38: known returns held values without minting — the proxy must never mint a credential just to scrub a response (D-1)
- L46: release is best-effort teardown (a connector revokes its token); failures are reported, never fatal
- L61: *.example.com matches subdomains at any depth, never example.com itself
- L77: Placeholder format mhp_<NAME>_<22 random alphanumerics> (~131 bits): readable in logs, useless across runs, accidental match impossible
- L88: Rejection sampling: bytes at or above the limit are discarded so every alphabet character is equally likely
- L92: randomAlphanumeric: ~5.95 bits per character; also the run's proxy credential
- L110: Host header carries the port only when it is not the scheme's default (RFC 9112 3.2)

### `apps/cli/src/proxy.package/proxy-run.ts`

- L1: proxy run (PF4): broker/connector variables reach the child only as placeholders; the real value is written into requests only at the proxy
- L64: ProxySeams are test-only: upstream destinations and connector API reach; absent in production
- L86: Sandbox mode (20): listen binds beyond the loopback for containers/netns; advertise is the host:port the child is told
- L118: parseListenAddress accepts IPv4, host name, or bracketed/bare IPv6; port 0 = ephemeral; exported for tests
- L172: A broker rule's credential is the variable's own bytes, resolved per request
- L183: Unwrap justified: the proxy writes the value into a request toward a host the rule names — the sanctioned consumption path; never stored elsewhere
- L191: A connector rule's credential, or the fail-fast error before the child starts
- L207: Fail fast before the child starts: a connector that cannot mint has nothing to broker
- L214: Unwrap justified: the connector consumes the input in memory to mint a short-lived credential (D3); the input never reaches the child
- L302: Variables no rule names follow unlisted; a connector's inputs never reach the child whatever the config says
- L336: describeProxyConfig: one line of names and hosts only, never a value — what a person accepts in proxy accept
- L373: proxyControlEnv points the child's clients at the proxy and the run's CA: bundle = system roots + CA; caOnly = CA alone
- L390: An inherited NO_PROXY could route a brokered host around the proxy — cleared
- L393: Node 24+ fetch (undici) honours the proxy variables only when NODE_USE_ENV_PROXY is set
- L395: OpenSSL-based clients replace their store with SSL_CERT_FILE, so the bundle carries the whole store
- L411: Roots for tunnelled hosts: the runtime's Mozilla roots plus the OS store where exposed (a corporate TLS-inspecting root — D-13a)
- L451: announcePlan says on stderr what the child will get before anything starts (P5: the config decides where values go)
- L494: Placeholders ride the same injection checks as values (name shape, control names, case collisions)
- L511: --listen/--advertise are usage-checked, with the non-loopback warning
- L540: Teardown revokes connector-minted credentials (best effort, a Note on failure), then closes the proxy
- L562: proxyRunOp brokers the environment's values to one command and returns the child's exit code
- L581: The CA and leaves read the same clock as the connector's JWTs — one time source per run, and a TestClock drives all of them
- L591: Per-request log lines are written synchronously as they happen (names, hosts, paths without query — never a value)
- L596: The private directory is created first: a failure there leaves nothing to tear down
- L605: The run's proxy credential is covered by redaction too: a printenv under an agent must not leave it in a transcript (R-10)
- L617: Every client must present this run's proxy credential (userinfo in the proxy URL — D-14b)
- L631: The CA certificate is public and the bundle is roots plus CA — neither is a secret; the CA key stays in memory
- L643: Control variables are written last: a co-member-chosen variable named HTTPS_PROXY must not redirect the child's traffic
- L651: Redaction covers pass-through values and the brokered values known at start (defence in depth)

### `apps/cli/src/proxy.package/proxy-server-connect.ts`

- L1: Raw-wire level of the proxy: request-head limit, raw responses, CONNECT/absolute-form parsers, and the tunnel socket pipe

### `apps/cli/src/proxy.package/proxy-server-http.ts`

- L1: HTTP helpers shared by the proxy's layers: capped body reads, flattened headers, plain-text responses, and the hop-by-hop set
- L8: Hop-by-hop headers describe one hop and must not be forwarded (RFC 9110 7.6.1)

### `apps/cli/src/proxy.package/proxy-server-request.ts`

- L1: Inspected request: placeholder search across surfaces, the refusal for a disallowed use, substitution, and the wire-form scrub patterns
- L18: Found records where a placeholder was found, for the refusal wording
- L99: resolveValues returns current real values only for the credentials this request actually uses
- L115: refusalFor: the refusal for a placeholder used where its rule does not allow it (null = every use allowed)
- L149: Request-target values must be percent-encoded (C-4); a header value must stay a single Latin-1 line — an unusable value is reported, never mangled
- L166: Only a value landing in a header as text must be header-safe; a Basic credential is re-encoded, a path-only placeholder is never a header (R-9)
- L180: The response must be readable to be scrubbed, so accept-encoding is forced to identity (HTTP/1.1 upstream keeps it simple)
- L217: UnsendableValueError: a brokered value that cannot travel in a header (line break or non-Latin-1)
- L227: Authorization: a Basic credential is substituted decoded and re-encoded; anything else as text
- L242: Scrub patterns include the wire forms the proxy itself creates (percent-encoded values an origin may echo) — R-21
- L267: wirePatterns covers this request's re-encoded Basic blob: an echo is scrubbed back to the placeholder-carrying blob the client sent (R-21)

### `apps/cli/src/proxy.package/proxy-server-response.ts`

- L1: Relayed response: undo content encoding, drop un-re-framable headers, stream the body back with real values replaced by placeholders
- L15: An unknown or stacked Content-Encoding cannot be scrubbed, so the response is refused rather than forwarded unread (fail closed — D-12)
- L28: zstd decompression exists only on Node 22.15+/Bun; older runtimes refuse the response
- L45: Forwarded response headers: hop-by-hop and length dropped, Content-Encoding dropped when decompressed here, every value scrubbed
- L80: relayResponse streams the response back with values replaced by placeholders; done receives the status or failed
- L92: HEAD/204/304 carry no body to re-frame — the origin's framing headers stay
- L100: A server that compresses anyway would hide an echoed value from the scrubber: decompress here and deliver identity (fail closed — 18 D)
- L128: pipeline carries backpressure end to end (a slow client no longer buffers the whole body — C-6) and tears every stage down on error

### `apps/cli/src/proxy.package/proxy-server.ts`

- L1: Forward proxy (P1/P2/P4/P6/P7): the child holds placeholders; the real value exists only in this process and is written into the request at send time
- L95: Decision paths exclude the query — a query can carry a pass-through value the child put there (D-7)
- L127: unmatched: destinations no rule names are tunnelled untouched or refused
- L130: Hop servers listen on Unix sockets in the run's private dir (0700): a TCP loopback port would let any local process get substitutions (R-2)
- L142: The proxy credential keeps other local processes off this run's proxy (D-14b); absent = open
- L148: listen defaults to loopback ephemeral; a sandbox reaches the proxy via a reachable address, still credential-gated
- L155: advertise is the address the child is told when it differs from the bound one; port 0 = the bound port
- L162: Test seams only: connect redirects upstream, ca adds test roots; production passes neither
- L171: lookup is the host-local guard's resolver (sandbox mode); the system resolver by default
- L187: MAX_INSPECTED_BODY caps inspected request bodies at 32 MiB — uploads belong to unbrokered hosts
- L190: pinned: the connection goes to the guard-checked address when the guard resolved one (R-19)
- L216: Sandbox mode: a destination no rule names must not be host-local — the proxy would reach it from the host's own namespace (R-12)
- L234: Hop servers speak plaintext on Unix sockets in the private directory, never on a TCP port
- L247: Scrub patterns come from values already held — never minting (a connector mints only for a request using its placeholder — D-1)
- L259: One inspected request: inspect, refuse or substitute, forward, scrub the response
- L263: The inspected request, forwarded: substitution, upstream, scrubbed response
- L300: An unsendable value fails before anything leaves — nothing was sent
- L310: When the client leaves before the answer, reading the origin stops
- L338: Plain HTTP toward an unnamed host is inspected with nothing substituted (relayed)
- L357: One inspected request handler: inspect, refuse or substitute, forward, scrub
- L530: expectedAuthorization is null when no credential is required
- L538: presentsCredential compares the request head against this run's credential in constant time
- L654: Plain HTTP hands the whole buffered bytes to the loopback server
- L683: A blind tunnel is never inspected — the client's own TLS end to end (to the checked address in sandbox mode)
- L691: Brokered: TLS is terminated with a leaf for this host and the plaintext handed to the bound loopback server
- L694: Bytes sent before the 200 (an eagerly sent ClientHello) are pushed back onto the socket
- L743: Socket stays paused until the loopback hop connects (C-13, measured): resuming earlier loses an eager ClientHello and hangs
- L753: Open tunnels and MITM connections are ended at close — they would hold the listeners open

### `apps/cli/src/push.package/push.ts`

- L80: One trailing newline (LF/CRLF) is dropped from the stdin value, guarding against echo-sourced contamination.
- L677: An existing variable's variableId comes from a server-distributed meta-statement (no character-set check beyond non-empty), so the local side is neutralized for display too.

### `apps/cli/src/retry.ts`

- L1: Shared combinator for CAS-conflict retries (the retry procedure of AUTH_SPEC §12-4 / §12-5). The skeleton "attempt → classify conflict →
- L21: The members of E carrying `_tag` K (never when none do).
- L26: One attempt (from the current state through signing and sending). Succeeds with the accepted value or fails with a typed error.
- L28: Classifies the failure: a classifiable value for a retryable conflict, null for a definite error (mapped to CliError and propagated).
- L30: Recovery from a conflict. A failure (definite error) propagates as is.
- L34: A failure class that bypasses classification and propagates as its own tagged error (an outer retry's signal — the unclassified path's
- L53: Retries a CAS-style operation: run `attempt`, classify failures into retryable conflicts, `recover` a fresh state (re-sync, re-resolve
- L96: instanceof matches catchTag semantics here: the bypassed error is always constructed through this class. The cast narrows E to its K-tagged

### `apps/cli/src/rotation-report.ts`

- L1: Reporting of rotation results and exit-code derivation (shared by the sweeps of env rotate / server revoke / member remove / change-role).
- L16: Reporting of partial completion / completion-unverified. The epoch has advanced, and holders of the old epoch's DEK can still read the
- L30: The remaining count of an interrupted run is an upper bound, not a measurement (the re-scan was never reached, so the contested ones may
- L45: When there is a cause of failure, state it (so the bare fact "only the epoch advanced" is not lost behind a raw error). Only a run that
- L63: Reporting of rotation results and the exit code. A completion summary reports the re-encryption record; an incomplete portion (partial
- L73: Whether the run requested a new epoch (--reason given or --new-epoch).
- L83: Check-only (nothing incomplete, no new epoch requested). It is also the landing point of the re-run that the partial-completion guidance
- L100: A resume is not "the requested rotation": no new epoch was created, so the completion report must not look like a rotation success (closing
- L109: A reasonless run = only requesting "resume the incomplete if any"
- L112: A run that requested a rotation (--reason / --new-epoch) switched to a resume, so **the exit code also** does not say success: closing the

### `apps/cli/src/rotation-sweep.ts`

- L1: The shared implementation of sweeping rotation mandates (CRYPTO_SPEC §7). revoke_server (server-revoke) and remove_member / demotion below
- L23 (2026-11-28 tree): `RotationSummary` and `ReencryptedVariable` are declared here, as the result of the injected `SweepRotate` callback. `env.package` produces the summary and imports the types; declared in env-rotate.ts they made the sweep import a feature package for a type. The records on the summary's fields stay under `apps/cli/src/env.package/env-rotate.ts` (L53, L67)
- L53: The injected rotation's mode: force = a new epoch is mandatory / verify = resume-or-confirm only.
- L56: Injection of one environment's rotation (cli.ts passes envRotateOp wrapped with a floor).
- L62: The all-environment sweep's result (the reporting material shared by revoke / remove / demotion / narrowing).
- L64: Environments where a rotation (forced or resumed) ran (environment ID → result).
- L68: Whether the run demanded a new epoch (true = forced / false = a verification-pass resumption).
- L71: Environments whose rotation failed (§7 — never silently skipped).
- L73: Environments **confirmed** to have an epoch after the baseline and no unfinished re-encryption.
- L77: Environment → the mandate's baseline seq (the maximum when several mandates apply).
- L80: Folds a mandate list into "environment → baseline seq" (the shared input of the sweep and the unconverged judgment). Several mandates on
- L100: The sweep's targets and carry-overs (split by the actor's fulfillment range — shared by the member family and device revocation).
- L102: Mandate environments the actor can fulfill → baseline seq.
- L104: Mandate environments outside the actor's (effective) scope that are undeleted and unconverged (noted — left to other fulfillers).
- L106: Of the targets, environments skipped as verified-deleted.
- L110: Splits the mandate's environment set by "the range the actor can fulfill" (CRYPTO_SPEC §7 — even the executor cannot rotate outside their
- L142: Whether environment E is unconverged against a baseline seq: E's current epoch's start seq being before the baseline = E's current DEK was
- L163: Generalized derivation of rotation mandates (spec section 7 kinds) plus the standing warning for unconverged mandates (B2 ruling).
- L170: §7's rotation mandate kinds (all 5 — `device-revoked` added in DK K4).
- L178: A §7 rotation mandate entry (all 5 kinds — `scope-narrowed` added in 2026-09-15 ES K4, `device-revoked` in DK K4). The kind decides the
- L196: The mandate's environment set (CRYPTO_SPEC §7 — concretized to the chain-derived environment set at seq. Ascending). remove = the target's
- L204: `device-revoked` only: the revoked devices' FPs (ascending — for display and re-registration checks).
- L208: Every rotation mandate entry on the chain (§7): `remove_member` (always), a `change_role` demoting below member (judged by whether the role
- L227: The mandates one applied operation produces (0–2 — a simultaneous demotion and narrowing make 2).
- L235: If the state just before cannot be derived, fail-closed to all environments (never silently narrowed)
- L262: A device revocation's mandate (CRYPTO_SPEC §7 "revoking a device" — design record K4-8): each revoked device's **effective scope** (the
- L295: change_role's mandates: demotion (all environments of the new scope) and narrowing (old \ new) — two when simultaneous.
- L302: If the state just before cannot be derived, fail closed (the same discipline as the remove branch — noted by pullfrog): fall to the "was a
- L330: An unconverged mandate (environments remain whose current epoch has not begun after the mandate entry).
- L335: Deriving unconverged rotation mandates (chain-derived only). Environment E is unconverged for mandate M = E ∈ M's environment set (the
- L363: The guidance for a mandate that was rolled back (the target has been re-added / re-promoted / re-widened / re-granted). Guiding toward a
- L377: Per-kind guidance for the converging command (an actionable warning — the B2 ruling). Looks at the target's current state; when it was
- L402: The guidance for a device-revocation mandate (K4-8 turn 2): since a revocation is not an operation that can be re-run, always steer toward
- L423: change-role cannot be re-run against a target deleted after the demotion (current members only)
- L449: Resolving unconverged mandates — chain-derived only, so no request is made (deleted environments come from the verified chain's
- L461: One mandate's warning line (shared by the standing warning and project verify's detail display).
- L469: The standing warning for unconverged rotation mandates (the B2 ruling). Called after every command's chain sync (converging commands
- L492: Turning one environment's rotation into a result (failures are collected, not thrown — for §7's all-environment sweep).
- L509: The sweep of §7's mandate environments: an environment whose current epoch began before the baseline gets a forced rotation; the rest get
- L546: The epoch began after the baseline, but whether that round's *re-encryption completed** is not knowable from the chain (§12-7's
- L560: Resumed (or a partial completion remains) — the display and exit code are derived from RotationSummary by the caller's reportRotation

### `apps/cli/src/rotation.ts`

- L1: `maruhi rotation list|dismiss` (AUDIT_SPEC §4.1 / §6 / §7). - list: fetches and displays the server's derived view (currently active
- L53: One flag of the derived view (the received form of api-schema's RotationFlagSchema).
- L62: AUDIT_SPEC §3.3's trigger (2026-09-14 ES. `revoke_device` is 2026-09-19 DK K3's device-revocation variant — a mechanical follow of the wire
- L68: The restore that re-opened a resolved flag (AUDIT_SPEC §4.1-5 / §7 — 2026-09-27 VH).
- L72: Fetches the flag view (the shared entry of display, count reporting, and dismiss-target resolution).
- L91: The variables of one environment that carry an effective flag — what `env rm` names before the deletion takes their verified names
- L110: Fetches the pending sealed proposals addressed to the caller (member or above — the server filters by scope; PF7b). A proposal of an
- L138: The variable-name resolution result (only verified-statement-derived — unresolvable = null).
- L149: For each environment appearing in the list, fetches the verified metadata (active + tombstone) and builds a variableId → state index. An
- L156: One environment's verified metadata, or null with a note (the display is SHOULD — a failure never stops the listing).
- L213: The environments to walk: the chain's set minus the ones the verified chain shows as deleted (delete_environment — CRYPTO_SPEC §6.2: a
- L229: The values whose schema declares a max age (layout v3 — CRYPTO_SPEC §4.2) and whose latest push is past it, or within `windowDays` of it
- L251: Its ages are unknown, which a check cannot pass on (A-11)
- L280: Prints the expiring values (nothing when none — the section exists only when there is something to do). Returns the rows for
- L317: The variableId → display name index per environment (the name-only view of resolveVariableStates). Shared with `maruhi audit`'s
- L338: The rotation config the checklist consults (PF6 R3): the default path in the working directory, when it exists and names this project. A
- L368: The next action for one flagged pair (PF6 R3 — the concrete form of ADR-0014 decision 3 "human error is guarded by mechanisms"): the exact
- L398: The change_role variant (demotion / scope shrinking — AUDIT_SPEC §4.1) is not a deletion, so distinguish it by trigger
- L419: The exit code `maruhi rotation list` uses to say "something is due" under `--fail-on-due` / `--fail-on-flags` (PF7a S-B). Distinct from 1
- L426: The options of `maruhi rotation list` (the fail-on switches are the CI-cron shape — PF7a).
- L430: How many days ahead `--fail-on-due` looks (0 = past due only; the listing always shows the 14-day window).
- L434: Exit ROTATION_DUE_EXIT_CODE while a sealed proposal minted by a CI job awaits a member (PF7b — A-9).
- L440: null = the flags could not be read (an unknown part — A-16).
- L482: The fail-on verdict: which switch fired, in the order they are reported.
- L494: Why the list is unknown (a reader's token, or a failed read) — `--fail-on-pending` cannot pass on it.
- L500: `maruhi rotation list`: displays the currently active flags (all members — class 1).
- L501: The pending sealed proposals (PF7b — CRYPTO_SPEC §5.3), one line: a member or above sees the count and the command; a reader is never a
- L518: The server lists the environments in the member's scope only: a scoped member's list is partial, which a check cannot pass on (A-12)
- L550: What a check could not read (an unknown age, an unknown proposal list, the flags): a check cannot PASS on it.
- L585: The fail-on verdict that closes the listing (after everything was shown): something known due is due whatever else could not be read — exit
- L624: The flag rows per environment: the name when the verified metadata gives it, the basis, the target, the trigger, and the next step.
- L635: Display order is detection time → (for the same time within one sweep) a stable sort by variableId. The audit seq does not go on the wire
- L650: A re-opened flag says why it came back (a rollback restored a value from before the flag — AUDIT_SPEC §4.1-5)
- L674: A failed flags read is one unknown part, not an outage of the whole check: the due walk and the pending read go on, a known due value is
- L717: `--all`'s target resolution: folds the currently active flags (with `--env`, only that environment) into pairs (multiple flags of the same
- L755: The dismiss request's form (the part settled **without communication** — decided from the arguments alone).
- L764: Interprets `maruhi rotation dismiss`'s request. A check needing no network (a missing target) fails here — placed after the prior sync, the
- L794: `maruhi rotation dismiss`'s target resolution: `--all` is every currently active flag (with `--env`, only that environment); an individual
- L816: `maruhi rotation dismiss`: executes the withdrawal (admin — the server checks the authority).
- L851: Only flags of this trigger (a role change / device revocation leaves the member's other flags out).
- L866: The checklist at remove / revoke / narrowing completion (PF6 R3 — the leaver checklist; formerly the flag-count report of ruling B2). Lists
- L909: Confirmed fetches first (the certain exposure), then by name

### `apps/cli/src/run.ts`

- L1: `maruhi run -- <cmd>`: values are passed only by in-memory injection into the child's environment variables (CLAUDE.md's diskless
- L24: One driven vendor-CLI process (`maruhi sync` — sync-exec.ts). The value travels only on the child's standard input; `command` carries names
- L31: Working directory of the child (the vendor CLI resolves its project from it).
- L33: Non-secret additions to the inherited environment (vendor telemetry off).
- L35: Bytes written to the child's stdin, then closed (the only path a value takes).
- L42: Combined stdout + stderr of the child, whole and untruncated: cutting it before redaction could leave a suffix of an echoed value that no
- L52: One script of the `exec` rotation connector (connector-exec.ts — PF8). Unlike ExecInput, `extraEnv` **does** carry secrets: the current
- L67: Outcome of one captured script (stdout as bytes — it is the credential, never decoded here).
- L74: A captured script that maruhi stopped after it started (its stdout passed the cap) — distinct from a launch failure.
- L83: A captured script that exited while a process it started kept writing to its stdout: the answer cannot be told from that output (D-14). The
- L102: Keep the parent alive for the child's whole life: SIGINT is ignored by the parent (the terminal delivers Ctrl+C to the child too, which
- L110: Run-output redaction (ROADMAP Phase 3 ⑤ — run.ts's `redactionFragments`). When present, the child's stdout and stderr are received on pipes
- L124: Runs a vendor CLI with bytes on its stdin and its stdio captured (`maruhi sync`). Fails with a typed error when the command cannot be
- L130: Runs a script of the `exec` rotation connector with secrets in its environment and its stdout captured as bytes (connector-exec.ts — PF8).
- L139: Runs the command of a `maruhi agent` session (agent.ts): stdio inherited, the parent's environment passed through **unfiltered** plus
- L161: Execution-control environment variable names are refused for injection: a variable name is plaintext metadata unbound by the AAD, so a
- L185: Names that can redirect what rc files / config directories point at: swapping HOME makes bash / zsh / various tools read an attacker path's
- L196: bash/zsh variables that become command execution via prompt evaluation (M2). PS1 / PS4 also become execution control via command
- L214: Forcing interactive mode (M2): a REPL opens after the child exits and executes the input that follows
- L226: Windows's execution resolution (M2): PATHEXT is extension search, COMSPEC is the shell itself, SYSTEMROOT / WINDIR can redirect the
- L233: What gets launched when the child **starts another program**: LESSOPEN / LESSCLOSE are executed as commands verbatim in `|cmd %s` form, and
- L244: Stand-in programs for passphrase entry: ssh / sudo execute the target
- L247: The interpreter's init hooks / module search. LUA_INIT runs arbitrary Lua, and LUA_PATH / LUA_CPATH redirect require's search targets
- L253: The search targets of glibc / loader behavior and auxiliary data. GLIBC_TUNABLES changes behavior via tunables, and LOCPATH / NLSPATH /
- L265: shell function autoload and TLS trust roots. The same execution / trust boundary as the existing BASH_ENV / ZDOTDIR / NODE_EXTRA_CA_CERTS
- L296: A blanket prefix refusal of NODE_ / PYTHON_ / BUN_ is not taken: it would sweep up masses of legitimate non-execution-control variables
- L331: The environment passed to the child. The parent's general environment is inherited, but maruhi's own control / credential namespace is not.
- L354: extraEnv already refused MARUHI_* in buildInjectionEnv, but a future caller that uses the ProcessRunner boundary directly must still not
- L363: Injected environment variable names are limited to POSIX identifiers (structurally blocks injection paths containing special characters
- L369: Builds the env-var map to inject: variable display names become env names. Names and values are validated for env-var safety (no `=`, no
- L379: Windows environment variable names are case-insensitive, so allowing names differing only in case to coexist would silently crush one side.
- L393: Environment variable names are limited to POSIX identifiers ([A-Za-z_][A-Za-z0-9_]*). This filters out not only `=` / NUL / control
- L414: Reason for unwrapping: injection into the child process's env (this function's product). Unwrapped only at the last moment before
- L441: Message shown when `maruhi run` has no command after `--`. Shared by the argument check at the CLI entry point and the guard in runOp. The
- L450: Presence fail-fast (design doc §1-4 — rulings CT / CU): when a required = true declared variable exists in the verified set, exit with a
- L461: The closing clause of what did not happen (run = the child was never started, sync = nothing was sent).
- L469: The strict error of a child never started (presence — verified statements only). Two recovery paths are spelled out: set the value
- L490: The advisory type check's (§14.3-7) judgment. The declared type is a closed set (§4.2 — "" = unspecified is outside the check). The
- L511: Advisory declared-type check at injection time (§14.3-7): mismatches are warnings only and execution continues (type conformance is never
- L525: Reason for unwrapping: the advisory type check just before injection (in memory only). Nothing but the judgment result (boolean) leaves
- L539: Run-output redaction (ROADMAP Phase 3 ⑤ — the trigger). The injected values are known exactly, so the child's stdout / stderr can be
- L554: Further secrets to scrub (`proxy run`: the brokered values known at start).
- L565: Reason for unwrapping: the fragments are the search patterns of the redaction itself (what the child's output is scrubbed of). They stay
- L576: An empty string cannot execute (`maruhi run -- "$CMD"` with CMD unset arrives in this shape). "One argument is present" and "there is a
- L580: A mistake in how it was written = a usage error (2). Same treatment as the entry-point check

### `apps/cli/src/schema.package/command.ts`

- L24: schemaShowConfig: maruhi schema display — the bare parent doubles as show, same shape as audit
- L146: --type: unspecified = keep, none = explicit clear; the given value itself never appears in the error
- L164: --max-age: unspecified = keep, none = clear, else 1..3650 days; the given text never appears in the error
- L184: Contradictory schema set flags are rejected by Command.validate before the handler (usage error, exit 2, fixed messages)
- L207: Partial update (1-2): unspecified = keep, only an explicit flag returns a column to empty
- L238: schema set's report displays the type as a declaration — the word verified is never used (14.3)
- L262: Column interpretation precedes the network (partial update 1-2)
- L266: The entropy warning (ruling CW, fail-closed) is judged before communication or signing

### `apps/cli/src/schema.package/env-file.ts`

- L69: name is carried only for duplicate-name (a valid name); invalid/not-an-assignment line content may be a value and is not carried
- L77: EnvFileEntry: the value is Redacted — never used beyond observation
- L85: valueFaithful gates the push proposal: an unfaithful parse is not observed and no push is proposed (fail-closed)
- L93: descriptionCandidate is assembled from the contiguous comments right before the assignment
- L109: parseValue: escapes, expansion and multi-line values are not interpreted; unfaithful shapes return faithful = false
- L121: Escapes or a same-kind embedded quote cannot be faithfully reconstructed by this parser
- L126: An unclosed quote (multi-line or broken) is returned unfaithful
- L129: Unquoted inline comments follow dotenv/docker --env-file; the comment is not carried into the push path as part of the value
- L135: parseEnvFile: malformed lines carry only line number and reason — the content may be a value
- L151: A blank line delimits a comment block — a detached comment is not a description candidate
- L173: Duplicates are skipped with a reason (never silent last/first-wins); only the first occurrence becomes a candidate
- L185: The value is wrapped in Redacted at parse — from here only observeValue's observation unwraps it
- L200: The number shape duplicates run.ts's test deliberately: the import side stays self-contained inside Redacted's observation boundary
- L207: Placeholder-ness only narrows the proposal UX (the send default is always do-not); a misjudgment costs only proposed/not-proposed
- L232: Unwrap justified: observing the shape; the product is a closed-set type name and a boolean, never the value or a fragment

### `apps/cli/src/schema.package/schema-import.ts`

- L1: schema import ceremony (1-3): client-side read, per-variable editable approval, declared registration, optional activation push
- L60: MAX_DESCRIPTION_LENGTH is the server's acceptance cap (12-8), used only for pre-filtering
- L63: The import ceremony requires an interactive human terminal (no --yes, ADR-0016 decision 7); the 2-channel boundary is deliberate vs the 3-channel key-material gate
- L108: PushValue true means also perform the value push (activation) — the user's explicit choice only.
- L133: A candidate's presentation line never shows the value — only the type candidate and real-value-ness
- L140: Only y/yes affirm a yes/no prompt — the default is the negative
- L159: Edit-route name checks accept exactly the parser's set, else only the edit route would reach the server's slow 400 and halt the import
- L176: Edit type: blank = keep, none = unspecified; outside the closed set warns and keeps
- L238: Edit sub-prompts: blank = keep as-is; invalid input warns and keeps as-is
- L259: interpretApprovalAnswer is a pure function with no display or side effects
- L274: High-entropy findings need a dedicated explicit confirmation (fail-closed, ruling CW); no --allow-high-entropy equivalent is needed
- L308: The entropy warning never carries the found value; it is emitted per candidate every time, never ledger-suppressed
- L355: Approval continues to the value-push question only for a value that looks real, and only after approval settles (default do-not-send)
- L366: An unfaithful value is neither observed nor offered a push (fail-closed — never encrypt a misread value)
- L385: The over-limit comment note is emitted before presentation (not prompt-scoped) and needs no repeat on retry
- L403: Sending a value is always the user's per-variable explicit choice (default do not send); the value stays E2EE
- L427: declareApproved reuses schemaSetOp's creation piece; requireCreation keeps it from switching into reissuing an existing variable
- L445: An import declares no max age — set it later with schema set --max-age
- L463: pushApprovedValue reuses pushVariable; here the value is transcribed Redacted<string> to Redacted<Uint8Array> for the first time
- L475: Unwrap justified: the encoding's input; the product is Redacted again and plaintext never leaves the expression
- L505: Source-file deletion is offered only on completion and explicit confirmation (1-3 (4)); the default is not to delete
- L530: schema import: serial per-variable composites (O(N), finding F'), optional activation pushes, completion deletion offer
- L550: A rename via edit may collide with no name — not even an unprocessed candidate in the file (warned at edit time)
- L604: Existing-name matching uses verified statements only (12-2; active and declared mixed per 12-7)
- L617: The deletion offer requires every candidate declared this run — never assert declared on an interrupted or all-skipped run

### `apps/cli/src/schema.package/schema-lint.ts`

- L1: schema lint (finding G, 1-7): best-effort drift detection; dynamic access cannot be caught and the caveat is always included
- L72: Optional chaining (process.env?.X) is the same shape of literal reference
- L87: The left boundary blocks mistaking an identifier ending in ENV for an env reference (\b is not enough — _ is a word character)
- L101: Destructuring pattern: nested destructures are out of scope; [^{}]* spans multi-line destructuring
- L115: Value-side string literals are blanked so a comma inside a default cannot create a phantom identifier and false-fail the lint
- L126: Rename/default entries take the left side as the env name; a quoted key is accepted only if identifier-shaped
- L197: collectSourceFiles walks paths best-effort for scannable sources
- L201: An explicitly specified file is never filtered by extension — never silently ignore the user's designation
- L211: Symlinks are never followed — never build a cycle or an escape outside the repository
- L248: A swept-in binary is detected by a NUL byte and skipped (extensions can be faked)
- L259: Scan error wording carries the user's paths but not the OS error detail (same discipline as import's file reading)
- L295: The cross-check target is the verified live name set; a v1 variable's name is first-class regardless of the schema column
- L309: Count lines are emitted even at 0 — the output's shape does not vary by run (env diff's discipline)
- L322: The best-effort caveat is always emitted on stderr regardless of the conclusion — a checking gap is not a guarantee gap

### `apps/cli/src/schema.package/schema-snapshot.ts`

- L1: Schema snapshot (1-6): the store is the source of truth; the snapshot is a pure, unsigned artifact of the verified statement set only
- L67: Snapshot framing (ruling CW): the snapshot is generated data, not instructions; the store stays the source of truth
- L118: Snapshot build is deterministic: names and required sorted in UTF-16 code-unit order (same rule as the schema table and env diff)
- L129: Object.fromEntries is used so a variable named __proto__ cannot be eaten by the setter and silently disappear
- L176: schema export prints only the artifact to stdout; warnings go to stderr (project anchor precedent)
- L194: recordOf collapses any non-object JSON shape to an empty object
- L218: propertySetDivergence reports names only on the file side / only on the store side
- L225: Field comparison uses own-property lookup — a variable named toString must not resolve to an inherited property
- L260: Divergence diagnosis reports down to variable and field names only — description content is never emitted (2 discipline)
- L281: A different-environment file is named by its title mismatch; the file side's title content is never emitted (attacker-writable)
- L300: A byte mismatch with matching structure is reported as a framing/formatting/ordering difference (regenerate the file)
- L308: verify-snapshot compares exact bytes of the deterministic form and fails loudly (exit 1) on any divergence (1-6)

### `apps/cli/src/schema.package/schema-statement.ts`

- L113: required is signed as a mandatory explicit string true/false (4.2)
- L116: max_age_days is signed as a string, empty = none (4.2)
- L136: The wire statement is derived mechanically from the signed context (meta-statement.ts discipline)
- L164: Signing and the self-computed hash are shared with the v1 creation form (meta-statement.ts)

### `apps/cli/src/schema.package/schema.ts`

- L99: Deleted statements are left out of the live schema mapping (the pull's verification already refuses one) — exhaustive, not relabelled
- L127: A row's type is displayed as a declaration — the word verified is never used (14.3)
- L135: schema show prints from the verified statement set; descriptions neutralized; non-TTY output gets the untrusted-data header (CW)
- L166: EntropyCheckedField covers only the values the user typed this time.
- L172: Entropy gate (CW, fail-closed): interactive gets warning + confirmation; non-interactive is refused unless --allow-high-entropy; the value is never in the message
- L199: An explicit --allow-high-entropy still surfaces the warning — never pass silently
- L228: FieldUpdate is a partial update (1-2): keep = inherit the previous statement's value
- L246: schema set performs the name's NFC normalization itself (12-1)
- L252: The author is one's own internal user_id with the master sig key (4.2)
- L255: requireCreation: import may only create declarations — landing on an existing variable fails typed, never switches to a reissue
- L265: SchemaSetSummary: display is the caller's (command.ts)
- L275: Creation defaults (1-2): no predecessor to inherit, so the partial-update rule does not apply
- L278: required defaults true on creation: a false default would make the declaration contribute nothing to fail-fast (CT supplement)
- L303: tombstones are verified — var rm's deleted judgment material; the name is kept (4.2)
- L376: Pre-signing check is fail-closed while the server stays the source of truth (12-5): a first v3 reissue on v1 requires an explicit required
- L412: requireVerifiedEnvironment is the prologue shared by schema set / var rm attempts (resolves fallow's duplication finding)
- L454: Partial update (1-2) merges over the previous statement's columns; a fresh creation uses the creation defaults (round-3 ruling)
- L461: Declaration-only mode never silently switches to reissuing an existing variable
- L474: Manifest reissue and the 3-F intent append are shared by creation and reissue (meta-confirm.ts, shared with push)
- L505: Declaration creation is the valueless composite (12-5): declared, metaVersion 1
- L542: Schema reissue is a status-unchanged v3 continuation; a v1 target is raised to v3 — the legitimate direction of 4.2 monotonicity
- L548: Name and status are unchanged in a schema reissue (12-5) — renaming goes through the rename path
- L586: Only CAS conflicts are retryable for schema set (12-5); anything else is a definitive error
- L612: Normalization is the client's job before signing (4.2 / 12-1)
- L622: Effect confirmation (12-10 (3)): success is defined as confirmation on a verifiable distribution

### `apps/cli/src/server.package/command.ts`

- L209: A convergent command: the always-on unconverged-duties warning is suppressed because its own sweep report carries it.

### `apps/cli/src/sweep-rotate.ts`

- L1: The per-environment rotation injected into §7's whole-environment sweep (shared by server revoke / member remove / change-role). The
- L17: A guard for when a chain-derived environment ID fails the CLI's format check (normally unreachable).
- L24: The per-environment rotation injected into §7's whole-environment sweep. Since obligation-entry appends and earlier rotates have advanced

### `apps/cli/src/sync.package/command.ts`

- L1: Header: maruhi sync (discipline in commands/index.ts)
- L24: sync plan/apply take no --env: the environment is decided by the repository config targets; --project is checked against the config
- L60: sync init touches neither network nor files: it assembles the config JSON from flags and prints it to stdout (ruling F)
- L138: openSyncTarget reads the config exactly once and opens the project once — never compare two disagreeing verified views
- L152: The config is read before any network — a broken file's detection is never placed behind a round trip
- L162: When the token environment equals a sync environment, the same floor handle is used — two handles would desynchronize the receipt's floor

### `apps/cli/src/sync.package/index.ts`

- L1: sync.package surface follows the package-entry convention for consistency (its matching edge is type-only)

### `apps/cli/src/sync.package/sync-ci.ts`

- L1: ci sync uses the workload lease, independent of token/keychain/session; no receipt is written — CI holds no signing key
- L37: ci-lease/sync-plan are imported lazily (P-6): index.ts re-exports this file, so an eager import would be paid by every CLI run
- L50: materialOf: a leased environment's material — its absence is an implementation inconsistency
- L61: ci sync leases the source (and token) environment and re-applies everything, deleting nothing (no receipt, no signing key)
- L111: No receipt in CI: every selected variable is an add (full re-apply); no deletion arises

### `apps/cli/src/sync.package/sync-config.ts`

- L1: Sync config is non-secret and versioned with the code (X1), like the project anchor; no integration token is held in it
- L86: namedCommand records that the config named the executable — true even if it spells the default
- L95: onPush (N1/P1): apply directly from the writer's CLI, or trigger CI via gh workflow run so the writer never holds the target's token
- L112: namedCommand records that the config wrote workflow.command — true even if it spells the default
- L126: variables is an explicit list or all active variables of the environment
- L128: exclude: when the token lives in the source environment its name lands here structurally — the token is never carried (W3)
- L136: production targets require --yes on apply (M4)
- L149: receiptsEnvironment is where receipt variables live (X3 (a))
- L154: Target names share the environment-ID character class: they become part of the receipt variable name and need no neutralizing
- L162: A gh argv value must be non-empty and not start with - — never let a config build a flag-shaped argument
- L254: VariableSelection: all (minus exclude) or an explicit list
- L399: An omitted driver resolves to the preset's default (exec if it has one, else http); naming an unavailable driver is refused with its reason
- L477: Option mutual consistency is checked by the preset's check (Netlify context/branch/secret, GitHub environment/app)
- L487: Token in the source environment: an error on the explicit list; under all it is silently excluded — the token is never carried
- L524: onPush apply is refused at config time for production (ruling J); workflow is allowed for production because CI's --yes is visible
- L595: Absent an explicit production flag the preset decides; as a misoperation guard the default falls toward production
- L637: The receipts environment is never a sync source — that shape would inject receipt variables into a child or carry a receipt to a target
- L647: Post-push sync requires the config to name its project (ruling B) — never silently apply cwd's config to another project's push
- L693: Loading the default config: absent = null; present but broken is reported, not skipped
- L707: An unknown target name is a writing mistake (2); the typed name is never shown — only the candidates

### `apps/cli/src/sync.package/sync-exec.ts`

- L1: Exec driver passes values on stdin alone: argv carries only names/options and the ArgTemplate type has no value token
- L63: ArgTemplate deliberately has no token for the value — values travel on stdin only
- L94: delete is a JSON null inside the write process, or another command's argv
- L98: describeOptions lists only non-secret options (token-like options do not exist) for the plan/apply header line
- L106: check covers option consistency inexpressible in one OptionSpec (e.g. GitHub environment secrets are actions-app only)
- L118: VERCEL_MAX_VALUE_BYTES uses macOS's 16 KiB pipe capacity, not Linux's 64 KiB — the safe side across environments (Vercel reads only the first chunk)
- L126: GH_ENV: telemetry off, no update check, no interactive prompt — the prompt is cut structurally, not just by non-TTY stdio
- L154: GitHub environment names land on gh's argv: only a leading - (the flag shape) is removed
- L157: Exec presets are data-only; Netlify has none because its CLI takes the value as an argument — the http driver is the only safe recipe
- L256: GitHub's 48 KB cap is unconfirmed in unit/measurement and gh has no truncation path — do not depend on an unconfirmed number
- L261: gh seals empty stdin as an empty body (never read as no-value); a newline-only value is refused earlier by trailingNewline
- L287: repo unset = gh resolves from cwd's git remote (visible on the cwd output line)
- L289: Environment secrets exist for the actions app only; gh refuses only after reading stdin, so it is stopped at config time
- L325: In a json-object write the name lives on stdin's JSON side — a name token in the template is a declaration mistake (internal error)
- L414: buildInvocations is pure; the caller has already UTF-8-checked values; Redacted is unwrapped and re-wrapped as the stdin bytes
- L439: A JSON batch carries writes and deletes (null) together, batch items per process
- L442: Unwrap justified: assembling stdin's JSON body; the product is wrapped in Redacted again
- L445: A non-UTF-8 value reaching here is an implementation inconsistency — it drops rather than silently writing an empty string; wording carries neither value nor name
- L473: The raw value goes as-is — no newline is appended (trailing newlines are checkValueConstraints' concern)
- L494: The display cap is applied after scrubbing — cutting first would split a value and leak its unmatched second half
- L507: scrubVendorOutput replaces every synced value (and each line of a multi-line one), neutralizes controls, then keeps the tail — shown only on failure
- L540: Wrangler receives JSON, so an echoed body shows the value JSON-escaped — the escaped form is added to the scrub fragments
- L547: Fragments are replaced longest-first so a short fragment cannot crush part of a longer one and let it slip

### `apps/cli/src/sync.package/sync-http-presets.ts`

- L13: Vercel's per-request limit is undocumented; the 64 KB/deployment total does not depend on count, so the batch sits on the conservative side
- L18: Netlify contexts are the closed set of swagger's context; branch takes the branch option's name into context_parameter
- L30: Secrets cannot be placed in all/dev/dev-server contexts (docs + CLI dev-name check) — excluded
- L36: A secret cannot have the post_processing scope; the CLI's other 3 scopes are copied (non-secret sends no scopes, leaving Netlify's default)
- L92: Wrangler's legacy script name: a named environment is <name>-<env>
- L151: The API stores the value verbatim — the CLI's stdin-sourced constraints do not apply
- L160: projectId/teamId are opaque IDs, not the header line's name — not listed in describeOptions
- L162: Vercel type derivation: development cannot be sensitive; --no-sensitive is encrypted (readable back); everything else is sensitive
- L177: Netlify has no upsert and an array POST's partial failure is undocumented — one request per variable so delivered names attribute exactly
- L218: PATCH cannot change is_secret: never place a secret-meant value onto an existing non-secret variable
- L229: Delete covers only this target's context value; if it was the last value the whole key is deleted, other contexts untouched
- L252: Netlify's 5,000-character limit: an excess surfaces as an API failure, never silent truncation
- L261: accountId/siteId are opaque IDs — not listed in describeOptions
- L278: Netlify defaults to secret (unreadable back, same direction as Vercel sensitive); on a non-secret context the default flips to false

### `apps/cli/src/sync.package/sync-http-read.ts`

- L1: Vendor-response readers: one per response kind; extracted fragments pass through scrubbed before display
- L53: CLOUDFLARE_WORKER_NOT_FOUND mirrors wrangler's isWorkerNotFoundError codes
- L104: A write 2xx without created is not the expected shape (schema change or intermediary) — not read as delivered
- L121: An empty failed means everything was delivered (created's shape wobbles between one entry and an array)
- L128: If failed names cannot be identified, the whole batch is undelivered — never mis-record as delivered
- L182: Netlify read: a write 2xx must also carry the name in key (same posture as Vercel's created); the echoed value is discarded

### `apps/cli/src/sync.package/sync-http-run.ts`

- L1: Http run procedures: the list is read once for name/ID matching only (values never read); create-or-update stops at the first failure
- L43: fetchListing discards values unread; a possible next page means absent is not evidence (fail-closed)
- L98: guardUpdate reports only the variable and attribute names — no value
- L117: Delete matching: an element belongs only if it is this target's environment — a same-named variable of another environment is never deleted
- L135: lookupIds: whole = all of the item's elements matched (only removeItem presets use it)
- L176: createOrUpdate sends one variable at a time and stops at the first failure; a create racing a same-named create surfaces as a target-side failure
- L191: The listing did respond, so the failure is reported as the listing's — never as not-sent
- L204: Judging by a list with a continuation could double-create — stop without sending anything
- L232: Names delivered earlier in the batch are not lost when one variable fails typed — they go to the receipt
- L261: updateOne passes the updateGuards before sending one update
- L270: A guard stop sends nothing; the delivered share still goes to the receipt
- L281: create is not an upsert: on failure the list is re-read and the send switches to an update if the name is now there
- L300: Even if the re-read listing fails, the create's failure is reported — failing here would keep already-delivered names off the receipt
- L337: runBatch folds a typed send failure into the batch's failure — failing here would erase earlier batches' delivered progress
- L387: lookupAndRemove: look the ID up in the list, then delete per value (or per item)
- L396: The listing did respond, so its failure is reported as the listing's — never as not-sent
- L409: A name missing from a list with a continuation cannot be called gone — not recorded delivered, left on the receipt (fail-closed)
- L423: Absent from a complete list = already deleted at the target (values are never read)

### `apps/cli/src/sync.package/sync-http-send.ts`

- L1: Http send retries transport failures and 429/502/503/504 (upserts/deletes are idempotent) and honors Retry-After up to a cap; scrubbed redacts fragments
- L22: SendRetryable carries the failure fragment and the response's Retry-After (null for transport failure — the schedule waits out backoff)
- L45: send returns the body whole for the caller to interpret and scrub — never logged here
- L69: A transport-layer failure's message describes only the destination — no body
- L86: Backoff is exponential; a response's Retry-After overrides that step's wait, and the schedule records the step so an over-cap Retry-After is told apart from exhausted attempts
- L118: describeTransport carries only the destination host and error kind — no body or headers
- L126: scrubbed extracts showable fragments from a response body and redacts values and tokens

### `apps/cli/src/sync.package/sync-http.ts`

- L1: Http driver (stage 2): maruhi's own bulk upserts on machines without the vendor CLI — same config and plan/apply as the exec driver, not a substitute for the CLI
- L73: PathToken deliberately has no token for the value — a value may only sit in an entry leaf
- L86: EntryToken is the only place a value token sits (the per-variable entry template leaf)
- L107: EntriesLayout: single = the request carries exactly one variable and the entries token is that entry
- L123: entry is one variable's entry — the only place a value token sits
- L125: deletedEntry exists only on presets whose delete rides along in-write (a JSON null under Workers' merge-patch)
- L133: The list request is used for ID/key matching only — never for values
- L137: itemsField: null = the body itself is the array
- L140: nextPage: a name missing from a list with a continuation is evidence of neither gone nor nonexistent (fail-closed)
- L149: Write strategy: one-request batch upsert, or list-then-create/update one request per variable (Netlify); the list is read for key names only
- L164: updateGuards: an attribute an update cannot change (Netlify is_secret) blocks sending a secret-meant value onto a non-secret variable
- L186: Delete is expressed in-write (merge-patch null) or by lookup-then-delete
- L192: Delete matching never deletes a same-named variable of a different environment: targetField/branchField equality selects the ids
- L210: removeItem fires when the matched elements were all of the item's elements — leaving no empty variable
- L236: describeOptions lists only non-sensitive set string options in declaration order (IDs are redundant and excluded)
- L243: check covers cross-option consistency; its reason becomes the config validation message and the entered value is not shown
- L250: derive produces values from config options (a script name, Vercel's type) — values themselves are never touched
- L252: tokenHint is guidance for creating the integration token, pointing at the docs section
- L264: maxDelay caps honoring Retry-After — beyond it the request fails instead of waiting
- L268: Production retry tuning: 3 attempts, doubling from 0.5 s, Retry-After honored up to 30 s
- L286: A non-JSON body (a WAF block page) is treated as an unreadable response
- L355: Query rendering does not double-apply path encoding — UrlParams encodes afterwards
- L362: renderEntry places the unwrapped plaintext only as request-body material — it never flows to logs or errors
- L454: buildBatches is pure: upsert presets batch per request; create-or-update holds every write in one batch (lists once, sends per variable)
- L501: delivered names are split out of a partial-success response (Vercel's failed[]) here
- L503: The failure message is already redacted and carries only variable names and response fragments
- L506: what discriminates the five failure sentence shapes and never carries a value
- L517: buildWriteRequest unwraps the value into the body here and hands the product only to send; a single declaration's name goes on the path token
- L547: renderEntries expands writes and riding deletes with their names (the value is unwrapped here)
- L555: Unwrap justified: the value leaf of a body entry — the product flows only into the request body; failure display uses redacted response fragments only
- L561: A non-UTF-8 value reaching the http driver is a defensive line — prepareWork already filtered these before sending
- L575: hasNonHeaderCharacter: C0 controls, DEL, or outside ISO-8859-1 cannot go on a header value (fetch refuses them)
- L591: checkIntegrationToken's message carries only the variable name
- L597: A header-unsafe character (echo's trailing newline is typical) refuses the token

### `apps/cli/src/sync.package/sync-init.ts`

- L1: sync init (ruling F): emit the non-secret config as JSON to stdout like project anchor — no file written, no network; the product must pass the strict parser unchanged
- L117: http is written explicitly even on an http-only preset — a form where the plaintext's destination is readable; exec (the default) is omitted
- L167: The generated config is validated through the strict parser unchanged; a failure reports the write-up error with a reason
- L175: syncInitOp emits the config JSON to stdout — the command's output (decision 9)

### `apps/cli/src/sync.package/sync-plan.ts`

- L1: sync plan/apply core: the target is never read back (one-way, ADR-0014) — the receipt is the only matching material; plan never decrypts
- L91: declaredRequired: selected variables with only a required declaration carry nothing on apply
- L101: SourceVariable derives the plaintext length from the ciphertext length — plan never decrypts
- L113: sourceVariablesOf measures the plaintext length from the decrypted variables (apply/ci material)
- L125: Unwrap justified: measuring the plaintext length — the product is only the length; apply judges on the bytes it actually sends
- L134: sourceFromVerified derives only the plaintext length from ct||tag (16-byte GCM tag) — never decrypts
- L160: selectNames: explicit-list names existing neither active nor declared are a hard error — nothing is synced
- L186: classifyVariable judges one variable's plan line (name/size/emptiness here; content constraints at apply)
- L194: The name rule needs no plaintext, so it is judged in plan; apply's check stays as the defense line; wording carries only name and rule
- L234: computePlan: a receipt-only name is a delete even when the driver could not store it today — the delete carries no value
- L253: Declared-only variables carry nothing: required ones feed enforceDeclaredPresence; optional ones stay off the plan
- L264: Receipt names no longer carried (left the selection or disappeared) are deletes
- L291: planLine renders symbol + name + version — a value never lands
- L308: describeDestination shows only declared non-secret option values — neither values nor secrets land
- L331: reportPlan prints names and versions only to stdout (the command's output)
- L387: reviewPlan is the shared plan/apply epilogue; CI (no receipt) passes through the same stage as none-in-ci
- L417: A required declaration with no value in the selection means nothing is carried (the same rule as run)
- L439: syncPlanOp: receipt + verified names/versions only — source values are not decrypted and the vendor API is not contacted
- L475: SyncApplyInput adds the signing key and --yes to plan's input
- L493: prepareWork checks every value's content constraints first — one refused value means nothing is sent
- L497: prepareWork turns the plan into writes and deletes (content constraints checked first)
- L519: Unwrap justified: the constraint check's input before sending — the product is only a boolean and a variable name
- L551: failure.what carries no value (the executable name and exit code / the API's name)
- L553: detail is maruhi's own explanation, not vendor output — it does not ride the vendor-output slot in failDriver
- L565: runInvocations stops at the first failure but reports earlier successes so the receipt can record them; a start failure is that invocation's failure too
- L590: A start failure is folded into the invocation's failure (same shape as http's runBatch) — aborting would drop earlier delivered names from the receipt
- L606: A process that never ran has no output, so the start failure's wording travels on detail, not the vendor-output slot
- L623: Vendor output is untrusted: scrub the values, neutralize control characters, keep only the tail
- L636: runBatches stops at the first failure and returns what was delivered
- L670: The failure's what is authored by runBatch — never attach refused to a retry-exhausted attempt
- L693: runDriver prints one line naming where the plaintext goes before sending anything
- L704: The receiving executable and cwd are logged: the config's command/cwd changes the plaintext's destination, visible in terminal and CI logs
- L735: Unwrap justified: checking the token's header-safe shape — the product is Redacted again
- L742: fetchIntegrationToken decrypts just the one token variable, just before sending
- L808: saveReceipt returns null when nothing was written — a write failure is a warning because the target is already updated and the next apply is idempotent
- L855: A delete failure's recovery is rebuilding the receipt — but that also forgets unattempted deletions, so they are named for manual removal first
- L873: With no output lines, the message never says shown above (some CLIs fail with empty output)
- L878: maruhi's own explanation is spoken as the failure message's continuation
- L900: Vendor output is shown with an executable-name/hostname prefix — it is the vendor's speech
- L908: reportApply reports the run's result; a failure is a typed error with the scrubbed output attached
- L935: Apply to a production target needs --yes (M4)
- L951: syncApplyOp: plan, write the changed variables through the driver, then record what landed in the receipt
- L960: Apply's plan is metadata-only; values are taken in a second select-narrowed pull so no plaintext is built for variables not being sent
- L984: Apply decrypts like run; the plaintext stays in Redacted all the way to the driver's body/stdin assembly
- L1010: The integration token is fetched just before sending — a path that ends without sending never decrypts it
- L1024: The receipt advances only by what was actually delivered — even on a failed run, so the next plan shows only the remainder
- L1035: The receipt's push starts from the possibly-advanced view (the load-time view can be stale)

### `apps/cli/src/sync.package/sync-preset.ts`

- L1: A preset is one interface x 2 driver kinds sharing the preset id, so switching drivers keeps prior delivery records usable; Netlify is http-only (SY4 ruling A)
- L38: isProduction is the production judgment when unstated — the default of the misoperation guard
- L63: No named wrangler environment = the top-level Worker = production
- L88: GitHub repository secrets affect every workflow (production); environment secrets count only when named production — names fold case-insensitively

### `apps/cli/src/sync.package/sync-push.ts`

- L1: Post-push sync (N1/P1): only a human changes a value, so at that moment the writer's CLI is present — it applies directly or launches CI via gh workflow run
- L81: context/sync-plan are imported lazily (P-6): index.ts re-exports this file, so an eager import would be paid by every CLI run
- L93: loadPushSyncConfig reads before the push touches the network; --no-sync reads nothing; --no-sync with --config is refused before the handler
- L115: PushSyncDecision is decided before the push, so a usage error stops the cleanup before anything is sent.
- L124: A default-path config naming an executable never hands plaintext to a config-named program — it runs only under an explicit --config
- L136: targetCarries: an explicit list, or all minus exclude
- L143: decidePushSync: an explicit config of another project is a usage error before the push; the default config is then simply not used
- L159: A manual-sync-only config is unrelated to push — its project is not collated either (project is obligatory only with onPush)
- L188: namesCommandToRun: a named command is whatever the file says, even spelling the default; only an explicit config may run it after a push
- L203: gh exit code 4 means authentication is needed (ghcmd's exitAuth)
- L206: The workflow dispatch carries no value and no variable name on the command line — CI reads values from maruhi; stdin is empty
- L232: recoveryHint is common to direct-apply and CI-launch failures
- L237: triggerWorkflow reports only gh workflow run's acceptance (exit 0)
- L260: gh's output is untrusted: scrub-then-truncate discipline applies even though no values should be there
- L269: floorLedger holds exactly one floor handle per environment for one push — a second handle would start from the pre-push snapshot
- L295: applyTarget runs the existing apply as-is (unchanged rows skipped)
- L309: One floor handle per environment: push's handle for the source, the ledger's for receipts and the unified token environment
- L322: The push's environment (the sync source) passes push's advanced floor handle as-is
- L328: A production target cannot become apply at config stage; even if reached, requireProductionConsent stops it into a warning
- L338: syncAfterPush: one target's failure is a warning (the push is done; receipt lag is the mark) and the rest still process — only evidence fails

### `apps/cli/src/sync.package/sync-receipt.ts`

- L1: Sync receipt (W2/X3): stored as an ordinary E2EE variable; it carries no value-derived digest (a leakage path for guessable values) — the version number alone
- L56: RECEIPT_VERSION_LIMIT is the per-variable version cap (12-8, the server policy value)
- L66: decodeReceipt never includes the value itself in a malformed reason
- L90: The receipt variables record uses a null prototype: a variable named __proto__ must not resolve to an inherited property
- L103: encodeReceipt is deterministic (names ascending) — the same content is the same bytes
- L131: loadReceipt refuses a receipt written by another preset: its deliveries describe a different platform — reset it instead
- L150: Only the receipt variable is decrypted (pull's select contract) — no other plaintext is materialized even in the receipts environment
- L156: loadReceipt returns the view advanced by bounded re-sync for later pull/push to take over
- L164: Unwrap justified: interpreting the receipt JSON — a name-to-version mapping, not a secret; the product is a struct and messages carry only a reason
- L177: A different-preset receipt loses its delivered/deleted meaning: the name list is shown before removal, and maruhi never deletes from a place the config no longer points at
- L206: receiptVersionWarning: the nearing-cap warning text (null when not applicable)
- L219: storeReceipt writes the receipt as a new variable version, signed with the caller's master key like any push (4.1)

### `apps/cli/src/sync.package/sync-rotate.ts`

- L1: Receipt advancement after rotation (M1): re-encryption changes the version, not the plaintext, and only the rotating CLI knows — so it advances the receipt in-run
- L58: chain-sync/sync-receipt are imported lazily (P-6): index.ts re-exports this file, so an eager import would be paid by every CLI run
- L63: checkRotateConfigProject runs before the rotation, closing the shape where an epoch advances under a different project's config
- L101: advanceReceipt moves a variable only when the receipt points at the version just before the accepted write (same plaintext); behind stays behind
- L142: Cleanup resync starts from a verified view confirmed to be an extension of the pre-rotation view; communication failures fold into warnings, evidence passes through
- L157: The receipts floor handle is shared with the rotate when it is the same environment — never two handles on one environment
- L199: Before the first sync there is nothing to advance — skipped quietly (plan says everything is new)
- L231: The receipt's push hands the advanced view to the next step (the pull may have advanced it)
- L272: advanceReceiptsAfterRotation: one target's failure is a warning (the rotation is done) and the rest still process; only evidence fails the command
- L283: Nothing re-encrypted (check-only or could not push) = nothing to advance
- L293: A cleanup resync failure stays a warning — failing outside the envelope would flip the exit code after a successful report
- L311: One target's receipt failure does not stop the rest and does not change the exit code (cleanup)

### `apps/cli/src/sync.package/sync-types.ts`

- L20: OptionSpec.pattern shapes a string option that rides on argv or a URL (not a closed set, not combined with values); hint is the refusal text
- L32: TrailingNewlineHandling: the driver refuses values whose bytes it could not deliver unchanged (kept / strippedFromSingleLine / stripped)
- L43: NameConstraint: the maruhi name is sent unchanged, so a name the target would rename or refuse is refused here first, before anything is sent
- L55: maxBytes: exceeding a value's cap is refused — truncation never happens silently

### `apps/cli/src/var.package/command.ts`

- L311: Both rotate configs are read before any network: a broken or absent rotation config is a usage problem, not something to find after a pull.
- L347: --finalize syncs nothing, so it reads neither sync flag — the validate rule rejects them with it.

### `apps/cli/src/var.package/var-rotate.ts`

- L1: var rotate design (PF6): the old credential stays valid at the issuer through the dual-credential grace period, finalize invalidates the previous version's credential read as a verified ancestor, and there is no state file — the value history is the rotation state; plaintext lives only in memory as Redacted and the report carries only issuer-side identifiers and version numbers.
- L309: The push-failure message states what was stored, what exists at the issuer, and the connector's own recovery step (the new credential is held only by this process); a companion already stored next to the old primary is named with its rollback so the pair does not stay mismatched.
- L334: The new credential is pushed companions first (the AWS key id), then the primary.
- L390: A line count that changed is worth a look before the push (D-16), so it is warned on.

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
