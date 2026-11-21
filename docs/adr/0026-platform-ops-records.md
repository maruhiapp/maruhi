# ADR-0026: Platform and operations decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 592 comments on platform and operations code were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `.github/actions/install-bun/action.yml`

- L1: Do not go back to oven-sh/setup-bun: it caches the executable under a seedable key and checks only by running the restored binary

### `.github/workflows/ci.yml`

- L44: Concurrency group is per-PR only; main pushes get a per-run group so intermediate commits are never silently dropped
- L536: Combined-layout config check is credential-free and follows the deploy path; self-host and restore workers still deploy through it (H3)

### `.github/workflows/installer.yml`

- L1: installer.yml validates install.sh and the formula against locally built artifacts on real OS runners, independent of any real release
- L24: 'Say nothing' telemetry settings applied as in ci.yml / release.yml
- L34: The build job produces the artifacts for validation plus the static checks of the shell script and formula
- L45: persist-credentials false: no token left on jobs that run dependency code
- L50: install.sh is checked as POSIX sh because its premise is that it does not break under dash / busybox
- L69: The target table's single source is scripts/shared.ts; the workflow only drops windows and never duplicates the list into YAML
- L83: The formula is generated from the real checksums.txt and syntax-checked with the golden example, whose shape the tests pin
- L96: All targets ship in one artifact: splitting per target would push a duplicate of the target list back into the upload side
- L107: The install job runs install-test.sh's positive cases and tampered negative cases on real OSes
- L132: Values go through env, never expanded as ${{ }} directly into run (GitHub hardening guidance)
- L145: setup-maruhi is exercised via a local path reference because the action/script coupling breaks are only detected when the action runs
- L170: The job env also reaches the composite action's steps, so MARUHI_BASE_URL set here mirrors the fixtures into install.sh

### `.github/workflows/ops-backup.yml`

- L1: ops-backup runs only for the operator account (OPS_BACKUP_ENABLED); the export token needs D1 Edit + R2 Edit (measured 2026-09-03)
- L22: Cron runs at a low-traffic hour because a D1 export blocks other requests during the export
- L26: Concurrency without cancellation: overlapping exports would block D1 twice as long, and an in-flight export is not discarded
- L40: The D1 size warning threshold is hosted-ops.md §3 row 1 (decimal 5 GB)
- L53: This job carries the operator's Cloudflare token, so it restores no Actions cache; Bun comes from the SHA-256-pinned zip
- L65: --mode hosted resolves the operator DB by ID from cloudflare.config.ts because cf has no `d1 export` command since 1.0.0-beta.6
- L96: The D1 size trip-wire fails the job at the threshold because the worker side does not hold D1's measured size
- L105: Both file_size and database_size are accepted in cf d1 get output: wrangler 4.124 renamed the API field

### `.github/workflows/release.yml`

- L1: Tag-driven release per ADR-0015: gate, version match, build, smoke, then publish; no approval gate until the first public release
- L32: Tag filter v[0-9]* so unrelated tags like vendor-... do not also run the full CI
- L34: workflow_dispatch is a dry run: everything except publish runs
- L37: Default permissions are emptied and the minimum stated per job instead of relying on the loose defaults
- L40: Release runs are serialized and never cancelled in progress: killing a run mid-publish could leave Release and npm diverged
- L48: 'Say nothing' telemetry settings applied to the release path as in ci.yml
- L54: No job restores an Actions cache: a poisoned default-branch cache entry could reach a published artifact, so downloads are SHA-256-pinned
- L74: The version's single source of truth is apps/cli/package.json; a tag mismatch stops the release before any artifact is built
- L88: fetch-depth 0: the main-ancestry check needs history
- L90: persist-credentials false: later fetches need only unauthenticated access to a public repo; no token left in .git/config
- L101: Strict canonical SemVer check: lax forms are rejected here, not at npm publish where Release and npm would diverge; also injection hardening
- L116: Tag must point at main ancestry; no re-fetch, because a manual fetch after persist-credentials:false breaks if the repo goes private
- L132: A stable tag stops here until the release approval gate exists, because it would publish to npm latest with nobody's approval
- L141: Binary generation is centralized in scripts/build-binaries.ts; the build procedure is not duplicated in the workflow
- L155: persist-credentials false: no token left on jobs that run dependency code
- L160: The running Bun bundles the published code, so it comes from the SHA-256-pinned zip, never a cache; embedded runtimes are pinned per target
- L169: The smoke matrix derives from TARGETS in scripts/shared.ts, so adding a target automatically gains a real-OS smoke
- L176: The matrix goes through an assignment, not a command substitution in echo, whose exit 0 would hide a failure until fromJson('')
- L185: npm staging is built in the build job (identical permissions/trust); the essential id-token isolation from publish-npm is preserved
- L192: Publish jobs recompute this job's artifact digest and refuse a mismatch, so a compromised verify/smoke job cannot swap what ships
- L214: Artifacts kept 60 days: a recovery re-run can start up to 30 days later and then wait up to 30 days for approval
- L219: overwrite true: a re-run would otherwise 409 on the same-named artifact, and with tag re-cutting banned that trap would burn an rc
- L232: Real-machine smoke on every target because cross-compiling only guarantees it builds; the list's single source is TARGETS in shared.ts
- L247: All archives are downloaded and one used: partial fetch is impossible, and splitting would duplicate the target list (revisit if it grows)
- L257: Values go through env, never expanded as ${{ }} directly into run, so the version string cannot become a shell injection path
- L273: Keychain probe is not a release gate (continue-on-error): runner keychain behavior is out of our control, but anomalies stay readable
- L291: The annotation is emitted via an explicit branch first: a bare test failing under -e would drop the crash-discrimination annotation
- L303: publish-github also checks the npm-package artifact, so a swapped or damaged package stops the release before the Release exists
- L309: npm staging lives inside build: if it is broken, build fails and the irreversible Release creation is never reached
- L323: Downloaded artifacts are verified against the build job's digest before use (see its digest step)
- L342: Downloaded artifacts are verified against the build job's digest before use (see its digest step)
- L356: Checksums are verified against coreutils, an implementation independent of the node:crypto generator, before publishing
- L377: npm auth is trusted publishing (OIDC) only, provenance forced via the npm CLI (bun publish lacks it); lifecycle scripts never run
- L386: build is declared in needs explicitly: with only the implicit dependency, a future needs change would fail after the irreversible Release
- L395: id-token: write is required for npm trusted publishing (OIDC) and provenance generation
- L403: Downloaded artifacts are verified against the build job's digest before use (see its digest step)
- L417: Node/npm come from a SHA-256-verified tarball, not setup-node, which on a cache miss runs Node unchecked while the OIDC token is in env
- L454: npm >= 11.5.1 is checked up front so an unmet requirement stops with a clearer message than publish's authentication error
- L469: The executable bit is restored because upload/download-artifact does not preserve file modes, keeping the published tarball correct
- L476: npm's publish-time manifest auto-correction is rejected by dry-run here: it otherwise continues with only a warning and exit 0 (measured)
- L501: Prereleases publish to the next dist-tag without moving latest
- L503: The path is always passed with ./ because a bare dist-npm is read by npm as a registry package name and fails (verified with --dry-run)

### `actions/setup-maruhi/action.yml`

- L1: setup-maruhi reuses packaging/install.sh instead of reimplementing its verify-then-write properties; Marketplace release is Phase 2

### `alchemy.run.ts`

- L1: Alchemy scope (ADR-0012): hosted worker, site, DB and backup bucket only; self-host/restore stay on cf so self-hosting remains Alchemy-free
- L37: Both Node compat layers stay off explicitly, independent of the date, because past 2026-08-04 the date alone would switch nodejs_compat on
- L53: D1 is managed by name, not id, so the first deploy adopts the existing DB instead of replacing it; no jurisdiction/hint (replace triggers)
- L75: The R2 bucket's full recorded configuration is declared in full because the reconcile reads an omitted prop as 'clear it'
- L143: Secrets Store secrets are looked up, never declared, so no plan or deploy carries a secret value; a missing secret fails the plan closed
- L186: redactQueryString stays on because query strings carry OAuth codes; check-hosted-config.ts asserts it as an invariant
- L200: The DO binding uses the provider's DurableObjectLike shape; the reconcile adopts the existing class by name, sqlite only for a new class
- L223: All four Secrets Store bindings are declared: an Alchemy upload rebuilds the binding list from this program and would drop an unbound one

### `apps/cli/scripts/build-binaries.ts`

- L1: Release binaries and checksums are built by one script shared by the release workflow and local verification, so formats are defined once (ADR-0015).
- L27: The running Bun is what bundles code beside the pinned runtime, so its version must equal the pin.
- L34: The strict-mode probe runs on this host, so the host must be a release target; checked before dist/ is cleared or anything is downloaded.
- L47: bun silently ignores an unknown flag, so an empty install cache and unreachable proxy turn a renamed flag's npm fallback into a failed build instead of an unpinned runtime.
- L62: Compiled binaries run only compiled-in code: eval/Function/vm/data:-URL/on-disk JS throw EvalError; BUN_OPTIONS can raise but not lower this, except BUN_BE_BUN=1.
- L71: One shared bun build --compile call so the probe is compiled exactly like release binaries; autoload of cwd .env/bunfig is disabled so neither can inject variables or preloads.
- L103: A misspelled flag would silently ship non-strict binaries, so a probe compiled for the host target must exit 0 in a booby-trapped .env/bunfig directory before the real build.
- L117: The probe runs without this environment's BUN_* variables: BUN_OPTIONS could enable strict mode itself and BUN_BE_BUN would run the bun CLI (help exits 0), masking a failure.
- L162: Windows uses tar.gz too (stock tar on Windows 10+ extracts it); if a zip-needing distribution path appears, revisit the whole release workflow.

### `apps/cli/scripts/build-npm.ts`

- L1: ADR-0015 npm policy: single Bun-assuming bundle with unpublished workspace deps folded in; publish via npm CLI for provenance (bun publish unsupported).
- L24: Version is SemVer-checked up front so a broken version stops before tag matching or publish.
- L38: bun build starts the bundle with the shebang and a // @bun pragma; the launcher replaces exactly those two lines, so a bun build regression there stops the build.
- L45: bin.js launcher forces --no-env-file/--env-file=/dev/null/--config=/dev/null so a cwd .env or bunfig.toml cannot inject variables or preload code into the CLI.
- L75: No ./ prefix on bin path: npm 11 publish normalization silently deletes a ./bin.js bin entry (observed in v0.1.0-rc.1).
- L79: Package is restricted to darwin/linux because the bin.js shell launcher only works there; npm refuses installs elsewhere.

### `apps/cli/scripts/bun-runtimes.ts`

- L1: Bun runtimes are digest-pinned in-repo instead of downloaded unpinned by bun build --compile; bump procedure keeps version, sha256s and install script in agreement.
- L61: Download returns bytes only when they match the pinned sha256 and writes nothing — fail-closed digest check.

### `apps/cli/scripts/formula.ts`

- L1: Formula generation takes TARGETS as single source of truth and throws on unknown target shapes rather than silently publishing a platform-short formula.
- L31: parseChecksums rejects malformed and duplicated lines because a formula built from a half-understood checksums file would ship a wrong digest.
- L71: Prereleases are -rc.N style; the brew tap only carries stable releases.
- L88: Mapping fails when the release is missing an archive: a formula silently short one platform is worse than none.
- L136: Windows targets are skipped because brew has no Windows; every other target must be present in the checksums file.

### `apps/cli/scripts/generate-formula.ts`

- L1: Homebrew tap updates are manual, not an automated PR, to avoid adding cross-repo write credentials to a release path already holding contents:write and id-token:write.
- L29: Version defaults to apps/cli/package.json as the single source of truth (ADR-0015 ruling 4).

### `apps/cli/scripts/print-smoke-matrix.ts`

- L1: Smoke matrix is derived from TARGETS in shared.ts (single source of truth) rather than duplicated in release.yml.

### `apps/cli/scripts/shared.ts`

- L5: TARGETS is the single source for targets so binary generation and smoke matrix cannot drift; darwin-x64 runner retires 2027-08 and must be revisited then.
- L30: Canonical SemVer pattern (no build metadata) matches npm's check at the head of the gate; a loose pattern would only fail at publish, desyncing Release and npm.
- L40: run() distinguishes spawn failure, signal death and non-zero exit so callers can report the actual failure kind.

### `apps/cli/src/live.ts`

- L1: The production service implementations (Bun runtime. ADR-0004: the CLI may use Bun-specific APIs). - Keychain = Bun.secrets (macOS Keychain
- L18: Read submodules directly (a package's index pulls in BunRedis etc. and crashes on environments that cannot resolve the `bun` module
- L69: On a keyring-daemon-less headless Linux, a Bun.secrets write was observed to block without answering. Leave room to wait for the keychain's
- L75: Wording dedicated to a mutating timeout: Effect's timeout cannot cancel an in-flight Bun.secrets.set / delete Promise, so the change may
- L116: Driving a vendor CLI (`maruhi sync`'s exec driver — sync-exec.ts). The value is **written to the child's stdin once and closed** (Bun
- L129: A missing / non-directory cwd surfaces as spawn's ENOENT / ENOTDIR, indistinguishable from a missing executable. Look first and name the
- L136: Reason for unwrapping: writing to the child process's stdin (the only path by which a value leaves maruhi. argv carries names only
- L143: The same discipline as run: inherit the parent's general environment, never pass MARUHI_*
- L157: A script of the `exec` rotation connector (connector-exec.ts — PF8): secrets ride in the child's environment (the `maruhi run` shape — the
- L182: A stdout past the cap is never the value: the script is stopped the moment it is passed (D-6). A flooded stderr is only dropped — the
- L193: A process the script left behind (a daemon, a `… &`) that inherited its pipes would hold both reads open after the script exited — and with
- L225: The working directory check and the spawn (a launch failure names only the executable and the directory).
- L251: What the capture observed about the script's exit and its pipes (D-12 / D-14).
- L253: When the script exited (null = not yet): bytes on stdout after that are not its answer unless its pipe closed at once.
- L257: Whether a pipe was still open at the end of the grace (a process the script left behind).
- L259: Whether maruhi stopped the script (a stdout past the cap while it ran).
- L263: The capture's verdict: a leftover's output is told from the answer and refused (D-14), a stdout past the cap was stopped (D-6), a flooded
- L282: A script that failed on its own reports its own failure (exit code and stderr); what a leftover wrote is moot since nothing is pushed (D-15)
- L290: A stdout past the cap after a non-zero self-exit is a leftover's; the script's own report is what matters
- L299: Whether bytes reached stdout after the script exited that are not its own flushed tail (the pipe did not close at once, or the cap was
- L308: The stderr text: a flooded stderr is dropped whole, never cut (a cut before the connector's scrubbing could split a secret — D-9); a pipe
- L320: How long after the script exited (or was told to stop) its pipes may stay open before they are closed (and a stop escalated).
- L322: How long after the script exited its stdout may still close as the script's own flushed tail (a pipe buffer drains in milliseconds).
- L325: A script's stdout is a credential and its stderr a few lines of commentary: anything past this is neither (D-6 / D-9).
- L329: Reads a stream up to `limit` bytes; null past the limit — with the stream cancelled (`cancel`: the writer gets EPIPE on its next write), or
- L377: The launch-failure wording (carries no values — only the executable name, cwd, and the OS error code).
- L386: The database client of the `postgres` / `mysql` rotation connectors: Bun's built-in SQL client (no dependency; the URL's scheme selects the
- L425: Values are injected into the child's environment variables in memory only (the diskless invariant). With `redact`, the child's stdout /
- L433: A keychain-less / CI MARUHI_TOKEN is for the parent's session resolution only. Never pass a child a longer-lived credential broader than
- L442: `proxy run`: the parent must outlive the child (it is the child's proxy) — the same signal shape as `maruhi agent`
- L446: The pipes drain right after the child exits. A grandchild that inherited them (a daemon the child left behind) must not pin this process
- L463: A launch failure (not installed, not on PATH, cwd missing). Never go fetch it (only an installed CLI — integration-options.md §3 supplement
- L477: SIGINT's handling while the child is alive (do nothing = leave it to the child's interactive shell).
- L480: `maruhi agent`'s child (agent.ts). Unlike run, the parent's environment is passed **unfiltered** (carrying `MARUHI_AGENT_SOCK` is this
- L510: Waits for `child` while the parent ignores SIGINT and forwards SIGTERM / SIGHUP to it (`maruhi agent` and `maruhi proxy run` — parents
- L540: Run-output redaction (ROADMAP Phase 3 ⑤; the trigger is run.ts's `redactionFragments`). The child's stdout and stderr arrive on pipes and
- L561: How long after the child's exit its pipes may still deliver output (a grandchild's) before the relay stops.
- L564: Starts relaying the child's stdout / stderr through the redaction. `done` settles when both pipes ended (or were aborted); `abort` cancels
- L587: The replacer holds back only bytes that could still begin a match (byte-replace.ts): output that resembles no value streams at once
- L596: Our reader is gone: close the child's side as a pipe would
- L625: The terminator of a CSI-style escape sequence (a letter or ~). Never mix arrow-key fragments into the input
- L638: Non-echoed input on a TTY (one secret line, e.g. a recovery code). Reads one character at a time in raw mode and shows nothing on the
- L713: The shared line reader for non-TTY (piped) input. The create-and-close-a-readline-each-time shape discards the next already-buffered line
- L733: A tail that ended without a newline (e.g. `printf`'s last line) is also returned as one line
- L766: 'end' fires only once: if the stream already ended after a previous read removed its listeners, waiting for the event never resolves. An
- L798: Detecting an AI coding agent (the secondary layer). The detection rules are std-env's `agentInfo` (a table of environment variables such as
- L811: The command that opens the OS default browser (the URL is passed as an argument — no shell expansion).
- L817: Using cmd's builtin `start` would let cmd's own parser interpret `&` `^` etc. inside the URL (spawn's quoting convention targets Win32 argv
- L828: Open a URL in the default browser (best effort). stdio is left unconnected (never dirty the terminal's display). A launch failure (missing
- L849: Synchronously write one line to an fd. `console.error` is not used: when stderr is a terminal Bun colors **all** console.error output red
- L872: Returns false when the reader has left (EPIPE) — the relayed child is then told so. A non-blocking fd's EAGAIN waits a millisecond before
- L879: A partial write (return value < remaining) continues from where it left off, EAGAIN (a non-blocking fd) retries until written, and EPIPE
- L903: One line reader per process for non-TTY input (keeps unconsumed lines across prompts)
- L928: The prompt goes to stderr (the interaction survives stdout being piped)
- L934: On non-TTY (piped input) there is no echo control to be had, so read as-is
- L947: Whether color is allowed (only stderr's prefixes — notice.ts). The judgment material's `process.*` is read only inside this implementation
- L960: The account's home directory from the system user database (getpwuid), which no environment variable moves — the anchor of the acceptance
- L977: Inside a `maruhi agent` session (MARUHI_AGENT_SOCK present), use the agent's memory instead of the OS keychain (KL2 — agent.ts). An
- L993: The secondary layer for value displayability (the first boundary is the Stdio TTY judgment above)
- L997: The local floor (§6.3) lives in the same non-sensitive family as the config (<config dir>/floor)
- L999: The invite anchors and issuance pins (§6.3 (a)) are the same family (<config dir>/invites)
- L1001: The verified-fingerprint ledger (KF) is the same family (<config dir>/known-fingerprints.json)
- L1004: The proxy configs a person accepted (pf4-design.md §21 R-8) live under the account's home from the system user database — not the
- L1013: Outbound HTTP adds no header of its own (no trace propagation — packages/core/src/egress.ts)

### `apps/cli/src/project.package/project-export.ts`

- L1: Project export design: the snapshot is the server's own content (no plaintext — diskless discipline) and the command refuses to overwrite; the trailer's chain head is cross-checked against the verified view synced first; the output file is a scoped resource whose every non-completed exit removes it, and cleanup removes only what the run provably created (the wx creates are the ownership proof).
- L87: An export never overwrites: a stale file next to a fresh one is how a migration goes wrong.
- L92: NotFound is the only error the exists check folds to absent — a check failing otherwise is a real error, never a silent "absent".
- L110: A removal failure in cleanup is a defect: there is no user-facing answer to "the cleanup itself failed".
- L127: The sink's error listener lives for its whole lifetime, so a stream error landing between operations is recorded and surfaces at the next operation instead of crashing the process (a Node stream without an error listener throws).
- L135: Whether the wx open committed is the only proof the file is this run's; an already-existing file (EEXIST, no open event) must never be removed.
- L171: Everything the stream does happens inside the suspend — an effect must not act while it is only being built.
- L229: end() must run after the finish listeners are attached — a finish in the gap would never reach the callback.
- L247: An already-closed file (autoDestroy on a refused open) must not leave the gzip's handle alive.
- L292: Cleanup may remove only the outputs this run provably created: ensureAbsent is a check, not ownership — a file landing at a checked path afterwards belongs to someone else (the wx creates are the proof, refusing EEXIST).
- L303: One export pass writes into a fresh file held as a scoped resource: any exit other than a completed attempt — failure, project change, interruption, defect — removes it.
- L344: The mark is read with the last page's marks (ruling J revision, round 5): with the marks unchanged since the first page, "marked" means no write landed here after the export.
- L384: The open may have committed during the close wait, so ownership is re-checked before deciding whether the file is this attempt's to remove.
- L389: The ownership flag is cleared once the file is dealt with, so a later cleanup does not remove whatever lands at the path next.
- L413: Either file the export wrote is removed when the run exits without success: a stale pair is worse than none — a migration needs both.
- L428: The companion is read at a chain head; a head other than the file trailer's is a mismatched pair (a member changed between the reads, and the destination would refuse it as stale), so the export restarts like any change, bounded.
- L437: A completed file whose companion was stale is still on disk and is removed; an attempt whose wx open refused EEXIST created nothing — a foreign file at the path is never this run's to delete.
- L454: The companion write and its ownership mark are one uninterruptible unit: an interrupt delivered mid-write must not leave a file on disk that no cleanup knows it may remove.
- L485: ensureAbsent stays outside the cleanup scope: a cleanup running on the refusal exit would delete the user's pre-existing file; even inside, only files this run provably created are removed.
- L513: BunFileSystem is provided inside the module: the command environment's FileSystem is deliberately a dying stub (cli-runner.ts), so the env must not supply it.

### `apps/cli/src/runtime-guard.ts`

- L1: A side-effect module that stops at the entry any runtime other than Bun (e.g. running the npm distribution on Node.js). Placed at the head

### `apps/server/cloudflare.config.ts`

- L3: Bindings shared across self-host/hosted because cf modes do not inherit; hosted re-declares; drift asserted by check-hosted-config.ts
- L67: Both nodejs_compat layers pinned off explicitly: the compat date alone would enable process/Buffer and copy secrets into process.env
- L88: as const preserves the literal types cf/config's WorkerConfig expects; a widened string fails the server typecheck
- L96: Each mode's worker is a defineWorker() constant so its literal binding types survive for cf-env.test.ts InferEnv checks
- L123: Hosted secrets live in the account default Secrets Store (ADR-0012 r3); the store id is an account identifier recorded nowhere else in the repo
- L138: Hosted/restore pin the account id because cf does not save the account choice and a multi-account prompt risks the wrong account; self-host stays unpinned
- L167: Maps HOSTED_WORKER to the `cf deploy --mode hosted` invocation
- L208: Restore worker is ops-only and non-HTTP: deploy only during restore work, then delete; its sole job is a per-minute cron over restore/jobs/
- L230: Restore worker's D1 is the production database: import jobs provision the imported project's users, identities, org and membership there after DO restore
- L241: Production DO namespace is bound cross-worker to maruhi-server-hosted; check-hosted-config.ts cross-checks the effective name
- L249: Drill namespace is a separate DO class inside the restore worker that does not intersect with production
- L263: Modes select workers via ctx.mode/--mode; D1 migrations moved to cf CLI flags; .dev.vars.example deliberately not migrated to secrets.required

### `apps/server/drizzle.config.ts`

- L1: drizzle-kit is generate-only (ADR-0006): migrations are applied by cf d1 migrations and applyD1Migrations; push/live connections are not used

### `apps/server/scripts/cf-config.ts`

- L1: Ops scripts resolve the D1 binding by evaluating the config per cf mode; cf d1 subcommands take the database ID, never the binding or name
- L27: Signed URLs in D1 export envelopes are scrubbed from errors because thrown strings land in CI logs

### `apps/server/scripts/check-hosted-config.ts`

- L1: Deploy config is carried twice (cf source + wrangler mirror for the vitest plugin) plus Alchemy literals; the drift check fails closed so tests validate the deployed worker
- L49: The restore worker exists only in cf form; no test spins it up, so it has no wrangler mirror to check
- L56: Guard: the bundler config must be a function of the mode; its export type also admits plain/promised configs the checks cannot use
- L65: Both config formats are normalized into one shape so every invariant can be asserted identically across wrangler snake_case and cf camelCase
- L116: WranglerLike is a narrow typed view over unstable_readConfig's loose config; only mirrored fields are read instead of blanket any
- L167: The CfWorker view takes every mode's keys as optional with unioned value types because a union of literal workers cannot expose mode-specific fields
- L209: Legacy migrations and new-style exports both declare sqlite DO classes; normalization folds either form into the class-name list
- L219: Entrypoint is made config-relative because unstable_readConfig absolutizes main while the cf side is config-relative
- L264: A cf binding always names its worker; a same-worker reference maps to wrangler's no-script_name case
- L315: assets.directory lives in the wrangler.config.ts bundler shim, not in cloudflare.config.ts
- L344: Secrets Store bindings excluded from parity comparisons: the wrangler mirror deliberately declares none; asserted separately
- L361: Hosted secrets bound from the Secrets Store (ADR-0012 rev 3): exactly four names in one store; no other mode may declare one
- L404: Invariants are checked on the wrangler mirror; the parity assertions carry them to the cf config transitively
- L422: D1 binding name and database_name must be identical; operations substitutes database_id
- L438: The self-host default must not require R2, so deploy does not break on accounts without an R2 subscription
- L444: Cron strings cross-checked against OPS_HOURLY_CRON: drift would silently reroute the hourly job to the daily side
- L450: Hosted invocation logs disabled: they embed request URLs (capability / OAuth code); aggregated metrics only (hosted-design §5-1)
- L458: Defense in depth: the query string (OAuth code etc.) is always dropped from URLs in logs and traces
- L466: Single-origin invariant (owner ruling): auth endpoint origin pinned to one custom domain; workers.dev must not survive
- L492: Restore worker binds the hosted worker's DO namespace across workers; a mismatch only surfaces during an incident
- L503: Every mode runs one compatibility date with both Node compat layers off; past 2026-08-04 the date alone would enable nodejs_compat
- L529: The restore worker is also the import path (PF3 ruling H) and must bind the production database under the same name and id
- L536: Section contract: alchemy.run.ts declarations are compared against the cf hosted worker; site literals are pinned by value
- L555: Path normalization is string-only so directories recorded relative to different bases can be compared
- L589: Both workers pin a custom domain: the hosted one is the single auth origin; the site's is the apex
- L617: D1 / R2 are managed in Alchemy (ADR-0012 rev 2); declarations must name the same database and bucket the cf config binds
- L634: The migrations prop is what makes the deploy own the hosted migration ledger
- L642: Bucket lifecycle rules pinned by value: the retention seconds are load-bearing and the provider syncs them to the live bucket
- L695: CORS / domains / public access declared explicitly empty/off: the explicit declaration is what this check can pin (O2 record)
- L706: Both managed resources are RemovalPolicy.protect'd; declarations are sliced so one resource's protect cannot satisfy the other
- L740: Deliberately omitted props must stay omitted: some take the provider's in-place update path and would be applied, not refused
- L799: Rate limits compared as a name-keyed record: a set of triples would not see two bindings' values or namespaces swapped
- L885: logs.enabled asserted separately because the wrangler-derived Norm carries no such field
- L890: workersDev asserted positively: an omitted prop is read by the provider as enabled, reviving workers.dev as a second auth origin
- L898: Hosted secrets bound by Secrets Store lookup (ADR-0012 rev 3): unbound would be dropped on deploy, declared would re-enter the deploy path
- L937: The secret-binding check is scoped to the HostedServer env block so the same text elsewhere cannot satisfy it
- L952: The lookup is anchored to the env entry itself: the secret must be bound under its own env name

### `apps/server/scripts/d1-api.ts`

- L1: cf dropped its d1 export/import commands, so ops scripts POST to the D1 REST endpoints directly; credentials come only from env vars and the token is never printed
- L83: d1ApiPost contract: a non-success envelope throws with the API's messages; signed URLs are scrubbed from raw text in errors

### `apps/server/scripts/d1-export.ts`

- L1: The export endpoint is a poll protocol this script owns because cf no longer ships d1 export; the API cancels an export that is not polled
- L36: MAX_POLLS=600 is ~10 minutes at 1s polling, the same order as wrangler's export

### `apps/server/scripts/d1-id.ts`

- L1: cf d1 takes the database ID, never the binding or name, so scripts resolve the ID from the config instead of hard-coding it

### `apps/server/scripts/d1-import.ts`

- L1: Script owns the init/ingest/poll orchestration wrangler hid since cf dropped d1 import; a failed import rolls back to the pre-import bookmark so retry is safe

### `apps/server/scripts/issue-signup-invite.ts`

- L41: The id generators are Effects since the 4.1 migration; this script is a runtime root, so it provides the layer itself

### `apps/server/scripts/reorder-d1-dump.lib.ts`

- L1: Lib/CLI split so tests pin the pure reorder functions with synthetic dumps; the CLI entry point holds the file I/O
- L54: FK ordering via Kahn's algorithm: self-references ignored, references to external tables count as satisfied, an empty round means a cycle
- L94: reorderD1Dump is pure; file I/O lives in the CLI

### `apps/server/scripts/reorder-d1-dump.ts`

- L1: Reorder is needed because export's per-table blocks break FK order on import and the defer_foreign_keys pragma does not take effect on the file import path; the no-newlines assumption fails closed

### `apps/server/scripts/tsconfig.json`

- L2: Ops scripts run under Bun, not in the Worker, so they get Bun's types in their own program; the server tsconfig stays Workers-only
- L8: DOM lib is included for the WebCrypto types of the @maruhi/crypto sources these scripts reach through server modules

### `apps/server/src/do/chain-do.ts`

- L173: The GitHub OAuth App's client_id. Public information, but the provisioning path is uniformly secret-shaped (AUTH_SPEC §3-2):
- L182: The GitHub OAuth App's client_secret (same two shapes as GITHUB_CLIENT_ID above; only dummy values may be committed).
- L189: The deployment keypair's input key material (same two shapes as GITHUB_CLIENT_ID above.
- L199: The seven *_RATE_LIMIT bindings below are required here because both serving modes declare them (test/cf-env.test.ts), but a deployment…
- L204: The source-IP rate limit of unauthenticated CLI-login start (AUTH_SPEC §4-1 (1) — the ratelimits of wrangler.jsonc.
- L210: The source-IP rate limit of unauthenticated CLI-login poll (AUTH_SPEC §4-1 (5) — looser than start so the normal path stays under the…
- L217: The source-IP rate limit of the unauthenticated OAuth callback.
- L228: The source-IP rate limit of lease issuance.
- L236: The source-IP rate limit of a `GET /auth/github/start` carrying a signup invite code (AUTH_SPEC §3).
- L246: The source-IP rate limit of the CLI login browser leg's entry (AUTH_SPEC §4-3).
- L255: The source-IP rate limit of the CLI login approval POST (AUTH_SPEC §4-3).
- L263: The destination of DO → R2 evacuations (docs/notes/hosted-ops.md §2-D / §2-F).
- L271: The tripwire-notification webhook (hosted-ops.md §2-B; same two shapes as GITHUB_CLIENT_ID above).

### `apps/server/src/do/do-ops.ts`

- L1: The project DO's side of the ops RPC (hosted-ops.md §2-D / §2-E):
- L26: The object key's prefix (`do`). The project ID never appears on the key.
- L29: A DO larger than this is not evacuated (oversize).
- L31: The watermark of the last success (audit seq, chain seq, the latest acceptance time of a head attestation).
- L41: For tests: the multipart part length.
- L84: The audit head at the restored log's end, as the derivation computed it — stored or not past the storage guard's line (empty string when…
- L90: The DO → R2 evacuation, run by opsBackup under the permit (= all tables consistent).
- L149: Every evacuation failure is a defect (do-snapshot-write.ts); it is answered with the static code and retried on the next sweep
- L152: A static message only (up to the class name).
- L168: The evacuation body opsRestore restores, fetched from the bucket.
- L188: A precondition failure answers the object without a body
- L197: The restore of one evacuation body into this (empty) DO, under the caller's permit (opsRestore; storage-guard.test.ts runs it under a…
- L216: A restore materializes a fresh destination DO (hosted-ops.md §2-E):
- L233: Discard the memory regardless of success or failure (no residue of a partial restore is handed out either)
- L244: A refusal is answered, never thrown past the permit
- L255: Extend the audit-head row to the end (bounded extension — a one-time operation at restore, so run it to convergence) below the same line
- L261: Always terminates because each call makes progress (the bounded contract of audit-store.ts)

### `apps/server/src/do/do-snapshot-export.ts`

- L1: Paged export (the owner-side transport of PF3 — AUTH_SPEC §11-6, docs/notes/pf3-design.md rulings A–D).
- L27: The marks a cursor binds: the chain head, the attestation mark and the mutation counter (kept by the schema's triggers — the mutation…
- L40: The mutation counter covers every tracked table, head attestations included (ruling C revision, round 4 — no separate attestation mark).
- L42: The DO schema version: an export spanning a deploy that migrates the schema restarts at the source, not at the destination (ruling C…
- L44: The line format's version, for the same reason (round 6 — a mixed file would be refused at the destination).
- L48: The tables whose rows the export bounds by `auditMaxSeq` (the log and its cumulative-hash column).
- L51: The stateless page cursor (opaque to the client — base64url JSON on the wire).
- L53: Index into the evacuation's table order (chain_entries last).
- L55: Whether the current table's `table` line was already emitted.
- L57: The last rowid emitted of the current table (-1 = none).
- L59: Rows emitted so far per table (the trailer's counts).
- L62: The seq of the `project.exported` row the first page appended (ruling D revision):
- L94: The audit head at a given seq (the paged export's trailer — the mark, not the live maximum); null when the column has not reached it.
- L118: The cursor's wire shape. Positions are embedded in SQL (the rowid) or index the table order:
- L141: null = not a cursor this server produced (the client starts over).
- L156: null = the first page (the header is emitted and the marks are taken).
- L158: The seq of the `project.exported` row of this export (the first page binds it into the cursor).
- L168: null = the trailer was emitted (the export is complete).
- L171: The bound of the exported audit log (the cursor's `exportedSeq` — the trailer repeats it).
- L176: The lines of one page and their UTF-8 size (newlines included).
- L184: UTF-8 bytes (display names may be non-ASCII), plus the newline
- L189: The cursor a page starts from: the given one, or the first page's (the header is emitted).

### `apps/server/src/do/do-snapshot-restore.ts`

- L1: The restore of an evacuation into an empty project DO (docs/notes/hosted-ops.md §2-E / §5-2):
- L23: DO SQLite bound-parameter limit (per statement — durable-objects/platform/limits).
- L26: Whether chain_entries is empty (the restore acceptance condition — creates no overwrite path).

### `apps/server/src/do/do-snapshot-write.ts`

- L1: The evacuation's write-out (DO → R2 — docs/notes/hosted-ops.md §2-D / §4-2):
- L23: A sink that writes to R2 while gzip-compressing.

### `apps/server/src/do/do-snapshot.ts`

- L1: Evacuation (DO → R2) and restore of the project DO — docs/notes/hosted-ops.md §2-D / §2-E / §4-2.
- L47: The line formats on the wire — the single source for the SnapshotLine types below (the union decode of do-snapshot-restore.ts's parseLine).
- L86: Only when the cumulative-hash column (audit_head_hashes) has reached MAX(seq)
- L105: Compiled once at module scope: `fromJsonString` composes JSON.parse and the schema, and rebuilding it per line makes a new AST every…
- L121: Latest acceptance time of a head attestation (head_attestations); 0 when none.
- L129: The deployment-local mutation counter (mutation_state — every write entry point bumps it).
- L133: The mutation counter (0 before the first write on this deployment).

### `apps/server/src/handlers/handlers-export.ts`

- L1: Handlers for the project export API (AUTH_SPEC §11-6 — PF3).

### `apps/server/src/handlers/handlers-mirror.ts`

- L1: Handlers for the mirror API (AUTH_SPEC §11-7 — PF2).

### `apps/server/src/handlers/json-stream.ts`

- L1: A JSON response body written in chunks (AUTH_SPEC §14-2 — the lease).
- L9: Text per chunk before it is encoded and handed to the runtime.
- L12: The pieces of `JSON.stringify(value)`, in order:

### `apps/server/src/import-check.ts`

- L1: The pre-checks of an import job (PF3 — AUTH_SPEC §11-6, docs/notes/pf3-design.md ruling H revision):
- L24: One chain_entries row as the snapshot carries it (values untyped until checked).
- L41: Not gzip, not JSON lines, or a chain table without its columns.
- L43: No chain_entries rows (nothing to import).
- L45: The rows do not form the chain the DO would accept (a row's hash or size, or the verifier).
- L48: Streams the snapshot once and collects its chain_entries rows (the table is last — a full read, like the restore itself).
- L76: Not gzip, or a truncated stream
- L81: One line as JSON (null = not a JSON object — a corrupted evacuation).
- L92: Remembers the chain table's columns and collects its rows (other tables pass through).
- L97: false = the line is not one a snapshot carries (the scan stops).
- L129: A row's entry as the wire schema accepts it (null = not a chain entry).
- L152: The snapshot's chain, verified as the DO verifies it on load (and as a mirror verifies a replica — AUTH_SPEC §11-7 `chain-invalid`):
- L192: The user ids the verified chain lists as owners (a re-run is accepted under any of their project rows — ruling I revision).
- L199: Confirms the companion against the verified chain:
- L213: The companion was read at a chain head: one that is not the file's is a mismatched pair (a member added or removed between the two reads)

### `apps/server/src/index.ts`

- L1: @maruhi/server — Workers + DO + D1. Effect v4 HttpApi (ADR-0005).
- L62: HttpApiBuilder.layer nominally requires HttpPlatform / FileSystem / Etag.Generator / Path (for a pure JSON API they are never invoked at…
- L86: The crypto services as plain service values for the per-request context:
- L99: The worker's env-reading boundary for secrets:
- L108: In-house counting of GitHub token requests (ops-signals.ts — the acceptance surface's behavior is unchanged).
- L124: The OIDC verifier (AUTH_SPEC §14-1). Since it holds the JWKS cache per isolate, exactly one is built per env (same lifetime as handlerCache)
- L138: Keep HttpApi Layer construction to once per env (stable per isolate).
- L154: A failed build must not poison the cache for the isolate's lifetime (the synchronous predecessor cached only after a successful build):
- L185: RFC 9457 rendering of framework-level failures (declared on the API in @maruhi/api-schema).
- L190: Handler-level crypto-service requirements (SecureRandom / Digest / Signature) are discharged here; the middleware's are global requires…
- L196: Disable Effect's default HTTP logger (HttpMiddleware.logger — annotates `http.url` on "Sent HTTP response").
- L227: Buffers the stream up to the cap and returns it (over-cap → null).
- L254: A cheap early rejection on the declared Content-Length (a missing header counts as 0 = passes).
- L260: The raw-body cap at the HTTP boundary (policy.ts).
- L278: The Request constructor refuses a non-null body for GET / HEAD (the Fetch spec).
- L289: Common security headers on every response.
- L318: Adds the standard `Retry-After` header to 429 responses.
- L336: A 429 without a JSON body (a future path) is returned as-is without the header — this is a representation enhancement and must not…
- L368: Since disableLogger (handlerFor) also stops the Effect logger's failure branch (with cause), unhandled failures / defects would leave…
- L379: Scheduled jobs (cloudflare.config.ts's triggers — branch on the cron string):
- L392: Only the webhook URL is read on this path (worker-env.ts's single-field reader; a failed store read disables the alerts, the same as an…

### `apps/server/src/ops/ops-alerts.ts`

- L1: Tripwire evaluation and notification — docs/notes/hosted-ops.md §2-B / §3.
- L34: Signal names (fixed vocabulary — hosted-ops §3).
- L61: The payload sent to the webhook (no identifiers).
- L77: The notification sink (tests plug in a capturing implementation).
- L84: Timeout of one webhook POST — the same bound as github.ts's REQUEST_TIMEOUT and jwks.ts's FETCH_TIMEOUT_MS:
- L92: The outbound client: no header of its own (packages/core/src/egress.ts).
- L100: A webhook send failure folds into the static line + `false` (kind name only — never the URL or the body).
- L110: The production implementation: POSTs JSON when a webhook URL is configured.
- L120: Static signal name + aggregates only
- L129: The webhook URL's only unwrap is the request build (a Workers Secret); it appears in no log line or error
- L209: The stored alert state is decoded, not cast: a malformed value restarts from empty
- L216: Unknown keys in the stored alert-state row carry over to the next save
- L225: A corrupted alert state row restarts from all-inactive: it is operational state only, not audit
- L282: If notification fails the state is not saved, so the next evaluation re-derives the same transition and re-sends

### `apps/server/src/ops/ops-backup.ts`

- L1: The DO → R2 evacuation sweep (worker side) — docs/notes/hosted-ops.md §2-D / §4-2 / §4-3.
- L47: Cut short by the budget or the cap (the cursor points mid-way).
- L55: For tests: the multipart part length (default is policy).
- L59: The once-per-isolate flag of warnMissingBucketOnce (module state like identities.ts's Refs).
- L81: No binding on the DO side (the worker side has one) = a configuration inconsistency; treated the same as an RPC failure
- L88: Evacuation of one project (an RPC failure is recorded as failure — retried next sweep).
- L122: Static message only (no project ID — the record lives on the D1 side)
- L155: Visits one page's worth. Return value = the last project visited (mid-page when the budget ran out).
- L188: The stored sweep cursor, decoded (not cast — a malformed value restarts from the beginning).
- L195: A corrupted cursor restarts from the beginning (operational state only — not audit); the save at the end of the sweep overwrites the bad row
- L205: Advances from the cursor to the end (or until the budget runs out), then saves the next cursor.
- L223: The end: next time starts from the beginning
- L241: The sweep body. Advances from the cursor within the budget; on reaching the end, resets the cursor to the beginning.

### `apps/server/src/ops/ops-policy.ts`

- L1: Draft values for the operations foundation — docs/notes/hosted-ops.md §3 / §4.
- L10: The ops counters' fixed window (1 hour — same granularity as GitHub's secondary rate limit).
- L13: Retention of counter rows (windows older than this are deleted at evaluation — bounding).
- L16: hosted-ops §3 row 3: the warning threshold for GitHub token requests / hour (80% of 2,000).
- L19: hosted-ops §3 row 5: the warning threshold for signup refusals / hour.
- L22: hosted-ops §3 row 7: projects with at least this many consecutive failures become a signal.
- L25: hosted-ops §2-B: the re-notification interval for signals that stay active.
- L28: hosted-ops §2-D: even when content is unchanged (audit seq and chain seq equal the last success), re-evacuate once this much time has…
- L36: hosted-ops §3 row 7: projects whose last success is older than this count as "evacuation behind".
- L48: hosted-ops §4-2: a DO exceeding this is not evacuated and signals `oversize` (holding the permit bounds tenant wait and the cron's wall…
- L55: hosted-ops §4-3: one sweep's wall-clock budget (inside the 15-minute cron cap).
- L58: hosted-ops §4-3: the cap on projects visited per sweep (inside the subrequest cap).
- L61: The sweep's `projects` enumeration page (one D1 query).
- L64: hosted-ops §1: the R2 multipart part length (inside the 5 MiB minimum; 640 parts even for 10 GB).
- L67: The row-read page for evacuation (rowid keyset — reads one statement at a time, synchronously).
- L70: The row count per restore transaction (DO SQLite's 100 bound parameters per statement are chunked separately).
- L73: The hourly cron string (**keep in sync manually** with cloudflare.config.ts's `triggers` — the same paired note as worker-env.ts's…

### `apps/server/src/ops/ops-signals.ts`

- L1: Write points for the operations counters — docs/notes/hosted-ops.md §2-A.
- L23: Counter +1 (best-effort — a failure leaves only a static log).
- L29: Static message only (metric names are fixed vocabulary)

### `apps/server/src/policy.ts`

- L1: Server acceptance policy for CRYPTO_SPEC §6.4.
- L11: §6.4: acceptance limit on the canonical byte string (entry_bytes) of one entry.
- L14: §6.4: acceptance limit on the number of entries in a whole chain.
- L17: §6.4 (Sc-3a): acceptance limit on cumulative canonical bytes across a whole chain.
- L28: Raw body limit at the HTTP boundary (implementation detail; the spec only defines limits in terms of canonical byte strings).
- L46: Data-plane acceptance policy (AUTH_SPEC §12-8; not a consensus rule — raising it in self-hosting is free).
- L53: §12-8: acceptance limit on a value's ciphertext (ct || tag).
- L56: §12-8 (Sc-3): the sum of the ciphertext bytes of the latest version of every active variable of one environment — what one with-values…
- L68: §12-8: active environments per project.
- L71: §12-8: environment rows per project (including tombstones; resource protection for ID incineration).
- L74: §12-8: active variables per environment.
- L77: §12-8: variable rows per environment (including tombstones).
- L80: AUDIT_SPEC §3.3 (Sc-5): the maximum variables one `rotation.recommended` aggregate row enumerates.
- L97: §12-8: versions per variable.
- L100: §12-7 (VH): the ciphertext byte budget of one version value range page.
- L108: §12-8: limit on the schema description (variables — layout v3) in Unicode code points.
- L118: §12-8: cumulative ciphertext bytes per project (amount currently stored; freed by deletion).
- L121: §12-8: DEK wraps per request.
- L128: §12-8: DEK wrap rows per project (amount currently stored; freed by environment deletion and wrap deletion).
- L137: §12-8 / CRYPTO_SPEC §6.4: pending proposals per project (four-eyes — PF1).
- L145: CRYPTO_SPEC §6.4: upper bound on `propose`'s `expires_at_ms` = server clock at acceptance + this value (30 days).
- L154: §12-8 / CRYPTO_SPEC §6.4: live devices per member (per project — 2026-09-19 DK).
- L162: AUDIT_SPEC §7 dismissal operation: dismissal targets per request.
- L170: Tenant quotas (AUTH_SPEC §11-3 / §12-8; hosted-design.md §3-3).
- L178: §11-3: active projects per org.
- L190: §12-8 DO storage total guard warning threshold (operational log — static message only, once per DO instance).
- L198: §12-8 DO storage total guard rejection threshold.
- L214: AUTH_SPEC §11-5: server-fixed page for project listing (D1 candidate order, ascending project_id).
- L223: Workload-lease acceptance policy (AUTH_SPEC §14-3 / AUDIT_SPEC §3.5).
- L230: §14-3: length of a lease's fixed window (1 hour).
- L233: §14-3: lease issuance count per fixed window (per project).
- L254: AUDIT_SPEC §3.5: recorded rows per fixed window for server.lease_denied.
- L261: AUTH_SPEC §16-1: length of the head-attestation fixed window (1 hour).
- L264: AUTH_SPEC §16-1: head-attestation submissions per fixed window (per member — draft value 60).
- L275: §14-1 first-come binding (2026-08-15 ruling — docs/notes/session-24.md):
- L288: Sealed value proposals (AUTH_SPEC §14-5 / CRYPTO_SPEC §5.3 — 2026-10-02 PF7b).
- L296: §14-5: the per-project fixed window of mints (the same hour-long window as leases, under its own `kind` — a job that re-leases in a…
- L304: §11-6 (PF3): one export page carries at most this many rows (the DO reads them in one synchronous statement under the permit — the same…
- L311: §11-6: one export page's line text is cut at this many bytes (a page ends after the row that crosses it).
- L314: §11-6: the per-project fixed window of exports (first pages — the same hour-long window as leases, under its own `kind`).
- L322: §11-7: a replication page may exceed the export's byte bound by one line (the export ends a page after the line that crosses it); the…

### `apps/server/src/restore-worker.ts`

- L1: The restore worker (operator-only, non-HTTP, non-permanent) — docs/notes/hosted-ops.md §2-E / §5-2.
- L45: The drill namespace (a distinct class name inside this worker — never intersects the production namespace).
- L50: The production worker's D1 (PF3 — AUTH_SPEC §11-6).
- L57: The production worker's namespace (the scriptName binding in the restore mode of cloudflare.config.ts).
- L63: Jobs in flight (claimed — the next cron will not pick up the same job).
- L70: An import (PF3): the key of the identities companion the exporting owner's `maruhi project export` wrote next to the snapshot.
- L81: The identities side of an import job (static codes only).
- L118: Only on an import job (identitiesKey).
- L123: Static codes only (exception messages are never written)
- L130: An import job whose snapshot carries a chain the DO would not load (checked before the DO is touched).
- L132: An import job refused by its pre-checks (`identities` says why); the DO was not touched.
- L138: Only on an import job (identitiesKey).
- L142: JSON text → an object, or null (non-JSON and non-objects are "malformed" — never thrown).
- L153: An optional string field: undefined when absent, null when present with another type.
- L175: The identities companion as `maruhi project export` writes it (api-schema's ExportIdentitiesSchema).
- L178: The chain head the companion was read at (the pre-check binds it to the file's).
- L183: One entry of the companion's `identities` (null = malformed).
- L199: The companion is a wire input: its ids are minted here, where they are parsed
- L236: What the pre-checks established (the restore and the D1 step build on it).
- L239: The genesis hash of the verified chain (the DO's name — no second scan of the file).
- L241: The verified chain's owners (a re-run is accepted under any of their project rows).
- L244: The etag of the snapshot object the chain was verified from (the DO restores that body or refuses).
- L259: The pre-checks of an import (ruling H revision):
- L283: The chain, not the file, decides who is a member
- L302: The DO restores this body and no other (its etag — ruling H revision, round 4)
- L307: A drill's report of the pre-checks (nothing is provisioned).
- L319: The D1 step of a production import: provisions the members and the projects row (db.package/import.ts) once the DO holds the project —…
- L347: Reads the project ID (the genesis entry's hash) out of an evacuation.
- L397: Reads one line as JSON (non-JSON = a corrupted evacuation — folded into a static code).
- L406: Remembers the chain_entries column names and picks up the seq-1 row's entry_hash_hex (= the project ID).
- L450: The restore RPC against the DO named by the snapshot's genesis (the failure codes of the pre-RPC stages are static).
- L454: The project id the import's pre-check established from the verified chain (no second scan — ruling H revision).
- L456: The etag of the snapshot the pre-check verified:
- L474: The workers-types RPC stub types distribute over union return values, so this converts back to the declared type (the same reason as…
- L489: The project id from the snapshot's genesis (a plain restore has no verified chain to take it from), with the etag of the object it was…
- L507: A corrupted evacuation (non-gzip, truncated gzip, non-JSON lines) is returned as a static code — letting the exception escape leaves the…
- L531: An import job: the pre-checks, then the DO restore, then (production only) the D1 step.
- L540: A drill rehearses the import: the DO half is the drill's own result, the identities half what production would do
- L549: The D1 step after the DO holds the project.
- L564: Enumerates the jobs, runs them in order, writes the results, and deletes the jobs (1 job = 1 result).
- L582: Job name = the key's basename minus .json (the result uses the same name + .json)
- L590: claim: move to running/ before executing (later crons do not look in jobs/)
- L596: The one-job to one-result invariant holds even on unexpected exceptions: the claim already removed the job, so throwing would strand it in running/
- L624: The restore worker has no HTTP handler by design (fetch undefined = 404); it is driven by cron only

### `apps/server/src/server-logger.ts`

- L1: The server's Effect logger: `Effect.logWarning` / `Effect.logError` reach Workers Logs exactly as the plain `console.warn` /…
- L43: Printed for a log call that carried no message part (a Cause-only call — see the header).
- L58: INFO / DEBUG / TRACE: dropped (see the header)
- L63: Replaces Effect's default loggers with the console.warn / console.error router above.

### `apps/server/src/worker-env.ts`

- L1: Small pieces shared inside the worker: the Env and secrets services and the DO RPC call helper (with its typed failure).
- L10: The Env fields that are secret configuration values (read only through `readWorkerSecrets` / `readWorkerSecret`).
- L17: One secret field as it arrives in the env, in either of the two shapes a deployment can carry:
- L28: The Env as handlers see it: the bindings and the non-secret configuration.
- L37: The worker's secret configuration values, resolved once per env from whichever binding shape the deployment carries (see…
- L66: Wraps one resolved secret value, labeled with its name (unset or empty → undefined).
- L74: Resolves one secret field to its string value (unset or empty → undefined).
- L93: The platform contract is Promise<string>; a non-string resolution is treated as unset rather than let through, so a platform-side…
- L102: Resolves one secret field to its labeled `Redacted` value — the single-field form of `readWorkerSecrets`, for the entry points that need…
- L115: The env-reading boundary for secrets: one call per entry point that receives the Workers env (index.ts's buildServices; the single-field…
- L145: Resolves the project DO's stub (DO name = project ID).
- L152: A DO RPC that rejected, or threw before returning its promise (DO unreachable, a DO-side defect, a storage fault).
- L165: The workers-types RPC stub types distribute a union return value into a per-member Promise intersection, so this converts back to the DO…
- L177: The period (seconds) of the ratelimits binding's fixed window.
- L192: Normalization of rate-limit keys: IPv6 is rounded to its /64 prefix.
- L210: IPv4-mapped (::ffff:a.b.c.d) uses the embedded IPv4 as the key:
- L234: An embedded IPv4 may only sit at the address's end (RFC 4291 §2.2 (3)); only the tail half's last piece may carry it, rejecting shapes like 1.2.3.4::
- L281: Octets are strict decimal: Number() coercion would pass '', '0x10' and '1e2' through, which the later range check cannot catch after conversion
- L306: Rate limiting fails closed on a missing binding (a config mistake must not silently disable it) but fails open on a missing header or limiter failure
- L342: Fail-open is explicit but never silent: only the error kind name is logged, since error.message is uncontrolled and could carry the key; no IPs logged

### `apps/server/wrangler.config.ts`

- L3: wrangler.config.ts is the bundler shim for the wrangler build cf delegates to; the asset directory lives here, not in cloudflare.config.ts

### `apps/server/wrangler.jsonc`

- L3: wrangler.jsonc stays as the test-harness mirror of the deployment config (ADR-0012); parity with cloudflare.config.ts is asserted by check-hosted-config.ts
- L16: Both Node compat layers are pinned off whatever the compatibility date implies; the reason is at COMPATIBILITY_FLAGS in cloudflare.config.ts
- L19: workers.dev stays the self-host default: the OAuth callback URL is derived from the origin even when routes assigns a custom domain
- L23: Preview URLs are disabled so the origins of auth endpoints are not multiplied; the OAuth callback is pinned to a single deploy URL
- L27: Dashboard and API share one Worker (ruling BM): the __Host- cookie, CSP connect-src 'self' and the OAuth callback each require one origin
- L37: run_worker_first covers the API path space; /invites/* is required or the _redirects catch-all swallows each accept POST as a 301 (measured fix)
- L48: html_handling is pinned explicitly (ruling BH): the canonical /invite to invite.html URL (§15-3) depends on this default
- L57: Rate limits are per-colo, available on every plan, and match SELF_HOSTING.md's WAF values; period changes must also align IP_RATE_LIMIT_PERIOD_SECONDS
- L80: The callback limit is looser than start (10) because concurrent logins bunch up behind one office NAT (deepsec R7)
- L88: Poll limit 30/min: the happy path polls every 5 seconds = 12/min, leaving room for concurrent flows and clock skew
- L96: The signup-start limit covers only code-bearing starts; the plain login path is unlimited (§3, H1)
- L104: The verify limit exists because the flow-signing key is resolved (get-or-create) before vsig verification, so an unauthenticated flood reaches D1 writes
- L113: The approve limit bounds CAS amplification: the ticket is the only credential, so every well-formed unauthenticated POST runs the decision CAS
- L123: DO declaration uses exports (successor to migrations): once deployed with exports a Worker cannot go back; namespace recreated 2026-09-26
- L135: Self-host operators replace the placeholder database_id with the ID from cf d1 create --name maruhi
- L143: GitHub OAuth credentials are Workers Secrets, not file values, so committing or forking this config needs no edit; without them auth returns 503 (§3-2)
- L152: Cron duties: daily sweeps expired sessions; hourly runs the evacuation sweep and tripwires, branching on the OPS_HOURLY_CRON string
- L164: The hosted env re-declares non-inheritable keys per wrangler's rules (drift checked by check-hosted-config.ts); this mirror declares no store bindings
- L183: Serving domains per the 2026-09-03 owner ruling: product origin my.maruhi.app, apex is LP + docs on a separate Worker, maruhi.dev is a 301
- L237: This database_id is the operator account's real hosted DB (hosted-ops §7 O3, set 2026-09-03); the ID is not secret
- L244: OPS_BACKUP_BUCKET is the DO to R2 evacuation destination; the bucket is operator-created with a lifecycle rule; the worker only uses put / get
- L249: Invocation logs are disabled: the default Fetch log embeds the request URL (capability paths, OAuth codes) for 7 days (PR #137 review)
- L270: The CPU cap is 5 minutes because evacuating a large DO (JSON + gzip) can exceed the default 30s CPU (hosted-ops §4-2)

### `apps/site/scripts/build-theme.ts`

- L1: Theme artifacts are generated from apps/web/theme/maruhi.css and committed; drift is detected by theme.test.ts (regenerated = committed).

### `apps/site/scripts/postbuild.ts`

- L52: Style attributes are externalized only inside element tags; entity decoding folds &amp; last so earlier entity halves are not corrupted.
- L165: The externalized-stylesheet link is injected only into pages using sa- classes, placed just before </head> so it follows the other stylesheets.
- L281: Cloudflare _headers silently truncates lines over 2,000 chars, so the CSP line length is enforced as a build failure as the hash set grows.
- L316: Agent-facing .md/.txt twins get exact-path charset'd content types generated from the shipped file list, avoiding splat-pattern ambiguity.
- L341: Cloudflare _headers caps at 100 rules with silent non-application beyond it, so the twin-block rule count is enforced as a build failure.

### `apps/site/scripts/preview.ts`

- L1: Preview serves dist under production semantics via wrangler dev with a generated config, not cf dev.

### `apps/site/scripts/theme.ts`

- L1: Brand definitions live only in apps/web/theme (ADR-0013, ruling B); site theme artifacts are generated from maruhi.css and committed, drift-checked by test.
- L57: Token block is the :scope rule inside the maruhi @scope of @layer astryx-theme; since @astryxdesign 0.7.15 the generator also writes concrete pairs elsewhere.
- L87: Exactly one --<token>: light-dark(hex, hex) declaration per token is required; multiple differing pairs mean the generation premise changed, so extraction fails.

### `apps/site/scripts/wrangler-config.ts`

- L1: cf dev would delegate to astro dev and serve the source tree, not dist; this renders cloudflare.config.ts serving fields in wrangler-native form for local serving.

### `apps/site/src/astro-components.d.ts`

- L1: astro/client declares no *.astro wildcard module, so the .astro import type shim lives here for TypeScript files importing components.

### `apps/site/src/components/ui/search/providers/pagefind.ts`

- L64: In sliced builds (NIMBUS_BUILD_ONLY) each slice keeps its Pagefind bundle under its prefix and merge names the other slices' bundles, so one search box covers the site.

### `apps/site/src/content.config.ts`

- L2: z is imported from astro/zod, not the deprecated re-export from astro:content.
- L8: The collection is named guide, not docs: Nimbus 0.20 fixes the primary docs collection at the site root, but maruhi serves its docs under /docs via the route-folder mount.

### `apps/site/src/pages/404.astro`

- L6: The 404 page is prerendered so it stays a static route under output: "server"; hosts serve it via their not-found handling.

### `apps/site/src/pages/og/[...slug].ts`

- L6: OG cards are prerendered as static assets so output: 'server' doesn't turn image generation into an on-demand route.

### `apps/site/wrangler.config.ts`

- L3: wrangler.config.ts is the bundler shim for cf deploy/dev; the assets directory lives here because cloudflare.config.ts has no assets.directory field.

### `apps/web/scripts/write-headers.ts`

- L37: theme.css is bundled verbatim under a fixed name because vite folds the theme into the hashed SPA bundle; byte equality is pinned, so it is not duplicate management.
- L136: Copy fidelity (ruling BH): vite's publicDir copies of invite.html/pages.css are pinned byte-equal to the reviewed source; /theme.css is out of scope because this script writes it.
- L154: pages.css var() references must resolve transitively to values in theme/maruhi.css — name existence is not enough, since theme tokens can reference undefined Astryx-core tokens.
- L176: Same-name token redeclaration resolves first-wins: the first declaration is the astryx base/theme brand value and resolving to it is enough.
- L281: The written _headers is re-verified for the /invite CSP block so a future edit dropping the write still fails the build.

### `apps/web/src/Root.tsx`

- L7: The OG image needs an absolute URL, so the serving origin is a build-time env var (MARUHI_WEB_ORIGIN) defaulting to the hosted origin; self-hosters point it at their deploy (ruling D).

### `apps/web/test/e2e.test.ts`

- L378: Fixed-name CSS relies on Workers Static Assets' revalidation default (max-age=0, must-revalidate) as the grounds for not versioning URLs (DP4 ruling G); if the default changes, this check notices.

### `apps/web/vite.config.ts`

- L9: PUBLIC_PASSTHROUGH protects publicDir's untransformed copies from layer-split's HTML handling, kept in step with the byte-equality targets write-headers.ts checks.
- L15: The layer-split adaptation is a local patch on a vendor plugin awaiting the ADR-0013 option-5 upstream fix; if the plugin is missing or its shape changed, the build fails loudly rather than silently undoing part of the workaround.

### `packaging/homebrew/maruhi.example.rb`

- L34: The archive contains a single binary; mh is linked by the installer side (ADR-0015 rulings 6/7)

### `packaging/install.sh`

- L2: install.sh design (ADR-0015): only external access is github.com, no telemetry, SHA-256 verification mandatory before anything is written
- L39: Supported targets are pinned against shared.ts TARGETS minus windows by installer.test.ts, so the table cannot drift as a duplicate
- L45: Invariant: every variable referenced under set -u is initialized in this block
- L66: No intermediate state on a failure path: TMP_DIR is the whole work set; PARTIAL_FILE is the staging file renamed into the destination
- L137: With neither sha256sum nor shasum present it does not install: no install without verification
- L162: musl is refused up front because the shipped binaries link glibc and would otherwise fail at run time with an unrelated-looking 'not found'
- L180: Under Rosetta, uname -m seen from sh is x86_64, so the native darwin-arm64 build is installed instead
- L207: Version characters are restricted because the value ends up on a URL; `+` is excluded on both producer and fetch sides by convention
- L222: With a mirror given and no version, neither tag resolution nor version collation is done (early return)
- L226: Latest-tag resolution reads the releases/latest redirect instead of the GitHub API; the untestable success branch is verified by hand once
- L259: curl flags chosen for the download: -f maps HTTP errors to non-zero, -L follows Release asset redirects, --retry covers transient failures
- L276: Only this target's checksums line is extracted and verified; a count other than 1 or a wrong format is refused, tampering or accident alike
- L303: The downloaded binary is run before the install destination is touched, so a wrong target or libc mismatch is a failure that left nothing
- L318: A non-regular-file destination is refused early because mv would slip inside it, producing a 'thought it installed' state
- L325: The binary is staged in the same directory and renamed: no half-written executable shows, and a running binary is not overwritten (ETXTBSY)
- L352: The mh symlink is relative so it survives the whole install directory moving

### `scripts/dev-setup-cursor.sh`

- L2: dev-setup-cursor.sh is the whole Cursor Cloud install: it ships in reviewed PRs, every step is idempotent, and it is not for a local machine
- L45: The ~/.bashrc line must name the literal $HOME path, so setup verifies the installer's reported path matches the line it writes

### `scripts/install-bun.sh`

- L2: install-bun.sh is the single Bun installer for CI, Claude Code web and Cursor Cloud; zip is SHA-256-verified; curl|bash/setup-bun rejected
- L48: die() annotates with ::error:: under GitHub Actions because the message is a workflow command
- L99: The new bun is copied next to the target and renamed, so replacing an older bun is atomic

### `scripts/install-headless-shell.sh`

- L2: install-headless-shell.sh is the single browser installer for CI and Cursor Cloud; stdout carries only the executable path
- L46: die() annotates with ::error:: under GitHub Actions because the message is a workflow command
- L67: One install at a time: the swap is two renames another run must not interleave with; the lock is held until the script exits
- L71: The work dir sits next to the install on the same filesystem, so the verified tree is moved in by rename, never copied
- L80: stdout carries only the executable's path, so the SHA-256 check reports on stderr
- L90: An older install is replaced only with a complete new one; -T never moves the tree into an existing directory

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
