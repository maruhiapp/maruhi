# ADR-0025: Authentication and authorization decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 777 comments on server authentication and authorization were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/checkpoint.package/checkpoint.ts`

- L184: Effective-admin authority is min(token scope, chain role) (§9-2): role from the verified view, scope from /auth/me tokenScopes (absent = session principal = full power), so no 403 is hit (§16-2).

### `apps/cli/src/config.ts`

- L21: identityBacking is the cross-check source for the invite mutual check (CRYPTO_SPEC 6.5 IV2); org-directory is reserved, not implemented
- L56: Unset identityBacking defaults to github-signing-keys (supplement 21 ruling B)
- L152: An unknown identityBacking value falls back to the default with the check intact: never fall toward a typo removing the check; none works only when spelled out

### `apps/cli/src/context.ts`

- L172: Before a mirror fallback read, the mirror must declare itself a mirror of this server: a promoted project is a primary now, and another deployment's mirror is not this project's replica
- L590: IV revision: when the invite link pins the inviter's sig key, the key itself is checked in addition to the fingerprint, fixing the issuance verification key to the chain key
- L784: A mirror refuses attestations (AUTH_SPEC §11-7): the fallback read reconciles the gossip it serves but submits nothing there

### `apps/cli/src/errors.ts`

- L23: The unreachable flag gates the mirror fallback (PF2, AUTH_SPEC §11-7): it fires on no-answer/gateway failures and nothing else — a primary's answer is never retried against a replica

### `apps/cli/src/failure.ts`

- L163: LeaseUnavailable guidance is per-reason (§14-3): all reasons mean 'not a credential problem', but the next step differs (re-run / administrator / deploy config)
- L206: isUnreachable defines the mirror-fallback trigger: no response or a gateway's own status counts; any typed answer or interpretable status does not (PF2, AUTH_SPEC §11-7)
- L226: A 500 is the server failing to answer the read (crashed handler), not an answer about the read — a read-only mirror fallback is as right for it as for a gateway 502 (PF2 ruling E revision)
- L278: Expiry folds into the same 401 as revocation on the wire (AUTH_SPEC §6, W3a), so the guidance names both possibilities

### `apps/cli/src/invite.package/command.ts`

- L33: An owner is never granted via an invite (AUTH_SPEC §15-1), so INVITE_ROLES stops at admin.
- L106: Invite scope from flags: --env repetition = listed (ascending, duplicates refused), --no-envs = listed{}, omitted = all (ruling K — there is no --all-envs).
- L234: Each of --env/--no-envs sets the whole scope: an invite has no --all-envs, and omitting both is all.

### `apps/cli/src/login.ts`

- L1: maruhi login / logout (AUTH_SPEC §4 / §6). login is a server-mediated web-flow handoff (§4): start → display verificationUrl and userCode
- L45: Operational caps for server-declared values: never sleep a long time on a hostile / misconfigured server's huge value without reaching the
- L53: Clamps the polling interval into [min, max] (the minimum is the wire-shared MIN_CLI_POLL_INTERVAL_SECONDS — §4-1 (5)). 0 / negative /
- L66: Whether the URL may be handed to the browser auto-launch (fail-closed). verificationUrl is untrusted input from the server's response and
- L83: The browser auto-launch UX branch (§4-1 (2) — a branch reusing ADR-0016 decision 7's existing services, not a new security gate). Attempted
- L103: The guidance goes to stderr (ruling D-2: interactive guidance takes the same path as prompts. stdout carries only the login's result). Not
- L121: Displaying the flow's validity window (ruling D-1). The value is derived from the server response's expiresInSeconds (after clampExpires =
- L139: login's pre-flight fail-fast (AUTH_SPEC §3 / hosted-design.md §2-2 (i)(ii)). Before calling `POST /auth/cli/start`, check `GET
- L169: The guidance goes to stderr (ruling D-2)
- L175: On a non-interactive environment proceed without the confirmation (the guard's purpose is blocking a well-meaning waste and the guidance UX
- L184: Whether interactive terminal × non-agent (reusing ADR-0016 decision 7's existing services).
- L195: The self-report confirmation of holding an existing account (no is the default — stops a would-be new user before start).
- L212: One poll's outcome (a rate limit is not a failure — it adjusts the next interval).
- L240: An expiry (typed — §4-2) stops polling and steers to re-login
- L242: Uniform rejection (§4-2): a credential mismatch, re-polling a consumed flow, etc. The reason cannot be told apart (the server builds no
- L250: A 429 is not a failure (§4-1 (5) — the server may refuse excessive polling). Back off by the indicated wait and continue
- L259: `maruhi login`: start → browser approval → poll → keychain (AUTH_SPEC §4).
- L263: Display the issued PAT's raw value on the terminal exactly once (AUTH_SPEC §6's "one terminal display at issuance" — ruling CK. For feeding
- L271: Whether tokenName is this machine's default name (`cli:<hostname>`) (ruling CM — the default name's source of truth is the caller's
- L280: The explicit TTL (days. AUTH_SPEC §6 — W3a. Omitted = the server default of 90 days).
- L287: The pre-flight fail-fast (AUTH_SPEC §3 — the signupPolicy advisory check. Before start)
- L290: Starting (§4-1 (1) — the server records nothing. The flow's credentials are only the two identifiers obtained here)
- L300: The validity window is derived from the server's response (ruling D-1 — the same clamped value the deadline judgment uses)
- L303: Interactive guidance goes to stderr (ruling D-2: the same path as prompts. Visible even under `maruhi login > file`). Only the login's
- L324: Acquisition (§4-1 (5)). The deadline is checked **before** each wait (when the next polling time passes it the flow expires during the wait
- L334: The step's first input — a synthetic pre-poll state for the leading wait (a real poll's outcome feeds the next step from then on)
- L376: The local judgment material for the approaching-expiry advance warning (ruling CL)
- L379: Never use JSON.stringify(record) — Redacted.toJSON() returns a redaction and "<redacted>" would be written to the keychain (keychain.ts's
- L383: If it cannot be saved, do not orphan the issued token: attempt the server-side revocation before failing (the original error = the
- L409: The raw value's only display point (AUTH_SPEC §6 "one terminal display at issuance" — ruling CK). It is unwrapped only for this display
- L426: Surfacing the provisioned login's identity swap (ruling CM): since the keychain's slot is per origin, this issuance also replaced this
- L440: The expiry is fixed at issuance (AUTH_SPEC §6's default TTL — W3a). Since it becomes a 401 on expiry, make when re-login is needed visible
- L451: The guidance for the next step after login (device addition / storage reminder — the entry to CRYPTO_SPEC §8's flow). Auxiliary, so a
- L489: The guidance for MARUHI_TOKEN being left set after logout (null when none remains). Every state besides `active` **fails without reaching
- L506: The reason reuses the resolution side's wording as-is (rephrasing would disagree with the next failure)
- L515: `maruhi logout`: revoke the presented token, then remove it from the keychain.
- L532: A corrupt record cannot call the revocation, but leaving it is unusable either — delete it
- L544: The keychain removal happens **before** the revocation: if removal failed after revoking, the keychain would keep a token the server
- L551: An already-revoked (401) counts as success. Anything else (the network etc.) fails and tells the user a live token may remain server-side
- L560: resolveSession prefers MARUHI_TOKEN over the keychain (session.ts). A leftover env var means "logged out yet the CLI keeps working", so

### `apps/cli/src/mirror.package/mirror-deployment.ts`

- L1: Deployment identity: two origins are one deployment when the origin matches or both publish the same server key fingerprint on /auth/config; mark and promote refuse or name a way out with it.
- L11: The fingerprint is self-reported, so equality only ever refuses (a mirror of itself) or names a way out — it never lifts a guard; without a fingerprint on either side the strings decide.

### `apps/cli/src/oidc-github.ts`

- L1: Fetching the GitHub Actions OIDC token and reading its claims (the client side of AUTH_SPEC §14-1 — v1's only supported issuer is GitHub
- L44: The runner-supplied issuance endpoint (missing or empty both count as "absent").
- L49: The runner token is also a bearer credential, but it exists only in this module's locals and is consumed by the header right after (it does
- L65: Validates the issuance endpoint URL and attaches the audience parameter. Non-`https:`, embedded credentials, and unparseable are null (the
- L77: `http:` is allowed only for loopback (for tests and local mocks — plaintext never crosses the network). Everything else requires `https:`.
- L91: The issuance endpoint's JSON body — only `{ value ` is read (any other shape is "uninterpretable", and nothing else leaves it).
- L95: The HttpClient layer the issuance fetch runs on — the repo's shared egress client (no trace headers) with `redirect: "manual"` fixed for
- L104: The message an `HttpClientError` carries: the transport's own cause (the fetch rejection — a refused connection, a DNS failure) when it has
- L116: The bound on the runner's issuance endpoint (the same as the API client's header bound).
- L119: The bound on the issuance fetch when a token is in hand: its remaining life minus a margin, never above the default — a hung endpoint must
- L140: Left of the token's life for the request that presents it, after a fetch that times out.
- L142: The shortest bound worth giving the fetch; a token in hand with less life than this is no fallback.
- L145: Fetches a fresh GitHub Actions OIDC token for `audience`. Each caller fetches it **immediately before** the request that presents it: the
- L165: Validate the URL before sending the runner token (a bearer credential): refuse non-`https:` (plaintext http, custom schemes) and embedded
- L198: A hung issuance endpoint must not hold the job: the lease's token fallback and the recovery message are reached while that token lives
- L204: Inside this region every failure is foreign — transport, a hung endpoint, an undecodable body — so each is normalized to its own verdict
- L217: `local: true` rebuilds the layer per use: a layer is shared between `Effect.provide` calls by default, so the `FetchHttpClient.layer`
- L243: The bare string that arrived from outside the environment is wrapped here. From here on the token only flows as Redacted (unwrapping is the
- L250: base64url → bytes (null when malformed. Never put a token fragment onto an exception message).
- L286: The token's `exp` as a millisecond instant (null when absent or malformed) — the fallback check of a mint (K-6).
- L288: Why it is unwrapped: reading one numeric claim of my own token; nothing else leaves
- L297: payload → the 3 claims the lease binds (a reason code when malformed).
- L321: Reads the claims the lease path binds (CRYPTO_SPEC §9.1: issuer / sub / aud) from the workload's own token. The digest itself is computed
- L335: Why it is unwrapped: reading the claims of my own token (decoding the payload segment). The product is only the 3 strings iss / sub / aud
- L345: Extracts a single `aud` claim value (only a single string | a 1-element array is accepted).

### `apps/cli/src/project.package/command.ts`

- L112: project policy schema is keyless and chain-free: the policy is a server acceptance setting, not a chain entry (§12-11).

### `apps/cli/src/project.package/project-init.ts`

- L51: A missing personal org is normally impossible (auto-created at sign-up, §9-1); if it happens it is reported accurately as a server-side state anomaly.

### `apps/cli/src/project.package/project-schema-policy.ts`

- L1: The schema policy is a server acceptance setting, not a chain entry (§12-11), so neither path syncs or verifies the chain or needs the master key; the value carries no secret, so the command is not gated in agent environments.
- L56: The policy PUT is sent even when the read already shows the requested tier (the server treats a same-value PUT as a no-op without an audit row), so the final state is the requested one even if the read raced another change; the read only shapes the message.

### `apps/cli/src/server.package/command.ts`

- L57: --environments is mandatory on grant — the minimal-disclosure default is that environments are explicitly listed (session-22 §2's ruling); an empty element is refused as a misspelling.
- L97: The /auth/config endpoint supplying the key is unauthenticated, so a tokenless client reads it; naming the server itself is the default spelled out.

### `apps/cli/src/server.package/server-grant.ts`

- L356: --key-from grants a mirror's key on the server — the only place that accepts appends; the grant and the wraps reach the mirror by replication (AUTH_SPEC §11-7 ruling F).

### `apps/cli/src/session.ts`

- L1: Resolution of the authenticated session (maruhi token) and the master key. Token resolution order: the MARUHI_TOKEN env var (a read-only
- L64: Normalized server origin (keychain scoping key and API base URL).
- L70: The master keypair loaded from the keychain, imported and ready to use. `encKeyPair` / `sigKeyPair` are not wrapped in `Redacted`: both are
- L82: Computed from this device's public keys (the actor FP of every entry it signs).
- L86: Whether the hostname is loopback: localhost / ::1 (including the URL's bracketed form) / an IPv4 literal in 127.0.0.0/8 (DNS names and
- L103: Validates and normalizes a base URL: https anywhere, http only on loopback (tokens travel in cleartext otherwise; wrangler dev and mock
- L111: The value's origin. For anything but the command line (config, env var) it is not "a typo", so instead of a usage error (2) it says where
- L125: The URL itself is not returned (a URL with embedded credentials is one possible written shape)
- L128: No branch returns the URL (it could carry credentials in the shape `http://user:token@host/x?token=…`). It is a usage error, so the exit
- L142: Resolves the server base URL: --server flag → config. Fails with guidance.
- L164: Guidance for not-logged-in. Inside an agent session, "run it inside agent" is off the mark (you are already inside one), so it only says
- L177: The window for the early expiry warning (ruling CL — warn from 14 days remaining; drafted value). Makes expiry (401) observable ahead of
- L185: Emits one line to stderr when the expiry enters the warning window (ruling CL). - stderr is used to keep stdout machine-readable (not
- L215: Session resolution via the MARUHI_TOKEN path (for keychain-less environments and CI). The env var is the only entry point where a plaintext
- L224: The value with surrounding whitespace dropped (already trimmed by the caller — the same value is used for checks and for sending).
- L231: If the placeholder itself was supplied, name the reason before any traffic. Now that `Redacted` exists, pasting the
- L241: MARUHI_TOKEN is bound to the connection target origin: without this requirement, a Bearer token would be sent to any origin resolved by
- L253: An env var is not the command line either (say where to fix)
- L265: Since W3a (the default TTL in AUTH_SPEC §6), the most likely cause of this 401 in routinely unattended environments is **expiry** (every
- L274: A server that did not answer is not an authentication failure: the flag lets a configured mirror take the read over (context.ts)
- L284: The early expiry warning (ruling CL): /auth/me is called on this path every run anyway, so tokenExpiresAtMs (ruling CI's self-disclosure)
- L295: Whether MARUHI_TOKEN works for this origin. The check exists so logout guidance (the next step of resolveSession) does not diverge from
- L311: The shape is unusable. **The reason carries the normalization side's wording verbatim** — if we phrased "not parseable as a URL" vs "http
- L326: The state where the placeholder itself was pasted (sessionFromEnvToken rejects it by name)
- L334: A shape that is unusable vs. a shape that is correct but points at another origin have different fixes. The former's reason **carries the
- L350: Which deployment a session is for (PF2 — AUTH_SPEC §11-7): the server a command addresses, or the configured mirror a read falls back to.
- L361: Resolves the authenticated session for `origin`. The MARUHI_TOKEN env path resolves the user id via `GET /auth/me` (the keychain record
- L380: MARUHI_TOKEN is the server's credential (bound to MARUHI_TOKEN_ORIGIN); it is never sent to the mirror. The keychain token of the mirror
- L384: Surrounding whitespace is dropped exactly once here. Newlines and spaces mixed in by pasting are perfectly normal, and using different
- L403: The keychain half of resolveSession (`what` names a mirror in the not-logged-in guidance).
- L421: A stored placeholder is distinguished from "a corrupt record": neither the cause (a maruhi bug) nor the recovery steps (a record written by
- L433: The early expiry warning (ruling CL): the expiry was saved to the record at login (expiresAtMs in keychain.ts), so a local check without
- L444: The environment check before declaring "the record is corrupt". importMasterKeys failure happens **both when the key material is broken and
- L466: The probe's verdict is a boolean by definition: any failure — a typed crypto error or a defect (a contract-violating rejection) — means the
- L474: Round-trips generate → export → import with a disposable key (key material never leaves).
- L496: The common part when the environment is the cause (the cause, and the next step identical across paths). **"What is intact" differs per
- L511: The environment-caused wording for an unloadable keychain key (**never have the user delete** is the point).
- L515: The wording when judged corrupt. Decided **only after confirming the environment is not the cause**. Another format (an unknown suite) is
- L529: Choosing the refusal wording for an existing record. "It already exists" may be said only **when a genuinely usable key is there**.
- L553: Importable = a genuinely usable key. This alone is the true overwrite refusal
- L555: The exit differs by why it cannot be read (corrupt / foreign format / environment). Split by tag — if a new failure kind appears, the type
- L565: Wording for an unreadable record. **Deletion is recommended only when it is judged corrupt** (never have a record written by a future
- L576: Fails when a master key is already stored for (origin, userId); returns the keychain entry name otherwise. The shared overwrite-protection
- L596: "It already exists" may be said only **when a readable record actually exists**. Returning the refusal wording (a usable key exists) for an
- L607: Stores a master-key record, re-checking absence immediately before the write and verifying afterwards that the stored record is the one
- L648: Replaces the existing key **only when it matches the value we saw** (`device add --replace` — DK K13-8). Same detection as
- L672: The wording when another write is found mid-way through `device add`'s store / replace (shared by storing with no key and `--replace`). The
- L682: The wording when a concurrent write is detected. The point is there is nothing to copy down: this key was never stored anywhere and no
- L691: The wording when a reserve key bearing the mark sits in the keychain (DK K16).
- L696: storeMasterKeyGuarded + the 2 success lines (naming the store and the FP). The common ending of `key generate` / `key recover` — never
- L708: Whether this store came from `device add` (uses `device add`'s concurrent-write wording — the request is already created: DK K13-14).
- L717: A reserve key is never put in the keychain (CRYPTO_SPEC §8 — DK K16; layered defense of how the type is closed, K4-1 a-5)
- L766: The reserve key lives only in the recovery ledger (CRYPTO_SPEC §8 — DK K16). A marked key sitting in the keychain is a breach of the store
- L771: A record that parsed but cannot be imported as key material is the same dead end (the overwrite-protection guard refuses every command), so
- L793: Cannot import the key material itself (importMasterKeys failure). Distinguished **by type** so the caller can swap the wording by "which
- L805: It carries no breakdown (hex that cannot be interpreted / WebCrypto that cannot read): the caller guides to the same exit either way, so an
- L810: The record claims a suite this version does not know (not corruption).
- L815: importMasterKeys failure. The caller decides the wording per path. The class itself is not exported: callers split on the `Effect.catchTag`
- L824: Imports a stored master-key record into usable (non-extractable) key objects. keygen also uses it as the pre-store self-check (never writes
- L833: A future suite's key record is never silently interpreted as v1
- L837: Why unwrap: importing the key material (hex → bytes → non-extractable CryptoKey). The resulting encKeyPair / sigKeyPair are extractable
- L847: A CryptoResult error (an import exception for broken key material, folded into a value by the crypto side) is treated as corrupt

### `apps/cli/src/token.ts`

- L1: The `maruhi token` group (AUTH_SPEC §6 — design record dk-design.md §9 K4-13). No values, no keys, no agent gate: a catalog of tokens (id

### `apps/server/scripts/issue-signup-invite.ts`

- L1: No issuance API/UI by design: the script only generates the code and its hash, the operator registers the hash in D1; raw code shown once, single-use, expiring

### `apps/server/src/auth-domain.ts`

- L1: Server-internal domain types for authentication (AUTH_SPEC §2-§6).
- L17: Provider-verified identity (the output of the AUTH_SPEC §3 / §4 authentication dance).
- L29: Result of getOrCreateUser (AUTH_SPEC §1-5:
- L35: Reason for signup denial (AUTH_SPEC §3 signup control) — core's SIGNUP_DENIAL_REASONS, the `auth.signup_denied` audit payload's reason…
- L42: Result of get-or-create through the signupPolicy gate (AUTH_SPEC §3).
- L59: Domain representation of a session row (no raw value exists; id is a hash).
- L66: Domain representation of an API token row (no raw value exists).
- L76: One row of the token list (AUTH_SPEC §6 — W3a).
- L92: Domain representation of a recovery blob row (AUTH_SPEC §13 — the wrapped master secret key of CRYPTO_SPEC §8).
- L104: Result of the rate-limit check for blob fetch (AUTH_SPEC §13-3 fixed window).

### `apps/server/src/auth-shared.ts`

- L1: Shared helpers between the auth handlers (handlers-auth.ts / handlers-auth-cli.ts).
- L24: State + flow-binding cookie dedicated to the CLI browser leg (§4-1 (3)).
- L36: Carrier cookie for the signup invite code (AUTH_SPEC §3).
- L58: effect's HttpServerRequest.url carries only the path.
- L83: Terminal of the §3-1 first leg, shared by the web and CLI legs; only the state cookie's name and value differ between the paths
- L104: Missing GitHub OAuth config redirects to the setup guide with 503 instead of an opaque GitHub or token-exchange failure (§3)
- L134: auth.login_failed records the reason kind only (§3.1 prohibition), capped per authMethod + reason bucket against flood amplification
- L160: auth.signup_denied records no external IDs, capped per reason; the operations tripwire counts these rows (§3.1)

### `apps/server/src/auth.package/cli-flow.ts`

- L1: Flow credentials for CLI login (AUTH_SPEC §4-1 (1) / §4-2).
- L29: Flow lifetime (AUTH_SPEC §4-1 (1) drafted value:
- L32: Purpose tags for domain separation (§4-2 — one must not pass verification as the other)
- L40: Imports D1-stored key material (hex) as a WebCrypto HMAC key.
- L68: userCode (§4-1 (2) — a short display code for human comparison.
- L72: 32 characters chosen for low visual ambiguity (the Crockford Base32 alphabet).
- L76: Comparison code (`XXXX-XXXX`). A friction device shown on both the CLI and the approval page.
- L94: flowToken (§4-1 (1) — CLI-only bearer. Never on the browser channel)
- L98: Issues a self-contained flowToken (a MAC covering 256-bit randomness + flowId + expiry).
- L105: macHex is WebCrypto HMAC (a protocol operation, not a randomness draw); a rejection stays a defect, as when this was a plain Promise…
- L114: Flow token verified MAC first, then pairwise flowId match, then expiry; invalid is uniform rejection, expired a typed termination (§4-2)
- L150: vsig'd scopes are signed and verified as the exact JSON string placed on the URL, with no reinterpretation of the canonical form
- L203: Verify-arrival failures (missing, tampered, expired) all yield null: a uniform error page, fail-closed before any GitHub redirect (§4-2)

### `apps/server/src/auth.package/cli-pages.ts`

- L1: Server-rendered pages for CLI login (AUTH_SPEC §4-1 (4)).
- L26: Escapes HTML text / attribute values (the implementation point of inert rendering).
- L36: The self-hosted assets the pages reference (build output of apps/web/public / theme).
- L44: The CSP shared by all pages (duplicated across the meta tag and the delivery header — same rationale as invite.html; the header-side…
- L55: The CSP for the delivery header. `frame-ancestors 'none'` is the approval page's clickjacking defense (default-src does **not** fall…
- L66: Page frame matches invite.html; the astryx mark is required because /theme.css tokens are scoped to it; color-scheme is for pre-CSS dark
- L106: Every CLI flow failure renders the same error wording, so the page is no oracle into flow state (§4-2)
- L121: Signup guidance page (ruling DH: CLI login creates no account); wording follows signupPolicy so invite users are not led to a denial
- L179: The approval ticket is single-use and short-lived; its raw value is embedded only in this page
- L189: The confirmation code is the page's largest element: comparison is the last defense against phishing (§4-3)
- L236: The approval-complete page never shows the token: the poll side receives the PAT

### `apps/server/src/auth.package/github.ts`

- L1: The authentication dance with GitHub (AUTH_SPEC §3 / §4; ADR-0009:
- L30: GitHub call timeout matches the OIDC issuer fetch bound: an auth-path request must not hang on a peer that never answers
- L37: GitHubAuthError carries the reason code only; token values and external IDs are not carried
- L42: GitHubApiShape is exposed for decoration: the counting in ops-signals.ts
- L49: fetchIdentity is web-flow only, where the token's provenance is the immediately preceding exchangeCode (§3-2)
- L59: A 200 from the token endpoint may carry an OAuth error body: an absent access_token is a failed exchange, not a malformed answer (§3-2)
- L68: In GitHub's /user answer the integer id is the identifier; the login is a display snapshot only
- L84: A User-Agent is always attached because both github.com and api.github.com may require one
- L91: fetchJson contract: null means a non-2xx answer (each caller decides its meaning); transport, timeout and shape errors stay in the channel
- L109: The client secret's only unwrap is the token-endpoint body field; an unconfigured secret omits it (start fails closed with 503 first)
- L176: attempt folds failures and null answers into the typed error and provides the HTTP client locally; index.ts is not involved here
- L197: The client secret stays Redacted until the token-exchange body

### `apps/server/src/auth.package/index.ts`

- L1: The public surface of auth.package (the ImportLint boundary).

### `apps/server/src/auth.package/middleware.ts`

- L1: The actual implementation of AuthMiddleware (@maruhi/api-schema) (AUTH_SPEC §5 / §11-1 / §11-4).
- L31: The CSRF countermeasure header. Stateful GETs (bulk pull with values, recovery-blob fetch) also require it on the handler side…
- L38: RFC 7235: auth-scheme is case-insensitive.
- L47: Credential precedence (fixed): when an Authorization header exists, only it is consulted (no fallback to the cookie even when it is…
- L82: CSRF check for session principals on stateful GETs (AUTH_SPEC §11-4's explicit list).
- L99: Refreshes the cookie's Max-Age on every session-authenticated response (reflects §5's sliding expiry on the browser side too — extending…
- L127: The implementation body of AuthMiddleware.
- L142: Session capability restriction (AUTH_SPEC §5 — outside the allow enumeration is fail-closed 403).

### `apps/server/src/auth.package/session.ts`

- L1: The actual implementation of SessionService (AUTH_SPEC §5).
- L20: Write-thinning for the sliding renewal: when less than 1 hour has passed since the last extension, the D1 UPDATE is skipped (avoids a…
- L27: A failed digest is an environment defect (as a rejected `crypto.subtle.digest` promise was before the services migration), so it is…
- L41: Expired rows are swept here (keeps server-side revocability)
- L70: Explicit revocation goes through revokeByHash, which carries the audit event (distinct from the expiry sweep's deleteByHash — AUDIT_SPEC…

### `apps/server/src/auth.package/signup-pages.ts`

- L1: Guidance pages for signup control (AUTH_SPEC §3).
- L27: Denial page for signupPolicy = closed (§3 — ends after the OAuth round trip, creating no rows).
- L67: The invalid-invite page does not differentiate unknown, expired or consumed codes (§3)

### `apps/server/src/auth.package/token.ts`

- L1: The actual implementation of TokenService (AUTH_SPEC §6).
- L28: Display prefix (e.g. `maruhi_pat_Ab12…`).
- L33: A failed digest is an environment defect (as a rejected `crypto.subtle.digest` promise was before the services migration), so it is…
- L40: Maps a hash-matched record onto a principal (expired / mismatched become anonymous).
- L45: Expiry check (AUTH_SPEC §6 — W3a ruling CE)
- L50: A principal that passed the check always carries a non-null expiry (W3a ruling CI — /auth/me self-disclosure)
- L60: Write-thinning for last_used_at (avoids a D1 UPDATE per request; granularity 1 hour).
- L85: expires_at is fixed at issuance (AUTH_SPEC §6 — deliberately asymmetric to the session §5 sliding renewal:
- L89: Same (user, name) = reissuance = rotation (the old row's revocation and the new row's insertion happen in one atomic batch).
- L125: In self-revocation (CLI logout) the actor's token = the revocation target itself

### `apps/server/src/authz.ts`

- L1: Request authorization helpers for the chain API (AUTH_SPEC §9-2 / §11).
- L17: The token permission level an appended entry requires (AUTH_SPEC §6 / §16-2).
- L47: §11-1: exact match between the authenticated principal's internal user_id and entry.actor.user_id (acceptance policy).
- L57: Operations on an existing project: out of scope = 404 (§11-2), insufficient level = 403.
- L82: Non-asserting scope-level check (a shape that **only checks** the scope half of effective permission = min(scope, chain role) — material…
- L104: The scope-intersection filter handed to candidate enumeration for the project list (AUTH_SPEC §11-5).
- L133: Token requirement for operations of the key-material class (AUTH_SPEC §13-2 / §15-2):
- L160: The `*` × admin scope requirement on the token-principal side of the access classes above and below:
- L175: Principal requirement for the self-axis audit read (AUDIT_SPEC §6 — `GET /auth/audit/events`):
- L194: Principal requirement for the token-management surface (AUTH_SPEC §6 — W3a:
- L214: Project creation (init): the project does not exist yet, so it is outside existence hiding.

### `apps/server/src/db.package/audit.ts`

- L1: Audit layer is append-only (§1-4): appends ride each repository's own batch so audit and primary write share a transaction
- L40: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L46: userId omission means an unauthenticated external principal (login_failed only); type=system is not for failed attempts
- L56: Audit event input is the spec-listed payload per event (discriminated union) plus actor and common columns (§3.1-§3.2)
- L69: Payload is schema-checked before insert (an unlisted key is a defect); auth_method rides the payload as on the DO side
- L78: rowId is the wire row identifier (§5.1 row_id — §7's opaque cursor)
- L92: userAuditInsert is bundled into a repository's batch so the audit row shares the primary write's transaction (§3.1)
- L97: Guarded-insert select columns are shared so callers cannot silently diverge when the audit row shape changes (§5.2)
- L118: replacedTokenId is the id of the row the same batch deletes, read in SQL (§3.1)
- L136: A guarded insert produces at most one row, so a row_id constant picked at statement-build time suffices (§5.1)
- L150: orgAuditInsert is bundled into a repository's batch, like the user-family insert (§3.2)
- L155: login_failed recording is capped per auth_method+reason bucket: a single or method-only window would be floodable (§3.1)
- L180: Bucket key carries no external ID or IP — only the classification the audit row itself carries (§1-2)
- L185: Suppression markers are left at powers of ten so suppression volume is observable while writes stay logarithmic (§3.1)
- L196: signup_denied suppression uses the same fixed-window / power-of-ten discipline; bucket is event name + reason (§3.1)
- L208: Milestone judged by integer division to avoid log10 rounding error at decimal carry boundaries
- L221: Cursor resolution happens under each read's visibility predicate; an out-of-predicate id is an empty page, never an oracle (§7)
- L232: D1StoredAuditEventRow is the §7 read shape of a D1 audit row; stored NULL surfaces as null
- L235: rowId is the wire row identifier: a 16-byte random hex (§5.1)
- L248: INVITE_AUDIT_EVENTS is invite lifecycle only (§3.2); org-family events are not mixed in
- L254: login_failed append is fixed-window capped with suppression markers; do not pass a source identifier (§1-2 line)
- L267: signup_denied bucket is per reason so a flood for one reason cannot erase a targeted denial for another (§3.1)
- L279: Project invite read is the §7 exception clause; the permission axis is enforced by the worker handler, not this layer
- L289: login_failed has no actor user_id, so it appears on no self axis; it is the operator view's remit (§6, L-4)
- L303: A corrupted payload column parses to null so a bad row does not turn the read into a defect
- L353: org_id stays in the projection though currently always NULL: dropping it would silently lose it when the org axis arrives
- L368: Cursor row_id resolves to seq under the same visibility predicate — never an existence oracle (§7)
- L385: Window counting uses a dedicated counter row, not a log scan: scanning would make the flood itself a cost amplifier (§3.1)
- L433: Within a window recorded grows to the cap before suppressed grows, so cap-reached + suppressed>=1 identifies a suppressed request
- L441: Suppression is never silent: a marker row at each power of ten reveals scale while writes stay logarithmically bounded
- L447: A marker's payload is only classification, window, cap and count — it describes the window's state, not one request (§3.1)
- L487: Bucket namespaces are separated by event name so signup_denied keys cannot collide with login_failed's [method, reason] key
- L502: Project audit read narrows to invite.* only: org-family events with the same project_id are the org admin axis's remit (§7)

### `apps/server/src/db.package/cli-flows.ts`

- L1: Module scope: repository of the CLI login flow rows (§4-1 (4)-(5))
- L15: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L25: Concurrent-flow cap is the §4-1 (4) drafted value; it cannot be held cheaply and recovers with the 15-minute TTL
- L34: Rows are kept past expiry by a grace headroom: deleting earlier would let a poll misread no-row as pending forever (§4-1 (5))
- L56: Only the ticket's SHA-256 is stored; the raw 256-bit value lives only on the approval page
- L61: The poll's record excludes ticket_hash; the ticket comparison happens inside the CAS
- L73: rejected is a uniform error (another user, expired, terminal) with the reason not differentiated; capacity alerts operations
- L83: Create-or-match bundles an opportunistic delete and a conditional INSERT so concurrent creation cannot exceed the cap
- L95: Decide CAS: unknown, expired and used tickets uniformly return false; approval records login_succeeded in the same batch (§4-2)
- L108: Poll lookup contract: no row = null and the caller derives pending (§4-1 (5))
- L110: Single-issuance gate: only the CAS winner issues a PAT; a post-CAS issuance failure stays consumed (fail-closed)
- L125: Cap judgment and insert are one INSERT...SELECT so concurrent creations never both observe under-limit (§4-1 (4) (iii))
- L138: Opportunistic delete targets only rows past expiry + headroom; consumed/denied rows are kept within the headroom (§4-1 (5))
- L169: Only a same-user awaiting in-validity re-arrival replaces the ticket; a different user_id never matches, so no rotation (§4-1)
- L195: No row after a failed conditional INSERT means the cap dropped it (capacity); a row means uniformly rejected
- L215: A denial carries no audit event (§4-2): only an approval is login_succeeded, and an explicit denial is not a failure-family event
- L220: Approval = auth.login_succeeded (cli_handoff, §4-2); actor user_id is copied from the row under the changes() guard
- L263: A stored scopes column only our own write path can produce being broken = implementation bug / DB corruption

### `apps/server/src/db.package/devices.ts`

- L1: Device registry is an advisory ledger, never an input to verification or authorization; the chain is the source of truth (§13-11)
- L28: D1 access via the shared tryD1 adapter (ADR-0006); only domain-level branches are returned as values
- L45: DeviceAddRequestRecord returns only unexpired requests
- L56: Registry upsert enters a new row only under the cap via conditional INSERT; updating an existing row does not count toward it
- L73: remove's boolean tells the caller whether a row disappeared; false maps to the caller's uniform 404
- L75: Same-FP unexpired request = request-exists, existing registry row = device-registered (§13-11's 409s); expired is replaced
- L89: requestList returns unexpired requests only
- L99: requestCancel's boolean reports an actual disappearance; expired rows can be removed too, doubling as cleanup
- L104: requestSweep is called before create/list and deletes only that user's expired requests
- L144: Single capped INSERT...SELECT...ON CONFLICT: public keys are immutable when the FP matches; updates pass on the WHERE's OR side
- L200: An unexpired same-FP request conflicts; an expired one is replaced via ON CONFLICT ... WHERE expires_at <= now

### `apps/server/src/db.package/errors.ts`

- L1: errors.ts is a leaf with no inbound edges inside db.package so repo files and repos.ts assembly never form an import cycle
- L8: Only UNIQUE violations are domain-recoverable; constraint carries the violated target so callers need not re-match raw text
- L30: tryD1 (ADR-0006): UNIQUE becomes D1UniqueConflictError, everything else D1FailureError turned into a defect via orDie
- L53: Misclassifying a transient or FK failure as conflict would misdirect incident investigation, so classification is conservative
- L72: Conflict target capture stops at the first colon: the target list never contains one, but workerd appends a SQLite code tail

### `apps/server/src/db.package/flow-signing-keys.ts`

- L1: Module scope: repository of the CLI login flow signing key — at most one row (§4-2)
- L13: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L24: The signing-key row has a fixed id: at most one row exists (§4-2)
- L28: First-use auto-generation is INSERT OR IGNORE + read-back, first-one-wins, so concurrent first uses cannot split the key (§4-2)
- L58: An empty SELECT right after INSERT OR IGNORE means a D1 failure = defect

### `apps/server/src/db.package/identities.ts`

- L1: Module scope: identity ledger — users, linked provider identities, automatic personal org, signupPolicy gate (§1-§3, §9-1)
- L29: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L41: getOrCreateUser is the single idempotent entry; the signupPolicy gate sits before the create branch and never affects existing users
- L57: lookupUser never creates (ruling DH): a missing account on the CLI browser leg ends in signup guidance, no side effects
- L65: providerLoginOf is the GitHub display login snapshot feeding §15-3's il; null when unlinked or unstored
- L70: identitiesOf returns linked GitHub identities for export; users without a link are absent, never invented (§11-6 PF3)
- L78: signupPolicy: no row = open (spec default); an unknown stored value = closed, fail-closed against operator misconfiguration (§3)
- L86: Invite-code pre-validation is not an existence oracle (256-bit single-use random); consumption happens only in the creation CAS
- L101: LinkedIdentityRecord is the export's form: §2's lookup key plus the display login
- L109: IN chunk sized inside D1's bound-parameter cap with headroom
- L159: readSignupPolicy: no row = open; unknown value = closed (fail-closed) (§3)
- L188: The policy condition is evaluated inside the creation batch's transaction, so a mid-flight transition leaves no race window (§3)
- L202: SignupGate is the creation gate's specification: open's policy condition or invite's consumption CAS (§3)
- L207: A lost gate (policy transition or concurrent code consumption) makes the caller re-judge
- L210: User + identity + personal org + membership are created in one atomic batch; a PK conflict means the concurrent signup won
- L244: Ids are drawn through SecureRandom first; the batch itself is then built synchronously
- L265: Creation statements chain on changes() = 1, so a batch whose gate lost writes not a single row
- L381: Invite consumption CAS shares the creation transaction: neither a burned-code-only nor an unconsumed-code outcome exists (§3)
- L405: A UNIQUE violation on (provider, provider_user_id) means the other signup won and the caller re-looks-up; other failures are defects
- L417: Verified email is refreshed at login as self-repair for a signup-time GitHub email outage; null never wipes the stored value
- L440: findPendingSignupInvite does not consume; consumption is the creation batch's job
- L463: Unknown-policy warning fires once per instance (monitor hits /auth/config periodically) and never logs the stored value (§11-5)
- L470: getOrCreateUser retries re-read the setting after a lost gate, converging in one pass in steady state (§1-5, §3)
- L497: An existing user bypasses the signupPolicy gate (it blocks only fresh creation); a presented code is not consumed (§3)
- L538: After a batch conflict the re-lookup must find the user; still missing is a D1 failure = defect

### `apps/server/src/db.package/index.ts`

- L1: db.package public surface: only repo Context tags, needed shape types and constructors leave the boundary (ADR-0006)

### `apps/server/src/db.package/invites.ts`

- L1: Module scope: project invitations repository — invite records and invite.* audit appended in the same batch (§15)
- L26: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L37: INVITE_TTL_MS is the §15-1 drafted value: issuance + 7 days
- L40: Lookback counting can never be looser than the spec's fixed window — it lands on the stricter side by construction (§15-2)
- L53: Pending-invite cap is the §15-2 drafted value (100 per project); expired invites are not counted
- L60: scope is part of the issuance text (§15-2, 2026-09-14 ES)
- L63: The server stores the issuance text without verifying it (CRYPTO_SPEC §6.5)
- L68: Issuance judgment order is pinned to the spec's written order (cap, then window), re-evaluated inside one INSERT...SELECT (§15-2)
- L83: findByLinkPub is the acceptance path: holding the link key is the capability (§15)
- L87: list includes the acceptance block — the input of the inviter client's §6.5 independent verification (§15-2)
- L89: Acceptance CAS and invite.accepted audit are one batch; D1 batch sequentiality makes changes() refer to the UPDATE (§15-1, §5.2)
- L107: Revoking an expired pending invite is allowed (admin cleanup); revokeCas has no effect on completed/revoked — caller derives 410
- L121: Completion is a derived state reconciled at add_member acceptance; the chain is the source of truth, no independent event (§15-4)
- L142: InvitationRow is the select-result shape; the Drizzle type never leaves this boundary
- L165: The acceptance block exists only when all 6 columns are populated (status at accepted or later)
- L184: issuanceOf assembles the issuance text; all 4 columns are NOT NULL (CRYPTO_SPEC §6.5)
- L194: A broken scope column falls fail-closed to an empty listed scope (grants no environment) instead of making the row unacceptable
- L219: Completion decisions stay fail-closed: a broken scope column yields null and never matches, unlike the display path's fallback
- L240: Scope comparison is set equality (§6.2); duplicates collapse so the comparison stays total even on a malformed stored row
- L269: Only invitations.id / invitations.link_pub map to 409 fields; any other constraint is re-raised as a defect, never swallowed
- L283: Both caps are re-evaluated inside the same INSERT statement (conditionalInviteInsert)
- L323: inviteIssueRejection derives the refusal reason in spec order for explanation only; admission is the single statement's job
- L373: Guarded audit insert copies project_id from the stored invitation row, never from a wire-declared value (§3.2/§5.2)
- L396: Audit columns are shared with audit.ts; project_id is copied from the target row, never composed from a wire value
- L409: Judgment and insert are one INSERT...SELECT: separate SELECT-then-INSERT would let concurrent issuers exceed the cap
- L452: A race that re-opens admission falls to a retryable typed rate-limit; it never falls back to breaking the cap
- L548: Scope lists are compared as sets in memory because stored order is not significant (§6.2); SQL narrows candidates only
- L576: The completion UPDATE repeats the status condition so a row revoked after the candidate read is not completed (CAS discipline)

### `apps/server/src/db.package/key-wraps.ts`

- L1: key-wraps module: Drizzle stays in-file; audit (9 KL3 events) is recorded in the same batch; rejections follow other lanes (§13-6)
- L53: D1 access via the shared tryD1 adapter (ADR-0006); only domain-level branches are returned as values
- L60: KEY_WRAP_WINDOW_MS is the §13-8 fixed-window length (all 1 hour)
- L62: Blob-fetch cap reinterprets §13-3's 5/hour as summed over kinds (§13-8)
- L64: Handoff-request cap: 5 per hour per ward (§13-8)
- L66: Approval-window cap: 20 segment fetches + approvals per hour per approver (§13-8)
- L69: Expired handoff requests are opportunistically deleted after a 1-hour grace past expiry
- L84: This input is decoded from the approval request and written to the auth.key_handoff_approved audit row
- L92: consumeWindow records the audit in the same batch only on allowance; rejections are not recorded
- L105: Window reset on recovery-code reissue: a new blob does not inherit the attempt history against the old one
- L165: handoffFind returns only requests that have not expired
- L180: handoffMarkCollected records auth.key_handoff_collected exactly once, at the first fetch
- L188: handoffSweep deletes requests past expiry + grace; approvals are removed by cascade
- L196: Device rows fold into logical segments per share_index: designation/revocation audit events are per guardian, not per device (DK)
- L238: Guarded audit inserts keep write and audit row 1:1 via the changes() chain over the write's own condition
- L320: Window expiry is judged against the excluded row's nowMs; WHERE false yields 0 RETURNING rows = refusal
- L378: Cap check and insert share one INSERT...SELECT...WHERE; on 0 rows the id's existence distinguishes conflict from limit
- L472: Segment rows and audit enter only when the group row was inserted (changes() = 1) in the same atomic batch
- L492: Conditioning segments on the id's existence would append to an existing group on a client id collision and end in a PK defect
- L520: Splitting the audit into a second batch would open a row-without-audit window and duplicate groups on retry
- L537: Designation is one audit event per logical segment (guardian), not per device row (2026-09-19 DK)
- L576: Delete audit rows enter only when a group row was actually deleted, so a losing concurrent delete records nothing (1:1 events)
- L629: Device rows are read in FP order to make the distribution head row deterministic (design record §8 K3-10)
- L702: The handoff cap is structural: the PK plus the handler's role check bound the reachable row count even across the race window (§13-8)
- L760: collected_at is set only while NULL so the audit records a restore exactly once, not on every poll
- L800: approvalRow covers guardian segments only; the old device-path blob column was removed under DK K4

### `apps/server/src/db.package/ops.ts`

- L1: Ops repo holds operator-only mutable state (not the audit log) plus windowed aggregation over existing audit rows (hosted-ops)
- L26: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L35: OpsStorageLevel uses the same vocabulary as storage-guard.ts's checks
- L38: Evacuation failure codes are static — safe to put in logs and results
- L67: A skipped evacuation is not counted as success; last_success is kept as-is
- L72: Oversize is not a failure: the consecutive-failure counter is untouched; only backup_oversize_projects is lit (§4-2)
- L86: OpsBackupSummary aggregates contain no identifiers (hosted-ops §3 rows 2/7)
- L97: incrementCounter is a single UPSERT on the fixed-window counter
- L108: listProjectIdsAfter enumerates projects in id order from an exclusive cursor
- L136: toCount coerces a D1 aggregate value to a non-negative integer
- L171: On oversize the failure counter resets to 0: no success can occur, so stale failures must not keep the alert lit forever
- L190: Census (storageLevel) is updated only when measured; kept as-is on RPC failure
- L290: Backup aggregates run in a single conditional-sum query; row count is at most the project count

### `apps/server/src/db.package/orgs.ts`

- L1: Module scope: org membership roles — not involved in project access (§9-1)
- L14: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty

### `apps/server/src/db.package/projects.ts`

- L1: Module scope: org-attribution metadata and the §11-5 membership projection — never an authorization table (§11-3, §11-5)
- L15: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L21: The membership projection is a discovery-only candidate index, never an authorization input; the chain is the source of truth
- L30: insertIfAbsent is idempotent; audit and genesis projection ride the same batch, so a conflict rolls the audit row back too (§11-3)
- L50: countInOrg is a best-effort judgment input with no atomicity against DO acceptance (§11-3); v1 counts every row (no tombstones)
- L60: upsertMember maintains the projection after add_member acceptance and lazily on chain fetch (self-repair + backfill) (§11-5)
- L72: deleteMember removes a stale projection row so the projection converges toward the chain truth (§11-5)
- L79: List candidates come only from projection rows; the caller's DO check decides what may go on the response (§11-5)
- L103: Scope-IN chunk sized with headroom under D1's 100-parameter cap after the 3 fixed parameters; a single IN would exceed it
- L132: A PK conflict rolls back the whole batch (insert and audit both no-op); a non-conflict failure stays a defect
- L194: The scope IN is chunked because D1's cap is 100 and the token scope cap is also 100 — a single IN would hard-fail wide tokens

### `apps/server/src/db.package/recovery.ts`

- L1: Module scope: recovery-code wrap repository — at most one blob per user (§13)
- L17: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L27: Since KL3 the recovery fetch limit is counted in one window summed by kind with passkey/guardian fetches; the value is unchanged (§13-8)
- L37: Registration/re-issuance is a replacing upsert: the old wrap disappears at acceptance; the same event covers first registration (§13-1)
- L51: recordFetch is best-effort: concurrent requests may slightly exceed the count; a 404 is not counted (§13-3)
- L77: A re-issuance resets the summed fetch window: trial history against the old blob is not carried to the new one (§13-8)
- L126: The caller judges the 404 via find first, so an unregistered user does not consume the fetch window (§13-3 line unchanged)

### `apps/server/src/db.package/repos.ts`

- L1: repos.ts confines Drizzle to this file (ADR-0006); D1 failures are classified by tryD1 and treated as defects
- L56: makeDbServices builds the repository service set once at worker startup
- L59: The recovery-code fetch window also uses the key-wrap ledger's summed window (§13-8)
- L73: OpsRepo wiring: counters, evacuation records, state kv (hosted-ops §6)
- L76: DeviceRepo is advisory only (§13-11, DK K3)

### `apps/server/src/db.package/schema.ts`

- L1: Schema rules (§2): Drizzle types never leave db.package; every reference from other structures goes through users
- L52: users.id is the internal ULID — the principal identifier across the whole system
- L54: email is for display/notifications only, never an identifier; only GitHub-verified addresses are stored
- L68: provider vocabulary is 'github' today, with future providers (workos etc.) anticipated
- L70: provider_user_id stores GitHub's numeric ID as a string, not the login — a login can change
- L86: Planned future org columns (sso_connection_id, allowed_domains, enforce_sso) are recorded but not created now
- L102: The org role does not participate in project access (§9-1)
- L111: Session id stores only the SHA-256 of the 256-bit session value; the raw value is never stored
- L117: auth_method is written only by issueSession; it is needed for the SSO-enforcement policy
- L135: token_hash stores SHA-256 only; the raw token is returned only once at issuance
- L137: token_prefix exists for display (e.g. maruhi_pat_Ab12…)
- L139: scopes is stored as a JSON array of TokenScope (§6 representation)
- L148: A same-named token is a rotation (§6); a DB unique constraint guarantees one row even under concurrent issuance
- L153: deployment_settings has no code write path by design — operator cf/SQL only, no admin UI will be built; unknown = closed (§3)
- L167: Signup invites store only the hash of a 256-bit bearer; a code grants account creation only, bound to no project/org/role (§3)
- L188: The invite id (ULID) is the same value as the audit payload's signupInviteId
- L190: token_hash is the SHA-256 of the whole presented string; the raw value exists only at issuance
- L192: Invite status is pending/used; expiry is derived from expires_at, as with §15 invitations
- L194: Signup invite expiry is issuance + 7 days (drafting value, computed by the issuance script)
- L203: The flow signing key is auth-layer credential protection outside CRYPTO_SPEC's scope; first-to-insert wins + read back (§4-2)
- L211: The signing-key row id is fixed — currently only one row, 'v1'
- L213: key_hex format: an HMAC-SHA-256 key, 256-bit, 64 lowercase hex chars
- L218: A flow row is born only at the callback's create-or-match CAS (ruling DH: start is unrecorded); no intermediate state exists (§4-1)
- L238: flowId is the public correlator: 128-bit random, 32 lowercase hex chars
- L245: token_name's default is resolved at start — a final value the vsig covers
- L247: Flow scopes use the same JSON-array representation as api_tokens.scopes
- L250: user_code is a short display code for comparison — not a secret (§4-1 (2))
- L252: ticket_hash stores only the SHA-256 of the 256-bit approval ticket
- L254: The flow expiry is the same value as flowToken/vsig's signed expiry
- L258: The clf_expires index exists for the opportunistic delete of rows past expiry + slack
- L263: recovery_wraps holds at most one row per user (§13-1)
- L268: suite is the suite identifier (CRYPTO_SPEC §2 design principle 4)
- L270: nonce format: 96-bit, 24 lowercase hex chars
- L272: ciphertext is AES-256-GCM ct||tag as lowercase hex; the server never decrypts or interprets it
- L284: masterKeyWraps is Class S's new path (passkey-prf); recovery-code stays on recovery_wraps
- L297: params is JSON public parameters; the server does not interpret it
- L307: guardianGroups is Class G: guardian groups (a wrap of B under the group KEK)
- L328: One share row per guardian device (DK): the same logical segment is sealed to each device key; devices cannot open each other's (§13-6)
- L346: share_index is 1..n — a logical segment, one per guardian
- L352: guardian_enc_pub is the seal target — a key the ward client has confirmed
- L354: The FP column exists because there is one row per guardian device (DK)
- L359: Share ciphertext is a 32-byte segment + 16-byte tag = 48 bytes
- L373: Device registry is advisory only, never an authorization input; no audit events (same discipline as §6 token listing) (§13-11)
- L381: Device key FP is recomputed from the body's public keys and matched; display name follows the §6 token-name acceptance discipline
- L404: token_id on a device row is advisory (§6); never an input to authorization
- L410: Device-add requests carry no state column: a row is an unconsumed request; the approver recomputes the FP from the response (§13-11)
- L429: Class H: E.pub is not stored — request_id is its derived value
- L433: request_id is the SHA-256 hex of E.pub (CRYPTO_SPEC §8.4)
- L441: Handoff request expiry is issuance + 15 minutes
- L443: collected_at marks the first obtained approval; auth.key_handoff_collected is recorded exactly once
- L449: Class H approvals are a response scope that dies with its request
- L456: source holds a guardian group id; the old device-path 'device' value was removed in DK K4
- L470: key_wrap_windows is mutable counter state, not an audit row (same character as login_failed_windows) (§13-8)
- L490: Project ID = genesis entry hash, 64 lowercase hex chars (CRYPTO_SPEC §6.4)
- L492: org_id is NOT NULL: a project without an org does not exist (§11-3)
- L502: project_members is a discovery-only candidate index, never an authorization input — the two-sources-of-truth ban (§11-5, §6.4)
- L522: project_id here is the genesis hash (64 lowercase hex chars)
- L530: The pm_user_project index serves the §11-5 candidate enumeration (cursor paging on the user axis, ascending project_id)
- L541: invitations.project_id has no FK to projects on purpose: an invite is chain-authorized and may exist during a §11-3 repair
- L548: link_pub is the acceptance resolution key (UNIQUE), declared by the client at issuance (§6.5)
- L554: head_hash/head_seq record the inviter's verified head at issuance — a public value
- L557: The server stores and serves the issuance signature without verifying it
- L559: Invite role never includes owner (§15-1)
- L561: scope_kind is 'all' | 'listed' (§15-2, 2026-09-14 ES)
- L563: scope_environments is part of the signed issuance statement; the server stores and serves it without verifying
- L571: Invite status vocabulary; expiry is derived from expires_at
- L573: Invite expiry is issuance + 7 days (§15-1 drafting value)
- L579: accept_signature is the input for the inviter client's independent verification (CRYPTO_SPEC §6.5)
- L581: link_signature is the link key's joint signature over the same byte string (§6.5)
- L587: inv_link_pub is the acceptance resolution key (§15-2)
- L589: inv_project_status serves the pending cap (status condition) and the listing
- L591: inv_project_created serves the issuance fixed-window rate limit (created_at range)
- L615: auditEventColumns uses Drizzle's shared-column-object pattern for the user/org audit tables
- L618: row_id is the wire identifier (16-byte random hex); seq never goes on the wire (§5.1/§7)
- L622: event names follow the AUDIT_SPEC §3 domain.verb form
- L624: On the D1 side actor_type is currently only 'user'; login_failed is a user with no user_id (§2)
- L632: payload JSON holds supplements such as auth_method and snapshots — nothing §1-2/1-3 forbids
- L636: The login_failed counter is mutable state, not an audit row; scanning the log per append would amplify the flood it bounds (§3.1)
- L650: The counting bucket is currently an auth_method kind name (github_oauth / cli_handoff)
- L656: suppressed_count is the basis of the suppression marker
- L675: oae_project index serves paging of the project_id-scoped invite.* read (§7)
- L688: Ops counters are bounded: rows older than 7 days are deleted at evaluation time (hosted-ops §2-A)
- L699: Ops counter windows start on an hour boundary (unix ms)
- L706: do_id_hex is the one-way image of idFromName(projectId), kept to cross-check against the R2 key (§4-2)
- L722: last_attestation_mark is the latest head-attestation acceptance time — the skip rule's third component (do-snapshot readWatermarks)
- L726: last_failure_code holds a static failure code only, never an error message body
- L730: ops_state is a small kv for sweep cursors and alert states (JSON strings)

### `apps/server/src/db.package/sessions.ts`

- L1: Module scope: sessions repository — the id is a hash; the raw value never reaches this layer (§5)
- L16: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L36: touch is the sliding update (§5): advances last_used_at and expires_at
- L38: Expired-row cleanup is not a revocation event, so deleteByHash/deleteExpired record nothing (§3.1)
- L46: deleteExpired is the bulk cleanup called from cron; an unpresented row disappears only here
- L54: login_succeeded is 1:1 with session creation (no independent session_created event); the id hash rides the payload (§3.1, §10)
- L101: The revocation event is written from the DELETE's returning: a read-then-delete pair would double-record concurrent logouts

### `apps/server/src/db.package/tokens.ts`

- L1: Module scope: API tokens repository — token_hash additionally gets a timing-safe comparison at the service layer (§6)
- L17: D1 access via the shared tryD1 adapter (ADR-0006); methods orDie at the boundary, keeping public error channels empty
- L35: expiresAtMs is the validity period fixed at issuance (§6 default TTL, W3a)
- L41: Same-name issuance rotates atomically in one batch; the replaced token id rides the token_created payload (§6)
- L54: listForUser never selects token_hash (a distribution surface); expired rows are returned as inventory, only verification 401s (§6)
- L62: revokeById's false is the caller's uniform 404 — §6's existence concealment; actor may be a session or another token (§2)
- L118: Rotation's first audit INSERT reads the old id, so replacedTokenId matches the row actually deleted in the same batch
- L149: createNewTokenWithinLimit folds the limit check and INSERT into one statement
- L173: Admission is the repo's conditional INSERT: a service-layer count-then-insert would race concurrent issuances past the limit
- L187: A same-name token appearing mid-flight is retried as a rotation last, to distinguish it from a new-name quota rejection
- L199: Expired token rows stay visible as inventory stock (unlike revocation's deletion); token_hash is never selected
- L221: A broken stored scopes column is an implementation bug / DB corruption — the row is never silently dropped
- L240: Revocation audit follows the DELETE's returning; on ambiguity the code falls toward the missing side over the duplicate side
- L248: Ownership is enforced at the repo boundary: deleting by id alone would let the admin API revoke another user's token (§6)
- L286: A broken stored scopes column is an implementation bug / DB corruption

### `apps/server/src/do/lease-chain-grants.ts`

- L1: The chain-read grants of issued leases (AUTH_SPEC §14-2 — Sc-3a):
- L9: How long an issued lease's chain read stays open (it follows within the same request).
- L28: Records `head` under a fresh 256-bit token (expired grants are dropped on the way).
- L35: Synchronous in-memory map: the draw cannot go through the SecureRandom service (see ids.ts's randomHexSync note)
- L42: The head granted under `token`, consumed; undefined when unknown, spent or expired.

### `apps/server/src/handlers/handlers-audit.ts`

- L1: Handlers for the audit-event read API (AUDIT_SPEC §6 / §7 — C1).
- L31: Stored row's actor_type column → actor kind (on the D1 side the write path is 'user' only).
- L36: Maps the optional query onto RPC input. undefined drops the key itself.
- L44: D1 audit row → wire form. `seq` is **never** exposed to anyone (§7 — D1's autoincrement is a sequence shared across the whole…
- L63: A value from JSON.parse is always JSON vocabulary at runtime (Schema.Json validation at encode time is the last line of defense).
- L77: The scope half of class-2 visibility (min(scope, chain role) — §12-3).
- L98: Plain strings: audit rows replay stored text, so the id filters match it verbatim (audit-api.ts's AuditEventSchema)
- L111: Effective permission admin (AUTH_SPEC §16-2):
- L139: The account-wide history (including watch-list events) is not readable by scope-limited tokens (same level as §13-2 — see the…

### `apps/server/src/handlers/handlers-auth-cli.ts`

- L1: Handlers for CLI login (server-mediated web-flow handoff — AUTH_SPEC §4).
- L77: The default token name when issuance parameters are omitted (§6's semantics treat it the same as the default scope).
- L80: The default scope when omitted (AUTH_SPEC §6:
- L83: Resolution of the flow-signing key (AUTH_SPEC §4-2):
- L100: Malformed form (only ever written by our own generation path) is a defect
- L104: The per-IP rate-limit prologue of the CLI login handlers (§4-1 (1) / (5), §4-3):
- L126: Response for scriptless HTML pages (§4-1 (4) — same delivery discipline as §15-3's invite landing page).
- L148: The uniform error page (§4-2 — failure reasons are not differentiated even in HTTP status).
- L153: Cleans the flow-binding cookie off the CLI branch's terminal responses (single use).
- L167: The (i)-a restore result: binding parameters that passed verification, or a uniform-refusal class.
- L173: The callback's CLI branch (i)-a: restore and verify the flow-binding cookie.
- L193: The state is the `cli.` prefix + a randomHex nonce (minted at the verify handler's second stage below), and constantTimeEqual compares…
- L231: The callback's CLI branch (iii)–(iv): creation CAS of the flow row (create-or-match) and rendering of the approval page.
- L252: The only signer is the server (cliStart JSON.stringify's Schema-validated scopes).
- L271: rejected (different user_id, expired, terminal state) and capacity (overall cap) both get the uniform error page (§4-1 (4) (iii) / §4-2…
- L275: Reaching the cap is an event that does not occur in normal operation = the H3 tripwire (hosted-ops.md §3 row 4).
- L283: (iv): the approval page (scriptless).
- L300: The callback's CLI flow branch (AUTH_SPEC §4-1 (4) — the processing order is fixed by the spec).
- L329: (i)-a: restore the flow-binding cookie (state match + vsig re-verification)
- L341: (i)-b: code exchange + user-info fetch (§3's second stage).
- L357: (ii): account lookup only (no creation — ruling DH).
- L366: Only the guidance wording follows signupPolicy; the acceptance source of truth stays the server gate (§3)
- L385: Per-IP rate limiting sits first in the handler: record-free, it protects CPU rather than the DB (§4-1 (1))
- L389: An unconfigured server fails closed before reaching GitHub (§4-1 (1))
- L405: Start stores nothing (ruling DH); authenticity is carried by flowToken and vsig, the two MAC systems
- L425: Rate limit first: the signing key is resolved before vsig verification, so an unauthenticated flood would reach D1 writes (§4-3)
- L431: Vsig/expiry verification is stateless and fail-closed: failure ends with the uniform error page before any GitHub redirect (§4-1 (3))
- L450: The state carries the cli. prefix to mark the CLI branch; the cookie carries state + the vsig-signed parameter set (§3 stage 1)
- L467: Rate limit first: every well-formed unauthenticated POST reaches the decision CAS, so the limit bounds D1 write amplification (§4-3)
- L472: The approval ticket alone is the credential (not a session); missing/unknown decisions get the undifferentiated error page (§4-2)
- L486: Decide CAS: the single latest ticket wins; approval's login_succeeded is recorded in the same batch as the CAS
- L503: The CAS-won row always exists (deletion happens only after expiry + slack); its userCode is shown on the completion page
- L515: Poll verification is stateless: invalid = uniform refusal (tampering); expired = a typed termination for the legitimate holder (§4-2)
- L533: No row on poll is the normal case of a record-free start — the browser leg simply has not arrived yet (§4-1 (5))
- L542: A re-poll of an already-issued flow gets the same uniform refusal as a CAS loser (§4-2)
- L546: Single issuance is structural: only the consume-CAS winner issues; a post-CAS failure stays consumed (fail-closed, §4-1 (5))
- L558: Issuance reuses §6 discipline (rotation, cap, token_created audit) with the row's stored parameters

### `apps/server/src/handlers/handlers-auth.ts`

- L1: Handlers for the auth endpoints (AUTH_SPEC §3 / §4 / §5 / §6).
- L56: The shape of the signup-code cookie value:
- L80: The signup hash's wire form is lowercase SHA-256 hex; deviations fold into 'not presented'
- L83: A state mismatch or malformed cookie shape restores to 'not presented', not an error
- L98: Signup-code cookie is single-use: expiry attaches only when the request carried it, on every HTML/302 terminal (§3)
- L124: /auth/config exposes only public information; never add client_secret — the 200 doubles as a registration confirmation (§4)
- L133: Server keypair's public face is public information and is added when configured; both fields omitted when unconfigured (§4, §9)
- L141: signupPolicy here is advisory only — never an input to verification or authorization; it feeds the CLI pre-flight fail-fast (§3)
- L177: Code-bearing start is rate-limited first: it reads D1 unauthenticated, and the 256-bit code check is not an existence oracle (§3)
- L196: Guidance does not distinguish unknown/revoked/consumed; pre-validation is fail-fast, the callback CAS is the acceptance authority (§3)
- L202: Only the code's hash rides the cookie, bound to this start's state; consumption happens in the account-creation transaction (§3)
- L224: Callback rate limit sits first: the GitHub token budget is a shared per-app quota, and the state check cannot serve as a throttle
- L243: The callback URL stays the single §3 URL, branching on the cli. state prefix; the CLI branch issues no session (§4-1 (3))
- L249: The CLI leg never references a signup code (ruling DH), but a leftover cookie still gets its single-use expiry here (§3)
- L272: The GitHub token's job ends at the exchange — it is not stored (§3/§10)
- L274: Only the code hash arrives via cookie; a state-mismatched carry-over folds into 'not presented'; consumption is a CAS (§3)
- L292: A signupPolicy denial creates no user rows (fail-closed); the record is the capped signup_denied and the page is script-less (§3)
- L336: providerLogin feeds the invite link's il: a display snapshot of the user's own GitHub login — self information only (§15-3)
- L340: Token principals get back only their own presented credential's scopes/expiry — attributes that disclose nothing new (ruling CI)
- L361: 401/CSRF are AuthMiddleware's job; this handler runs after it
- L366: Logout is session-only: a token principal is a no-op and must not destroy an unrelated browser Web session
- L389: The revocation target is only the presented token itself (the v1 line); arriving via session is out of scope
- L403: Token management requires * x admin (ruling CH); the 403 is computed from calling credentials alone, no target information
- L408: The token list contains only the caller's own rows (no wire target selector exists) and records no audit event (§11-5 discipline)
- L421: Check order (ruling CG): 401, then 403 from credentials alone, then a uniform 404 that hides foreign ownership
- L428: Ownership (id x userId) is enforced at the repo boundary; token_revoked records actor = the executing principal (§3.1)
- L451: Recovery registration and reissue are the same replacement upsert; the audit is recorded by upsert in the same batch (§13-1/§13-5)
- L473: This GET carries state (the fetch count), so the CSRF header check applies — it blocks third-party sites consuming the window (§13-2)
- L481: The rate limit is not counted ahead of the existence check: an unregistered 404 is outside the counted set (§13-3)
- L489: An unknown-suite stored wrap is a future version's write or corruption — die as a bug, never serve as v1; judged before counting (§13-4)
- L497: recovery_blob_fetched is recorded by recordFetch in the same batch as the count; a denial (no serve) is not recorded (§13-5)

### `apps/server/src/handlers/handlers-devices.ts`

- L1: Handlers for the device registry and device-add requests (AUTH_SPEC §13-11 — 2026-09-19 DK K3).
- L44: Recomputation of the device-key FP (CRYPTO_SPEC §3 — first 16 bytes of SHA-256(enc ‖ sig)).
- L58: A wrapped crypto failure stays a defect, like the die the pre-bridge code raised on a failed fingerprint computation
- L63: Match between the path's `:fp` and the FP recomputed from the body's public keys (mismatch = 400).
- L101: Every authenticated principal (session principals have already passed §5's allowed enumeration).
- L159: Opportunistic deletion (the caller's own expired requests)
- L161: Fixed window of 5 per hour per user (§13-11).

### `apps/server/src/handlers/handlers-invites.ts`

- L1: Handlers for the invite API (AUTH_SPEC §15 — 2026-09-13 IV revision).
- L62: Derives the unusability reason (§15-1: expiry is derived from expires_at).
- L105: Computes the acceptor key FP (AUDIT_SPEC §3.2:
- L120: A wrapped crypto failure here stays a defect, like the throw the pre-bridge code raised on a failed fingerprint computation
- L125: Verifies both accept signatures (CRYPTO_SPEC §6.5 v2).
- L165: §15-2: issuing a role = admin invite is owner-only (same level as the add_member permission table)
- L176: scope is format-checked only (Schema) — existence and containment are the agreed rules at add_member acceptance
- L194: The response carries no secret (§15-1). The id is already client-assigned
- L211: B1a ruling: acceptance is a key-declaration-class operation (same-level token condition as §13-2)
- L215: Holding the link key is the capability (§15-1).
- L235: Single-use CAS (pending → accepted — §15-1).
- L252: A CAS loss = a concurrent transition (first-come acceptance or revocation) or expiry reached.
- L264: Minimal response (§15-1: builds no surface that would make server declarations trusted — inviter info and the anchor are carried by the…
- L294: Revocation works on pending | accepted (cleaning up expired pending rows also allowed — B1a ruling).

### `apps/server/src/handlers/handlers-key-wraps.ts`

- L242: Approval authorization is judged from stored role rows, never the payload's declared values; a ward cannot self-approve (§13-7, K4)
- L259: Deletion endpoints share one response contract: 204 when removed, 404 when the target is absent
- L266: A handoff request is visible only to the ward or their guardian; anything else is a uniform 404
- L318: prfSaltHex is a public parameter: recovery needs the salt before the ceremony (§13-7, 2026-09-13 revision)
- L334: wrap_id is client-assigned — the AAD binds it (CRYPTO_SPEC §8.1)
- L367: A not-registered 404 does not consume the fetch window (§13-8)
- L440: group_id is client-assigned — the AAD / segment info binds it (CRYPTO_SPEC §8.3)
- L524: The guardian list folds device rows into one row per logical segment/group (2026-09-19 DK)
- L555: Group attributes come from the first device row; every row is a deviceShares entry (design record §8 K3-10)
- L564: Segment fetches are counted in the approval window — a watch-list event (§13-8)
- L611: key_handoff_requested is recorded in the same batch as the insert; a 409 (existing id) is not recorded as a request
- L674: The approval's audit rides the insert batch; window consumption carries no audit so the approval is not recorded twice
- L713: Fetching approvals is ward-only; guardians get the uniform 404

### `apps/server/src/handlers/handlers-lease.ts`

- L1: Handlers for workload leases (AUTH_SPEC §14 = CRYPTO_SPEC §9.1) and the sealed-proposal mint that shares their credential (AUTH_SPEC…
- L52: claims_digest (CRYPTO_SPEC §9.1) is computed from the **verified** token's issuer / sub / aud.
- L66: `aud` does exist (there are just several), so it is not missing-claim — use distinct vocabulary so an operator chasing the reason code…
- L71: Unreachable because the verifier has already dropped empty fields (stringClaim / audiencesOf), but a wrapped crypto error is still…
- L83: The DO's LeaseOutcome → api-schema typed errors (the response side of §14-3's check order).
- L101: A first-come-binding violation (§14-1) is not folded into 404:
- L122: The authentication stage shared by the lease and the sealed-proposal mint (§14-1 / §14-5):
- L132: 0. Request-level rate limiting on the source IP.
- L151: 1. The authentication stage (§14-1):
- L156: The first-come-binding key (§14-1) is already computed by the verifier from the signed bytes (signing input) — not a hash of the raw…
- L177: The mint's rejections → api-schema errors:
- L196: Authenticates the workload (step 1), then runs one DO RPC under its credential — everything from authorization onward is that single RPC…
- L208: An RPC failure has no typed answer here:
- L227: The value wire form is identical to the bulk pull (§12-7) — they share the verification-material bundling discipline, so the workload's…
- L246: The latest manifest (§14-2 — material for the workload's verification duty §9.1 (5); required since 0.28-draft)
- L249: The value snapshot at checkpoint time (§14-2 — same material as §12-7.
- L256: Encoded up front (an invalid body is still a 500 before any byte is sent), then written in chunks:
- L266: The mint's pre-flight (§14-5 — O-4): the same credential and authorization, no wraps, nothing stored — a job learns before the issuer is…
- L291: The sealed-proposal mint (§14-5 = CRYPTO_SPEC §5.3):

### `apps/server/src/handlers/handlers-membership.ts`

- L1: Handlers for the membership-log API (CRYPTO_SPEC §6.4 + AUTH_SPEC §11).
- L49: Mapping of outcomes at the RPC boundary onto the api-schema typed errors / success responses.
- L58: The §11-3 idempotent repair: when the DO is initialized but the projects row is missing, insert the row and return success as long as…
- L100: org.project_created (AUDIT_SPEC §3.2) and the genesis actor's membership projection row (§11-5) are recorded by insertIfAbsent in the…
- L115: AUTH_SPEC §11-3: the org's active-project count limit.
- L123: The type argument is spelled out: T inference from DataOutcome<never> (always rejected) falls to unknown on union-versus-union
- L131: The worker-side pre-check before handing to the DO:
- L152: The genesis entry hash IS the project id (§6.4 — the mint of the computed hash)
- L164: The size pre-check runs first (an oversized entry is dropped with 413 before any semantic judgment — resource protection outranks…
- L168: §11-1: init's genesis actor = the authenticated principal
- L171: §11-3: creation permission = member-or-above of the target org (a membership row suffices)
- L178: §11-3 project-count / org limit: the check runs after the org permission check (do not leak whether the limit is reached to a principal…
- L202: The token-principal scope intersection happens at the **candidate index stage** (out-of-scope = absent — the same information content as…
- L215: §11-5: the D1 projection is only a candidate index (not used for authorization).
- L227: Defense in depth: the candidates are already SQL-intersected, but apply the same predicate to the response rows too (even if the…
- L235: Read-time confirmation: confirm membership with each candidate's DO and return only passing rows, together with the chain-derived role…
- L244: A failure of the confirmation RPC (RpcCallError — DO unreachable, stored chain corrupted, etc.) is isolated per candidate:
- L281: memberRoleFor's rejection vocabulary is just the 2 kinds above (the reader floor is met by every member) — anything else is an invariant…

### `apps/server/src/invite-domain.ts`

- L1: Server-side domain types for invites (AUTH_SPEC §15 — 2026-09-13 IV revision).
- L12: Chain roles grantable via an invite (owner is never granted through invites — §15-1).
- L15: The to-be-granted scope (AUTH_SPEC §15-2 — 2026-09-14 ES; same shape as CRYPTO_SPEC §6.2).
- L21: The stored invite state (expiry is derived from expires_at, not a stored state).
- L24: The issue document (CRYPTO_SPEC §6.5): the client-generated link public key, the inviter's verified head at issuance, and the issue…
- L36: The acceptance block (status accepted and onward — §15-1).
- L41: The §6.5 accept signature (the acceptor's chain sig key) — material for the inviter client's independent verification
- L43: The §6.5 link signature (link key) — same material
- L53: The to-be-granted scope (part of the issue document — covered by the issue signature.
- L63: The acceptance decision for issuance (§15-2's acceptance policy.
- L70: The committed values passed to the accept CAS (pending → accepted).
- L83: The acceptor key FP copied into the audit payload (AUDIT_SPEC §3.2), computed from the accepting keys.
- L87: The target of the accepted → completed comparison at add_member acceptance (§15-2).
- L93: The role granted by the fulfilling add_member (CRYPTO_SPEC §6.2).

### `apps/server/src/lease-policy.ts`

- L1: Evaluation of lease_policy (AUTH_SPEC §14-1's authorization stage).
- L24: The part of the token the policy evaluation reads.
- L33: Evaluation of one claim constraint (v1 = exact match only — §14-1).
- L51: Evaluation of one lease_policy element: issuer_url matches the token's issuer, audience is contained in the token's `aud`, and **every**…
- L74: The authorization decision by existential quantification (§14-1).

### `apps/server/src/oidc.package/index.ts`

- L1: The public surface of oidc.package (the ImportLint boundary).

### `apps/server/src/oidc.package/jwks.ts`

- L1: OIDC discovery + JWKS fetch with a TTL cache (AUTH_SPEC §14-1).
- L51: One JWKS entry, as fetched (the raw JSON object).
- L58: Derives the verification algorithm from the JWK itself — **a design that structurally closes off alg confusion**:
- L77: `use` is optional, but when declared it must be "sig"
- L90: TTL of a discovery document (jwks_uri is effectively immutable, so it is long).
- L94: Cooldown for a forced refresh triggered by an unknown kid.
- L101: Interval after a **failed** refresh before the next refresh is attempted.
- L112: The upper bound for how long the last successful JWKS may keep being used after a refresh failure.
- L121: Size limit of a fetched document (in **bytes**).
- L129: Timeout of one fetch. This is an outbound fetch triggered from the unauthenticated path (leases); do not let a request hang on an issuer…
- L136: Any failure that leaves no usable verification key (transport, non-OK status, decode, oversize body, timeout, post-failure cooldown).
- L147: A resolved verification key: the JWK imported through effect/jose.
- L158: Resolve the verification key for `kid` from the issuer's JWKS.
- L183: The whole cache state lives in one `SynchronizedRef` — the last successful values, the failure timestamps, and the in-flight `Deferred`s…
- L218: The discovery document's fields the pin checks read (issuer + jwks_uri).
- L224: The JWKS document. Every entry must be a JSON object — the schema rejects a non-object entry wholesale (503), the verdict the pre-Effect…
- L237: The `HttpClient` layer the package's fetches run on — the repo's shared egress client (trace propagation disabled), with `redirect:
- L247: Decode with a fatal UTF-8 decoder: invalid bytes must be a decode failure (503), not silently repaired into U+FFFD by the non-fatal…
- L254: GET `url` and decode the JSON body with `schema` via `HttpClientResponse.schemaBodyJson` (typed decoding — no `as` casts).
- L271: Inside this region every error is foreign — transport, a hung issuer, schema decode — so the pipeline below normalizes them wholesale.
- L300: Reject invalid UTF-8 before re-wrapping — see utf8FatalDecoder
- L312: Normalize each foreign error to its own reason — no flattening:
- L327: Extract `jwks_uri` from a decoded discovery document.
- L350: Pick the usable key matching `kid` (a missing kid is allowed only when there is exactly one key).
- L356: A token without a kid is accepted only when the candidate is uniquely determined.
- L376: Inside the TTL an unknown kid triggers exactly one re-fetch under a cooldown (§14-1 JWKS cache strategy)
- L391: A re-fetch inside the TTL is a forced refresh, so its time seeds the cooldown origin; a TTL-expired refresh leaves it unchanged
- L407: InFlightSlot exists because Deferred is invariant in its value type: the slot picks the concrete record rather than the record being generic
- L434: The JWKS cache is per isolate; the refs are makeUnsafe so the constructor stays synchronous and a cold-start rush shares one in-flight load
- L444: The single-flight load runs detached and uninterruptible so it cannot die with its first requester; settle commits atomically in the load's update
- L495: The load is exit-materialized: on any exit the in-flight entry drops and the Deferred settles, or every later joiner would hang
- L501: A defect in the load still reads as 'jwks unavailable' to joiners, as the old catch-all mapped every rejection to the same 503
- L523: Discovery resolves only jwks_uri (effectively immutable), so a failed fetch reuses the last success; freshness is held by the JWKS grace window
- L583: The failure side needs its own cooldown: isUsable returns false at the TTL branch and never reaches the forced-refresh cooldown
- L611: The failure stamp lands unconditionally in the load's own settle, even if every caller was interrupted; a held stale set keeps the seed stamp
- L636: The failure and held-stale stamps already landed atomically in the settle; this continuation only reads the verdict
- L642: Stale-while-revalidate: a good value inside the grace window keeps verifying; signature verification itself always runs
- L665: Key import is effect/jose's: it re-checks JWK metadata and refuses private members; a refused key is skipped, the old WebCrypto verdict

### `apps/server/src/oidc.package/verifier.ts`

- L1: OIDC token verification (AUTH_SPEC §14-1's authentication stage).
- L31: The supported-issuer list (§14-1): **a static configuration uniform across the whole deployment** that carries no project existence or…
- L44: The tolerated skew of the time checks (§14-1:
- L55: Only the values the lease path uses, extracted from the verified token.
- L65: `aud` takes both string / array forms, so it is always normalized to an array.
- L68: The verified `exp` (seconds). Input to the binding row's lifetime in first-come binding (§14-1) — the lifetime must be at least "the…
- L74: The first-come-binding key (§14-1) = SHA-256 of the JWS signing input (`header.payload`).
- L124: Numeric claims (`exp` / `iat` / `nbf`) accept only finite numbers in seconds.
- L130: `aud` is a string / string array (RFC 7519).
- L150: The 3 decoded segments (shape satisfied, contents not yet checked).
- L160: Decodes one base64url segment. Returns null for anything malformed.
- L181: Decodes one base64url segment as UTF-8 JSON.
- L198: Decodes the 3 segments of a compact JWS (stage 1).
- L232: crit is rejected by mere presence (zero extensions implemented; dropped checks became 2025-26 CVEs); typ is deliberately unchecked — maruhi issues no JWTs
- L281: exp and iat are both required (§14-1): a token lacking them could become a credential usable without expiry
- L300: The verifier is one per isolate and confines the JWKS cache; jwks is an argument so tests can substitute it
- L315: Allowlist matching runs before any external fetch (the DoS rationale in the header comment)
- L321: A JWKS fetch failure is fail-closed but 503, not 401: a transient outage told as bad credentials would make CI treat it as non-retryable
- L330: The header alg is used only for the match check against the JWK-derived expectation, never as an input to branching
- L338: Only the signature segment is re-encoded canonically: malleated signature segments are deliberately accepted; the signed content passes byte-for-byte
- L370: The first-come-binding key hashes the signed bytes, computed only after signature verification passes; a failed digest is an environment defect

### `apps/web/src/dashboard/api.ts`

- L1: api.ts is same-origin only (ruling BM, connect-src 'self' + __Host- cookie), centralizes status classification and wording, always sends the CSRF header on mutations, and does no Schema decoding (ruling BR).

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
