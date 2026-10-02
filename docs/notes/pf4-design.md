# PF4 design record — `maruhi proxy run` (2026-10-01 design and implementation session)

**Position**: the ROADMAP H series "no-revision group", third item =
**PF4: `maruhi proxy run` (credential brokering + short-lived connectors)**
(order VH → PF5 → PF4 → PF6 — 2026-09-14 owner ruling). The ROADMAP entry
also bundles **Phase 3 ⑤ run-output redaction** ("designed at the same
time … may be bundled with the proxy for timing"); both landed in this
session. This record carries the overall picture, the option enumeration
and rulings (P1–P9), the competitor survey the rulings were checked
against, the exhaustion loop, the residuals, and the implementation.

**Approval (2026-10-01)**: the owner delegated every open point ("for each
point to rule, keep searching for a strictly-better or structurally-better
option until none is left, lay the options out, and pick the one you
recommend"), asked for parity with or superiority over competitors, and
ruled backward compatibility out of scope (zero users). The rulings below
are the designer's picks under that delegation. **One item is flagged for
the owner's explicit confirmation** (§13: the ephemeral CA and the connector
JWT are crypto *in the CLI* that CRYPTO_SPEC does not describe — the record
argues they are transport and third-party-protocol clients, not spec
operations, and asks the owner to confirm or ask for a spec note).

**Premises (not relitigated)**: ADR-0014 decision 2 ② (credential
brokering: agents receive only placeholders, swapped for real values at the
communication boundary; composed with E2EE so that "neither server nor
agent holds plaintext"); integration-options.md §6 D3 (shortening at the
broker — the substituted value is a just-issued short-lived token; the
issuer is the proxy on each person's machine; the server is uninvolved) and
§7 part ② (the connector frame is a client implementation — "spec impact:
unchanged"); the ROADMAP Phase 3 ⑤ design (byte-domain streaming exact-match
redaction, the two-layer trigger, the carry-over); ADR-0016 decision 7
(`run` is a sanctioned consumption path allowed under agents); the
`maruhi sync` conventions (a non-secret repository config, strict parsing,
output scrubbing — SY2); pf5-design.md 3-E / D-1′ ("values never pass
through the agent" is false for `maruhi run`; PF4 is the answer).

---

## 1. Overall picture

### 1-1. Problem

`maruhi run` keeps values off disk, but the child holds them and can print
them; an agent that runs a program under `maruhi run` reads that output
(`run -- printenv` is agent-gate's known bypass). Competitors answer with
brokering proxies whose **server holds the plaintext** (Infisical Agent
Proxy, Agent Vault; Phase's announced egress proxy). maruhi's answer keeps
the E2EE property: the only process that ever holds a value is the CLI on
the member's machine, and under `proxy run` even the program the member
runs does not.

### 1-2. Mechanism sketch

```
maruhi proxy run --env dev -- claude
  │  config → environment → verified pull (as run) → presence fail-fast → classify by maruhi.proxy.json
  │  ephemeral CA (P-256, in memory) · proxy on 127.0.0.1:<port> · CA cert + bundle in a 0700 temp dir
  ▼
child env: GITHUB_TOKEN=mhp_GITHUB_TOKEN_<22 random>   DATABASE_URL=<real: passthrough>   OTHER: withheld
           HTTPS_PROXY/HTTP_PROXY=http://127.0.0.1:<port>  NO_PROXY=""  SSL_CERT_FILE/REQUESTS_CA_BUNDLE/
           CURL_CA_BUNDLE/GIT_SSL_CAINFO/AWS_CA_BUNDLE/PIP_CERT/CARGO_HTTP_CAINFO/…=<bundle>  NODE_EXTRA_CA_CERTS/DENO_CERT=<ca>  NODE_USE_ENV_PROXY=1
  │
  ├─ CONNECT api.github.com:443 (a rule names it) → 200 → TLS terminated with a leaf for that host
  │     → loopback http handler bound to that target → inspect (placeholders in path / query / headers
  │       [Basic decoded] / body) → refuse (403) or substitute → upstream https (system roots)
  │       → response streamed back with real values replaced by placeholders
  ├─ CONNECT other.host:443 (no rule)              → 200 → blind TCP tunnel (never inspected; 403 when unmatched = block)
  └─ GET http://host/… (plain, absolute form)      → the same inspection; substitution only for `http://` rule hosts
connector rule: GITHUB_TOKEN placeholder; on first use the proxy signs an RS256 App JWT with GH_APP_PRIVATE_KEY,
  POST /app/installations/{id}/access_tokens → 1 h token cached and re-minted 5 min before expiry; inputs never injected
exit: proxy closed, temp dir removed, "N brokered, N tunnelled, N blocked, N failed"
```

Nothing on the server side changes: no endpoint, no acceptance rule, no
audit event beyond the pull's own `var.read`, no spec text (§13 for the
one point flagged).

### 1-3. Competitor survey (checked before ruling)

| Product | Shape | What maruhi takes / rejects |
|---|---|---|
| Infisical Agent Proxy (GA 2026-07) / Agent Vault (OSS) | Explicit forward proxy: HTTPS as CONNECT, plain as absolute-form; MITM with an org root CA stored **in Infisical**, per-host leaves; "dummy value" placeholders (overridable); per-service rules with header-rewrite or substitution roles and listed surfaces (`path` / `query` / `header` / `body`); `--unmatched-host allow\|block`; activity logs with decision + names, never values; separate machine identities for proxy and agent | Takes: CONNECT + absolute form, per-rule surfaces, `unmatched` policy, log field set, downgrade refusal. Rejects: the server holding the plaintext and the CA (the proxy here is the member's CLI; the CA is per run, in memory) |
| Claude Code sandbox-runtime (`credentials.envVars[].mode: mask`, `injectHosts`, `tlsTerminate`) | Per-session sentinel; substitution only on `injectHosts`; fails closed without TLS termination; response scrubbing; `extract` regex for structured values; SigV4 re-signing; mask settings honoured only from user/managed settings, never from the repo | Takes: inject-hosts binding, fail-closed, response scrubbing (also Daytona). Rejects for v1: regex extraction and SigV4 re-signing (recorded as follow-ups). The "never from the repo" rule is weighed in P5 |
| Daytona Secrets | `dtn_secret_<id>` placeholders; headers only; response scrubbing; CA baked into the image | Takes: response scrubbing, headers-only default. maruhi lets a rule widen the surfaces |
| 1Password `op run` | Output masking, labelled "best effort" (2026-09); buffering broke TUIs | The ⑤ design streams in the byte domain; the docs say "second line of defence" |
| Doppler, Phase | No brokering shipped (Phase: announced, not documented) | — |
| Teleport Machine ID | Local authenticated tunnels for non-HTTP (db / app) | Recorded: the shape for non-HTTP protocols if ever wanted; v1 passes those values through and redacts |

## 2. Ruling P1 — where the proxy runs and what it is

| # | Shape | Verdict |
|---|---|---|
| 1-A | **A subcommand of the CLI (`maruhi proxy run -- <cmd>`), a loopback proxy that lives exactly as long as the child** | **Adopted** |
| 1-B | A standalone daemon (`maruhi proxy serve`) agents connect to across the network (Infisical standalone mode) | Rejected for v1: a listening socket beyond the loopback needs its own authentication (Infisical's `Proxy-Authorization` identity tokens) and an orphan-lifetime story; the one-run shape has neither problem. Recorded as a follow-up for sandboxes on other hosts |
| 1-C | A server-side broker (the maruhi Worker substitutes) | Rejected: the server would hold plaintext — the inversion of E2EE and of the whole pitch |
| 1-D | A separate package / binary | Rejected (as PF5 1-B): a second artifact and a second copy of the verified pull |
| 1-E | Transparent interception (iptables / netns) | Rejected: platform-specific privileges; the explicit proxy is what every client supports. The docs name a container with `--network host` for the guarantee |

**Why 1-A is strictly better**: the proxy inherits the member's session and
the verified pull byte for byte (one implementation), has no credential to
provision, and its lifetime is the child's — nothing to orphan, nothing to
revoke.

## 3. Ruling P2 — the interception mechanism (measured under Bun 1.4.2)

| # | Shape | Verdict |
|---|---|---|
| 2-A | `node:http` server with the `connect` event (the Node idiom) | **Rejected by measurement**: Bun 1.4.2's node:http CONNECT path corrupts the tunnelled bytes (the client's TLS fails with `WRONG_VERSION_NUMBER` / `packet length too long`; works under Node). A probe is in the session log |
| 2-B | **`node:net` raw listener parsing one request head; brokered CONNECT → `tls.TLSSocket(isServer)` wrap with the host's leaf → a loopback `node:http` server bound to that target; unbrokered CONNECT → blind pipe; plain absolute-form → a loopback plain server** | **Adopted** (measured working under Bun and Node with curl, Node, and Bun clients) |
| 2-C | `https.createServer({ SNICallback })` on the loopback and pipe the CONNECT'd socket into it | **Rejected by measurement**: Bun ignores an `SNICallback`-only configuration and serves plaintext |
| 2-D | `Bun.serve` + `Bun.listen` (Bun-only APIs) | Rejected: vitest runs under Node, so the proxy core would be testable only through Bun probes; 2-B tests in-process on Node and is pinned under Bun by one probe (`test/live-proxy.test.ts`) |
| 2-E | A third-party proxy library (http-proxy, mitmproxy-like) | Rejected: a new dependency on the CLI's supply chain for ~400 lines of standard-library code |

**Why the loopback hop**: Bun's node:http server cannot adopt a `TLSSocket`
as a connection (`server.emit("connection")` is Node-only). One loopback
round trip per connection buys a single, runtime-independent HTTP parser
(keep-alive, chunked, pipelining handled by node:http). **The handler
trusts the CONNECT target, never the `Host` header** (one loopback server
per brokered authority) — otherwise `CONNECT api.github.com` + `Host:
evil.example` would carry a real value to the wrong host.

**Only brokered hosts are intercepted.** A CONNECT to a host no rule names
is a blind tunnel: certificate pinning, mTLS, and HTTP/2 to those hosts are
untouched, and the child's own TLS verification applies end to end. This is
the strictly-better round over "intercept everything" (Infisical's shape):
less breakage, and nothing is gained by inspecting traffic that can carry
no real value (the child holds only placeholders).

## 4. Ruling P3 — the certificate authority

| # | Shape | Verdict |
|---|---|---|
| 3-A | **An ephemeral CA per run: P-256 key pair generated in memory, self-signed root, per-host leaves on demand; the CA certificate (public) and a bundle (runtime roots + CA) written to a 0700 temp directory for the child's lifetime; the key never written** | **Adopted** |
| 3-B | A persistent per-machine CA (`~/.config/maruhi/ca.pem`, Infisical / mitmproxy style) | Rejected: a long-lived CA key on disk is exactly the kind of material the diskless invariant keeps out of files, and a stolen one intercepts every future run |
| 3-C | A CA stored on the maruhi server (Infisical's org root CA) | Rejected: the server would hold a key that intercepts members' traffic |
| 3-D | Call the system `openssl` to make certificates | Rejected: not installed everywhere (Windows), and spawning a tool for this is worse than 200 lines of DER |
| 3-E | Ed25519 certificates | Rejected: not accepted by every TLS client stack; P-256 / SHA-256 is universal |

The DER writer (der.ts) encodes only what a TLS client needs (RFC 5280
version, serial, CN, validity, SPKI, basicConstraints, keyUsage,
extKeyUsage, subjectAltName dNSName / iPAddress, key identifiers) and the
IEEE P1363 → DER signature conversion; it parses nothing. Pinned by
node:crypto's `X509Certificate` (chain verification, host check) and a real
handshake. **Why the bundle carries the system roots**: OpenSSL-based
clients replace their store with `SSL_CERT_FILE`, and the unbrokered hosts
(tunnelled, verified by the child) still need the real roots. Validity is
30 days with a 5-minute back-date (clock skew in containers); the key dies
with the process, so the validity window protects nothing beyond the run.

## 5. Ruling P4 — placeholders

| # | Shape | Verdict |
|---|---|---|
| 4-A | **`mhp_<NAME>_<22 random alphanumerics>` (~131 bits), fresh per run; a rule may fix the placeholder for clients that validate a credential's shape** | **Adopted** |
| 4-B | `__name__` (Agent Vault) | Rejected: guessable, stable across runs, and a plausible literal in traffic |
| 4-C | The real value's shape mimicked (a fake `ghp_…`) by default | Rejected: looks like a leaked token to every scanner on the way; opt-in per rule covers the clients that need it |
| 4-D | Random without the name | Rejected: a human reading a transcript or the verbose log cannot tell which variable a placeholder stands for; the name is not secret |

The random tail makes an accidental match impossible and one run's
placeholders useless to another; the prefix makes a placeholder in a log
self-explanatory. A placeholder is **the capability** for substitution on
that run (§12).

## 6. Ruling P5 — where the rules live

| # | Shape | Verdict |
|---|---|---|
| 5-A | **`maruhi.proxy.json` in the repository (non-secret: variable names and hosts), the sync-config conventions (version, strict keys, `--config`, optional `project` checked against the flag), with the rules in effect printed before the child starts** | **Adopted** |
| 5-B | Rules in the schema statements (a signed `hosts` declaration per variable — CRYPTO_SPEC §14) | Not for PF4: a spec revision (the item is in the no-revision group), and it binds a team to one routing for every use. **Recorded as the follow-up that would make the rules signed and team-shared** |
| 5-C | Rules only on the command line (`--allow NAME=host`) | Rejected alone: unrepeatable; kept out of v1 to have one place to review |
| 5-D | Rules in the user's config directory only (Claude Code's "never from the repo") | Rejected as the only location: the team shares the routing with the code, like `maruhi.sync.json`. The threat it addresses is weighed below |
| 5-E | Rules stored as maruhi variables (E2EE, team-shared — SY2's early option (b)) | Rejected: decrypting a config to decide routing adds a value-bearing read for a non-secret; the committed file is reviewable in a PR |

**The repo-editable config and the agent**: an agent with a shell can edit
`maruhi.proxy.json`. The edit affects the *next* `proxy run` the human
launches — the running proxy's rules are fixed at start, and the human sees
them printed. An agent that launches its own nested `proxy run` with an
edited config gains nothing it did not already have: it could run `maruhi
run` directly (ADR-0016 decision 7 keeps `run` allowed under agents). So the
config's trust level equals the repository's, and the guarantee is "what the
human launched". Fail-closed defaults make a mistaken file safe: unlisted
variables are **withheld** (not injected), and unmatched hosts are
tunnelled (no real value can leak through a tunnel).

## 7. Ruling P6 — substitution: what, where, and refusal

| # | Shape | Verdict |
|---|---|---|
| 6-A | Substitute everywhere in the request | Rejected: a placeholder written into an issue body or a gist is substituted and **published by the API** — an exfiltration path through an allowed host |
| 6-B | **Per-rule surfaces (`header` default; `path`, `query`, `body` opt-in), Infisical's vocabulary; a `Basic` credential decoded, substituted, re-encoded** | **Adopted** |
| 6-C | Header allow-list (`Authorization` only) | Rejected: `X-Api-Key`, `PRIVATE-TOKEN`, `apikey` are common; headers are not stored content |
| 6-D | Placeholder found where the rule does not allow it → forward unchanged | Rejected: the API fails with a confusing error and the agent retries; **refusing with a message that names the variable and the rule (403, "the request was not sent")** is fail-closed and teaches the agent |
| 6-E | Inspect bodies by streaming (chunked upstream) | Rejected for v1: a refusal after headers are sent can only be a connection reset. Bodies are buffered up to 32 MiB (API calls); larger bodies toward a brokered host are refused with guidance (uploads belong to unbrokered hosts). Recorded |
| 6-F | Response scrubbing (real → placeholder, byte domain, streaming; `Accept-Encoding: identity` upstream so the body is readable) | **Adopted** (Daytona / Claude Code have it; GitHub's token endpoints and many "whoami" APIs echo credentials) |
| 6-G | Downgrade: an `https://` URL in plain text | **Refused** (400), as Infisical does |

The byte-domain replacer (byte-replace.ts) is **shared with the ⑤
redaction** and inherits the `maruhi sync` fragment rule (whole / per line /
JSON-escaped, longest first); the carry-over bound is (longest pattern − 1)
bytes, cut at a newline when every pattern is single-line.

## 8. Ruling P7 — unmatched hosts and the egress story

| # | Shape | Verdict |
|---|---|---|
| 7-A | **`unmatched: allow` (default — blind tunnel) \| `block` (403)** | **Adopted** |
| 7-B | Always block (an allow-list proxy) | Rejected as the default: an agent needs npm, docs, its own API; brokering is about values, not reachability |
| 7-C | Always allow | Rejected as the only option: `block` is cheap and turns the proxy into the egress allow-list a sandbox wants (with the stated caveat that the variables are advisory) |

## 9. Ruling P8 — connectors (integration-options.md §6 D3)

| # | Shape | Verdict |
|---|---|---|
| 8-A | **A connector frame (`mint` from consumed inputs → a credential with an expiry; cache; re-mint before expiry; one flight) with `github-app` as the first connector: RS256 App JWT (WebCrypto RSASSA-PKCS1-v1_5; PKCS#1 PEM wrapped to PKCS#8), `POST /app/installations/{id}/access_tokens`, 1 h token, 5-minute refresh margin** | **Adopted** |
| 8-B | OAuth refresh → access as a second connector | Deferred: generic RFC 6749 §6 is small, but provider client-auth variants (Basic vs body, PKCE public clients) need a per-provider table to be useful. Recorded as the next connector |
| 8-C | AWS STS | Rejected for the broker: STS returns a 3-tuple used with SigV4, which the child signs itself — substitution is impossible without re-signing at the proxy (Claude Code does this). The docs name federation (OIDC → STS) as the position (integration-options.md D5) |
| 8-D | Connector inputs injected too (`unlisted: passthrough`) | Rejected structurally: the parser refuses a rule that would inject a consumed input, and the plan skips consumed inputs under `unlisted: passthrough` — the App key never reaches the child |
| 8-E | Mint at startup | Rejected: a token minted for a run that never calls GitHub is waste and widens the exposure window; minting on first use with a fail-fast on **missing inputs** (child never started) keeps both properties |

Connector failures reach the child as `502` with the connector, the
variable, the HTTP status, and the provider's `message` — never an input or
the token.

## 10. Ruling P9 — the child's environment and signals

- **Control variables written after the variables**: a variable named
  `HTTPS_PROXY` (a co-member can choose names — run.ts's AAD note) cannot
  redirect the child's traffic. `NO_PROXY` is set empty so an inherited
  exclusion cannot route a brokered host around the proxy. `NODE_USE_ENV_PROXY=1`
  makes Node 24's fetch honour the proxy (the Agent SDK's secure-deployment
  guide names this gap).
- **Placeholders ride `buildInjectionEnv`** like values: the execution-control
  denylist, the POSIX-name rule, and the case-collision check apply to a
  connector's env name as well.
- **Signals held** (`holdSignals`): the parent ignores SIGINT (the terminal
  delivers it to the child, which owns it) and forwards SIGTERM / SIGHUP —
  the `maruhi agent` shape, now shared (`holdingSignals` in live.ts). The
  proxy must outlive the child.
- **Pass-through values go to the ⑤ redaction** under the same trigger as
  `maruhi run`.
- Teardown runs in `Effect.ensuring`: the proxy closes and the CA directory
  is removed whatever the child did; a removal failure is a warning naming
  the directory (it holds only the public certificate).

## 11. Run-output redaction (Phase 3 ⑤) — implementation of the ROADMAP design

**Revision (2026-10-02, §19 D-4)**: the first implementation applied the
newline cut only when no fragment spanned a line, so a PEM value held the
carry-over for its whole length — the ROADMAP's "live logs stream line by
line even for PEM keys" was not delivered. The replacer now takes
`cutAtNewline`, which the redaction and the response scrub pass because
`scrubPatterns` carries every line of a multi-line value (each line is
caught on its own; a multi-line value renders as one `[redacted]` per
line). The replacer core was also rewritten after §19 C-2 (a short match
at a chunk edge could hide a longer pattern): it now scans the source bytes
left to right, longest match first, and holds source bytes, with the
correctness argument in byte-replace.ts.

The ROADMAP entry specified the design; this session implemented it as
written: trigger = known agent **or** stdout / stderr non-terminal (stdin
alone is not a trigger — run.ts `redactionFragments`); the child's stdout /
stderr are received on pipes and relayed through the byte-domain replacer
(live.ts `relayRedacted`); fragments = raw values, line-split forms,
JSON-escaped forms, longest first; carry-over = (longest fragment − 1)
bytes, cut at a newline when every fragment is single-line; binary output
byte-transparent (pinned by a 0..255 byte sweep under Bun); `[redacted]` as
the replacement. `run`, `ci run`, and `proxy run` (pass-through values) all
go through it. **One decision made here**: synchronous fd writes
(`writeBytes`, the `writeLine` discipline) rather than `process.stdout.write`
— the latter is asynchronous against a pipe and bin.ts's `process.exit`
clips its tail (live.ts's measured note).

## 12. Residuals (explicit)

- **The proxy variables are advisory**: a child can unset `HTTPS_PROXY` and
  connect directly — it then sends the placeholder and fails (safe), but a
  child with the member's session can run `maruhi run` itself. The
  guarantee needs a sandbox without the keychain / `MARUHI_TOKEN`, with the
  host's proxy reachable (docs). Infisical's own blog states the same limit
- **A placeholder is a capability for that run**: the proxy port is
  reachable by every local process; knowing a placeholder lets a process
  make brokered requests toward the rule's hosts. Same boundary as the
  `maruhi agent` socket (same user), weaker by the random-placeholder
  knowledge rather than a filesystem mode
- **Not substituted**: a placeholder transformed by the client (base64 other
  than `Basic`, a hash, a signature — SigV4), or parsed as a JWT. Follow-ups:
  a per-rule `extract` regex and SigV4 re-signing (Claude Code has both)
- **Brokered hosts lose pinning / mTLS / HTTP/2 / WebSockets**; bodies over
  32 MiB toward them are refused. Unbrokered hosts are untouched
- **No upstream proxy chaining**: `https.request` ignores the parent's
  `HTTPS_PROXY`; behind a corporate proxy the run's proxy connects directly
- **Early bytes after CONNECT**: a client that sends its ClientHello before
  the `200` has those bytes `unshift`ed back onto the socket before the TLS
  wrap; the wrap reading them is best effort (every tested client waits)
- **Non-HTTP protocols** (Postgres, SSH, SMTP): pass-through plus redaction;
  the Teleport-style local authenticated tunnel is the recorded shape if
  ever wanted
- **The ⑤ redaction** is exact-match: transformed output passes; an unknown
  agent on a PTY triggers neither layer (the ROADMAP's stated residual)
- **The rules are repository-trusted** (P5): a signed carrier (5-B) is the
  follow-up that would change that
- **Connector tokens are cached in memory for up to an hour** per run; a
  process dump of the proxy exposes them (as it exposes every decrypted value
  of any `run`)

## 13. Item flagged for the owner — crypto outside CRYPTO_SPEC

Two operations use WebCrypto in the CLI without a CRYPTO_SPEC section:
(a) the ephemeral CA (ECDSA P-256 / SHA-256 signatures over hand-encoded
X.509) and (b) the GitHub App JWT (RSASSA-PKCS1-v1_5 / SHA-256 over the
member's App key). The record's position: both are **transport and
third-party-protocol clients**, not operations on maruhi's data — (a)
protects the loopback hop between the child and the proxy and dies with
the process; (b) is GitHub's authentication protocol, the same class as the
vendor-API drivers of `maruhi sync`. CRYPTO_SPEC §12's prohibition is on
inventing protocols and primitives for maruhi's own data; neither is
touched, test vectors are unchanged, and `packages/crypto` is untouched.
**The owner is asked to confirm this reading, or to ask for a one-paragraph
CRYPTO_SPEC note stating that TLS termination certificates and connector
protocol clients are outside the spec's scope.** The code is isolated
(der.ts, proxy-cert.ts, proxy-connector.ts) so either outcome is a
documentation change.

**Independent review (§19 D-8) verdict**: defensible in spirit, a literal
breach of CLAUDE.md's "do not implement crypto operations that are not in
the spec" — recommended to take the spec note before merge rather than
leave it as "confirm the reading". The designer agrees and **drafts the
note here for the owner's approval** (spec changes go spec-first with
human approval — CLAUDE.md; nothing in CRYPTO_SPEC.md is edited by this
PR):

> *Draft for CRYPTO_SPEC §12 (prohibitions) — scope note.* This
> specification governs the protection of maruhi's own data (values, keys,
> statements, the chain, wraps, leases). Two classes of cryptographic use in
> the CLI are outside its scope and are not spec operations: (a) transport
> protection the CLI terminates for its own child process (`maruhi proxy
> run`'s per-run certificate authority: ECDSA P-256 / SHA-256 over X.509,
> key in memory only, lifetime = the run); (b) clients of third-party
> authentication protocols on the member's behalf (the `github-app`
> connector's RS256 JWT with the member's own App key). Both use WebCrypto
> only, invent no protocol, and never touch a maruhi protocol object or a
> test vector. Adding a new class to this list is a spec revision.

**Owner ruling (2026-10-02)**: the owner asked whether the designer saw a
problem with the reading, and on "no" authorized writing the note. The
scope note above is now in CRYPTO_SPEC §12 (prohibitions), word for word
except for the pointer to this section. CLAUDE.md is left as it is (the
owner's instruction file; its "WebCrypto only" and "no custom protocols"
rules continue to apply to both classes). The CA key is generated
non-extractable (only a leaf's key is exported, for node:tls — §19 D-8 nit).

## 14. Exhaustion loop (owner-requested — a self-review; pf5-design.md §15's caveat applies)

| Ruling | Round 2 — new candidates | Round 3 | Outcome |
|---|---|---|---|
| P1 where | 1-F reuse the `maruhi agent` daemon as the proxy host: puts the agent-facing network surface inside the process whose job is holding key material (PF5 1-G's reasoning). Rejected. 1-G `maruhi run --proxy` as a flag instead of a subcommand: `proxy run` has its own config, flags, and output and will grow (`proxy serve`); a flag would make `run`'s help carry both. Kept as a subcommand group | nothing new | **unchanged** |
| P2 mechanism | 2-F SOCKS5 for non-HTTP TCP (Claude Code sandbox-runtime): no substitution is possible on an opaque TCP stream, so it buys only an egress allow-list for non-HTTP; `unmatched: block` plus pass-through covers the value story. Not adopted; recorded. 2-G one TLS listener with per-host `tls` contexts (`Bun.serve` `tls: [{serverName}]`): Bun-only and needs the host set at listen time; the per-target loopback server is lazy and runtime-independent | nothing new | **unchanged** |
| P3 CA | 3-F reuse the device key for the CA: mixes the E2EE identity into TLS interception and would put a spec key into a certificate. Rejected. 3-G shorter validity (1 h): a long agent session would start failing mid-run for no security gain (the key dies with the process). Rejected | nothing new | **unchanged** |
| P4 placeholder | 4-E encode the rule's hosts into the placeholder: leaks nothing but also helps nothing (the proxy knows the rule). Rejected | nothing new | **unchanged** |
| P5 rules | 5-F `proxy init` that emits a config skeleton from the schema (every variable withheld with hints): a convenience worth having; **recorded as the next CLI follow-up**, not in PF4's scope. 5-G honour `mode: passthrough` only from a user-level file (Claude Code): the repo file would then be unable to express the common "DATABASE_URL is pass-through" case the team shares; the printed summary and the withhold default carry the safety instead | nothing new | **unchanged** (5-F recorded) |
| P6 substitution | 6-H per-header allow-list as a rule option (`headers: ["authorization"]`): a finer knob than `surfaces` with no observed demand. Not adopted. **6-I scrub response headers too** (a `Set-Cookie` or an echo header carrying the token): the first relay copied response headers unchanged — a value in a response header would have reached the child. **Adopted**: each response header value goes through the same real → placeholder replacement before `writeHead` (pinned by the echo test's `x-echo-authorization`) | nothing new | **6-I adopted** |
| P7 unmatched | 7-D a per-host allow-list separate from the rules (`egress: [...]`): `unmatched: block` + the rule hosts already form one; a second list is a second place to review. Rejected | nothing new | **unchanged** |
| P8 connectors | 8-F `maruhi run --ephemeral` (D2 — client-side short-lived DB users) as a connector: it needs to create and later delete a provider-side object (a DB role), a different lifecycle (teardown) than "mint a token"; the frame's `Minted` shape would need a `revoke`. Recorded with 8-B. 8-G a generic "exec a program to mint" connector: hands plaintext inputs to an arbitrary program's argv/stdin — the shape the diskless rules avoid. Rejected | nothing new | **unchanged** |
| P9 env | 9-A pass `MARUHI_PROXY=1` so a nested `maruhi` can refuse: `buildChildEnvironment` strips `MARUHI_*` by design (run.ts's reasoning for the whole namespace); a marker would need an exception for exactly the mechanism that makes a co-member-chosen name harmless. Rejected | nothing new | **unchanged** |

**This loop's result**: one addition (6-I — response headers scrubbed);
follow-ups recorded — 5-F `proxy init`, 8-B OAuth refresh connector, 1-B a
network-reachable mode for sandboxes on other hosts, 5-B signed rules.

## 15. Re-check round (self review against the running implementation)

- **R-1 (P2)**: `handleRequest` first forwarded to the `Host` header's host;
  changed to one loopback server per CONNECT authority before any test
  (pinned: the request's `Host` is overwritten with the target authority)
- **R-2 (P6)**: the test client used `agent: false` with `createConnection`,
  which Node ignores (connects to localhost:80) — a test-side error, fixed;
  the production path never had it
- **R-3 (P9)**: `NO_PROXY` inherited from the parent would have bypassed a
  brokered host; now set empty
- **R-4 (⑤)**: `process.stdout.write` would have clipped the relayed tail
  under `process.exit`; synchronous `writeBytes`
- **R-5 (P8)**: a failed mint was first cached as a failure; now a failure
  is not cached and the next request retries (pinned)
- **R-6 (P3)**: node:crypto's `X509Certificate.keyUsage` is the *extended*
  key usage; the test asserted the wrong field and was corrected (the CA's
  keyCertSign is in `basicConstraints` + `keyUsage` DER, verified by the
  chain check)
- Quality gate: fallow flagged five functions over the complexity
  threshold and two duplicates; all split or shared (`parseConfigHeader`
  now serves sync-config and proxy-config)

## 16. What does not change

- CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC: nothing (§13 asks for confirmation of
  the reading). Test vectors untouched; `packages/crypto` untouched
- The server: nothing
- `maruhi run`'s injection: byte-identical; it gains the ⑤ redaction under
  the stated trigger only. `ci run` the same
- The value-display gate (ADR-0016 decision 7): unchanged; `run` and
  `proxy run` stay allowed under agents

## 17. Implementation

- `apps/cli/src/byte-replace.ts` — the byte-domain replacer and the scrub
  fragment rule (shared by the proxy and the ⑤ redaction)
- `apps/cli/src/der.ts` — the DER writer, PEM, PKCS#1 → PKCS#8
- `apps/cli/src/proxy-cert.ts` — the ephemeral CA and leaves
- `apps/cli/src/proxy-config.ts` — `maruhi.proxy.json` (strict parser,
  `--project` check)
- `apps/cli/src/proxy-rules.ts` — targets, host matching, placeholders
- `apps/cli/src/proxy-server.ts` — the forward proxy (CONNECT / MITM /
  tunnel / plain, inspection, substitution, response scrubbing, decisions)
- `apps/cli/src/proxy-connector.ts` — the connector frame, `github-app`
- `apps/cli/src/proxy-run.ts` — the command body (plan, CA files, control
  env, summary) and the `ProxySeams` test reference
- `apps/cli/src/run.ts` — `RunInput` (`holdSignals`, `redact`),
  `redactionFragments` (the ⑤ trigger); `apps/cli/src/live.ts` —
  `relayRedacted`, `holdingSignals`, `writeBytes`; `apps/cli/src/agent.ts`
  — `runtimeBaseDir` shared
- `apps/cli/src/effect-cli.ts` — `maruhi proxy run`; `cli-formatter.ts` —
  the run-shaped command set
- `apps/cli/src/json-record.ts` — `isRecord`, `unknownKeys`,
  `parseConfigHeader` (shared with sync-config.ts)
- Tests: `byte-replace`, `proxy-cert`, `proxy-config`, `proxy-connector`,
  `proxy-server` (Node, end to end over sockets), `proxy-run` (through
  `runCli`), `live-proxy` and `live-run` (Bun probes with curl / Bun fetch
  / a real child), the ⑤ trigger cases in `pull-run.test.ts`; the help
  golden and the `redacted.test.ts` unwrap inventory updated
- Public docs: `/docs/credential-brokering` (new), `/docs/ai-agents`
  (the run section rewritten), README docs list

## 18. Exhaustion loop on the decisions made during implementation (2026-10-02 — owner-requested)

The owner asked whether every point needing a ruling was looped until no
option remained. It was not: §14 looped the nine design rulings, but a
set of decisions made while implementing were taken directly (the same
gap pf5-design.md §17 closed for PF5). This section runs the loop on each
of them (a self-review again — §14's caveat applies). Two produced a
strictly-better option and were implemented in this round (D, E); one is
an owner question (M).

| # | Decision taken | Round 2 — candidates | Round 3 | Outcome |
|---|---|---|---|---|
| A | A rule naming a variable the environment lacks → **Warning, nothing injected**; a connector input missing → **error before the child starts** | (a) error for both: makes one config unusable across environments that differ in variables (dev lacks what prod has) and refuses a run that is otherwise safe. (b) warning for both: a connector that cannot mint would fail at first use with a 502 inside the agent's session instead of at the human's prompt. (c) a per-rule `optional: true`: a knob for a case the warning already handles | nothing new | **unchanged** |
| B | Decisions reported on **stderr** (summary always; one line per request with `--verbose`), no log file | (a) `--log-file` JSON lines (Infisical): a request path or query can carry a pass-through value the child put there — a log file would then hold a plaintext value on disk, against the diskless invariant. (b) buffer the per-request lines and print at exit (keeps an agent's TUI clean): loses the live view `--verbose` exists for; the summary already covers the quiet case. (c) a `NoticeLedger`-style dedupe: lines are per request and differ | nothing new | **unchanged** (B-a rejected on the invariant) |
| C | Inherited `NO_PROXY` replaced by an **empty** value | (a) keep the parent's `NO_PROXY` minus the rule hosts: wildcard rules and CIDR entries make the subtraction unreliable, and an exclusion that survives routes a brokered host around the proxy (the placeholder then fails safely, but brokering silently stops). (b) keep the parent's value unchanged: the same hole. Empty is the fail-closed choice; local servers still work through the proxy's plain path | nothing new | **unchanged** |
| D | `Accept-Encoding: identity` upstream so the response is scrubbable | (a) **decompress gzip / deflate / br in the proxy when a server compresses anyway, deliver identity**: a server that ignores the request header would otherwise hide an echoed value from the scrubber — the scrub would be fail-open for exactly those servers. ~20 lines of `node:zlib`. (b) refuse a compressed response (502): breaks legitimate servers for a case the proxy can handle. (c) re-compress after scrubbing: no gain for the client; cost | nothing new | **(a) adopted and implemented** (pinned by the `/gzip` origin test) |
| E | The CA-file variables set: SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / GIT_SSL_CAINFO / AWS_CA_BUNDLE (bundle), NODE_EXTRA_CA_CERTS / DENO_CERT (CA) | (a) **add PIP_CERT, CARGO_HTTP_CAINFO, NIX_SSL_CERT_FILE, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH** (pip, cargo, nix, gRPC-based cloud SDKs): more clients honour the CA at zero cost. (b) JAVA_TOOL_OPTIONS for the JVM trust store: an execution-control variable (run.ts's denylist) that would also need a keystore file — documented as the client's own flags instead. (c) SSL_CERT_DIR: a directory of hashed certificates (c_rehash) — a second artifact for clients the file already covers | nothing new | **(a) adopted and implemented** |
| F | ALPN **http/1.1 only** on brokered hosts | (a) HTTP/2 termination (`node:http2` over the TLSSocket): a second server stack in the loopback hop for no brokering gain; every client falls back. (b) h2 upstream only: the client side is what negotiates. Recorded as a residual (docs) | nothing new | **unchanged** |
| G | Request bodies toward brokered hosts **buffered up to 32 MiB**, larger refused with guidance (6-E) | (a) stream with substitution and chunked upstream: a surface refusal after headers are sent can only be a reset — the agent gets no reason. (b) a configurable cap: a knob for uploads that belong to unbrokered hosts anyway. (c) stream when no matching rule allows `body` (nothing to substitute): inspection for misuse (a placeholder in the body → 403) still needs the bytes | nothing new | **unchanged** |
| H | One loopback `node:http` server **per brokered authority** (the handler trusts the CONNECT target) | (a) one server plus a map from the loopback connection's remote port to the target: works, but ties correctness to a port bookkeeping step a refactor can drop — the bug R-1 fixed would come back silently. (b) encode the target in a synthetic header the wrapper injects: a client-forgeable header is the very thing P2 refuses to trust | nothing new | **unchanged** |
| I | Placeholder = `mhp_<NAME>_<22 alphanumerics>` | (a) shorter (16): still unguessable (~95 bits), but 22 costs nothing and some clients cap tokens well above this. (b) a shape flag per rule (`placeholderShape: "ghp"`) generating a format-valid fake: the fixed `placeholder` string already covers format-validating clients | nothing new | **unchanged** |
| J | Connector tokens cached in the proxy's memory until five minutes before expiry; **not minted at startup** (8-E) | (a) mint at startup to fail fast on a bad App key: fail-fast is already given for missing inputs; a bad key surfaces as a 502 with GitHub's message at first use, and an unused run mints nothing. (b) refresh margin 10 min: GitHub tokens live 60 min; 5 min absorbs clock skew and a slow request | nothing new | **unchanged** |
| K | `maruhi.proxy.json` as its **own file** (not a section of `maruhi.sync.json`) | (a) a unified `maruhi.json` with `sync` and `proxy` sections: a rename of a shipped SY artifact for no functional gain; the two files have different reviewers (deploy owners vs whoever runs agents). (b) `maruhi.proxy.json` next to `maruhi.sync.json` with a shared header parser (`parseConfigHeader`): done | nothing new | **unchanged** |
| L | Pass-through values are **not** looked for in inspected requests (only placeholders are) | (a) refuse a request toward a brokered host that carries a pass-through value (known-value exfiltration guard): exact match on values the proxy already holds — but a legitimate flow can carry one (a deploy API receiving a `DATABASE_URL`, exactly what `maruhi sync` does), so a refusal needs a per-rule or per-run policy; unmatched tunnels cannot be inspected either way. (b) warn in the verbose log only. **Recorded as a follow-up** (`passthroughInRequests: allow \| block` or a per-variable flag) rather than adopted blind | nothing new | **unchanged** (L-a recorded) |
| M | `maruhi run` under a detected agent **stays plain `run`** (ADR-0016 decision 7) | (a) when `maruhi.proxy.json` exists and an agent is detected, `maruhi run` behaves as `proxy run`: an agent that forgets (or is never told) to use `proxy run` still gets placeholders — strictly safer for the agent case. It changes `run`'s contract under agents, which decision 7 fixed as "allowed as-is". (b) a Warning from `run` under an agent when a proxy config exists ("use `maruhi proxy run`"): no contract change, less protection. **An owner ruling (ADR-0016 revision), not a PF4 decision — put to the owner** | nothing new | **owner question** |
| N | Pass-through values go to the ⑤ redaction; **placeholders do not** | (a) redact placeholders too: they are not secrets, and hiding them makes an agent's log unreadable for no gain | nothing new | **unchanged** |
| O | Signals held for `proxy run` (SIGINT ignored, SIGTERM / SIGHUP forwarded) — the `maruhi agent` shape; plain `run` unchanged | (a) hold signals for plain `run` too: a behaviour change outside PF4's scope with no proxy to protect. (b) kill the child on SIGINT to the parent: the terminal already delivers SIGINT to the child; doubling it changes interactive shells' behaviour | nothing new | **unchanged** |

**This loop's result**: two adoptions (D — compressed responses are
decompressed before scrubbing; E — four more CA-file variables), one
follow-up (L — a pass-through exfiltration guard with a policy knob), one
owner question (M — `run` under an agent when a proxy config exists).

## 19. Independent review round (2026-10-02 — owner-requested)

Two independent reviewer agents attacked the branch: one on code
correctness and security (**C-n** below, with probes run under Node 22 and
Bun 1.4.2), one on design, spec consistency, and docs (**D-n**). Each
finding was verified before acting. The self-run loops (§14, §18) had
missed every finding below — the same lesson as pf5-design.md §16.

### 19-1. Code / security findings

| # | Finding (severity) | Verified | Disposition |
|---|---|---|---|
| C-1 | **The redaction relay broke pipe semantics** (high): `maruhi run -- yes \| head -1` never ended (`writeBytes` swallowed EPIPE and kept reading the child), and a grandchild holding the pipes (`sleep 20 &`) pinned `run` until it exited | Yes — reproduced both (hang vs 12 ms with inherited stdio) | **Fixed**: on EPIPE the reader is cancelled and the child gets SIGPIPE (the semantics a pipe gives); after the child exits the relays get a 500 ms grace, then are cancelled. Pinned under Bun (`pipe-probe.ts`: flood → exit 141 in ~15 ms; grandchild → ~515 ms) |
| C-2 | **The carry-over held *replaced* bytes**, so a shorter pattern consumed at a chunk edge hid a longer one (medium): `DATABASE_URL` ⊃ `DB_PASSWORD`, cut inside the URL → `postgres://user:[redacted]@db…` leaked the rest; 21 of 51 cuts differed from the whole-buffer result | Yes — reproduced | **Fixed**: the replacer core is a single left-to-right scan over **source** bytes, longest match first, applying only matches that start before the cut and holding source bytes (correctness argument in byte-replace.ts). Pinned over every cut position with nested secrets |
| C-3 | **`proxy.close()` hung while any client connection was open** (medium): the raw `net.Server` has no `closeAllConnections`; a tunnel a grandchild kept open pinned `proxy run` and the CA directory was never removed | Yes — reproduced (no resolve in 3 s) | **Fixed**: client sockets are tracked and destroyed in `close()` (the bridge tears the other side down). Pinned: close with an open tunnel resolves at once |
| C-4 | **No encoding of substituted values** (medium): a value with a space, `&`, `#`, `%` in the query, or a CR/LF in a header, ended as `500 internal error (TypeError)` (the HTTP client refused the request — no injection possible under either runtime, but the value was unusable there) | Yes | **Fixed**: path / query substitution percent-encodes the value; a header value that is not a single Latin-1 line is refused with a 502 naming the variable; a body is written as it is (documented) |
| C-5 | **`scrubbers()` minted connectors on every inspected request**, including toward unrelated hosts (medium; = D-1) | Yes | **Fixed** (see D-1) |
| C-6 | **No backpressure in the response relay, client disconnect ignored** (medium): a 64 MiB body read slowly grew the proxy by ~110 MiB | Yes — measured | **Fixed**: `stream.pipeline(upstream, decoder?, Transform(replacer), res)` carries backpressure and tears every stage down; `res.on("close")` destroys the upstream request |
| C-7 | `Host` sent with the default port (medium; = D-13b) | Yes | **Fixed**: `hostHeaderOf` omits a default port |
| C-8 | `--verbose` printed the query string (medium; = D-7) | Yes | **Fixed**: decisions carry the path without its query; the verbose line is written synchronously |
| C-9 | Plain HTTP toward an unmatched host went through inspection but was counted "brokered" (medium; = D-3) | Yes | **Fixed**: a `relayed` decision kind and summary count; documented |
| C-10 | **SAN `dNSName` malformed for hosts of 128+ characters** (low): the context tag's content was sliced off an IA5String whose length needed two bytes | Yes — reproduced with openssl | **Fixed**: `tlv(0x82, bytes)`; pinned with a 180-character host |
| C-11 | Sequential `split/join` let replacement output take part in later matches (low) | Yes | **Fixed** by the single-scan rewrite (C-2); pinned |
| C-12 | A fixed `placeholder` could be any 8 printable characters (`"password"`), rewriting ordinary traffic and tripping 403s; two placeholders could nest (low) | Yes | **Fixed**: 16 characters minimum; a placeholder that contains or is contained in another is refused |
| C-13 | The early-ClientHello wrap works only with `socket.resume()` deferred into the `net.connect` callback (low) | Yes — both orders measured by the reviewer | **Commented** in code (a refactor that resumes early loses the ClientHello); still untested by a client (curl waits for the 200) — residual |
| C-14 | Over-long head: 431 written but reading continued (low) | Yes | **Fixed**: listener removed, socket destroyed after the response |
| C-15 | A failed loopback `listen` was cached forever for that authority (low) | Yes | **Fixed**: the rejected promise is dropped from the map |
| C-16 | HEAD / 204 / 304 lost `Content-Length` (low) | Yes | **Fixed**: bodiless responses keep their framing headers and relay no body; pinned |
| C-17 | `writeBytes` busy-looped on EAGAIN (low, pre-existing in `writeLine`, now exercised by bulk output) | Yes | **Fixed**: a one-millisecond `Atomics.wait` between retries |
| C-18 | The response scrub lacked the per-line / JSON-escaped forms (low; = D-5) | Yes | **Fixed** (see D-5) |
| C-19 | A trailing-dot authority (`api.example.test.`) was treated as unmatched (nit) | Yes | **Fixed**: normalized in `parseAuthority` / absolute-form parsing; pinned |
| C-20 | Dead / odd code: `decisionLines`, a `typeof … === "string"` that was always true, a type assertion on `parseAbsoluteForm`'s result, fire-and-forget verbose logging (nit) | Yes | **Fixed** (`originFormOf`; `Effect.runSync`) |
| C-21 | Under redaction the child loses `isTTY` even when only stderr is redirected or an agent runs on a PTY (nit) | Yes — by design | **Documented** (docs: "an interactive program loses colours and terminal detection") |

### 19-2. Design / spec / docs findings

| # | Finding (severity) | Verified | Disposition |
|---|---|---|---|
| D-1 | **The connector minted on the first brokered request to *any* host** (high): `scrubbers()` resolved every credential to build scrub patterns, so a run talking only to OpenAI minted a GitHub token, and a bad App key re-attempted a mint on every request (swallowed). Docs, P8 / 8-E and §18 J said otherwise | Yes | **Fixed**: `BrokeredCredential.known()` returns the values already held **without minting** (a broker rule's value; a connector's current and previous token); the scrub uses `known()`, and `resolve()` runs only for the credentials a request actually uses. Pinned: a request using only GITHUB_TOKEN never calls the connector |
| D-2 | **Docs and ROADMAP promised refusal of a placeholder toward "any other host"; a blind tunnel sends it** (high) | Yes (the live probe asserts exactly that) | **Fixed**: docs reworded — refused toward a host the proxy inspects; toward a host no rule names it travels as the placeholder and the host rejects it (nothing substituted). ROADMAP entry reworded |
| D-3 | "Hosts no rule names are not intercepted" was false for plain HTTP, and such requests were tallied "brokered" (medium) | Yes | **Fixed** (C-9): `relayed` kind; the docs state the asymmetry |
| D-4 | **The newline cut deviated from the ROADMAP ⑤ design** (medium): applied only when no fragment spanned a line, so PEM values held lines back; §11 and the ROADMAP said "implemented as written" | Yes | **Fixed**: `cutAtNewline` (§11 revised); pinned (a PEM's lines are emitted as they complete) |
| D-5 | The response scrub used the raw value only, not the shared fragment rule (medium) — a value with `"` or a newline echoed in JSON passed | Yes | **Fixed**: `scrubPatterns(credential.known(), placeholder)` per credential; the previous token of a re-minted connector is scrubbed too. Pinned (a quoted value echoed in JSON) |
| D-6 | Docs said running `maruhi run` in a terminal "changes nothing", but under a detected agent host the child is piped even at a TTY (medium) | Yes | **Fixed**: docs say "in a terminal that no agent host controls" and describe the piped-output consequence |
| D-7 | `--verbose` printed paths with the query (medium) | Yes | **Fixed** (C-8) |
| D-8 | §13 is a literal breach of a CLAUDE.md absolute rule and should not stay as "confirm the reading"; the ROADMAP's bold "No spec revision" overstated; the CA key was extractable (medium) | Yes | **Partly fixed, rest for the owner**: the spec note is drafted in §13 for approval (spec-first with human approval — not written into CRYPTO_SPEC by this PR); the ROADMAP says "pending the §13 confirmation"; the CA key is now non-extractable |
| D-9 | The client-compatibility list was largely untested; Go reads `SSL_CERT_FILE` on Linux only (so `gh` on macOS would fail) (medium) | Yes (Go's root_unix.go build tags) | **Fixed**: the docs separate "verified on Linux" from "expected from documented behaviour" and name the macOS Go caveat |
| D-10 | `http://` rules could name any host — a value in cleartext over the network, contradicting "only on the loopback" (medium) | Yes | **Fixed**: plain `http://` is accepted only for `localhost`, `*.localhost`, `127.0.0.0/8`; pinned |
| D-11 | The docs' own `AGENTS.md` snippet steered agents to `maruhi run` (medium) | Yes | **Fixed**: the snippet says `proxy run` when `maruhi.proxy.json` exists. On owner question M the reviewer recommends (b) a Warning from `run`, not an automatic switch on a fail-open detection signal — recorded with M |
| D-12 | "Decompressed first" overstated: zstd / stacked / unknown encodings were forwarded compressed and **unscrubbed** (medium) | Yes | **Fixed**: `zstd` handled where the runtime has it; an unknown or stacked encoding is refused (502, fail closed); pinned |
| D-13 | Record / docs inaccuracies (low): (a) "system roots" were the runtime's bundled roots (corporate roots lost); (b) default port in `Host`; (c) IPv6 CONNECT refused undocumented; (d) summary mixed units; (e) "nothing else is written" — two files; (f) a `mkdtemp` failure left the started proxy open; (g) `User-Agent` differed from sync-http's `maruhi-cli/`; (h) token exposure outlasts the run | Yes | **Fixed**: (a) bundled + `tls.getCACertificates("system")` where available, docs say so; (b) C-7; (c) documented; (d) the summary names units; (e) docs say two files; (f) the directory is created first and each resource has its own `ensuring`; (g) `maruhi-cli/`; (h) see D-14a |
| D-14 | Strictly-better options the loops missed: (a) **revoke the installation token at teardown**; (b) **a per-run proxy credential in the proxy URL** (closes the "anyone on the machine" residual; every common client sends `Proxy-Authorization` from userinfo); (c) **add brokered values to the ⑤ redaction** for `proxy run` | (b) measured: curl, Bun (option and env), Node undici, Python urllib, git all send it | **All three adopted**: `release()` on connectors (`DELETE /installation/token`, both current and previous tokens, best effort with a Note on failure); `credential` on the proxy (407 with `Proxy-Authenticate` otherwise; constant-time compare; the address printed on stderr carries no credential); broker values join the redaction fragments. Pinned end to end |
| D-15 | Record wording nits (0700 dir vs 0600 files; no independent-review section yet) | Yes | **Fixed** (this section) |

Checked by the reviewers and found correct: no header or request-line
injection via a substituted value under either runtime; the CONNECT target
binding (never the `Host` header); the blind tunnel's end-to-end TLS; the
Basic decode / substitute / re-encode; keep-alive, pipelining, `Expect:
100-continue`, HEAD through the loopback hop; the X.509 chain (openssl and
node:crypto), the ECDSA and PKCS#8 encodings, the CA key never serialized;
the connector's single in-flight mint, refresh margin, error wording, and
the structural "inputs never injected" rule; the control-variable ordering
and `MARUHI_*` filtering; the redaction trigger; the English-only and
no-telemetry rules; ADR-0014 / ADR-0016 consistency (the agent-triggered
piping is a ROADMAP-authorized contract change for `run`, now stated in the
docs); the `maruhi.proxy.json` and temp-file treatment under the diskless
invariant.

**Owner question M (§18), with the reviewer's recommendation**: prefer (b)
— `maruhi run` under a detected agent prints a Warning pointing at `proxy
run` when `maruhi.proxy.json` exists — over (a) an automatic switch, which
would change `run`'s contract on a fail-open deny-list signal plus a repo
file's presence. If the owner wants (a), make it a committed config key so
the human's file opts in, and record it as an ADR-0016 revision. Neither is
implemented here.

**Residuals added by this round**: the early-ClientHello path is untested
by a real client; a body value is substituted raw (an `&` or `"` inside a
form or JSON body is the client's to encode); a background process the
child leaves behind loses its output half a second after the child exits
under redaction; connector revocation is best effort (a network failure
leaves the token to expire on GitHub's side).

## 20. Ruling M settled — the structural answer, and the in-account default (2026-10-02 — owner ruling)

The owner asked whether a **structural** solution to M exists rather than a
stopgap, and authorized the designer's recommendation if not.

**Finding: a structural solution exists only across a security-principal
boundary.** Inside one OS user account there is none: the OS keychain is a
per-user store (any process of the user reads it with the same `maruhi`
binary; macOS code-signing ACLs cannot tell the agent's `maruhi` from the
human's), and same-user processes are mutually transparent (ptrace,
`/proc/<pid>/mem` — KL2's record says the same of the `maruhi agent`
holder). Every in-account mechanism — agent detection, a repository file, a
user-config policy, a gate — is advisory against a hostile process with the
user's keys. Considered and rejected as "structural": a key-holding daemon
that fences callers by process ancestry (SO_PEERCRED / LOCAL_PEERPID —
technically sound, but it requires the device key **not** to be in the OS
keychain, a change of the workstation persistence model, and is still
defeated by ptrace); a server-side refusal (E2EE: decryption is the key's,
the server has no say); signed rules in the schema (5-B — hardens the rules,
not the holder of the key).

**Adopted — two tracks, both implemented**:

1. **The structural track (i), first-class**: the agent runs where it has no
   maruhi credential (a container, a devcontainer, another OS user), and the
   host's `maruhi proxy run` is its only path. `proxy run --listen host[:port]`
   binds beyond the loopback (the loopback MITM hop servers stay on the
   loopback), `--advertise host[:port]` is the name the sandbox knows the
   host by (the proxy URL and its credential carry it). A non-loopback bind
   prints a Warning. The docs carry the Docker Desktop recipe (`--listen
   0.0.0.0 --advertise host.docker.internal`, the CA bundle mounted). This is
   Infisical's "the agent identity has only the Proxy permission" in maruhi's
   terms, without a server holding anything.
2. **The in-account default (f)** — not a stopgap but the permanent answer
   for local use without a sandbox: when `maruhi.proxy.json` is present in
   the working directory, **`maruhi run` brokers exactly as `proxy run`**
   (shared `brokeredRun`), for people and agents alike — the repository's
   file decides, detection decides nothing about injection. **`maruhi run
   --plain`** keeps the real-value shape and is gated like a ceremony
   (`ensurePlainRunAllowed` — a known agent is refused; stdin and stdout must
   be terminals): the one shape that hands a program the plaintext while the
   repository has said the values are brokered requires a person. A broken
   config is reported, never skipped (skipping would silently inject real
   values). Without a config, `run` is unchanged; `ci run` reads no config.
   Recorded as **ADR-0016 revision 2**.

**Why (f) over the reviewer's (b)** (a Warning): a Warning is read by neither
an agent under injection nor reliably by a human inside an agent host, and
it keeps the detection signal as the thing that decides. (f) inverts the
default — protective without detection, permissive only through the
existing fail-closed human gate — which is the structure decision 7 itself
uses for display. The `AGENTS.md` snippet in the docs can say plain `maruhi
run` again, since `run` now does the right thing.

**Residuals stated**: (f) raises the bar from "run a command" to "defeat the
human gate or read another process's memory" — qualitatively meaningful
against a prompt-injected agent, not a boundary against a hostile one; the
repository file is editable by an agent in the repository (the trust level
of today's `run`) — *as first written this residual undercut the bar: an
agent could rewrite the file to `passthrough` and run again; closed by the
acceptance ceremony of §21 R-8 (a config is applied only once a person
accepted its content on the machine)*; `--plain` cannot be used from a pipe
or CI when a config exists (by design — `ci run` is the CI path). The ancestry-fencing holder
and the signed rules (5-B) stay recorded as follow-ups, both weaker than the
sandbox shape and both large.

**Pinned**: `run` with a config brokers (placeholder, pass-through, proxy
variables, signals held); `--plain` at a human terminal injects the real
values and says the config is not applied; `--plain` under a detected agent
or without a terminal is refused before any network, child not started;
plain `run` without a config is byte-identical; a broken config in the
working directory is an error; `--listen` / `--advertise` bind and
advertise as told and a malformed address is a usage error; the help golden
carries the new flags.

## 21. Pull-request review round (2026-10-02 — review bots on PR #243)

Two review bots (pullfrog, Cursor Bugbot) read the full diff after the PR
opened. Six findings; every one verified against the code and fixed in the
same round (R-1 … R-6), plus the CI gate's two findings (R-7).

- **R-1 (pullfrog) — the redaction over-matched short values.** Every
  injected value and every line of a multi-line value became a pattern,
  whatever its length; with `PORT=3000` or a JSON value's `{` line injected,
  every occurrence of those bytes in CI logs or in redirected output became
  `[redacted]`, and `run -- pg_dump > dump` could corrupt the dump. Options
  looped: (a) a fixed length floor; (b) an entropy threshold (unpredictable
  for the user — a passphrase of words fails it); (c) exempting values by
  their declared type (`number` / `boolean` — the declaration is
  member-written metadata, so a schema edit could switch a value's redaction
  off: fail-open, rejected); (d) telling a file redirect from a pipe (does
  not address CI logs, and a file is the persisted transcript the redaction
  exists for). **(a) adopted**: `MIN_FRAGMENT_LENGTH = 8` in `scrubPatterns`
  (whole value, lines, JSON-escaped forms alike — the proxy's response scrub
  included, so a short brokered value is not scrubbed either). An incidental
  8-byte match in unrelated output is not plausible; a secret under 8 bytes
  protects nothing. The reviewer's open question (should a file redirect
  trigger at all) is answered no change: the trigger stays "stdout or
  stderr is not a terminal".
- **R-2 (pullfrog) — the hop servers were on TCP loopback ports without
  the credential check.** The per-host plaintext handlers behind the TLS
  termination and the plain-HTTP handler listened on `127.0.0.1:0`; any
  local process (or another OS user on the host — the sandbox shape) that
  found the port could send a placeholder straight to a hop and have the
  real value substituted: a confused deputy that bypassed D-14b. Options:
  a remote-port allowlist of the sockets the proxy itself opened (racy —
  the server's `connection` and the client's `connect` order is not
  defined in one process), a one-connection listener per bridge (a window
  between listen and connect), Unix domain sockets inside the run's 0700
  directory (the OS fence; measured working under Bun 1.4.2 and Node for
  both `net.connect(path)` and `http.Server`). **Unix sockets adopted**:
  `ProxyOptions.hopDir` (the `privateRuntimeDir` the run already creates),
  sockets `plain` and `h<n>`. Paths are length-limited (104 / 108 bytes) —
  a too-deep directory fails `startProxy` with the existing message.
  Windows (named pipes) stays outside support. Pinned: the directory holds
  socket files only, one per brokered authority plus `plain`.
- **R-3 (pullfrog) — `release()` stopped at the first revocation
  failure**, leaving the second held token alive for GitHub's full hour.
  Every revocation is attempted; the failures are reported together.
- **R-4 (Bugbot) — `*.localhost` was unusable.** The two-label wildcard
  check rejected it before the loopback exception ran, and the error text
  told the user to write exactly that. `*.localhost` is now the one
  single-label wildcard, and every name under `.localhost` is the loopback
  (RFC 6761) with or without a wildcard; `*.127.0.0.1` stays refused.
- **R-5 (Bugbot) — a failed leaf issuance was cached**, so one transient
  WebCrypto failure kept a host unreachable for the rest of the run. The
  rejected promise is evicted; pinned with a one-shot `exportKey` failure.
- **R-6 (Bugbot) — `--listen ::1` was misparsed** (split at the last
  colon). Bracketed `[::1]:port` / `[::1]` and a bare IPv6 literal (more
  than one colon, no bracket) are parsed; the parser is split into two
  helpers to stay under the complexity gate.
- **R-7 (CI fallow gate)** — the unused `ia5String` DER helper is removed;
  `loadSyncConfigIfPresent` / `loadProxyConfigIfPresent` share
  `loadIfPresent` in json-record.ts (the 17-line clone).

A second pass of the bots on the merge commit added three findings:

- **R-8 (Cursor Security Reviewer, HIGH) — an agent rewrites the config.**
  `--plain` is a human ceremony, but `maruhi run` / `proxy run` applied
  whatever `maruhi.proxy.json` said; an in-account agent could set
  `unlisted: passthrough` or add a host it controls and run again, which is
  the plaintext the ceremony denies. §20 had stated the residual ("the
  repository file is editable by an agent") but framed (f)'s bar as "defeat
  the human gate", which this shows was too strong: the bar was "edit one
  file in the repository". Options looped: (a) document the residual
  honestly and nothing else (leaves ruling M's rationale weaker than the
  owner was told); (b) gate `passthrough` behind the ceremony on every run
  (kills the agent use case — pass-through exists for the agent's non-HTTP
  values); (c) **acceptance by a person — the direnv model**: the accepted
  file's content is recorded per user outside the repository
  (`<config dir>/proxy-accepted.json`); a content match applies silently;
  a new or changed file is accepted, and recorded, when the ceremony
  evidence is present (no known agent, stdin and stdout terminals) and
  refused otherwise with a message naming who accepts and how; (d) the same
  record in the OS keychain (a real fence on macOS through the item ACL,
  none on Linux; and the keychain is reserved for the two secrets by the
  CLI's persistence rule); (e) pure trust-on-first-use without the
  ceremony (an agent would "first-use" its own file — rejected); (f)
  signed rules — the config's hash recorded on the project's chain by an
  owner, four-eyes-able, which an agent cannot forge (structural inside
  maruhi's trust model; a spec revision; large). **(c) adopted now, (f)
  stays the recorded structural successor** — the UX is the same (a person
  accepts the rules), so (c) is its local precursor, not a detour. The
  content is stored verbatim rather than hashed (no cryptography needed
  for a non-secret file, and a mismatch can be explained); the record is
  keyed by the config's resolved path so `./maruhi.proxy.json` and
  `--config /…/maruhi.proxy.json` are one entry; the ledger follows the
  fingerprint-ledger discipline (0600, atomic rename, a corrupt file is
  reported and never overwritten). *As first implemented, acceptance was
  implicit — a person's next terminal run recorded a new or changed file;
  R-14 below replaced it with the explicit `maruhi proxy accept`.* Residual, stated plainly: the record is
  a file the same user can write — the bar is now "edit a file outside the
  repository that nothing in the repository points at", meaningful against
  a prompt-injected agent working in the repository, not a boundary against
  a hostile same-user process (the sandbox shape remains that). A person
  running `maruhi run … | tee log` for the first time is refused once and
  told to run it from the terminal first. Pinned end to end (agent refused
  before any network, pipe refused, a person accepts and the agent runs,
  the agent's rewrite is refused, the person accepts the change, the cwd
  default and `--config` share the entry, a corrupt record is reported).
  ADR-0016 revision 2 carries the sentence.
- **R-9 (Bugbot) — `isHeaderSafe` applied to every substituted value**,
  so a multi-line secret with `surfaces: ["body"]` was refused although
  body substitution is byte-based. The check now runs on the header as it
  will be sent (a `Basic` credential is base64 and passes; a placeholder
  found only in the path, query, or body is never a header). Pinned.
- **R-10 (Bugbot) — the run's proxy credential was not in the redaction**:
  `printenv` under an agent would have left the `HTTPS_PROXY` userinfo in a
  transcript, and whoever holds it can use the proxy. The credential's
  bytes join the redaction fragments. Pinned.

A third pass (on the R-1 … R-7 commit) added two:

- **R-11 (Bugbot) — an IPv6 `--listen` built an invalid proxy URL** (the
  authority was `host:port` without brackets, and an advertised address
  with a colon was taken as "already has a port"). `advertise` is parsed
  like `listen` (`host[:port]`, port 0 = the bound port) and both are
  formatted by one `formatAuthority` that brackets an IPv6 literal (RFC
  3986). Pinned through the CLI (`--advertise [fd00::2]:3128` → the URL's
  host is `[fd00::2]`).
- **R-12 (Cursor Security Reviewer, MEDIUM) — in sandbox mode the proxy
  could reach host-local services.** With `--listen 0.0.0.0` (the Docker
  recipe) and `unmatched: allow`, a destination no rule names is tunnelled
  or relayed from the host's network namespace, so a sandboxed child could
  ask for `http://169.254.169.254/` (the cloud metadata service) or
  `127.0.0.1:<a host service>` — crossing the isolation the mode is for.
  Options: (a) `unmatched: block` by default in sandbox mode (an egress
  allow-list — the strongest, but it makes every unrelated host a rule, and
  the mode's premise is "the agent's traffic is its own except the brokered
  hosts"); (b) a deny-list of host-local destinations (loopback, link-local,
  unspecified — by literal, by name, and by what the name resolves to), off
  on the loopback binding (the child is on the host already and gains
  nothing from the proxy), bypassed by a rule naming the host (the member's
  explicit decision — `http://localhost:8787` for a dev server); (c) (b)
  plus private ranges (10/8, 172.16/12, 192.168/16, fc00::/7 — rejected: a
  bridge-networked sandbox reaches them on its own, and an internal API on
  one is an ordinary destination). **(b) adopted** (`proxy-guard.ts`): the
  name is resolved *before* the connection and the result checked, so a
  name pointing at the loopback is caught; a name that does not resolve is
  refused (fail closed — the connection would fail anyway). (a) stays
  available to the member as `unmatched: block`, and the docs say so. *The
  residual first written here — "a DNS answer that changes between the
  check and the connect, a race in milliseconds" — was wrong in kind, not
  just degree: see R-19.* Pinned: literal,
  name, resolved metadata address, unresolvable name, plain `localhost`
  refused; a public name tunnelled; a rule-named loopback host still
  brokered; the loopback binding unguarded.

A fourth pass (on the R-8 … R-10 commit) found the acceptance ceremony's
two gaps and one ledger nit:

- **R-13 (pullfrog) — delete the file, or change directory.** R-8 applied
  only when a config was present; `rm maruhi.proxy.json` (or
  `maruhi run --project <id>` from another directory) made `proxyConfig`
  null and the real values were injected with no ceremony — the same
  outcome with less effort. **Every brokered run now marks its project as
  brokered on this machine** (in the same ledger, `projects`), and plain
  `run` for a marked project without a config in the working directory is
  gated like `--plain`: a person at a terminal may inject the real values
  (with a Note saying what is happening), an agent or a pipe is refused
  and told to run from the repository that holds the config. A project
  never brokered on the machine is unchanged. The mark is written after the
  project resolves (a failure to write it is a Note — the run itself is the
  safe shape).
- **R-14 (pullfrog) — implicit acceptance.** A changed file was recorded
  as a side effect of the person's next ordinary `maruhi run` in a
  terminal, so an agent's rewrite only had to wait for the user's next
  `maruhi run -- npm run dev`. Options: (a) an interactive confirmation
  inside `run` showing the rules (the person is already there, but a
  reflexive "y" in a flow about something else is weak evidence of
  review); (b) **an explicit command, `maruhi proxy accept [--config]`**,
  the direnv shape — a new or changed file is refused everywhere, at a
  terminal too, with a message naming the command; the command is itself
  the human ceremony (agent and non-terminal refused), prints the rules it
  accepts (brokered variables and hosts, pass-through and withheld names,
  the two defaults — names only), and says whether it is a first use, a
  replacement, or a no-op. **(b) adopted.** Nothing in `run` or
  `proxy run` writes the record any more.
- **R-15 (Bugbot) — `readLedger` folded every read error into
  `missing`**, so an `EACCES` / `EISDIR` on the ledger would have let a
  writer replace it with an empty book. Only `ENOENT` is `missing`; any
  other read failure reads as `corrupt`, which no writer overwrites (the
  pins / fingerprint-ledger discipline). own-devices.ts shares the reader
  and gains the same behaviour.
- (nit) `privateRuntimeDir`'s JSDoc now names the hop sockets as well as
  the CA files.

Pinned end to end: agent and pipe refused with the command named; a person
at a terminal refused too until `proxy accept`; `proxy accept` refused to
an agent and to a pipe; accept → agent runs; rewrite → refused → accept
("replaces the content accepted before") → runs; a second accept is a
no-op; the cwd default and `--config` share one entry; the file deleted →
agent and pipe refused, a person allowed with the Note; another directory
→ the same gate; a corrupt record reported by both commands and never
overwritten.

A fifth pass (on the R-11 / R-12 commit) found the guard's own gap:

- **R-16 (pullfrog, Bugbot, Cursor Security Reviewer — all three) — the
  host-local guard matched text, not value.** `::1`, `::`, `fe80:` and the
  dotted mapped form were strings; `CONNECT 0:0:0:0:0:0:0:1:443`,
  `::0:1`, the hex-mapped `::ffff:7f00:1` and `::ffff:a9fe:a9fe` passed
  as "an IP literal, not local" and were tunnelled to the loopback or the
  metadata service — the exact confused deputy R-12 closed. A bracketed
  `[::1]` from `URL.hostname` went the other way (sent to the resolver,
  refused as unresolvable). Options: hand-written IPv6 parsing to bytes
  (forty lines, our own bugs), canonicalizing through `new URL(…)` and
  unwrapping mapped hex pairs by hand, or `net.BlockList` with the ranges
  (parses every textual form; measured identical under Bun 1.4.2 and
  Node, hex-mapped forms included). **`net.BlockList` adopted**: 127/8,
  0/8, 169.254/16, ::1, ::, fe80::/10, the IPv4-mapped forms of the three
  IPv4 ranges (`::ffff:7f00:0/104`, `::ffff:0:0/104`,
  `::ffff:a9fe:0/112`), and the AWS IPv6 metadata address
  (`fd00:ec2::254`, which the security reviewer named — a ULA, so a range
  rule would not catch it). Brackets and zone ids are stripped before
  classification. Pinned: every alias form through `isHostLocalAddress`,
  four of them over `CONNECT` in the sandbox-mode proxy test, and the
  bracketed literal over plain HTTP.
- **R-17 (pullfrog) — the R-13 gate read a corrupt ledger as "never
  brokered"** and injected the real values. The mark's lookup now carries
  the three states and a `corrupt` record fails the gate closed with the
  same message the acceptance check gives (R-15's discipline). Pinned.

A sixth pass (Cursor Security Reviewer on the R-17 commit) found three
more, two of them against my own R-12 / R-13 residuals:

- **R-18 (HIGH) — the R-13 mark was armed by the first brokered run, not
  by `proxy accept`.** Between a person accepting the file and anyone
  running under it, deleting the file (or changing directory) still
  injected the real values, and a failure to write the mark was a Note.
  `proxy accept` now resolves the project the rules are for (the new
  `--project` flag, else the config's `project`, else the default
  project — no network) and marks it; a brokered run still marks (a
  config accepted for one project and used under another `--project`),
  and a mark that cannot be written is an error, not a Note. Pinned: the
  file deleted right after `proxy accept`, before any brokered run → the
  agent is refused.
- **R-19 (HIGH) — the guard resolved a name, then connected by name.** I
  had called the gap "a rebinding race in milliseconds"; the reviewer is
  right that it is not a race: a resolver the sandbox controls answers a
  public address to the guard's query and the metadata service to the
  connect's, deterministically (query counting). The guard's clearance now
  carries the address it checked (`Target.resolved`), and the tunnel and
  the plain relay connect to that address — one resolution, the one that
  was checked. Pinned with a counting resolver (one query, the connection
  asked for the first answer) for `CONNECT` and for plain HTTP.
- **R-20 (MEDIUM) — metadata endpoints outside link-local.** Alibaba
  Cloud's is `100.100.100.200`, in the shared address space (RFC 6598,
  100.64/10), which is never a public destination; the whole range and
  its IPv4-mapped form join the deny-list. The RFC 1918 ranges stay
  reachable (R-12's reasoning holds: an internal API on one is an ordinary
  destination; a metadata endpoint on one is not a pattern any provider
  uses).

A seventh pass (Cursor Security Reviewer on the R-18 … R-20 commit):

- **R-21 (MEDIUM) — the response scrub did not know the proxy's own
  wire forms.** The scrub matched a value raw, per line, and JSON-escaped
  (the `maruhi sync` rule), but the proxy itself puts two other forms on
  the wire: a value substituted into the path or query travels
  percent-encoded, and a `Basic` credential is decoded, substituted, and
  re-encoded as Base64. An origin that echoes the request URL or the
  `Authorization` header echoes those forms, which the child could decode.
  Two additions: the percent-encoded form of every held value joins the
  global patterns (when it differs from the raw text), and per request the
  re-encoded `Basic` blob is scrubbed back to the blob the client sent
  (which carries the placeholder). Transformations an origin applies on
  its own (its own Base64 of a bearer token, a hash) stay out of scope —
  exact match is the rule; what is new is that the proxy's *own* encodings
  count as exact. Pinned: the URL echo of a query-substituted value and
  the body-and-header echo of a `Basic` credential both come back as the
  client sent them.

An eighth pass (Cursor Security Reviewer on the R-21 commit):

- **R-22 (MEDIUM) — two more metadata endpoints outside the ranges**:
  Oracle Cloud's `192.0.0.192` (in the IETF protocol-assignment block,
  RFC 6890 192.0.0.0/24 — never a public destination; the block joins) and
  Azure's wire server `168.63.129.16` (a single address in otherwise
  public space; added as an address, with its mapped form). The list is
  now: loopback, unspecified, link-local, 100.64/10, 192.0.0.0/24,
  168.63.129.16, their IPv4-mapped forms, fd00:ec2::254. A deny-list of
  this kind is only as complete as the last provider surveyed; the
  member's complete answer remains `unmatched: block`, and the docs say so.
- **R-23 (HIGH) — the acceptance record followed `MARUHI_CONFIG_DIR` /
  `XDG_CONFIG_HOME`.** The ledger sat next to `config.json`, whose
  directory those variables redirect; an agent limited to the repository
  can set one for its own invocation, point the CLI at a directory it
  writes (a forged ledger — or an empty one, which reads as "never
  brokered"), and apply its own rules while the keychain still serves the
  token. The R-8 claim ("a file outside the repository that nothing in the
  repository points at") did not hold while an environment variable
  pointed at it. Options: (a) ignore the override variables for this one
  file and anchor it to the home directory — but `os.homedir()` reads
  `$HOME`, which an agent can also set; (b) **anchor it to the account's
  home from the system user database** (`os.userInfo().homedir`, getpwuid
  — no environment variable moves it); (c) keep the ledger in the OS
  keychain (a real fence on macOS; against the CLI's persistence rule —
  the keychain is for the token and the device key — and no fence on
  Linux); (d) an integrity tag over the ledger with a keychain-held key
  (a new local crypto operation: a spec revision, and (c)'s rule again);
  (e) the chain-recorded signed rules (the structural successor, already
  the follow-up). **(b) adopted**: `acceptedProxyConfigsPathOf(home)`
  builds `<home>/.config/maruhi/proxy-accepted.json`, and live.ts passes
  the passwd home. Consequence: a user who set `XDG_CONFIG_HOME` globally
  finds this one file under `~/.config/maruhi` rather than their XDG
  directory — stated in the docs. Residual: a uid without a passwd entry
  (some containers) falls back to `homedir()` and so to `$HOME`; the
  record says so. The same-user residual (the user's own process can
  write the file) is unchanged and remains the sandbox shape's job.

A ninth pass (Cursor Security Reviewer on the R-22 / R-23 commit):

- **R-24 (MEDIUM) — acceptance was not bound to a project.** The record
  was keyed by the file's resolved path and content; a file accepted for
  one project (another checkout, a more permissive one) could be pointed
  at this project's values with `--config`, since `checkProxyConfigProject`
  only fires when both the config's `project` and `--project` are set. The
  accepted entry now carries the projects it was accepted for;
  `proxy accept` adds the current project (the same content for a second
  project is "project added", a changed content starts the list over),
  and the check requires the project the run is about to decrypt — before
  any network when the project is known without it (the flag, the config's
  `project`, the default project), and again against the project the
  prologue resolved. A file accepted for another project is refused with a
  message naming `maruhi proxy accept --project`. Pinned.

Also in this round: `origin/main` merged (effect 4.0.0 stable — the
`effect/unstable/*` import paths moved to `effect/*`; two conflicts, ROADMAP
and ci-run.ts).
