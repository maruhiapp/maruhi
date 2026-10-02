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
