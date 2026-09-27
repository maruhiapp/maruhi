# Competitive comparison — maruhi vs Phase / Infisical / Doppler / Shelve / Keyway

Status: 2026-09-04 draft (internal memo. The competitor roundup in ADR-0014 Context〔2026-08-07〕re-verified against each company's public information and updated).
Competitor facts were checked on each company's official site, docs, and GitHub as of 2026-09-04. Items marked **[unverified]** could not be confirmed from public information.
maruhi-side facts are based on the current state of CRYPTO_SPEC / AUTH_SPEC / ADR / ROADMAP / SELF_HOSTING (pre-release; before the invite-only beta).

> **Correction**: the `keyway.ai` raised in the request is an AI company for commercial real estate (KeyDocs / KeyComps etc.), not the secrets-management Keyway.
> The secrets-management Keyway is **`keyway.sh`** (GitHub org `keywaysh`). This document covers the latter.

---

## 0. Conclusion (the big picture first)

maruhi's difference is not "feature count" but the **default trust model**. Ordering the 5 companies by "who can read the plaintext":

| | Default encryption model | Can the operator (server) read values? | Is there an operator-served Web that ships a decryptor? |
|---|---|---|---|
| **maruhi** | **E2EE (zero-knowledge) by default**. The server becomes "member N+1" only via a per-project, owner-signed opt-in (`grant_server`) | **Cannot** (exception: DEKs of granted environments only; grants are always displayed) | **None** (ADR-0018: hosted Web holds neither keys nor plaintext. Decryption happens only in each user's CLI) |
| Phase | E2EE by default. However sync, REST API, and external identities require enabling SSE (the environment root key is stored on the server) | Cannot by default. Can once SSE is enabled | Yes (the Web console decrypts in the browser) |
| Infisical | **Server-side encryption** (E2EE removed in 2023-06) | Can | Yes (the dashboard receives plaintext) |
| Doppler | **Server-side encryption** (wrapped by GCP KMS/HSM) | Can (can be limited to via customer KMS with Enterprise EKM) | Yes |
| Shelve | **Server-side encryption** (project DEK + platform KEK) | Can | Yes |
| Keyway (.sh) | **Server-side encryption** (separated Go crypto service. States itself "not zero-knowledge") | Can (its threat model states "you trust the operator") | Yes |

On top of that sit the **diskless invariant** (the product has no feature that generates `.env`), **serverless one-shot self-hosting** (`wrangler deploy` on the Cloudflare free tier), **zero telemetry**, and **fail-closed-by-default agent isolation**. This combination of five properties holding simultaneously is unique to maruhi; individual elements exist partially in competitors (the ADR-0014 correction "diskless run alone does not differentiate" is unchanged by this research).

On the other hand, maruhi clearly lags in feature breadth (sync targets, SDKs, rotation, dynamic secrets, PKI), track record (stars, customers, SOC 2), non-GitHub auth, Windows, and a GUI that can handle values. §4 lists these honestly.

---

## 1. Per-company summaries (as of 2026-09-04)

### Phase (phase.dev — Phi Security Inc.)
- Positioning: "Secrets management for teams and AI agents". GitHub ★913 (founded 2023-05). SOC 2 Type II (2025-11). Pre-seed (2025-07). Hosted only on AWS eu-central-1
- Crypto: **E2EE by default**. libsodium (XChaCha20-Poly1305 / X25519 / Ed25519 / Argon2id / BLAKE2b). Recovery via BIP39 24 words. Per-environment key pair wrapped to user public keys. **However** Secret Syncs (GitHub Actions / Vercel / AWS SM…), the public REST API, and External Identities (AWS IAM / Azure) **require enabling SSE (server-side encryption)**, which stores a copy of that environment's root key on the server. Has a "Sealed" type (write-once, no read-back)
- Self-host: Docker Compose / Helm / each cloud. **PostgreSQL + Redis (Valkey) + Django backend + worker + frontend + nginx**. No serverless option. EE features require a license key
- CLI (rewritten in Go in 2026-03): `phase run -- <cmd>` (memory injection), `phase shell`, **`phase secrets export` (dotenv / json / yaml / toml … 10 formats)**, offline mode (encrypted cache of API responses stored locally)
- License: MIT + `ee/` under a proprietary Enterprise license (open-core)
- Agent: `phase ai enable` installs a SKILL.md (Claude Code / Cursor / Copilot). The CLI detects agents, masks values as `[REDACTED]` by default, and blocks `phase shell`, `printenv`, etc. inside `phase run`. **No MCP server**. The homepage's "AI egress proxy" (hands a decoy value and substitutes the real value at the communication boundary) is **nowhere in the docs, changelog, or code [unverified — marketing ahead of implementation]**
- Pricing: Free (5 users/SAs, 3 apps, 3 environments) / Pro $10/user/mo (annual) / Enterprise $25
- Telemetry: self-host states "no external transmission". No telemetry traces in the CLI either

### Infisical (infisical.com)
- Positioning: "Security infrastructure for developers and AI agents". Integrated platform for secrets + PKI + SSH + KMS + PAM. GitHub ★29,102 (2022-08). Series A $16M (2025-06, Elad Gil). SOC 2 Type II / HIPAA / FIPS 140-3. US / EU regions
- Crypto: **server-side envelope encryption** (`ENCRYPTION_KEY` → KMS root → org / project data keys → AES-256-GCM). External KMS supported (AWS KMS / CloudHSM / GCP KMS). **E2EE became opt-out in 2023-06, and the current security docs describe only the server-side model** ("E2EE was received as a nice-to-have, not a must-have")
- Self-host: single Docker / Compose / Helm / ECS Fargate / GKE. **PostgreSQL 14+ and Redis required** (refuses to start without Redis). Recommended 2–4 vCPU / 4–8 GB. EE phones home to a license server (offline license available)
- CLI: `infisical run -- <cmd>` (`--watch` restarts), **`infisical export --output-file` (writes dotenv etc. to disk)**, **Infisical Agent (a sidecar renders secrets to files from templates)**
- Integrations: the widest. Machine-ID auth (Universal / K8s / AWS / Azure / GCP / **OIDC〔GitHub Actions documented〕** / SPIFFE), K8s Operator, many Secret Syncs, SDKs in 9 languages, Terraform / Pulumi / Ansible
- Team: RBAC, approval workflows, temporary access, SAML / LDAP / SCIM, audit logs, PITR, **rotation, dynamic secrets**, PKI (ACME), SSH certificates, KMS, PAM (session recording)
- Agent: **MCP server** (`get-secret` returns plaintext), **Agent Vault** (OSS, HTTPS_PROXY-style MITM credential proxy, 2026-04), **Agent Proxy** (GA 2026-07-30. A broker that substitutes real values for dummy credentials at the communication boundary. Available on all plans)
- License: MIT + `ee/` under a proprietary Enterprise license (open-core). CLI MIT, MCP Apache-2.0
- Pricing: Free (5 identities, 3 environments) / Pro $20/identity/mo / Advanced $40 / Enterprise
- Telemetry: server `TELEMETRY_ENABLED` **defaults to true** (opt-out). CLI has PostHog built in (`--telemetry` flag. Default value unverified)

### Doppler (doppler.com)
- Positioning: "Secrets management for humans and AI agents" / "Per-Seat Secrets Management. No Agent Fees." (pivoting from the old SecretOps toward AI agents / non-human identities). 76,000+ orgs (self-reported). Series A $20M (2022). SOC 2 / ISO 27001 (2025-09). GCP us-central1 only (no EU region)
- Crypto: **server-side encryption**. AES-256-GCM, workspace keys wrapped by GCP KMS (HSM), a tokenization service separates keys from the Web tier. The backend decrypts, and the dashboard, API, CLI, and all sync targets receive plaintext. Enterprise EKM can route through customer KMS. Only Doppler Share (one-off sharing) is browser E2EE
- Self-host: historically cloud-only. **"Doppler On-prem" announced 2026-06-08, Enterprise-only** (packaging undisclosed)
- CLI (Apache-2.0): `doppler run -- <cmd>`, `--mount` (named pipe). **`doppler secrets download --format=env|json|yaml` (writes `.env` to disk)**. **`doppler run` writes an encrypted snapshot to `~/.doppler/fallback` by default** (PBKDF2 + AES-256-GCM. The default passphrase is derived from the token etc.)
- Integrations: among the most (GitHub Actions / GitLab / CircleCI, AWS / GCP / Azure, Vercel / Netlify / Heroku / Railway / Render / Fly / Cloudflare Pages, K8s Operator, Terraform〔OIDC auth 2026-06〕). OIDC Service Account Identities (GitHub Actions / K8s / GitLab / AWS)
- Team: RBAC (custom roles are Enterprise), Change Requests (diff review + approval), rotation (via Lambda), dynamic secrets (Enterprise), activity log + rollback, SIEM forwarding
- Agent: official MCP server (experimental. Can read and write plaintext. Tags MCP operations in the audit log). `/agents` page (branch config + read-only expiring tokens). **No agent detection / refusal mode**
- Pricing: Developer (free up to 3 users, then $8) / Team $21/user/mo / Enterprise
- Telemetry: the CLI `analytics` flag is **on by default** (disable with `doppler configure flags disable analytics`. What it collects is undocumented)

### Shelve (shelve.cloud — HugoRCD, Apache-2.0)
- Positioning: "Open-source secret & environment management". For individuals and small teams in the Nuxt / Vue ecosystem. Since v3, "AI agents as first-class citizens". ★452 (founded 2024-02). Primarily solo-maintained (Hugo Richard). No company or funding disclosure. Released v3.1–3.4 in 2026-05–08, active
- Crypto: **server-side two-layer envelope** (project DEK with `iron-webcrypto` AES-256-GCM, DEK sealed by a KEK from `NUXT_PRIVATE_ENCRYPTION_KEY`). The server decrypts. No E2EE / zero-knowledge claims. Recovery is DB backup only
- Self-host: **Vercel is the official recommendation**. Nuxt / Nitro + PostgreSQL (Neon recommended) + Resend or GitHub / Google OAuth. A Docker image is mentioned on the landing page but no Dockerfile or docs found **[unverified]**. No serverless Edge (Workers) option
- CLI (`@shelve/cli`): `shelve run -- <cmd>` (memory injection. However **stores an AES-256-GCM encrypted cache in `~/.shelve/cache/` for 24h**), **`shelve pull` writes a plaintext `.env` to disk** (monorepo expands per package), `push` sends a local `.env`, `diff` / `sync` / `generate` (`.env.example`)
- Integrations: only push to GitHub Actions secrets via a GitHub App
- Team: Owner / Admin / Member, scoped API tokens (IP CIDR restriction, expiry), audit log (actor, IP, UA). **Version history / rollback undocumented**
- Agent: agent detection via std-env (Cursor / Claude / Codex). **`shelve pull` under an agent returns `AGENT_BLOCKED` without `--yes`** (same line of thinking as maruhi's ADR-0016 decision 7). `shelve init` generates 5 kinds of files such as `.cursorignore`. Agent Skills distributed at `/.well-known/skills/`. No MCP. JSON output does not include values
- Pricing: no pricing page. Hosted is "currently free"
- Telemetry: no traces in code or docs ("none found", not a "documented guarantee")

### Keyway (keyway.sh — Nicolas Ritouet, personal)
- Positioning: "Your secrets don't belong in AI context." / "GitHub-native secrets management. Repo access = secret access.". Origin: the founder had Claude autocomplete a `.env` DB password (2025-12 article). ★8 (monorepo created 2025-11, consolidated 2026-02). Solo development (almost all commits co-authored with Claude). No funding. Keyway Cloud is Railway, EU
- Crypto: **server-side AES-256-GCM**. Encryption happens in a separated Go gRPC "crypto service" (~300 lines, private network); claims "keys never touch the API server, DB, or public surface". However the API server temporarily handles plaintext and the API / dashboard return plaintext. **The threat model itself states "using Keyway Cloud means trusting the operator" (not zero-knowledge)**. Self-host `ENCRYPTION_KEY` docs are contradictory: "cannot be rotated after deploy" (SELF-HOSTING.md) vs "zero-downtime rotation possible" (threat model)
- Self-host: Docker Compose with 5 services (postgres / Go crypto / Fastify / Next.js / Caddy) + GitHub App required. No serverless
- CLI (Go): `init` / `push` (sends `.env`) / **`pull` (writes `.env` to disk by default)** / `run -- <cmd>` / `set` / `diff --show-values` / `scan` (leak detection). `KEYWAY_DISABLE_TELEMETRY`
- Integrations: bidirectional sync with Vercel / Netlify / Railway, GitHub Actions (`keyway-action`. Can also write `.env`)
- Team: no independent user management. **Permissions = mirror of GitHub repository roles** (production defaults to admin-only write). Activity log (Free 7 days → Team 90 days), version history / rollback
- Agent: MCP server (`@keywaysh/mcp`. **`keyway_get_secret` returns plaintext to the model**). No agent detection. The threat model itself admits "if you run an agent inside `keyway run`, secrets are in that process's environment". A gap between the pitch (AI-Proof) and the implementation
- License: **no LICENSE file in the monorepo** (GitHub API `license: null`). The archived old repo is MIT. The site text wavers between "MIT" and "BSD-3" **[unverified — legally undecided]**
- Pricing: three conflicting descriptions coexist (top page €0/€9/€19/€39, docs $4/$15/$39, a 2026-07 commit says "Pro removed, flattened") **[unverified]**
- Telemetry: CLI has PostHog **on by default** (opt-out). Dashboard also uses PostHog (optional on self-host)

---

## 2. Comparison tables

Legend: ● = present / default, ◐ = conditional / partial, ○ = absent, — = N/A / unknown. The maruhi column is based on **what is implemented**; ROADMAP-only items are marked "planned".

### 2-1. Trust model & crypto

| Consideration | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| Zero-knowledge by default (operator cannot read values) | ● | ● | ○ | ○ | ○ | ○ |
| Scope of server-side decryption | Per-project × environment owner-signed opt-in (`grant_server`). Recorded on the chain, verifiable by all members, always displayed | Per-app / SA SSE enablement (required for sync, API, external IDs) | Everything | Everything (EKM routes via customer KMS) | Everything | Everything |
| Operator-served Web that ships a decryptor | ○ (ADR-0018. Web is read + revoke only. The bundle contains no decryption code path) | ● (in-browser decryption) | ● (receives plaintext) | ● | ● | ● |
| Published crypto spec | ● CRYPTO_SPEC (the single source of truth, with test vectors, guarantees / non-guarantees explicit in §14) | ◐ architecture / cryptography docs | ◐ security internals | ◐ Security Fact Sheet | ◐ encryption.md | ◐ security / threat-model |
| No custom primitives | ● WebCrypto + HPKE (RFC 9180) | ● libsodium | ● | ● | ● iron-webcrypto | ● Go stdlib |
| Cryptographically bound membership | ● Signed hash chain (role, invite acceptance, server grant are append-only and verifiable by all members) | ◐ "cryptographic enforcement" of RBAC (details unpublished) | ○ (RBAC on the DB) | ○ | ○ | ○ (mirrors GitHub roles) |
| Authenticity of values & metadata (server alone cannot forge) | ● Value signatures, DEK commitments, manifest, checkpoints (CRYPTO_SPEC §14.2) | ◐ | ○ | ○ | ○ | ○ |
| Detection of rollback / omission / split view | ◐ Local floor + out-of-band anchor + checkpoints (limits explicit in §14.3) | — | — | — | — | — |
| Recovery | ● Recovery code (operator cannot restore. ADR-0014 decision 4) | ● BIP39 24 words | — (server holds keys) | — (account MFA only) | — (DB backup) | — (trash / history) |
| Audit log actor | Internal user_id + key FP only (provider IDs not written) | User | User | User | User + IP + UA | User |
| Post-hoc tamper detection of audit log | ◐ Notarizes cumulative audit hash in checkpoints | ○ | ○ | ○ | ○ | ○ |

### 2-2. Diskless & CLI

| Consideration | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| `run -- <cmd>` memory injection | ● | ● | ● | ● | ● | ● |
| **No `.env` generation / export feature in the product** | **● (invariant. In future only explicit SOPS-compatible operations)** | ○ `secrets export` 10 formats | ○ `export --output-file` + Agent renders files | ○ `secrets download` | ○ `pull` writes plaintext `.env` | ○ `pull` writes `.env` by default |
| No plaintext / encrypted cache on disk | ● (persistent state is only tokens, master key〔OS keychain〕, non-sensitive config) | ○ encrypted cache in offline mode | ◐ (CLI has a backup-deletion function [unverified]) | ○ encrypted snapshot at `~/.doppler/fallback` by default | ○ `~/.shelve/cache/` for 24h | ● [unverified] |
| Default for value display | `pull` is metadata-only. `pull --show` is a 2-layer fail-closed: TTY primary boundary + agent detection | Masked by default (under agent detection) | Shows | Shows | JSON output has no values | `diff --show-values` |
| "Contract" features that work without values | ● Value-free schema (`maruhi schema` / `schema export`〔JSON Schema〕/ `verify-snapshot` / `lint`). Required-ness fulfillment verifiable from signatures | ○ | ○ | ○ | ◐ `generate` (`.env.example`) | ○ |
| CLI implementation / distribution | Bun-compiled single binary (linux / darwin. Windows experimental) + npm (Bun required). Homebrew from v0.1.0 | Go | Go | Go | Node (Citty) | Go + npm + brew |
| CLI telemetry | **None ("say nothing")** | None | PostHog built in (default unverified) | **On by default** (opt-out) | No traces | **On by default** (opt-out) |

### 2-3. Self-host & operations

| Consideration | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| Self-host | ● | ● | ● | ◐ Enterprise-only On-prem (2026-06) | ● | ● |
| Required infrastructure | **Cloudflare account only** (Workers + DO SQLite + D1. **Works on the free tier**) | Postgres + Redis + Django + worker + frontend + nginx | Postgres + **Redis required** + Infisical (2–4 vCPU) | Undisclosed | Vercel + Postgres (Neon) + Resend / OAuth | Docker Compose 5 services + GitHub App |
| Serverless / Edge | ● | ○ | ○ | ○ | ◐ (Nuxt on Vercel. Postgres separate) | ○ |
| Deploy steps | Centered on `wrangler deploy`. ~10 minutes (SELF_HOSTING.md, verified by real deploy) | Compose / Helm | Compose / Helm / ECS | — | Vercel + DB setup | Compose |
| Operating standing processes (patching, DB maintenance) | None (managed) | Yes | Yes | — | DB can be managed | Yes |
| Server outbound traffic | None (no EE license verification exists) | None (offline license available) | **`TELEMETRY_ENABLED` defaults to true** + EE phones a license server | — | No traces | PostHog (optional) |
| Hosted version | In preparation (pre invite-only beta. `my.maruhi.app`. Free → paid at GA) | ● eu-central-1 | ● US / EU | ● us-central1 | ● free | ● Railway EU |
| Auth IdP | **GitHub OAuth only** (ADR-0009. WorkOS insertion point reserved) | Google / GitHub / GitLab / Okta / Entra / Authentik + SCIM | SAML / LDAP / SCIM / OIDC | SSO (Team+) / SCIM | Email OTP / GitHub / Google | GitHub only |
| Compliance | None (pre-release) | SOC 2 Type II | SOC 2 Type II / HIPAA / FIPS | SOC 2 / ISO 27001 | None | None |

### 2-4. Team, integrations & agents

| Consideration | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| Roles | 4 roles on the chain (owner / admin / member / reader) | RBAC + environment / path scopes | RBAC + custom roles + approvals | RBAC + Change Requests | Owner / Admin / Member | Mirror of GitHub roles |
| Key rotation on offboarding | ● Epoch rotation (removal / demotion obligates rotating all environments) + needs-rotation detection | ◐ | — (server keys) | — | — | — |
| CI integration | GitHub Actions only. **OIDC + temporary key wrap scoped to the response (lease)**. The server is only a "DEK broker" — it does not decrypt values and cannot inject fake values into CI (§9.1). CI side also verifies via repository anchor | Service tokens (no OIDC). Sync requires SSE | OIDC (GitHub Actions documented), K8s, AWS…, K8s Operator | OIDC Service Account Identities, K8s Operator | GitHub App pushes to Actions secrets | `keyway-action` (can also write `.env`) |
| Cloud / PaaS sync | ○ planned (SY series — gate for the invite-only beta. First-class targets are Vercel / Cloudflare Workers) | ● many (SSE required) | ● most | ● most | ○ | ◐ Vercel / Netlify / Railway |
| SDK | ○ (only the HttpApi-derived client) | Node / Python / Go | 9 languages | Node / Python | ○ | ○ |
| Version history / rollback | ◐ monotonic version + prev linkage (no display UI yet) | ● + PITR | ● + PITR | ● | ○ | ● |
| Rotation / dynamic secrets | ○ (future: upstream auto-rotation) | ● / ◐ AWS IAM only | ● / ● | ● / ● Enterprise | ○ | ○ |
| PKI / SSH / KMS / PAM | ○ | ○ | ● | ○ | ○ | ○ |
| GUI with values | ○ (ADR-0018. TUI → value-free `maruhi ui` → a value-ful GUI would be its own ADR) | ● Web console | ● | ● | ● | ● |
| Web dashboard (no keys) | ● read + revoke only (W series implemented. Design pass DP in progress) | ● | ● | ● | ● | ● |
| Refusing value display under agent detection | ● fail-closed 2 layers (primary TTY + std-env) | ● masking + blocks `shell` / `printenv` | ○ | ○ | ● blocks `pull` with `AGENT_BLOCKED` | ○ |
| MCP server | ○ (after demand is measured, as a thin wrapper over `maruhi schema`. **Policy: never serve values**) | ○ (SKILL.md approach) | ● returns plaintext | ● returns plaintext (experimental) | ○ (distributes Agent Skills) | ● returns plaintext |
| credential brokering (never giving agents the real value) | ○ planned (Phase 3 `maruhi proxy run`. Composed with E2EE so "neither server nor agent holds plaintext") | ◐ pitches an "AI egress proxy" but no implementation found | ● Agent Proxy (GA 2026-07) + Agent Vault | ○ | ○ | ○ |
| Exposing a value-free schema to agents | ● `maruhi schema` (names, types, required, descriptions only) | ○ | ○ | ○ | ○ | ○ |

### 2-5. License, pricing & maturity

| Consideration | maruhi | Phase | Infisical | Doppler | Shelve | Keyway |
|---|---|---|---|---|---|---|
| License | server / web = **FSL-1.1-MIT** (only competing-SaaS use prohibited, converts to MIT after 2 years). **CLI / crypto / core / api-schema = MIT** (the decryptor is OSI-licensed) | MIT + `ee/` proprietary (open-core) | MIT + `ee/` proprietary (open-core) | Core proprietary. CLI Apache-2.0 | Apache-2.0 (whole) | **No LICENSE** (descriptions inconsistent) [unverified] |
| Free tier | Self-host unlimited (CF free tier). Hosted free during beta | 5 users / 3 apps | 5 identities / 3 environments | 3 users | hosted free | 1 private repo |
| Paid | Undesigned (at GA) | $10–25 / user | $20–40 / identity | $8–21 / user | None | €9–39 (descriptions inconsistent) |
| Maturity | pre-release (v0.1.0-rc). Solo development. Real-deploy verified, dogfooding | ★913, SOC 2, Pre-seed | ★29k, Series A, cash-flow positive | 76k orgs, Series A | ★452, solo | ★8, solo |

---

## 3. maruhi's advantages (differences vs competitors)

The following are properties competitors lack or do not make the default. None of the pitch is "absolutely the safest" — it is framed as **"a wider circle of parties you don't have to trust"** (ADR-0014 decision 1).

1. **Zero-knowledge is the default, and exceptions are cryptographically visible**
   - Infisical / Doppler / Shelve / Keyway are server-side encryption: the operator (or an attacker holding the server) can read values. Phase is E2EE by default, but using sync, the REST API, or external identities stores a copy of the environment root key on the server (SSE).
   - maruhi's `grant_server` is the same "make the server a member" operation as Phase's SSE, but **it lands on the append-only chain with an owner signature, every member can verify it, the UI / CLI display it continuously while granted, and it can be undone via `revoke_server + rotate_epoch`**. Moreover, on the CI lease path the server only brokers DEKs and never decrypts values (CRYPTO_SPEC §9.1). That "how much was disclosed" is bound by crypto rather than an audit log is something none of the 5 have.

2. **The operator does not ship the decryptor (Web is outside the TCB)**
   - All 5 offer "view values in the Web". Even for E2EE Phase, as long as the operator-served JS is the decryptor, delivery-side malice or XSS leaks every secret. maruhi cuts this structurally in ADR-0018 (the hosted Web bundle contains no decryption code path; the session-scoped API is limited to read + revoke), and decryption happens only in the MIT-licensed CLI (source-verifiable, self-buildable). **maruhi is the only one whose "the operator can't read it" claim can be verified in code.**

3. **Diskless is an "invariant", not a "feature"**
   - As the ADR-0014 correction says, every competitor has `run` injection. The difference is **having no feature that writes `.env`** (Phase `export`, Infisical `export` / Agent, Doppler `download` + the default fallback file, and Shelve / Keyway `pull` all place plaintext or an encrypted cache on disk). maruhi places no encrypted cache either; `pull` defaults to metadata only, and value display is a 2-layer fail-closed of TTY primary boundary + agent detection.
   - The "migrate off `.env`" entry point is `schema import` (reads an explicitly-argumented `.env` client-side only, interactively approves each variable, and offers to delete the source file once all declarations exist) — provided as a **one-way street that never makes `.env` the source of truth**.

4. **Serverless one-shot self-hosting (zero operations, free tier)**
   - Phase / Infisical / Keyway require standing operations with Postgres (+ Redis) + multiple containers, Shelve needs Vercel + Postgres, Doppler is Enterprise-only On-prem. maruhi is **`wrangler deploy` onto the Cloudflare free tier in ~10 minutes**, with no patching, DB maintenance, or scale operations. It is the only answer for "want to self-host but don't want to babysit a VM".
   - There is also no server-side license verification or license-server phone-home (Infisical EE does phone home).

5. **Can state zero telemetry ("say nothing") as a guarantee**
   - Doppler CLI and Keyway CLI have analytics on by default; Infisical has server telemetry on by default + PostHog in the CLI. Phase documents no transmission from self-host; Shelve shows "no traces". maruhi makes client → zero outbound an absolute rule; even the install script talks to nothing but github.com. The boundary against operational observation (metrics of your own server) is already spelled out in hosted-design.md §5-1.

6. **Agent isolation is fail-closed by default**
   - Competitors today come in two strains: (a) handing plaintext over MCP (Infisical / Doppler / Keyway — Keyway pitches "AI-Proof" while its MCP returns plaintext), (b) detecting agents and masking / blocking (Phase, Shelve). maruhi has (b) as **2 layers — TTY primary + known-agent secondary** — plus the already-implemented third form of **value-free schema** (disclose only names, types, required, and descriptions to agents; required-fulness is verifiable from signatures, and `schema lint` checks drift against code): "hand over the contract, not the values". MCP is deferred as a thin wrapper that never serves values.
   - On credential brokering (substituting the real value at the communication boundary) Infisical leads (Agent Proxy GA). maruhi's Phase 3 `maruhi proxy run` plans to compose with E2EE so that "neither server nor agent holds plaintext" — the consistency is the difference (Infisical's broker presumes the server holds plaintext).

7. **Authenticity and freshness are handled in crypto, with non-guarantees stated**
   - Value signatures, DEK commitments, meta-statements, environment manifests, checkpoints, and head declarations mean the server alone cannot forge values, names, or DEKs, and detects rollback, omission, and split view (within stated limits). CI workloads are verified too via the repository anchor. No competitor docs have this layer.
   - At the same time, CRYPTO_SPEC §14.3 **enumerates non-guarantees**: availability, plaintext correctness, first-sync client freshness, and collusion residue — the foundation for the threat-model document (H5). Competitor security pages mostly list guarantees; explicit non-guarantees are rare.

8. **No provider IDs in the audit log; offboarding rotation is mandatory**
   - Actors are internal user_id + key FP only (GitHub IDs are not burned into the append-only structure). Removal / demotion obligates rotating all environments, with "needs-rotation detection" to enforce effectiveness. The polar opposite of Keyway's "GitHub role = permission".

9. **License composition is consistent with the trust model**
   - The side that decrypts (CLI / crypto / core / api-schema) is MIT; the server is FSL (only competing-SaaS prohibited, converts to MIT in 2 years). Compared to Phase / Infisical open-core (`ee/` needs a contract for production), Doppler's proprietary core, and Keyway's undecided license, **"the parts you want to verify are OSI-licensed"** and **"no restrictions on self-hosting"** are crisp.

---

## 4. maruhi's weaknesses (honestly)

Differences that must not be hidden by the pitch (ADR-0014 decision 5 "separate honestly").

- **Maturity & track record**: pre-release, solo development, 0 users, no SOC 2 etc. Orders of magnitude behind Infisical (★29k, Series A) and Doppler (76k orgs). Phase is SOC 2'd too
- **Breadth of integrations**: cloud / PaaS sync unimplemented (SY series in progress — gate for the invite-only beta), no SDK, no K8s Operator, CI is GitHub Actions only. Infisical / Doppler have dozens of sync targets
- **Auth**: GitHub OAuth only. No SSO / SAML / SCIM (WorkOS insertion point reserved — ADR-0009)
- **No GUI that handles values**: the Web is read + revoke only. Value entry, viewing, invite acceptance, and key operations are all CLI. Not a fit for "I want to see values in a dashboard" users (an intentional ADR-0018 choice, but an adoption barrier)
- **Zero-knowledge ceremony**: first-time key generation and recovery-code custody, mutual fingerprint verification on invite, device migration. Burdens the competitors (especially the 4 server-side ones) don't have. Frame it as "only first-time and invites"
- **Lose your keys and recovery code and the operator cannot restore** (the price of the promise)
- **Enterprise features**: no rotation, dynamic secrets, approval workflows, PKI / SSH / KMS / PAM. Infisical is an integrated platform, Doppler has Change Requests, Phase already has rotation + dynamic secrets
- **credential brokering / MCP unimplemented** (Infisical has Agent Proxy GA; Doppler / Keyway have MCP). For the "try it now" side of the agent pitch there's only value-free schema + agent-gate
- **Platform dependency**: Cloudflare-only (Workers / DO / D1). Can't run on-prem or on other clouds. Competitors run anywhere Docker does
- **Windows is experimental**, Homebrew unpublished, macOS notarized not yet, checksums unsigned
- **Hosted version not yet open** (HP1's "first 5 minutes" cannot yet be provided). All 5 competitors ship hosted
- **FSL is not OSI open source** (server side). Lined up against Phase / Infisical / Shelve calling themselves "open source" it needs a footnote

---

## 5. One-liner per competitor (what to say to whom)

| Counterpart | How close the experience is | The difference maruhi should state |
|---|---|---|
| **Phase** | Closest (E2EE default, agent detection, Ed25519 / X25519). **The comparison target** | Against "the moment you use sync or the API, SSE puts a key copy on the server": maruhi's grant stays on the chain signed, the server doesn't decrypt values on the CI lease path, and there's no decryption in Web. No Postgres + Redis. Telemetry is zero for both |
| **Infisical** | Main competitor (vault + diskless run + agent proxy) | Dropped E2EE in 2023 (operator, MCP, dashboard see plaintext). Standing operations with required Redis. Telemetry on by default. maruhi restores "not even the operator sees" as the default and has no feature that writes `.env` |
| **Doppler** | Polished experience, most integrations | Fully server-side + cloud-only (On-prem is Enterprise). `run` writes a fallback file by default. CLI analytics on by default. No EU region. maruhi runs in your own CF account |
| **Shelve** | Close in being OSS, solo-built, light. Agent-under `pull` blocking is the same idea | Server-side encryption means the operator can read. `pull` writes plaintext `.env` and `run` leaves an encrypted cache. Vercel + Postgres. maruhi is zero-knowledge + diskless invariant + one-shot Workers |
| **Keyway (.sh)** | Same "don't hand secrets to AI" pitch | Pitch and implementation diverge (MCP returns plaintext, no agent detection, admits "not zero-knowledge"). LICENSE undecided, pricing descriptions inconsistent, ★8. maruhi already implements the same pitch with fail-closed + value-free schema + E2EE |

---

## 6. Positioning sentence (current form of the ADR-0014 tagline)

> **maruhi is secrets management that defaults to handing plaintext to no one — not the operator, not the served Web, not agents — and never writes `.env`. It stands up in your own Cloudflare account with one `wrangler deploy` and sends nothing out.**

Stages: "don't show plaintext to the operator" (now) → "don't hand plaintext to the operator or agents" (Phase 3: `maruhi proxy run`) → "even if a human errs, the secret isn't there" (no-reveal policy).

---

## 6-1. How to use this on the LP / docs (2026-09-04 addendum — record of discussion with the owner)

**Selling points (in priority order)** — all "describe the mechanism plainly" (web-design-pass.md §2), never say "absolutely safest" (ADR-0014 guardrails):

1. The operator cannot read values, and you can verify that in code (E2EE default + decryption only in the MIT-licensed CLI + Web ships no decryptor)
2. Never writes `.env` (`maruhi run` memory injection only. The feature to generate/export simply doesn't exist — the difference is "no writing feature", not "has a diskless run")
3. One shot into your own Cloudflare account (`wrangler deploy`, ~10 min, free tier, no Postgres / Redis / standing VM)
4. Sends nothing (neither the CLI nor the installer talks to anything but github.com. Don't translate "言わざる" literally — describe the mechanism) <!-- english-exempt: quotes the source-language slogan being discussed -->
5. Hand agents only the contract (`maruhi schema` = names, types, required only. Value display is fail-closed in agent environments)
6. Also state what isn't guaranteed (CRYPTO_SPEC §14.3 → link to the threat-model document)

English copy candidates: "Secrets your vendor can't read. Not even us." / "Secrets that never touch disk. `maruhi run` and nothing else." / "One `wrangler deploy`. Your Cloudflare account. Zero telemetry."

**Handling the feature-matrix** — don't publish a broad feature comparison table (it would be near-empty on sync targets, SDK, SSO, rotation, dynamic secrets, GUI, SOC 2, and the row count dilutes. ADR-0014: "don't argue security by feature count"). A table naming competitors risks staleness and disputes (Phase's egress proxy may ship soon; Doppler On-prem's packaging is undisclosed; Keyway's pricing and license descriptions are inconsistent).

Recommended two-tier structure:
- **LP**: a 5-row trust-model table with no competitor names, columns being the 3 types "server-side-encrypted vault", "E2EE but decrypts in Web", "maruhi" (zero-knowledge by default? / ships a Web decryptor? / has a `.env`-writing feature? / needs a standing DB? / sends outbound?). Arguing by type never goes stale
- **docs**: the detailed competitor-named comparison comes later as a dated, sourced comparison page (the shape of Keyway's /vs/ page). §2–§4 of this document are the material. Put §4's weaknesses on the same page to stay consistent with selling point 6

Display discipline: even on the LP, don't use the word "verified" outside the CLI context where signature verification actually happens (CRYPTO_SPEC §14.3-7). "The operator can't read it" can be said; "proven safe" cannot. Don't say "On-prem" — say precisely "Runs in your own Cloudflare account" (On-prem in the strict sense = own DC / air-gap is ruled out as a consequence of ADR-0001).

## 7. Handoff (implications from this comparison. Not decisions)

- With Phase pitching an "AI egress proxy" and Infisical GA-ing Agent Proxy, **credential brokering will likely be "normal to have" within 2026**. Material for re-checking the priority of `maruhi proxy run` (Phase 3 ②)
- Keyway's "pitch / implementation gap" backs the value of **writing "what is not guaranteed" first** in maruhi's threat-model document (H5)
- Doppler's "Per-Seat, No Agent Fees", Phase's "SAs are free", Infisical's "per identity" — for the GA pricing design (L9) the **billing unit for machine / agent IDs** is the question
- 4 of 5 competitors offer hosted with a free tier. For the invite-only beta's "first 5 minutes" (H6), competitors' hosted experience is the comparison bar
- When to re-verify this comparison: when Phase's egress proxy ships, Doppler On-prem's packaging is revealed, and Keyway's LICENSE is decided

---

## Sources (checked 2026-09-04)

- Phase: https://phase.dev · https://phase.dev/security · https://phase.dev/pricing · https://phase.dev/changelog/ · https://docs.phase.dev/security/architecture · https://docs.phase.dev/security/cryptography · https://docs.phase.dev/console/apps · https://docs.phase.dev/cli/commands · https://docs.phase.dev/self-hosting · https://docs.phase.dev/self-hosting/configuration/envars · https://docs.phase.dev/integrations/agents/claude-code · https://docs.phase.dev/access-control/external-identities · https://github.com/phasehq/console(LICENSE, backend/ee/LICENSE)
- Infisical: https://infisical.com · https://infisical.com/pricing · https://infisical.com/docs/internals/security · https://infisical.com/docs/self-hosting/overview · https://infisical.com/docs/self-hosting/configuration/requirements · https://infisical.com/docs/self-hosting/configuration/envars · https://infisical.com/docs/self-hosting/ee · https://infisical.com/docs/cli/commands/run · https://infisical.com/docs/cli/commands/export · https://infisical.com/docs/integrations/platforms/infisical-agent · https://infisical.com/docs/documentation/platform/agent-proxy/overview · https://infisical.com/blog/infisical-update-june-2023 · https://infisical.com/blog/series-a · https://github.com/Infisical/infisical · https://github.com/Infisical/infisical-mcp-server · https://github.com/Infisical/agent-vault · https://github.com/Infisical/cli
- Doppler: https://www.doppler.com · https://www.doppler.com/pricing · https://www.doppler.com/security · https://www.doppler.com/agents · https://docs.doppler.com/docs/security-fact-sheet · https://docs.doppler.com/docs/enterprise-key-management · https://docs.doppler.com/docs/accessing-secrets · https://docs.doppler.com/docs/automatic-fallbacks · https://docs.doppler.com/docs/cli · https://docs.doppler.com/docs/environment-based-configuration · https://docs.doppler.com/docs/mcp · https://docs.doppler.com/docs/share-security · https://docs.doppler.com/changelog · https://github.com/DopplerHQ/cli
- Shelve: https://www.shelve.cloud/ · https://github.com/HugoRCD/shelve · https://shelve.cloud/raw/docs/core-features/encryption.md · https://shelve.cloud/raw/docs/cli/run.md · https://shelve.cloud/raw/docs/cli/agents-automation.md · https://shelve.cloud/raw/docs/cli/init.md · https://shelve.cloud/raw/docs/core-features/tokens.md · https://shelve.cloud/raw/docs/core-features/audit-logs.md · https://shelve.cloud/raw/docs/core-features/teams.md · https://www.shelve.cloud/docs/self-hosting/vercel · https://shelve.cloud/raw/docs/self-hosting/environment-variables.md · https://shelve.cloud/raw/docs/integrations/github.md
- Keyway: https://keyway.sh/ · https://keyway.sh/security · https://keyway.sh/threat-model · https://keyway.sh/articles/ai-coding-agents-secrets-security · https://docs.keyway.sh/cli · https://docs.keyway.sh/api · https://docs.keyway.sh/mcp · https://docs.keyway.sh/security · https://docs.keyway.sh/organizations · https://docs.keyway.sh/integrations · https://github.com/keywaysh/keyway(SELF-HOSTING.md, docker-compose.yml)· reference (unrelated same-name company): https://www.keyway.ai/
- maruhi: docs/CRYPTO_SPEC.md(§1 / §9 / §14)· docs/AUTH_SPEC.md · docs/AUDIT_SPEC.md · docs/SELF_HOSTING.md · docs/adr/0002 / 0003 / 0009 / 0014 / 0016 / 0018 · docs/notes/hosted-design.md(§1 / §5-1)· ROADMAP.md
