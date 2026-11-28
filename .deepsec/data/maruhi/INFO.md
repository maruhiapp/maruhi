# maruhi

A diskless, self-hostable secrets manager on Cloudflare Workers + Durable
Objects + D1. Clients encrypt with WebCrypto + HPKE (`maruhi/v1`). The
server stores ciphertext only. The CLI injects values into a child
process environment in memory (`maruhi run`) and must not write
plaintext to disk. Hosted web (`apps/web`) is metadata-only (ADR-0018)
— the shipped JS must not contain a decryptor.

## Auth shape

- **AuthMiddleware** / **authMiddlewareImpl**: Bearer `maruhi_pat_…`
  first, else session cookie `__Host-maruhi_session`. A present
  Authorization header never falls back to the cookie.
- **CSRF**: cookie writes need `x-maruhi-csrf: 1`. Stateful GETs
  (value pull, recovery blob) use **statefulGetCsrfViolated**.
- **Authorization**: `verifyChain` is the role source of truth. Token
  half (all in `authz.ts`) is **requiredPermissionForEntry**,
  **ensureTokenScopeForProject**, **ensureActorMatches**,
  **ensureKeyMaterialAccess**. Scope miss = 404 (existence hiding);
  insufficient permission = 403. Token scope is per project +
  permission. Member authorization is additionally
  environment-scoped on the chain: a member receives only the DEKs of
  environments in their on-chain scope, and a server grant covers
  only its listed environments — scope is checked against the
  verified chain, not the request.
- **Accept policy**: **verifyAcceptableEntry** before chain append.
  `create_environment` / `rotate_epoch` / `delete_environment` only
  via composite endpoints.
- **Sessions are DB-backed.** Stateless JWT-only sessions are forbidden.

## Threat model

1. **Plaintext leaving the client** — a secret, DEK, or master key on
   the server API, in logs, or on disk. Wire type is
   **EncryptedPayload** / **DistributedEncryptedPayload** only.
2. **Broken chain or wrap accept** — append or DEK wrap that skips
   verifyAcceptableEntry, actor match, or wrap-set completeness.
3. **Provider IDs in append-only logs** — GitHub login in membership
   or audit actors (must be internal user_id + key fingerprint).
4. **Value display or export** — CLI cat/export without
   **ensureValueDisplayAllowed**, or any `.env` writer.
5. **Hosted-web decryptor or XSS** — decrypt/wrap code in `apps/web`,
   `dangerouslySetInnerHTML`, or `'unsafe-inline'` CSP.

## Project-specific patterns to flag

- API payload or handler field that is a secret string instead of
  EncryptedPayload (`packages/api-schema/src/data.ts`).
- CLI writing values via `writeFile` or generating `.env*`.
- Audit or chain actor carrying `githubId` / provider login.
- New crypto outside WebCrypto + `hpke` (panva), or a new suite id
  without a CRYPTO_SPEC change. Sanctioned exception: server-side
  OIDC / JWT verification via `effect/jose`, confined to
  `apps/server/src/oidc.package/`.
- Chain / manifest / mirror acceptance that skips signature,
  sequence, or predecessor checks, or accepts a forked head without
  the gossip / attestation step — in `do/chain-accept.ts`,
  `do/chain-commit.ts`, `data/verify-manifest.ts`,
  `checkpoint-accept.ts`, `attestation-accept.ts`, or the mirror /
  snapshot accept paths (`do/do-mirror.ts` and the `do/do-mirror-*.ts`
  modules it calls, `do/do-snapshot-restore.ts`, and the chain fold both
  read, `do/chain-anchors.ts`).
- Four-eyes: a proposal completes only at `requiredApprovals`
  distinct live owner votes; the proposer's proposal counts as one
  vote and a further approve from the proposer is a duplicate. An
  approve path that lets one person reach quorum alone, or that
  applies the inner op without re-running its consensus checks at
  apply time, is a flag.
- Invite acceptance that does not consume the invite, bind it to the
  intended invitee / environment / role, or enforce expiry — or that
  skips the issuance signature or the link-key joint signature
  (`invite-domain.ts`, `handlers/handlers-invites.ts`,
  `db.package/invites.ts`).
- Lease / device-cap logic where a cap or expiry is computed from
  client-supplied values instead of being re-derived server-side
  from the verified chain (device caps are enforced in chain
  acceptance; lease authorization is evaluated from the on-chain
  server grant — `lease-policy.ts`, `handlers/handlers-lease.ts`,
  `handlers/handlers-devices.ts`).
- Master-key wrap ledger (`handlers/handlers-key-wraps.ts`): a wrap
  accept that skips ledger-state or handoff-approval checks, or a
  new wrap class (recovery code / passkey PRF / guardian / handoff)
  without a CRYPTO_SPEC §8 change.
- An endpoint in the signup / CLI-flow / lease class without a per-IP
  rate limit. Endpoints take the limit through
  **ipRateLimitAllowed** (`worker-env.ts`; **ensureIpRateLimit** in
  `handlers-auth-cli.ts`) backed by a declared `ratelimits` binding;
  a missing binding fails closed.
- A token, invite secret, or wrapped key written to logs or echoed in
  an error. Logging goes through `server-logger.ts`, and the API's
  **HttpApi.RedactedNames** annotation keeps the secret-named query
  params (`code`, `state`, `signup_code`, `vsig`) and the credential
  headers (`authorization`, `cookie`, `set-cookie`) out of logs.
- A server secret read outside the sanctioned resolver
  (**readWorkerSecret** / **readWorkerSecrets** in `worker-env.ts`).
  Hosted secret bindings are `string | SecretsStoreSecret`; the
  hosted stack binds them from the account Secrets Store by
  reference, never as plaintext values in deploy config.
- Operations tooling (`alchemy.run.ts`,
  `apps/server/cloudflare.config.ts`, `apps/server/src/ops/`):
  findings there are lower priority — except the secret-binding
  declarations in `cloudflare.config.ts` / `alchemy.run.ts`, which
  belong to the secret-resolution surface above.
- `dangerouslySetInnerHTML`, `'unsafe-inline'`, or third-party scripts
  in `apps/web`. Exceptions: `write-headers.ts` SHA-256-hashes the
  single bootstrap script and pins the SHA-256 of Astryx's fixed
  `astryx-layer-slide-rules` stylesheet in `style-src`.

## Known false-positives

- `packages/crypto/test-vectors/**` and `**/test/**` — dummy values.
- CLI TTY display (`display.ts`, recovery print) after
  `ensureValueDisplayAllowed` — plaintext on a human terminal is
  intended.
- `apps/cli/src/run.ts` / `ci.package/ci-run.ts` — in-memory env
  inject, not export.
- `apps/web/scripts/write-headers.ts` — hashed bootstrap script and
  pinned Astryx stylesheet hash in the CSP, not `'unsafe-inline'`.
- `.dev.vars.example` placeholders, local `.dev.vars` copies, and
  documented dummy secrets.
