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
  half is **requiredPermissionForOp**, **ensureTokenScopeForProject**,
  **ensureActorMatches**, **ensureKeyMaterialAccess**. Scope miss =
  404 (existence hiding); insufficient permission = 403.
- **Accept policy**: **verifyAcceptableEntry** before chain append.
  `create_environment` / `rotate_epoch` only via composite endpoints.
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
  without a CRYPTO_SPEC change.
- `dangerouslySetInnerHTML`, `'unsafe-inline'`, or third-party scripts
  in `apps/web`. Exception: `write-headers.ts` SHA-256-hashes the
  single bootstrap script.

## Known false-positives

- `packages/crypto/test-vectors/**` and `**/test/**` — dummy values.
- CLI TTY display (`display.ts`, recovery print) after
  `ensureValueDisplayAllowed` — plaintext on a human terminal is
  intended.
- `apps/cli/src/run.ts` / `ci-run.ts` — in-memory env inject, not export.
- `apps/web/scripts/write-headers.ts` — hashed bootstrap CSP, not
  `'unsafe-inline'`.
- `.dev.vars` placeholders and documented dummy secrets.
