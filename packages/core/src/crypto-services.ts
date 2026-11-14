// The seam through which the Effect-structured code in core, the
// server and the CLI draws secure randomness, message digests and
// asymmetric signature verification (Effect 4.1's `effect/crypto`
// services).
//
// Why a seam: randomness and hashing used to be ambient WebCrypto calls
// (`crypto.getRandomValues` / `crypto.subtle.digest`) scattered across
// core and the server. Routing them through the `SecureRandom` /
// `Digest` / `Signature` services makes every draw in that scope
// auditable at one point and lets tests substitute deterministic
// implementations with `Layer.mock` — the same "bind the policy to one
// place" shape as egress.ts.
//
// Both layers are the WebCrypto variants: they draw from the
// `WebCrypto` reference, which defaults to `globalThis.crypto`, so the
// same layer runs unchanged on workerd, in the browser and under Bun.
// No platform package is involved.
//
// Scope: this seam serves the Effect-structured code in core, the
// server and the CLI — the CLI's live and test layers provide it, and
// its Effect-structured id draws (ulid, newLedgerId) go through it.
// What stays outside is narrower. Genuinely synchronous call sites
// (the audit Durable Object's synchronous storage API, Drizzle
// statement construction, an in-memory grant map) cannot yield a
// service; those keep a plain-function surface in the server's
// ids.ts, documented there. The CLI's protocol-adjacent draws inside
// plain helpers (WebAuthn ceremony values, SigV4 hashing, TLS
// certificate material) likewise stay ambient: they are not produced
// by Effect programs. The spec-pinned E2EE core (@maruhi/crypto) is
// untouched: it does not consume these services.

import { Layer } from "effect";
import { Digest, SecureRandom, Signature } from "effect/crypto";

/**
 * The composed crypto-services layer for runtime roots (the server's
 * HttpApi assembly, the CLI's live layer, test environments). Provides
 * `SecureRandom`, `Digest` and `Signature` backed by WebCrypto. The
 * `Signature` layer's own `SecureRandom` requirement is provided to it
 * inside the composition, so the layer requires nothing from its
 * environment.
 */
export const cryptoServicesLayer: Layer.Layer<
  SecureRandom.SecureRandom | Digest.Digest | Signature.Signature
> = Layer.mergeAll(
  SecureRandom.layerWebCrypto,
  Digest.layerWebCrypto,
  Signature.layerWebCrypto.pipe(Layer.provide(SecureRandom.layerWebCrypto)),
);
