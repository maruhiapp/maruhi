// The single seam through which Effect-structured code draws secure
// randomness and message digests (Effect 4.1's `effect/crypto`
// services).
//
// Why a seam: randomness and hashing used to be ambient WebCrypto calls
// (`crypto.getRandomValues` / `crypto.subtle.digest`) scattered across
// core and the server. Routing them through the `SecureRandom` /
// `Digest` services makes every draw auditable at one point and lets
// tests substitute deterministic implementations with `Layer.mock` —
// the same "bind the policy to one place" shape as egress.ts.
//
// Both layers are the WebCrypto variants: they draw from the
// `WebCrypto` reference, which defaults to `globalThis.crypto`, so the
// same layer runs unchanged on workerd, in the browser and under Bun.
// No platform package is involved.
//
// Scope: this seam serves Effect-structured code only. Genuinely
// synchronous call sites (the audit Durable Object's synchronous
// storage API, Drizzle statement construction, an in-memory grant map)
// cannot yield a service; those keep a plain-function surface in the
// server's ids.ts, documented there. The spec-pinned E2EE core
// (@maruhi/crypto) is untouched: it does not consume these services.

import { Layer } from "effect";
import { Digest, SecureRandom } from "effect/crypto";

/**
 * The composed crypto-services layer for runtime roots (the server's
 * HttpApi assembly, the CLI's live layer, test environments). Provides
 * `SecureRandom` and `Digest` backed by WebCrypto.
 */
export const cryptoServicesLayer: Layer.Layer<SecureRandom.SecureRandom | Digest.Digest> =
  Layer.mergeAll(SecureRandom.layerWebCrypto, Digest.layerWebCrypto);
