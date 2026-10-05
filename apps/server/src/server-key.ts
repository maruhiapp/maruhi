// Derivation of the deployment keypair (CRYPTO_SPEC §9), provision of
// the public info, and at lease time the "unseal the wrap addressed
// to itself → re-wrap for the workload" step (§9.1).
//
// From the Workers Secret `SERVER_ENC_KEY_IKM` (32-byte hex) it
// derives an X25519 keypair via RFC 9180 DeriveKeyPair, and puts the
// public face (enc public key + the server-key FP =
// SHA-256(enc_pub)[:16]) on `/auth/config` (AUTH_SPEC §4).
//
// **Neither the secret key nor an unsealed DEK leaves this module's
// closure**. The only published operation is `reseal` (unsealing and
// re-wrapping fused into one, **returning only the lease wrap**); no
// interface returns a plaintext DEK — the type guarantees a DEK never
// appears in a return value, across the RPC boundary, or in logs (the
// server-side version of §10's API-boundary invariant).
// The server decrypts down to the DEK only; it never decrypts
// variable values (§9.1).
//
// An unset secret is "a pure E2EE deployment without selective
// disclosure" (the normal default). A malformed value (not hex,
// wrong length) is treated as unset too — since
// serverKeyFingerprintHex disappears from /auth/config, the grant CLI
// side turns "server key not configured" into an explicit error
// (troubleshooting in docs/SELF_HOSTING.md). Unlike an unset GitHub
// OAuth (503 SetupIncomplete) it is not fail-closed, because the
// server key is an optional feature and there is no reason to block
// the login path.

import { cryptoEffect, cryptoPromise } from "@maruhi/core";
import {
  computeServerKeyFingerprint,
  decodeHex,
  deriveEncryptionKeyPair,
  encodeHex,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  importEncryptionPublicKey,
  type LeaseWrapContext,
  unwrapDek,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { Context, Data, Effect } from "effect";

import type { WireSuite } from "./data/data-plane.ts";

const IKM_BYTES = 32;

/** The public face of the deployment keypair (distributed by /auth/config — AUTH_SPEC §4). */
export interface ServerKeyInfo {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: string;
}

/** A stored server-addressed wrap (one row of dek_wraps — §12-6). */
export interface StoredServerWrap {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/**
 * One lease wrap (response scope; never persisted — §9.1). The suite
 * is inherited from the stored row it was unsealed from: a lease is
 * "a re-wrap of a stored wrap", and material of a different suite is
 * not distributed as v1 (CRYPTO_SPEC §2 design principle 4).
 */
export interface LeaseWrapOutput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** reseal failure reasons (all are server-internal inconsistencies; the reason is not exposed in the response). */
export type ResealFailure = "not-configured" | "unwrap-failed" | "wrap-failed";

export interface ServerKeyShape {
  /** The public face if configured; null when unset (or malformed). */
  readonly info: Effect.Effect<ServerKeyInfo | null>;
  /**
   * Unseals a server-addressed wrap and re-wraps the same epoch DEK
   * to the workload's ephemeral public key (CRYPTO_SPEC §9.1). The
   * unsealed DEK stays inside this call, and the return value carries
   * **only the re-wrapped wrap**.
   *
   * A failure returns a reason code only (it carries no fragments of
   * ciphertext or key material).
   */
  readonly reseal: (input: {
    readonly projectId: string;
    readonly environmentId: string;
    readonly claimsDigestHex: string;
    readonly workloadPubHex: string;
    readonly wraps: readonly StoredServerWrap[];
  }) => Effect.Effect<readonly LeaseWrapOutput[], ResealFailure>;
}

export class ServerKey extends Context.Service<ServerKey, ServerKeyShape>()("ServerKey") {}

/** The derived server key (the public face + the keypair used for unsealing). */
interface DerivedServerKey {
  readonly info: ServerKeyInfo;
  readonly keyPair: EncryptionKeyPair;
}

/**
 * The domain error `derive` folds every wrapped crypto error into:
 * an underivable server key is an unconfigured deployment — the same
 * treatment as an unset or malformed ikm (the public face disappears
 * from /auth/config).
 */
class ServerKeyUnusableError extends Data.TaggedError("ServerKeyUnusable")<object> {}
const unusable = new ServerKeyUnusableError();

const derive = (ikmHex: string | undefined): Effect.Effect<DerivedServerKey | null> =>
  Effect.gen(function* () {
    if (ikmHex === undefined || ikmHex === "") {
      return null;
    }
    const ikm = decodeHex(ikmHex);
    if (ikm === null || ikm.length !== IKM_BYTES) {
      return null;
    }
    const pair = yield* cryptoEffect(() => deriveEncryptionKeyPair({ ikm }));
    // A rejection of the bare-Promise export is a platform defect,
    // not "unusable material" — the same defect the pre-bridge code
    // let the cached Promise's rejection propagate as
    const publicKey = yield* cryptoPromise("exportEncryptionPublicKey", () =>
      exportEncryptionPublicKey(pair.publicKey),
    ).pipe(Effect.orDie);
    const fingerprint = yield* cryptoEffect(() => computeServerKeyFingerprint(publicKey));
    return {
      info: {
        serverEncPubHex: encodeHex(publicKey),
        serverKeyFingerprintHex: encodeHex(fingerprint),
      },
      keyPair: pair,
    };
  }).pipe(
    Effect.mapError(() => unusable),
    Effect.catchTag("ServerKeyUnusable", () => Effect.succeed(null)),
  );

/**
 * Zero-fills the buffer of an unsealed DEK. In JS a copy made before
 * GC cannot be erased, so this is not a cryptographic boundary — but
 * it shrinks the window in which the DEK sits plainly on a long-lived
 * isolate's heap (defense in depth).
 */
function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

/**
 * A service built once at worker / DO startup. Derivation happens
 * once at first reference and is cached inside the isolate thereafter
 * (the ikm and the secret key stay inside the closure).
 */
export function makeServerKey(ikmHex: string | undefined): ServerKeyShape {
  // Effect.cached allocates its memo cell synchronously: one
  // derivation per isolate however many fibers race — the first run's
  // Exit (a derived key, a null "unconfigured", or a defect) is
  // replayed to every later call, the same guarantee the hand-made
  // `cached ??=` Promise gave
  const derived = Effect.runSync(Effect.cached(derive(ikmHex)));
  return {
    info: Effect.map(derived, (key) => key?.info ?? null),
    reseal: (input) =>
      Effect.gen(function* () {
        const key = yield* derived;
        if (key === null) {
          return yield* Effect.fail<ResealFailure>("not-configured");
        }
        const workloadPubBytes = decodeHex(input.workloadPubHex);
        if (workloadPubBytes === null) {
          return yield* Effect.fail<ResealFailure>("wrap-failed");
        }
        const workloadPublicKey = yield* cryptoEffect(() =>
          importEncryptionPublicKey(workloadPubBytes),
        ).pipe(
          // Import can fail even through the wire Schema (32-byte
          // hex) — an X25519 public key that is invalid as a point.
          // The caller maps it to a 400-equivalent
          Effect.mapError(() => "wrap-failed" as const),
        );
        const leases: LeaseWrapOutput[] = [];
        for (const wrap of input.wraps) {
          const enc = decodeHex(wrap.encHex);
          const ciphertext = decodeHex(wrap.ciphertextHex);
          if (enc === null || ciphertext === null) {
            return yield* Effect.fail<ResealFailure>("unwrap-failed");
          }
          const dek = yield* cryptoEffect(() =>
            unwrapDek({
              recipientKeyPair: key.keyPair,
              wrapped: { enc, ciphertext },
              context: {
                projectId: input.projectId,
                environmentId: input.environmentId,
                epoch: wrap.epoch,
                // §9: a server-addressed wrap carries the server-key
                // FP in the recipient position of its info
                recipientUserId: key.info.serverKeyFingerprintHex,
              },
            }),
          ).pipe(
            // An undecryptable poisoned wrap (a target of §12-6's
            // repair path). No DEK was obtained
            Effect.mapError(() => "unwrap-failed" as const),
          );
          const context: LeaseWrapContext = {
            projectId: input.projectId,
            environmentId: input.environmentId,
            epoch: wrap.epoch,
            claimsDigestHex: input.claimsDigestHex,
          };
          const leased = yield* cryptoEffect(() =>
            wrapLeaseDek({ workloadPublicKey, dek, context }),
          ).pipe(
            // The unsealed DEK is zero-filled on every exit —
            // success, wrap failure, and defect alike
            Effect.ensuring(Effect.sync(() => zeroize(dek))),
            Effect.mapError(() => "wrap-failed" as const),
          );
          leases.push({
            suite: wrap.suite,
            epoch: wrap.epoch,
            encHex: encodeHex(leased.enc),
            ciphertextHex: encodeHex(leased.ciphertext),
          });
        }
        return leases;
      }),
  };
}
