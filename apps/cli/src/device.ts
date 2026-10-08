// The `maruhi device` group (CRYPTO_SPEC §3 / §6.2 "device keys",
// AUTH_SPEC §13-11 — 2026-09-19 DK. Design record dk-design.md §9 K4-5 /
// K4-6 / K4-7 / K4-13 / K4-18).
//
// - `device add [--label] [--replace]` (the new device): generates a device
//   key, issues a request, saves, then prints the FP (hex + 12 words) and
//   waits (`--replace` is also "generate → request → guarded replacement" —
//   DK K13-8). The wait signal is the registry (advisory); the completion
//   check is each project's verified chain (K4-5). In the same view it
//   verifies and reports the keys' arrival on the registered projects
//   (whether a DEK addressed to this device exists on every epoch — DK K12)
//   and revoked keys. If the key already exists, a live request resumes the
//   wait, and without one it branches on the chain standing
//   (`device-standing.ts`) without creating a request (DK K13-2 — the
//   revision of K4-21 (c)). No gate (DK-D — the requesting side adds
//   nothing)
// - `device approve <fp|words> [--cap] [--env…]` (an already-registered
//   device): the ceremony gate (TTY + non-agent — agent-gate.ts) → FP is
//   **recomputed** from the public key of a request-list row and matched
//   (K4-6) → each project is opened and judged (if the cap of an
//   already-registered key differs from this run's cap, stop without
//   writing anything — K10-1) → `add_device` to each project → backfill →
//   local record (approved) → PUT to the registry (the signal) → cancel
//   the request (only when the PUT succeeded — on failure the request is
//   left: K9-1)
// - `device list [--project]`: cross-checks the chain (the truth), the
//   registry (server-reported), and the local records (provenance) to
//   display. No values, no keys needed, no gate
// - `device revoke <ref…> [--user] [--project] [--yes] [--revoke-token]`:
//   the reference is an FP prefix (8+ chars, unique) or the registry's
//   display name (only your own — confirm with the FP shown alongside).
//   Confirmation table → yes → `revoke_device` to each project → sweep
//   kind 5 (K4-8) → local record revoked → delete the registry row →
//   propose token revocation (K4-13 — automatic only with an explicit
//   `--revoke-token`)
//
// The registry is only ever used for display and the signal: a key is
// approved only when the FP recomputed from the request row's public key
// matches the FP the human carried; a device is revoked only when it is on
// the chain; the local records are written only by the 3 paths — sealing,
// approval, observation (K4-3).

import { type KeyFingerprintHex, type ProjectId, userKeyFingerprintHex } from "@maruhi/core";
import { decodeHex } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliError } from "./errors.ts";
import { fetchProjectMemberships } from "./project-list.ts";
import { compareCodePoints } from "./scope.ts";

/** One registry row (server-reported). */
export interface RegistryRow {
  readonly keyFingerprintHex: KeyFingerprintHex;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly label: string;
  readonly tokenId?: string | undefined;
  readonly createdAtMs: number;
}

export const FULL_FINGERPRINT = /^[0-9a-f]{32}$/;
export const FINGERPRINT_PREFIX = /^[0-9a-f]{8,32}$/;
export const WORD_COUNT = 12;

/** Recomputes the FP from the public key (the claimed FP of a registry or request row is never trusted — §13-11). */
export function recomputeFingerprint(
  encPubHex: string,
  sigPubHex: string,
): Effect.Effect<KeyFingerprintHex | null, CliError> {
  const enc = decodeHex(encPubHex);
  const sig = decodeHex(sigPubHex);
  if (enc === null || sig === null) {
    return Effect.succeed(null);
  }
  // A malformed stored key materializes as InvalidInput, which is
  // a fingerprint that cannot match — null (the caller treats it as
  // "no such key"). Anything else is an invariant break and dies
  return userKeyFingerprintHex(enc, sig).pipe(
    Effect.catchTag("CryptoInvalidInput", () => Effect.succeed(null)),
    Effect.orDie,
  );
}

/** Fetches the registry (null when unreadable — used only for display and the signal, so never fails). */
export function fetchRegistry(
  client: MaruhiClient,
): Effect.Effect<readonly RegistryRow[] | null, never> {
  return client.devices.list({}).pipe(
    Effect.map((response): readonly RegistryRow[] => response.devices),
    Effect.orElseSucceed(() => null),
  );
}

/** Resolves the project set: `--project` only when given, otherwise the membership list (claimed = for discovery). */
export function resolveProjectIds(
  client: MaruhiClient,
  project: ProjectId | undefined,
): Effect.Effect<readonly ProjectId[], CliError> {
  return project === undefined
    ? fetchProjectMemberships(client).pipe(
        Effect.map((rows) => rows.map((row) => row.projectId).toSorted(compareCodePoints)),
      )
    : Effect.succeed([project]);
}
