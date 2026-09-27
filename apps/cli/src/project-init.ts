// Project creation = genesis init (AUTH_SPEC §11-3 / CRYPTO_SPEC
// §6.4).
//
// - orgId is required (§11-3). No org-creation API exists; pick from
//   the orgs `GET /auth/me` returns (the personal org auto-created at
//   sign-up — §9-1). In solo use (one org), org is neither shown nor
//   selected (concept simplification is a display-layer concern)
// - Project ID = the genesis entry hash. The client can precompute
//   the ID with the same calculation, so the server's response is
//   collated against the precomputed value (the server is not
//   trusted)

import type { UserOrgSchema } from "@maruhi/api-schema";
import {
  SUITE_ID,
  type UnsignedChainEntry,
  computeChainEntryHash,
  signChainEntry,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { type CliError, cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { CliSession, MasterKeys } from "./session.ts";

type UserOrg = typeof UserOrgSchema.Type;

const GENESIS_PREV_HASH = "0".repeat(64);

/** The pure function for org selection returns a tagged Result (no instanceof discrimination — uniformity of idiom). */
type PickedOrg =
  | { readonly kind: "ok"; readonly org: UserOrg }
  | { readonly kind: "rejected"; readonly message: string };

function pickOrg(orgs: readonly UserOrg[], flag: string | undefined): PickedOrg {
  if (flag !== undefined) {
    const matched = orgs.find((org) => org.orgId === flag || org.slug === flag);
    return matched === undefined
      ? {
          kind: "rejected",
          message: `Org not found: ${flag} (your orgs: ${orgs.map((o) => displayText(o.slug)).join(", ")})`,
        }
      : { kind: "ok", org: matched };
  }
  const [first] = orgs;
  if (first === undefined) {
    // Normally impossible — a personal org is auto-created at
    // sign-up (§9-1). If it happens, report it accurately as a
    // server-side state anomaly
    return {
      kind: "rejected",
      message:
        "You do not belong to any org (a personal org should have been auto-created at sign-up — check the server-side state)",
    };
  }
  if (orgs.length === 1) {
    // Only the personal org (solo use). The org concept is not shown (§9-1)
    return { kind: "ok", org: first };
  }
  return {
    kind: "rejected",
    message: `You belong to multiple orgs. Specify one with --org <slug> (your orgs: ${orgs.map((o) => displayText(o.slug)).join(", ")})`,
  };
}

/** `maruhi project init`: sign a genesis entry and initialize the project. */
export function projectInitOp(input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly masterKeys: MasterKeys;
  readonly orgFlag?: string;
}): Effect.Effect<{ readonly projectId: string }, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const me = yield* input.client.auth.me({}).pipe(Effect.mapError(toCliError));
    const picked = pickOrg(me.orgs, input.orgFlag);
    if (picked.kind === "rejected") {
      return yield* Effect.fail(cliError(picked.message));
    }
    const org = picked.org;

    const unsigned: UnsignedChainEntry = {
      suite: SUITE_ID,
      seq: 1,
      prevHashHex: GENESIS_PREV_HASH,
      op: "genesis",
      payload: {
        encPubHex: input.masterKeys.record.encPubHex,
        sigPubHex: input.masterKeys.record.sigPubHex,
      },
      actor: {
        userId: input.session.userId,
        keyFingerprintHex: input.masterKeys.fingerprintHex,
      },
      timestampMs: Date.now(),
    };
    const signed = yield* Effect.tryPromise({
      try: () =>
        signChainEntry({ entry: unsigned, signingKey: input.masterKeys.sigKeyPair.privateKey }),
      catch: () => cliError("Failed to sign the genesis entry"),
    });
    if (!signed.ok) {
      return yield* Effect.fail(cliError("Failed to sign the genesis entry"));
    }
    // The project ID precomputed client-side (the genesis hash — §6.4)
    const expectedProjectId = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(signed.value),
      catch: () => cliError("Failed to compute the genesis hash (crypto error)"),
    });

    const head = yield* input.client.membership
      .init({ payload: { orgId: org.orgId, entry: signed.value } })
      .pipe(Effect.mapError(toCliError));

    // The server's issued value is not trusted: fail unless it exactly matches the precomputed value
    if (head.projectId !== expectedProjectId || head.headHashHex !== expectedProjectId) {
      return yield* Effect.fail(
        cliError(
          "The project ID returned by the server does not match the genesis hash (inconsistent server response)",
        ),
      );
    }

    yield* io.log(`Created project ${head.projectId}`);
    yield* io.log(`To make it the default: \`maruhi config set defaultProject ${head.projectId}\``);
    // schema import stays an independent command (not folded into
    // init — design doc §1-3). Add just one guidance line to init's
    // completion output
    yield* io.log(
      "To bootstrap a schema from an existing .env / .env.example: create an environment (`maruhi env create <id>`), then run `maruhi schema import <file>`",
    );
    return { projectId: head.projectId };
  });
}
