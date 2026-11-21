import type { UserOrgSchema } from "@maruhi/api-schema";
import { cryptoEffect, cryptoPromise, type ProjectId } from "@maruhi/core";
import {
  SUITE_ID,
  type UnsignedChainEntry,
  computeChainEntryHash,
  signChainEntry,
} from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { displayText } from "../display.ts";
import { type CliError, cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import type { CliSession, MasterKeys } from "../session.ts";

type UserOrg = typeof UserOrgSchema.Type;

const GENESIS_PREV_HASH = "0".repeat(64);

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
    return {
      kind: "rejected",
      message:
        "You do not belong to any org (a personal org should have been auto-created at sign-up — check the server-side state)",
    };
  }
  if (orgs.length === 1) {
    return { kind: "ok", org: first };
  }
  return {
    kind: "rejected",
    message: `You belong to multiple orgs. Specify one with --org <slug> (your orgs: ${orgs.map((o) => displayText(o.slug)).join(", ")})`,
  };
}

export const projectInitOp = Effect.fn("project-init.projectInitOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly session: CliSession;
  readonly masterKeys: MasterKeys;
  readonly orgFlag?: string;
}): Effect.fn.Return<{ readonly projectId: ProjectId }, CliError, CliIo> {
  const io = yield* CliIo;
  const me = yield* input.client.auth.me({}).pipe(Effect.mapError(toCliError));
  const picked = pickOrg(me.orgs, input.orgFlag);
  if (picked.kind === "rejected") {
    return yield* Effect.fail(cliError(picked.message));
  }
  const org = picked.org;

  const timestampMs = yield* Clock.currentTimeMillis;
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
    timestampMs,
  };
  const signed = yield* cryptoEffect(() =>
    signChainEntry({ entry: unsigned, signingKey: input.masterKeys.sigKeyPair.privateKey }),
  ).pipe(Effect.mapError(() => cliError("Failed to sign the genesis entry")));
  const expectedProjectId = yield* cryptoPromise("computeChainEntryHash", () =>
    computeChainEntryHash(signed),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the genesis hash (crypto error)")));

  const head = yield* input.client.membership
    .init({ payload: { orgId: org.orgId, entry: signed } })
    .pipe(Effect.mapError(toCliError));

  if (head.projectId !== expectedProjectId || head.headHashHex !== expectedProjectId) {
    return yield* Effect.fail(
      cliError(
        "The project ID returned by the server does not match the genesis hash (inconsistent server response)",
      ),
    );
  }

  yield* io.log(`Created project ${head.projectId}`);
  yield* io.log(`To make it the default: \`maruhi config set defaultProject ${head.projectId}\``);
  yield* io.log(
    "To bootstrap a schema from an existing .env / .env.example: create an environment (`maruhi env create <id>`), then run `maruhi schema import <file>`",
  );
  return { projectId: head.projectId };
});
