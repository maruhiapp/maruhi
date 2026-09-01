// プロジェクト作成 = genesis init(AUTH_SPEC §11-3 / CRYPTO_SPEC §6.4)。
//
// - orgId は必須(§11-3)。org 作成 API は存在せず、`GET /auth/me` が返す orgs
//   (サインアップ時に自動作成されるパーソナル org — §9-1)から選ぶ。
//   単独利用(org が 1 つ)では org を表示・選択させない(概念の簡素化は表示層)
// - プロジェクト ID = genesis エントリハッシュ。クライアントも同じ計算で ID を
//   予見できるため、サーバーの応答を予見値と突合する(サーバー不信)

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

/** org 選択の純関数はタグ付き Result で返す(instanceof 判別をしない — B-5 の慣用統一)。 */
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
    // サインアップ時にパーソナル org が自動作成される(§9-1)ため通常は
    // 起きない。起きたらサーバー側の状態異常として正確に報告する
    return {
      kind: "rejected",
      message:
        "You do not belong to any org (a personal org should have been auto-created at sign-up — check the server-side state)",
    };
  }
  if (orgs.length === 1) {
    // パーソナル org のみ(単独利用)。org 概念を表示しない(§9-1)
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
    // クライアント側で予見したプロジェクト ID(genesis ハッシュ — §6.4)
    const expectedProjectId = yield* Effect.tryPromise({
      try: () => computeChainEntryHash(signed.value),
      catch: () => cliError("Failed to compute the genesis hash (crypto error)"),
    });

    const head = yield* input.client.membership
      .init({ payload: { orgId: org.orgId, entry: signed.value } })
      .pipe(Effect.mapError(toCliError));

    // サーバー採番を信用しない: 予見値と厳密一致しなければ失敗させる
    if (head.projectId !== expectedProjectId || head.headHashHex !== expectedProjectId) {
      return yield* Effect.fail(
        cliError(
          "The project ID returned by the server does not match the genesis hash (inconsistent server response)",
        ),
      );
    }

    yield* io.log(`Created project ${head.projectId}`);
    yield* io.log(`To make it the default: maruhi config set defaultProject ${head.projectId}`);
    // schema import は独立コマンドのまま(init へ組み込まない — 設計文書 §1-3)。
    // init の完了出力に導線 1 行だけを足す
    yield* io.log(
      "To bootstrap a schema from an existing .env / .env.example: create an environment (maruhi env create <id>), then run maruhi schema import <file>",
    );
    return { projectId: head.projectId };
  });
}
