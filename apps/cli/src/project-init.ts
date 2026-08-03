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
import { CliError, cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import type { CliSession, MasterKeys } from "./session.ts";

type UserOrg = typeof UserOrgSchema.Type;

const GENESIS_PREV_HASH = "0".repeat(64);

function pickOrg(orgs: readonly UserOrg[], flag: string | undefined): UserOrg | CliError {
  if (flag !== undefined) {
    const matched = orgs.find((org) => org.orgId === flag || org.slug === flag);
    return (
      matched ??
      cliError(`org が見つかりません: ${flag}(所属 org: ${orgs.map((o) => o.slug).join(", ")})`)
    );
  }
  const [first] = orgs;
  if (first !== undefined && orgs.length === 1) {
    // パーソナル org のみ(単独利用)。org 概念を表示しない(§9-1)
    return first;
  }
  return cliError(
    `複数の org に所属しています。--org <slug> で指定してください(所属 org: ${orgs.map((o) => o.slug).join(", ")})`,
  );
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
    const org = pickOrg(me.orgs, input.orgFlag);
    if (org instanceof CliError) {
      return yield* Effect.fail(org);
    }

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
    const signed = yield* Effect.promise(() =>
      signChainEntry({ entry: unsigned, signingKey: input.masterKeys.sigKeyPair.privateKey }),
    );
    if (!signed.ok) {
      return yield* Effect.fail(cliError("genesis エントリの署名に失敗しました"));
    }
    // クライアント側で予見したプロジェクト ID(genesis ハッシュ — §6.4)
    const expectedProjectId = yield* Effect.promise(() => computeChainEntryHash(signed.value));

    const head = yield* input.client.membership
      .init({ payload: { orgId: org.orgId, entry: signed.value } })
      .pipe(Effect.mapError(toCliError));

    // サーバー採番を信用しない: 予見値と厳密一致しなければ失敗させる
    if (head.projectId !== expectedProjectId || head.headHashHex !== expectedProjectId) {
      return yield* Effect.fail(
        cliError(
          "サーバーが返したプロジェクト ID が genesis ハッシュと一致しません(サーバー応答の不整合)",
        ),
      );
    }

    yield* io.log(`プロジェクトを作成しました: ${head.projectId}`);
    yield* io.log(`既定にするには: maruhi config set defaultProject ${head.projectId}`);
    return { projectId: head.projectId };
  });
}
