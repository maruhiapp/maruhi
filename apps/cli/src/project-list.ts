// `maruhi project list`(AUTH_SPEC §11-5 — W2a): 自分がチェーン導出メンバーで
// あるプロジェクトの一覧。同 API の第一消費者としてサーバー実装を検証する。
//
// TCB 規律: 応答(projectId / role)は**サーバー申告**である(§11-5 — role は
// 読取時の DO 確認が返す値だが、クライアントから見れば検証を経ない申告)。
// 検証済み状態が要る場面は `maruhi project verify` の領分で、この表示は発見
// (どのプロジェクト ID を持っているか)のためのもの。トークンのスコープ外の
// プロジェクトは応答に現れない(§11-5 のスコープ交差)。

import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";

/**
 * ページ追跡の有界化(サーバー固定 100 件 / ページ — §11-5)。正直なサーバーでは
 * 到達しない量(10,000 プロジェクト)で、暴走・悪意サーバーの無限 nextAfter
 * 連鎖を有界にする。
 */
const MAX_LIST_PAGES = 100;

/** 一覧の 1 行(api-schema の ProjectMembershipSchema の受信形)。 */
interface MembershipRow {
  readonly projectId: string;
  readonly role: "owner" | "admin" | "member" | "reader";
}

/** 全ページを取得して 1 行 1 プロジェクトで表示する(stdout はデータのみ)。 */
export function projectListOp(input: {
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const rows: MembershipRow[] = [];
    let after: string | undefined;
    for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
      const response = yield* input.client.membership
        .list({ query: after === undefined ? {} : { after } })
        .pipe(Effect.mapError(toCliError));
      rows.push(...response.projects);
      after = response.nextAfter;
      if (after === undefined) {
        break;
      }
    }
    if (after !== undefined) {
      return yield* Effect.fail(
        cliError(
          `The server kept returning more pages past the ${MAX_LIST_PAGES}-page bound — stopping. This does not happen with an honest server; re-run and investigate the server if it persists`,
        ),
      );
    }
    if (rows.length === 0) {
      yield* io.log("No projects");
      yield* io.logError(
        "You are not a chain-derived member of any project visible to this credential (projects outside the token's scopes are not listed)",
      );
      return;
    }
    for (const row of rows) {
      yield* io.log(`${displayText(row.projectId)}\trole=${row.role}`);
    }
    yield* io.logError(
      `${countNoun(rows.length, "project")} as reported by the server — run \`maruhi project verify --project <id>\` for verified state`,
    );
  });
}
