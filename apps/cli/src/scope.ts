// メンバーの環境スコープ(CRYPTO_SPEC §6.2 / §6.3、AUTH_SPEC §9-2 / §12-3)の
// CLI 側の共通述語(2026-09-15 ES K4 — 設計録 es-design.md §10)。
//
// - 包含(K4-I): `packages/crypto` の公開 API `scopeIncludesEnvironment` から導出する
//   (内部の集合演算はコピーしない)。§6.2 の集合代数と同値: `all ⊇ 任意`、
//   `listed ⊇ all` は偽(all は将来の環境を含む U)、`listed{X} ⊇ listed{Y}` ⇔ Y ⊆ X
// - 通信前判定(K4-C): 対象環境 ∈ 自分の scope を、環境が確定する最も手前の共通
//   経路(context.ts の openEnvironment / dek-wrap.ts の requireWritingMember /
//   deks.ts の environmentKeysFor)と、複数環境を扱う経路(checkpoint / sync)の
//   明示呼び出しで判定する。サーバーの 403 `insufficient-scope` を待たない(§6.3)
// - 義務の環境集合(K4-J): `all` は義務 seq 時点で存在した環境集合に具体化する
//   (後に作成された環境の DEK を対象は持ちえない — rotation-sweep.ts の
//   `createdAtSeq > seq` 除外と同じ線)

import { isEnvironmentId } from "@maruhi/core";
import type { ChainMember, DeviceCap, MemberScope, ScopePayloadFields } from "@maruhi/crypto";
import {
  ALL_SCOPE,
  effectivePermissionOf,
  MAX_SCOPE_ENVIRONMENTS,
  scopeIncludesEnvironment,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError, usageError } from "./errors.ts";
import type { VerifiedProject } from "./sync.ts";

/** ユーザー向けの scope 表示(`all` / `no environments` / 環境 id の列挙。id は中和する)。 */
export function describeScope(scope: MemberScope | ScopePayloadFields): string {
  const member = toMemberScope(scope);
  if (member.kind === "all") {
    return "all environments";
  }
  return member.environmentIds.length === 0
    ? "no environments"
    : member.environmentIds.map((id) => displayText(id)).join(", ");
}

/** scope の一致(集合として比較 — 生成は昇順 SHOULD・検証は集合。CRYPTO_SPEC §6.2)。 */
export function sameScope(
  a: MemberScope | ScopePayloadFields,
  b: MemberScope | ScopePayloadFields,
): boolean {
  const left = toMemberScope(a);
  const right = toMemberScope(b);
  if (left.kind === "all" || right.kind === "all") {
    return left.kind === right.kind;
  }
  const ids = new Set(left.environmentIds);
  return (
    ids.size === new Set(right.environmentIds).size &&
    right.environmentIds.every((id) => ids.has(id))
  );
}

/** ワイヤ形(`scopeKind` / `scopeEnvironmentIds`)と導出形の両方を導出形へ。 */
function toMemberScope(scope: MemberScope | ScopePayloadFields): MemberScope {
  if ("kind" in scope) {
    return scope;
  }
  return scope.scopeKind === "all"
    ? ALL_SCOPE
    : { kind: "listed", environmentIds: [...scope.scopeEnvironmentIds] };
}

/**
 * 包含 `actor ⊇ target`(CRYPTO_SPEC §6.2 原則 1 の述語を通信前の案内に使う形)。
 * `all` は将来の環境を含む U なので、`listed` の actor は `all` を包含しない。
 */
export function scopeContains(actor: MemberScope, target: MemberScope): boolean {
  if (target.kind === "all") {
    return actor.kind === "all";
  }
  return target.environmentIds.every((id) => scopeIncludesEnvironment(actor, id));
}

/**
 * `--env <id>`(反復)/ `--all-envs` / `--no-envs` からの scope の組み立て(`invite create` /
 * `member change-role` 共通)。形式検査(§12-1)・重複拒否(§6.2 の構造規則)・
 * 上限 256・コードポイント昇順(生成は昇順 SHOULD)。両方省略なら null(= 呼び出し
 * 側の既定 — 招待は all、change-role は据え置き)。
 */
export function scopeFromFlags(input: {
  readonly env: readonly string[];
  readonly allEnvs: boolean;
  /** `--no-envs` = `listed{}`(§6.2 の空 listed — 管理だけする admin・後で入れる予定)。 */
  readonly noEnvs?: boolean;
}): Effect.Effect<MemberScope | null, CliError> {
  const modes = [input.allEnvs, input.noEnvs === true, input.env.length > 0].filter(Boolean);
  if (modes.length > 1) {
    return Effect.fail(usageError("--env, --all-envs and --no-envs cannot be combined"));
  }
  if (input.allEnvs) {
    return Effect.succeed(ALL_SCOPE);
  }
  if (input.noEnvs === true) {
    return Effect.succeed({ kind: "listed", environmentIds: [] });
  }
  if (input.env.length === 0) {
    return Effect.succeed(null);
  }
  if (input.env.length > MAX_SCOPE_ENVIRONMENTS) {
    return Effect.fail(
      usageError(`--env accepts at most ${MAX_SCOPE_ENVIRONMENTS} environments (CRYPTO_SPEC §6.2)`),
    );
  }
  const invalid = input.env.find((id) => !isEnvironmentId(id));
  if (invalid !== undefined) {
    return Effect.fail(
      usageError(
        "Invalid --env value (an environment ID must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)",
      ),
    );
  }
  const unique = new Set(input.env);
  if (unique.size !== input.env.length) {
    return Effect.fail(usageError("--env lists the same environment more than once"));
  }
  return Effect.succeed({
    kind: "listed",
    environmentIds: [...unique].toSorted(compareCodePoints),
  });
}

/** コードポイント昇順(§6.2 の生成 SHOULD。ロケール非依存)。 */
export function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * `listed` の各 id がチェーン上に存在すること(合意規則 `unknown-environment` の
 * 通信前判定 — typo を発行 / 追記の前に止める)。削除済み環境は列挙してよい(§6.2)。
 */
export function requireScopeEnvironmentsExist(
  verified: VerifiedProject,
  scope: MemberScope,
): Effect.Effect<void, CliError> {
  if (scope.kind === "all") {
    return Effect.void;
  }
  const unknown = scope.environmentIds.filter((id) => !verified.state.environments.has(id));
  if (unknown.length === 0) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      `Environment ${unknown.map((id) => displayText(id)).join(", ")} does not exist on this project's chain (a scope may list only environments whose create_environment entry precedes it — CRYPTO_SPEC §6.2 unknown-environment). Check the ID with \`maruhi env list\``,
    ),
  );
}

/** 自分が scope 外の環境を指したときの文言(K4-C — サーバーの 403 を待たない)。 */
export function outOfScopeMessage(input: {
  readonly member: ChainMember;
  /** 署名・開封する端末(与えられれば端末の scope cap を言い分ける — DK K4-17)。 */
  readonly device?: DeviceCap | undefined;
  readonly environmentId: string;
  /** 例: "pull values from" — 「<operation> environment X」の形に埋める。 */
  readonly operation: string;
}): string {
  const environment = displayText(input.environmentId);
  // 人の scope は含むが端末の scope cap が外している場合は、拡大を頼む相手が違う
  // (admin ではなく、cap 無しの自分の端末か `device approve` のやり直し)
  if (
    input.device !== undefined &&
    scopeIncludesEnvironment(input.member.scope, input.environmentId)
  ) {
    return `Cannot ${input.operation} environment ${environment}: this device's key is capped to ${describeScope(input.device.scope)} on this project's chain, which excludes it (your own scope: ${describeScope(input.member.scope)}). Use one of your devices whose cap covers it (\`maruhi device list\`), or re-register this device with a wider cap (\`maruhi device revoke\` then \`maruhi device add\` / \`maruhi device approve --env …\`)`;
  }
  return `Cannot ${input.operation} environment ${environment}: it is outside your environment scope on this project's chain (your scope: ${describeScope(input.member.scope)}). Ask a project admin to widen it (\`maruhi member change-role ${displayText(input.member.userId)} --env ${environment} …\`). Metadata-only commands such as \`maruhi schema\` still work`;
}

/**
 * 対象環境 ∈ 自分の scope(AUTH_SPEC §12-3 の「環境 ∈ scope」行の通信前判定)。
 * 自分が現メンバーでなければその旨で失敗する。`device` が与えられれば判定は
 * **端末の実効 scope**(人 ∩ 端末 — DK K4-17)で行う(値を開く端末は cap の外の
 * 環境の DEK を持たない)。環境の存在はここでは見ない(存在判定は各経路が担う —
 * チェーン導出で全メンバーに既知のため順序は漏洩に関係しない)。
 */
export function requireEnvironmentInScope(input: {
  readonly verified: VerifiedProject;
  readonly userId: string;
  readonly environmentId: string;
  readonly operation: string;
  readonly device?: DeviceCap | undefined;
}): Effect.Effect<ChainMember, CliError> {
  const member = input.verified.state.members.get(input.userId);
  if (member === undefined) {
    return Effect.fail(cliError("You are not a chain-derived member of this project"));
  }
  const scope =
    input.device === undefined ? member.scope : effectivePermissionOf(member, input.device).scope;
  if (!scopeIncludesEnvironment(scope, input.environmentId)) {
    return Effect.fail(
      cliError(
        outOfScopeMessage({
          member,
          device: input.device,
          environmentId: input.environmentId,
          operation: input.operation,
        }),
      ),
    );
  }
  return Effect.succeed(member);
}

/**
 * 義務の環境集合の具体化(K4-J): `seq` 時点で存在した(`createdAtSeq <= seq`)環境の
 * うち `scope` に含まれるもの。`all` はその時点の全環境。昇順。
 */
export function environmentsOfScopeAt(
  verified: VerifiedProject,
  scope: MemberScope,
  seq: number,
): readonly string[] {
  const ids: string[] = [];
  for (const [environmentId, environment] of verified.state.environments) {
    if (environment.createdAtSeq <= seq && scopeIncludesEnvironment(scope, environmentId)) {
      ids.push(environmentId);
    }
  }
  return ids.toSorted(compareCodePoints);
}

/**
 * scope の置換 旧 → 新 の差分を `seq` 時点の環境集合に具体化する: 拡大分
 * (新 \ 旧 — バックフィル義務)と縮小分(旧 \ 新 — rotate 義務。CRYPTO_SPEC §7)。
 */
export function scopeChangeAt(
  verified: VerifiedProject,
  previous: MemberScope,
  next: MemberScope,
  seq: number,
): { readonly widened: readonly string[]; readonly narrowed: readonly string[] } {
  const before = new Set(environmentsOfScopeAt(verified, previous, seq));
  const after = new Set(environmentsOfScopeAt(verified, next, seq));
  return {
    widened: [...after].filter((id) => !before.has(id)).toSorted(compareCodePoints),
    narrowed: [...before].filter((id) => !after.has(id)).toSorted(compareCodePoints),
  };
}
