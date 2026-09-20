// 要ローテーション検出(AUDIT_SPEC §4.1 = CRYPTO_SPEC §7 の実装)と
// フラグの解消導出(§4.1 手順 5)。
//
// - 検出は `remove_member` / `change_role`(降格・scope 縮小 — 2026-09-14 ES)/
//   `revoke_server` / `revoke_device`(端末の窓 — 2026-09-19 DK)の受理時に project DO 内で走り、ミラー追記と同一の同期タスクで
//   `rotation.recommended`(1 (variable × environment) 1 行 — §3.3)を追記する
//   (chain-accept.ts が結線)。座標系は監査 seq(DO 内の全順序 — チェーン受理も
//   データ操作も同じ列に載る)
// - 候補集合(§4.1 手順 2)は**環境別のアクセス窓**: 対象が環境 E の DEK を持ち
//   えた seq 区間の列。窓はチェーンミラーの payload の scope 状態(`all` /
//   `listed`)の遷移点だけで決まり、member(genesis / member_added / role_changed /
//   member_removed)と server(server_granted / server_revoked)で **1 つの窓導出を
//   共有する**(§4.1「実装は 1 つの窓導出を共有する」— 設計録 es-design.md §9
//   K3-E)。`all` = 全環境(将来分を含む)なので、`all` の期間中に作成された変数も
//   存在区間との重なりで自然に候補になる
// - 区間の重なり判定は開区間: max(start) < min(end)。隣接イベント(例: 変数
//   作成の直後に削除受理)の間にも実時間の窓があり「取得可能だった」は成立する
//   (実際の取得はイベントを挟むため rank (a) は正しく空になる)
// - 解消導出はイベント列の畳み込みのみ(フラグを可変ストアに持たない — §4.1)。
//   再暗号化マーカー付きの var.version_pushed は解消と見なさない(§4.1-5 —
//   義務ローテーションの sweep による全自動誤解消の遮断)

import type {
  AuditEventInput,
  AuditRotationRead,
  DeviceEventRow,
  MembershipEventRow,
  RotationFlagSourceRow,
  ScopeSnapshot,
  VariableLifecycleRow,
} from "./audit-store.ts";

/** 根拠ランク(§4.1 手順 3): read = 確実に取得した / readable = 取得可能だった。 */
export type RotationBasis = "read" | "readable";

/**
 * 検出を起こした op(§3.3 `rotation.recommended` の payload.trigger — 2026-09-14
 * ES): remove_member / change_role(降格・縮小)/ revoke_server。
 */
export type RotationTrigger = "remove_member" | "change_role" | "revoke_server" | "revoke_device";

/** 現在有効な要ローテーションフラグ(§4.1 手順 5 の導出結果。RPC 境界を渡る)。 */
export interface EffectiveRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: RotationBasis;
  /** remove_member / change_role 変種のみ。 */
  readonly targetUserId?: string;
  /** revoke_server 変種のみ。 */
  readonly targetServerKeyFingerprintHex?: string;
  // 監査 seq は持たない(2026-08-16 C1 裁定): 無欠番採番の序数はワイヤに
  // 載せられず(クラス 2 件数を漏らす — §7)、解消順序は導出の入力行順
  // (rotationFlagEvents の seq 順)で既に担保されるため、出力には不要
  readonly recommendedAtMs: number;
  /** 検出を起こした削除・降格 / 縮小・失効エントリの chain seq(payload から)。 */
  readonly triggerChainSeq: number;
  /** 検出を起こした op(payload から。K3 前の保存行は target の有無から補完)。 */
  readonly trigger: RotationTrigger;
}

/** 監査 seq 上の半開区間(end = +Infinity は未閉包)。 */
interface SeqInterval {
  readonly start: number;
  readonly end: number;
}

/** 変数の存在区間(§4.1 手順 2 の Q2 — var.created 〜 var.deleted)。 */
interface VariableLifetime {
  readonly environmentId: string;
  readonly variableId: string;
  readonly start: number;
  end: number;
}

const pairKey = (row: { readonly environmentId: string; readonly variableId: string }): string =>
  `${row.environmentId}\u0000${row.variableId}`;

/** 開区間どうしの重なり(整数 seq 列の間の実時間窓を含む — 冒頭コメント)。 */
function overlaps(a: SeqInterval, bStart: number, bEnd: number): boolean {
  return Math.max(a.start, bStart) < Math.min(a.end, bEnd);
}

/** seq がイベント区間の内部(両端のイベント自身は含まない)にあるか。 */
function within(seq: number, interval: SeqInterval): boolean {
  return interval.start < seq && seq < interval.end;
}

// ---------------------------------------------------------------------------
// 環境別アクセス窓(§4.1 手順 2 — member / server 共通の窓導出)
// ---------------------------------------------------------------------------

/**
 * scope 状態の遷移(ミラー行 1 つ = 1 遷移): open = 在籍 / grant の開始(scope
 * 付き)、update = 在籍中の scope の置換(change_role・拡大再 grant)、close =
 * 在籍 / grant の終了。窓導出はこの 3 種だけを見る(受信者クラスを跨いで同一)。
 */
interface ScopeTransition {
  readonly seq: number;
  readonly kind: "open" | "update" | "close";
  readonly scope: ScopeSnapshot;
}

const ALL_SCOPE: ScopeSnapshot = { kind: "all" };

function scopeIncludes(scope: ScopeSnapshot, environmentId: string): boolean {
  return scope.kind === "all" || scope.environmentIds.includes(environmentId);
}

/**
 * 環境 E のアクセス窓の列(§4.1 手順 2): E ∈ scope になった遷移で開き、E ∉ scope
 * になった遷移(update)または close で閉じる。在籍 / grant の区間を跨ぐ再開は
 * 別の窓。チェーン合意規則は二重追加・二重 grant を拒否するが、導出は防御的に
 * 「開いた区間があるときの open」を update と同じに扱い、「区間外の update」は
 * open と同じに扱う(壊れた入力では見逃さない側 — 設計録 §9 K3-F。区間外の
 * close だけは無視する = 削除後の遷移)。
 */
function accessWindows(
  transitions: readonly ScopeTransition[],
  environmentId: string,
): readonly SeqInterval[] {
  const windows: SeqInterval[] = [];
  // 窓導出の状態: 在籍 / grant 区間の内側か、E の窓がどの seq から開いているか
  const state = { openedAt: null as number | null };
  const closeWindow = (seq: number): void => {
    if (state.openedAt !== null) {
      windows.push({ start: state.openedAt, end: seq });
      state.openedAt = null;
    }
  };
  for (const transition of transitions) {
    if (transition.kind === "close") {
      closeWindow(transition.seq);
      continue;
    }
    if (scopeIncludes(transition.scope, environmentId)) {
      state.openedAt ??= transition.seq;
    } else {
      closeWindow(transition.seq);
    }
  }
  if (state.openedAt !== null) {
    windows.push({ start: state.openedAt, end: Number.POSITIVE_INFINITY });
  }
  return windows;
}

/**
 * Q1 の在籍区間イベント(genesis / member_added / role_changed / member_removed)
 * を scope 遷移に写す。genesis は構造的に `all`(CRYPTO_SPEC §6.2)。scope を
 * 読めない行(壊れた payload・K2 以前の形 — 再作成対象で存在しない前提)は
 * fail-safe に `all` として窓を開く(検出は見逃さない側が安全 — 設計録 §9 K3-F)。
 */
function membershipTransitions(events: readonly MembershipEventRow[]): readonly ScopeTransition[] {
  return events.map((event) => {
    if (event.event === "chain.member_removed") {
      return { seq: event.seq, kind: "close", scope: ALL_SCOPE };
    }
    const scope = event.scope ?? ALL_SCOPE;
    return {
      seq: event.seq,
      kind: event.event === "chain.role_changed" ? "update" : "open",
      scope,
    };
  });
}

/**
 * Q6 の grant 区間イベント(server_granted / server_revoked)を scope 遷移に写す。
 * 同一鍵 FP への再 grant は区間内では update、失効後の再 grant は新しい区間の
 * open。区間内の scope は**単調に和集合**で積む(合意規則は拡大のみ受理 —
 * CRYPTO_SPEC §6.3。仮に縮小する再 grant が通っても、サーバーが既に知る DEK の
 * 開示窓を失効前に閉じない = 「見せかけの縮小」を検出側でも塞ぐ fail-safe)。
 */
function grantTransitions(
  events: readonly {
    readonly seq: number;
    readonly event: string;
    readonly scopeEnvironmentIds: readonly string[] | null;
  }[],
): readonly ScopeTransition[] {
  const transitions: ScopeTransition[] = [];
  // 区間内の開示集合。null = 区間外。"all" = scope を読めない grant 行を含む
  // 区間(fail-safe に全環境 — member 軸の scope 不明と同じ倒し方。K3-F)
  let disclosed: Set<string> | "all" | null = null;
  for (const event of events) {
    if (event.event === "chain.server_revoked") {
      transitions.push({ seq: event.seq, kind: "close", scope: ALL_SCOPE });
      disclosed = null;
      continue;
    }
    const kind = disclosed === null ? "open" : "update";
    disclosed =
      disclosed === "all" || event.scopeEnvironmentIds === null
        ? "all"
        : new Set([...(disclosed ?? []), ...event.scopeEnvironmentIds]);
    transitions.push({
      seq: event.seq,
      kind,
      scope: disclosed === "all" ? ALL_SCOPE : { kind: "listed", environmentIds: [...disclosed] },
    });
  }
  return transitions;
}

/** 変数の存在区間の復元(Q2。variable_id は再利用されない — AUTH_SPEC §12-1)。 */
function variableLifetimes(
  rows: readonly VariableLifecycleRow[],
): ReadonlyMap<string, VariableLifetime> {
  const lifetimes = new Map<string, VariableLifetime>();
  for (const row of rows) {
    const key = pairKey(row);
    if (row.event === "var.created") {
      if (!lifetimes.has(key)) {
        lifetimes.set(key, {
          environmentId: row.environmentId,
          variableId: row.variableId,
          start: row.seq,
          end: Number.POSITIVE_INFINITY,
        });
      }
      continue;
    }
    const lifetime = lifetimes.get(key);
    if (lifetime !== undefined) {
      lifetime.end = row.seq;
    }
  }
  return lifetimes;
}

/** 環境ごとの窓を遅延導出して memo する(候補判定は変数ごと・窓は環境ごと)。 */
function windowsByEnvironment(
  transitions: readonly ScopeTransition[],
): (environmentId: string) => readonly SeqInterval[] {
  const memo = new Map<string, readonly SeqInterval[]>();
  return (environmentId) => {
    const cached = memo.get(environmentId);
    if (cached !== undefined) {
      return cached;
    }
    const windows = accessWindows(transitions, environmentId);
    memo.set(environmentId, windows);
    return windows;
  };
}

/** rotation.recommended 1 行の組み立て(§3.3 の記録細則 — actor は system)。 */
function recommendedEvent(input: {
  readonly nowMs: number;
  readonly lifetime: VariableLifetime;
  readonly basis: RotationBasis;
  readonly trigger: RotationTrigger;
  readonly triggerChainSeq: number;
  readonly targetUserId?: string;
  readonly targetKeyFingerprintHex?: string;
  /** revoke_device 変種のみ: 失効 FP 集合(AUDIT_SPEC §4.1 — payload に写す)。 */
  readonly revokedDeviceKeyFingerprints?: readonly string[];
}): AuditEventInput {
  return {
    event: "rotation.recommended",
    serverTs: input.nowMs,
    actorType: "system",
    ...(input.targetUserId === undefined ? {} : { targetUserId: input.targetUserId }),
    ...(input.targetKeyFingerprintHex === undefined
      ? {}
      : { targetKeyFingerprintHex: input.targetKeyFingerprintHex }),
    environmentId: input.lifetime.environmentId,
    variableId: input.lifetime.variableId,
    payload: {
      basis: input.basis,
      triggerChainSeq: input.triggerChainSeq,
      trigger: input.trigger,
      ...(input.revokedDeviceKeyFingerprints === undefined
        ? {}
        : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
    },
  };
}

/**
 * member 変種(remove_member / change_role)の共通骨格: 候補 = 対象窓と存在期間が
 * 重なる全 (variable × environment)(削除済み変数も含める — 上流 credential は
 * 変数を消しても失効しない)、(a) = 対象窓の内部にある対象の var.read(API
 * トークン経由を含む — actor.user_id で照合。読み取り自体もイベントなので厳密に
 * 区間内部で判定する)。`selectWindows` が変種ごとに「どの窓を検出対象にするか」を
 * 決める(remove = 全窓、change_role = 契機で閉じた窓)。
 */
function detectForMember(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: string;
  readonly trigger: RotationTrigger;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
  readonly selectWindows: (
    windows: readonly SeqInterval[],
    environmentId: string,
  ) => readonly SeqInterval[];
  readonly transitions: readonly ScopeTransition[];
  readonly revokedDeviceKeyFingerprints?: readonly string[];
}): readonly AuditEventInput[] {
  const windowsOf = windowsByEnvironment(input.transitions);
  const selected = new Map<string, readonly SeqInterval[]>();
  const candidates = [...variableLifetimes(input.read.variableLifecycles()).values()].filter(
    (lifetime) => {
      let windows = selected.get(lifetime.environmentId);
      if (windows === undefined) {
        windows = input.selectWindows(windowsOf(lifetime.environmentId), lifetime.environmentId);
        selected.set(lifetime.environmentId, windows);
      }
      return windows.some((window) => overlaps(window, lifetime.start, lifetime.end));
    },
  );
  if (candidates.length === 0) {
    return [];
  }
  const readPairs = new Set(
    input.read
      .variableReadsBy(input.targetUserId)
      .filter((row) =>
        (selected.get(row.environmentId) ?? []).some((window) => within(row.seq, window)),
      )
      .map(pairKey),
  );
  return candidates.map((lifetime) =>
    recommendedEvent({
      nowMs: input.nowMs,
      lifetime,
      basis: readPairs.has(pairKey(lifetime)) ? "read" : "readable",
      trigger: input.trigger,
      triggerChainSeq: input.triggerChainSeq,
      targetUserId: input.targetUserId,
      ...(input.revokedDeviceKeyFingerprints === undefined
        ? {}
        : { revokedDeviceKeyFingerprints: input.revokedDeviceKeyFingerprints }),
    }),
  );
}

/**
 * `remove_member` 受理時の検出(§4.1 手順 1〜3)。呼び出しはミラー追記の後
 * (在籍区間は直前に書いたミラー行で閉じている)。候補は在籍区間内の**全窓**
 * (過去に縮小で閉じた窓を含む — §4.1 手順 2 の字面。縮小時の検出と重複する
 * 行は同対の複数有効 recommended として残る = 再削除と同じ扱い)。返り値を
 * そのまま appendManySync すれば手順 4 になる。
 */
export function detectMemberRemoval(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: string;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly AuditEventInput[] {
  const events = input.read.membershipEventsFor(input.targetUserId);
  if (events.length === 0) {
    return [];
  }
  return detectForMember({
    ...input,
    trigger: "remove_member",
    transitions: membershipTransitions(events),
    selectWindows: (windows) => windows,
  });
}

/** member 以上(書き手)か — 降格(member 未満へ)の判定に使う。 */
const WRITER_ROLES: ReadonlySet<string> = new Set(["member", "admin", "owner"]);

/**
 * `change_role` 受理時の検出(§4.1 の change_role 変種 — 2026-09-14 ES)。
 * 呼び出しはミラー追記の後(直前に書いた `chain.role_changed` 行が Q1 の末尾)。
 * - **縮小**(旧 scope \ 新 scope ≠ ∅): 契機のミラー行で閉じた窓の環境が候補
 *   (CRYPTO_SPEC §7 — 縮小分は remove 相当)
 * - **降格**(旧 role ≥ member、新 role = reader): 契機直前に開いていた全窓(=
 *   旧 scope の全環境。新 scope に残る環境は reader として DEK を受け取り続ける
 *   ため窓自体は閉じないが、検出は契機 seq で切った窓で行う — 「上流の credential
 *   を知る者が権限を失った」事実の検出。§4.1)。同時に縮小も起きていれば和集合で
 *   1 (variable × environment) 1 行(§3.3 の粒度)
 * - 昇格・拡大・scope 不変の role 変更(降格でない)は候補なし
 */
export function detectRoleChange(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: string;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly AuditEventInput[] {
  const events = input.read.membershipEventsFor(input.targetUserId);
  const trigger = events.at(-1);
  if (trigger === undefined || trigger.event !== "chain.role_changed") {
    return [];
  }
  const previousRole =
    events.toReversed().find((event) => event.seq < trigger.seq && event.role !== null)?.role ??
    null;
  // role が読めない行(壊れた payload — 到達不能)は「降格だった」側に倒す
  // (見逃さない側 — 設計録 §9 K3-F): 旧 role 不明 = 書き手だったとみなし、
  // 新 role 不明 = 書き手でなくなったとみなす
  const demoted =
    (previousRole === null || WRITER_ROLES.has(previousRole)) &&
    (trigger.role === null || !WRITER_ROLES.has(trigger.role));
  // 契機行の scope が読めない場合、窓導出は all に倒して「縮小分」を検出できない
  // (窓が閉じない)ため、降格と同じく契機直前の全窓を候補にする(見逃さない側)
  const closeAll = demoted || trigger.scope === null;
  return detectForMember({
    ...input,
    trigger: "change_role",
    transitions: membershipTransitions(events),
    selectWindows: (windows) =>
      windows.flatMap((window) => {
        // 契機のミラー行で閉じた窓 = 縮小分
        if (window.end === trigger.seq) {
          return [window];
        }
        // 降格: 契機時点で開いたままの窓(新 scope に残る環境)を契機 seq で切る
        // (遷移列は契機行で終わるので、契機より後まで続く窓 = 未閉包の窓)
        if (closeAll && window.start < trigger.seq && window.end > trigger.seq) {
          return [{ start: window.start, end: trigger.seq }];
        }
        return [];
      }),
  });
}

/** 2 区間の交差(空なら null)。 */
function intersect(a: SeqInterval, b: SeqInterval): SeqInterval | null {
  const start = Math.max(a.start, b.start);
  const end = Math.min(a.end, b.end);
  return start < end ? { start, end } : null;
}

/**
 * 失効した端末の有効区間と端末 scope(§4.1 の revoke_device 変種 — 手順 1。設計録
 * dk-design.md §8 K3-11): 契機より前の最新の `chain.device_added`(payload の FP が
 * 一致)から契機まで。どの device_added にも無い FP は `add_member` / `genesis` の
 * 最初の鍵で、区間は在籍区間の開始(契機より前の最新の open 遷移)から、scope は
 * all(最初の鍵の cap は構造的に (owner, all) — CRYPTO_SPEC §6.2)。scope が読めない
 * 行は all(見逃さない側 — ES K3-F)。
 */
function revokedDeviceSpans(
  membership: readonly MembershipEventRow[],
  devices: readonly DeviceEventRow[],
  fingerprintsHex: readonly string[],
  triggerSeq: number,
): readonly { readonly interval: SeqInterval; readonly scope: ScopeSnapshot }[] {
  const tenureStart =
    membership
      .filter(
        (event) =>
          event.seq < triggerSeq &&
          (event.event === "chain.genesis" || event.event === "chain.member_added"),
      )
      .at(-1)?.seq ?? 0;
  return fingerprintsHex.map((fingerprintHex) => {
    const added = devices
      .filter(
        (event) =>
          event.seq < triggerSeq &&
          event.event === "chain.device_added" &&
          event.fingerprintsHex.includes(fingerprintHex),
      )
      .at(-1);
    return {
      interval: { start: added?.seq ?? tenureStart, end: triggerSeq },
      scope: added?.scope ?? ALL_SCOPE,
    };
  });
}

/**
 * `revoke_device` 受理時の検出(§4.1 の revoke_device 変種 — 2026-09-19 DK)。
 * 呼び出しはミラー追記の後(直前に書いた `chain.device_revoked` 行が契機)。
 * 候補 = 各失効端末の有効区間 ∩ 人の環境別アクセス窓 ∩ 端末 scope(端末 scope に
 * E を含まない端末は窓なし = 票だけの端末〔scope 空〕の失効は行を書かない)。
 * (a) は remove の変種と同じく actor.user_id の `var.read` を区間内で照合する
 * (`var.read` は FP を持たない — K1-12)。対象者は在籍を続けるため在籍区間は
 * 閉じない(契機 seq で切った窓で検出する — 降格の変種と同型)。
 */
export function detectDeviceRevocation(input: {
  readonly read: AuditRotationRead;
  readonly targetUserId: string;
  readonly deviceFingerprintsHex: readonly string[];
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly AuditEventInput[] {
  const membership = input.read.membershipEventsFor(input.targetUserId);
  if (membership.length === 0) {
    return [];
  }
  const trigger = input.read.deviceEventsFor(input.targetUserId).at(-1);
  if (trigger === undefined || trigger.event !== "chain.device_revoked") {
    return [];
  }
  const spans = revokedDeviceSpans(
    membership,
    input.read.deviceEventsFor(input.targetUserId),
    input.deviceFingerprintsHex,
    trigger.seq,
  );
  return detectForMember({
    ...input,
    trigger: "revoke_device",
    transitions: membershipTransitions(membership),
    revokedDeviceKeyFingerprints: input.deviceFingerprintsHex,
    selectWindows: (windows, environmentId) =>
      windows.flatMap((window) =>
        spans
          .filter((span) => scopeIncludes(span.scope, environmentId))
          .flatMap((span) => {
            const clipped = intersect(window, span.interval);
            return clipped === null ? [] : [clipped];
          }),
      ),
  });
}

/**
 * `revoke_server` 受理時の検出(§4.1 の revoke_server 変種)。区間 = 当該
 * サーバー鍵 FP の grant 区間(再 grant があれば区間ごと)、候補 = 各区間の
 * **環境別の開示窓**(拡大再 grant で後から入った環境は拡大 seq から — member と
 * 同じ窓導出)内の環境の変数、(a) = `server.lease_issued`(発行時点の環境内
 * アクティブ変数の全て — 環境単位配布)+ `server.value_decrypted`(予約)。
 */
export function detectServerRevocation(input: {
  readonly read: AuditRotationRead;
  readonly serverKeyFingerprintHex: string;
  readonly triggerChainSeq: number;
  readonly nowMs: number;
}): readonly AuditEventInput[] {
  const events = input.read.serverGrantEventsFor(input.serverKeyFingerprintHex);
  if (events.length === 0) {
    return [];
  }
  const windowsOf = windowsByEnvironment(grantTransitions(events));
  const lifetimes = [...variableLifetimes(input.read.variableLifecycles()).values()];
  const access = input.read.serverAccessEventsBy(input.serverKeyFingerprintHex);
  const results: AuditEventInput[] = [];
  for (const lifetime of lifetimes) {
    const windows = windowsOf(lifetime.environmentId).filter((window) =>
      overlaps(window, lifetime.start, lifetime.end),
    );
    if (windows.length === 0) {
      continue;
    }
    const fetched = access.some((row) => {
      if (row.environmentId !== lifetime.environmentId) {
        return false;
      }
      if (!windows.some((window) => within(row.seq, window))) {
        return false;
      }
      if (row.event === "server.lease_issued") {
        // 環境単位配布(§3.5): 発行時点にアクティブだった変数の全てが (a)
        return lifetime.start < row.seq && row.seq < lifetime.end;
      }
      // server.value_decrypted(予約 — v1 では発生しない): 変数粒度の照合
      return row.variableId === lifetime.variableId;
    });
    results.push(
      recommendedEvent({
        nowMs: input.nowMs,
        lifetime,
        basis: fetched ? "read" : "readable",
        trigger: "revoke_server",
        triggerChainSeq: input.triggerChainSeq,
        targetKeyFingerprintHex: input.serverKeyFingerprintHex,
      }),
    );
  }
  return results;
}

/** payload.trigger の読み出し(サーバー自身が書いた行 — 型は防御的に確認)。 */
function triggerOf(row: RotationFlagSourceRow): RotationTrigger {
  const trigger = row.payload?.["trigger"];
  if (
    trigger === "remove_member" ||
    trigger === "change_role" ||
    trigger === "revoke_server" ||
    trigger === "revoke_device"
  ) {
    return trigger;
  }
  // K3(2026-09-15)前の保存行は trigger を持たない: 当時の変種は remove_member /
  // revoke_server の 2 つだけなので target 列の種類から一意に補完できる
  return row.targetKeyFingerprintHex === null ? "remove_member" : "revoke_server";
}

/** recommended 行の payload から検出時の値を読む(サーバー自身が書いた行 — 型は防御的に確認)。 */
function flagOf(row: RotationFlagSourceRow): EffectiveRotationFlag {
  const basis = row.payload?.["basis"] === "read" ? "read" : "readable";
  const trigger = row.payload?.["triggerChainSeq"];
  return {
    environmentId: row.environmentId,
    variableId: row.variableId,
    basis,
    ...(row.targetUserId === null ? {} : { targetUserId: row.targetUserId }),
    ...(row.targetKeyFingerprintHex === null
      ? {}
      : { targetServerKeyFingerprintHex: row.targetKeyFingerprintHex }),
    recommendedAtMs: row.serverTs,
    triggerChainSeq: typeof trigger === "number" && trigger >= 1 ? trigger : 1,
    trigger: triggerOf(row),
  };
}

/**
 * フラグの解消導出(§4.1 手順 5): seq 順の畳み込み。recommended が積み、
 * それより後の `rotation.dismissed` または**再暗号化マーカーなしの**
 * `var.version_pushed` が同じ (variable × environment) の積みを消す。
 * 同じ対に複数の有効 recommended(再削除等)は全て返す(UI 側で束ねる)。
 */
export function deriveEffectiveFlags(
  rows: readonly RotationFlagSourceRow[],
): readonly EffectiveRotationFlag[] {
  const live = new Map<string, EffectiveRotationFlag[]>();
  for (const row of rows) {
    const key = pairKey(row);
    if (row.event === "rotation.recommended") {
      const flags = live.get(key);
      if (flags === undefined) {
        live.set(key, [flagOf(row)]);
      } else {
        flags.push(flagOf(row));
      }
      continue;
    }
    if (row.event === "var.version_pushed" && row.payload?.["reencryption"] === true) {
      // 再暗号化(同一平文の新エポック再 push — AUTH_SPEC §12-5)は上流の
      // 失効ではないため解消しない(§4.1-5)
      continue;
    }
    live.delete(key);
  }
  return [...live.values()].flat();
}
