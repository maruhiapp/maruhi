// チェーン取得応答からの表示用ビューの導出(S5 — 設計文書 §3)。
//
// これは**検証ではない**(ADR-0018 改訂 2・4 項 — Web バンドルにチェーン・署名
// 検証のコードを入れない): サーバーが返したエントリ列を、返された順で
// 機械的に畳み込むだけの表示変換であり、署名・ハッシュ連結・合意規則の検査を
// 一切行わない。結果はすべて「サーバー申告(as reported by the server)」で
// あり、UI もそう表示する。検証済みのメンバー集合が要る場面は
// `maruhi project verify`(CLI)の領分。
//
// 四眼(CRYPTO_SPEC §6.2 — PF1。設計録 es-design.md §12 K6-J): 方針と pending 提案も
// 同じ機械的な畳み込みで導く。approve / withdraw は提案を entry_hash で指すが、応答は
// エントリごとの hash を運ばないので、**次のエントリの prevHashHex**(末尾は headHashHex)
// から引く(hash を計算しない — 暗号を持ち込まない)。票数は記録をそのまま出さず、各
// approve の時点で「現 owner かつ鍵 FP が一致する投票者」を再集計する(K2 の実装メモ)。
// 鍵 FP は genesis の actor と、そのメンバーが署名した各エントリの actor から追跡し、
// add_member で前在籍と同じ鍵なら引き継ぐ(異なれば署名するまで「未知」= 数えない —
// 鍵が異なれば FP も異なるので合意規則も数えない)。定足数に達した approve は内側 op を
// 畳み込む(適用された remove を Members から消すために必要)。
//
// 端末鍵(CRYPTO_SPEC §3 / §6.2 — DK。設計録 dk-design.md §10 K5-1 / K5-2 / K5-4): メンバーは
// 端末の集合を持ち、`genesis` / `add_member` の鍵が最初の端末(cap は構造的に owner/all)、
// `add_device` / `revoke_device` が増減させる。`add_device` のワイヤは公開鍵 2 つと cap を
// 運び **FP を運ばない**(FP = SHA-256 の導出値)ので、端末は公開鍵対で同定し、FP は
// 「申告のバイト列から機械的に写せる範囲」でだけ束縛する: genesis の actor FP は最初の鍵、
// メンバーが署名したエントリの actor FP は「FP 未束縛の端末がちょうど 1 つ」のときだけ
// その端末に束縛する(hash は計算しない — K6-J)。`revoke_device` の FP は束縛済み端末に
// 一致すればその端末を外し、一致しない FP は未束縛端末の数だけ算術で外す(端末数は常に
// 正確、どれかは「unresolved」として正直に示す)。四眼の票は端末語彙で数える(§6.2)。
import type { ChainEntry } from "./types.ts";

/**
 * One device key of a member, derived from the reported entries (server-reported,
 * unverified). `keyFingerprintHex` is null while the fingerprint could not be
 * bound from the reported bytes (the `add_device` wire carries public keys, not
 * the fingerprint — K5-1); the cap and the adding seq are always reported.
 */
export interface ReportedDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  /** Role cap as reported (`owner` = no bound — CRYPTO_SPEC §6.2). */
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that put this key on the chain (genesis / add_member / add_device). */
  addedSeq: number;
}

/** One member row derived from the reported entries (server-reported, unverified). */
export interface ReportedMember {
  userId: string;
  role: string;
  /** Environment scope as reported (CRYPTO_SPEC §6.2 — `all`, or the listed environment ids). */
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  /** The reported chain seq that last set this member's role / scope. */
  sinceSeq: number;
  /** The member's device keys as reported (may include revoked-but-unresolved ones — see below). */
  devices: ReadonlyArray<ReportedDevice>;
  /**
   * Devices revoked among the fingerprint-less ones whose identity the reported
   * bytes cannot resolve (K5-1). The active device count is
   * `devices.length - unresolvedRevocations` (`reportedDeviceCount`).
   */
  unresolvedRevocations: number;
}

/** Active device count as reported (row count minus the unresolved revocations). */
export function reportedDeviceCount(
  member: Pick<ReportedMember, "devices" | "unresolvedRevocations">,
): number {
  return member.devices.length - member.unresolvedRevocations;
}

/** One granted server key derived from the reported entries (server-reported). */
export interface ReportedServer {
  keyFingerprintHex: string;
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
}

/** The four-eyes policy as reported (null = off). */
export interface ReportedPolicy {
  requiredApprovals: number;
  ops: ReadonlyArray<string>;
}

/** One pending proposal as reported (votes recounted under the policy current at the head). */
export interface ReportedProposal {
  proposalHashHex: string;
  proposalSeq: number;
  proposerUserId: string;
  /** `owner` puts the proposal signature into the signer set (one vote — §6.2). */
  proposerRoleAtProposal: string;
  innerOp: string;
  /** One-line summary of the inner operation (ids are shown raw — the UI neutralizes on render). */
  innerSummary: string;
  expiresAtMs: number;
  /** Distinct current owners whose signature counts (recounted — never the raw record). */
  votes: number;
  voterUserIds: ReadonlyArray<string>;
}

export interface ReportedChainView {
  members: ReportedMember[];
  servers: ReportedServer[];
  policy: ReportedPolicy | null;
  proposals: ReportedProposal[];
}

/** 投票の記録(user_id と署名時の鍵 FP — 原則 2 の S の要素)。 */
interface Vote {
  userId: string;
  keyFingerprintHex: string;
}

type EntryOf<Op extends ChainEntry["op"]> = Extract<ChainEntry, { op: Op }>;

/** 提案の内側 op(ワイヤ形 — approve の適用で畳み込む)。 */
type ProposableEntry = EntryOf<"propose">["payload"]["inner"];

interface PendingFold {
  seq: number;
  proposerUserId: string;
  proposerKeyFingerprintHex: string;
  proposerRoleAtProposal: string;
  inner: ProposableEntry;
  expiresAtMs: number;
  approvals: Vote[];
}

/** 端末 1 つの可変レコード(FP は束縛できたときだけ入る)。 */
interface MutableDevice {
  keyFingerprintHex: string | null;
  encPubHex: string;
  sigPubHex: string;
  roleCap: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  addedSeq: number;
}

/** メンバー 1 人の可変レコード(在籍 = 1 レコード。remove で消え、add_member で作り直す)。 */
interface MutableMember {
  userId: string;
  role: string;
  scopeKind: "all" | "listed";
  scopeEnvironmentIds: ReadonlyArray<string>;
  sinceSeq: number;
  devices: MutableDevice[];
  unresolvedRevocations: number;
  /**
   * この人が署名したが端末に束縛できなかった FP(未束縛端末が 2 つ以上のとき)。
   * 票の判定(K5-2)にだけ使い、失効で未束縛端末が減るたびに捨てる(fail-closed)。
   */
  unboundSignerFps: Set<string>;
}

interface FoldState {
  members: Map<string, MutableMember>;
  servers: Map<string, ReportedServer>;
  policy: ReportedPolicy | null;
  pending: Map<string, PendingFold>;
  /**
   * 学習済みの (user_id, 公開鍵対) → FP。一度束縛した鍵は失効後の再追加・再在籍でも同じ
   * FP を引き継ぐ(同じ鍵 ⇒ 同じ FP — K6-J の一般化)。user_id で区切るのは、鍵の同一性を
   * 人をまたいで推定しないため。
   */
  knownFingerprints: Map<string, string>;
}

type Scope = { scopeKind: "all" | "listed"; scopeEnvironmentIds: ReadonlyArray<string> };

function keyIdOf(userId: string, encPubHex: string, sigPubHex: string): string {
  return `${userId}:${encPubHex}:${sigPubHex}`;
}

/** 新しい端末レコード(学習済みなら FP を引き継ぐ)。 */
function newDevice(
  state: FoldState,
  userId: string,
  keys: { encPubHex: string; sigPubHex: string },
  cap: { roleCap: string } & Scope,
  addedSeq: number,
): MutableDevice {
  return {
    keyFingerprintHex:
      state.knownFingerprints.get(keyIdOf(userId, keys.encPubHex, keys.sigPubHex)) ?? null,
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    roleCap: cap.roleCap,
    scopeKind: cap.scopeKind,
    scopeEnvironmentIds: cap.scopeEnvironmentIds,
    addedSeq,
  };
}

/** genesis の作成者は構造的に scope = all(CRYPTO_SPEC §6.2)。最初の鍵の cap も (owner, all)。 */
const ALL_SCOPE = { scopeKind: "all", scopeEnvironmentIds: [] } as const;
const FIRST_DEVICE_CAP = { roleCap: "owner", ...ALL_SCOPE } as const;

/** 在籍の開始(genesis / add_member): レコードを作り直し、最初の端末 1 つを載せる。 */
function startTenure(
  state: FoldState,
  userId: string,
  role: string,
  scope: Scope,
  keys: { encPubHex: string; sigPubHex: string },
  seq: number,
): MutableMember {
  const member: MutableMember = {
    userId,
    role,
    scopeKind: scope.scopeKind,
    scopeEnvironmentIds: scope.scopeEnvironmentIds,
    sinceSeq: seq,
    devices: [newDevice(state, userId, keys, FIRST_DEVICE_CAP, seq)],
    unresolvedRevocations: 0,
    unboundSignerFps: new Set(),
  };
  state.members.set(userId, member);
  return member;
}

/** FP を端末に束縛して学習する。 */
function bindFingerprint(
  state: FoldState,
  userId: string,
  device: MutableDevice,
  fp: string,
): void {
  device.keyFingerprintHex = fp;
  state.knownFingerprints.set(keyIdOf(userId, device.encPubHex, device.sigPubHex), fp);
}

/** FP 未束縛の端末。 */
function unboundDevicesOf(member: MutableMember): MutableDevice[] {
  return member.devices.filter((d) => d.keyFingerprintHex === null);
}

/** 署名者のレコード(不在・または FP が既に束縛済みなら undefined = 結ぶものがない)。 */
function signerNeedingBinding(
  state: FoldState,
  userId: string,
  fp: string,
): MutableMember | undefined {
  const member = state.members.get(userId);
  if (member === undefined || member.devices.some((d) => d.keyFingerprintHex === fp))
    return undefined;
  return member;
}

/**
 * 署名した本人の actor FP をその人の端末へ結ぶ(K5-1): 既に束縛済みなら何もしない。
 * 未束縛の端末がちょうど 1 つならそれに束縛、2 つ以上なら同定せず「未束縛署名 FP」に
 * 入れる(票の判定にだけ使う — K5-2)。0 なら申告が読めない(無視)。
 */
function bindActor(state: FoldState, userId: string, fp: string): void {
  const member = signerNeedingBinding(state, userId, fp);
  if (member === undefined) return;
  const unbound = unboundDevicesOf(member);
  if (unbound.length >= 2) {
    member.unboundSignerFps.add(fp);
    return;
  }
  const sole = unbound[0];
  if (sole !== undefined) bindFingerprint(state, userId, sole, fp);
}

function applyChangeRole(
  state: FoldState,
  seq: number,
  payload: EntryOf<"change_role">["payload"],
): void {
  const existing = state.members.get(payload.targetUserId);
  if (existing !== undefined) {
    // 新 (role, scope) の全置換(§6.2 — 2026-09-15 ES K4 で scope も写す)。端末集合は不変
    existing.role = payload.newRole;
    existing.scopeKind = payload.scopeKind;
    existing.scopeEnvironmentIds = payload.scopeEnvironmentIds;
    existing.sinceSeq = seq;
  }
}

function applyGrantServer(
  state: FoldState,
  seq: number,
  payload: EntryOf<"grant_server">["payload"],
): void {
  state.servers.set(payload.serverKeyFingerprintHex, {
    keyFingerprintHex: payload.serverKeyFingerprintHex,
    scopeEnvironmentIds: payload.scopeEnvironmentIds,
    sinceSeq: seq,
  });
}

/** add_member: 在籍を開始(最初の端末 = payload の鍵。前在籍と同じ鍵なら FP を引き継ぐ)。 */
function applyAddMember(
  state: FoldState,
  seq: number,
  payload: EntryOf<"add_member">["payload"],
): void {
  startTenure(state, payload.targetUserId, payload.role, payload, payload, seq);
}

type OperationOf<Op extends ProposableEntry["op"]> = Extract<ProposableEntry, { op: Op }>;

// 適用済み op の畳み込み(直接追記と、定足数に達した approve の内側 op が共有する)。
// `seq` = 適用 seq(提案経由なら approve の seq — inclusive 規約)。create_environment /
// rotate_epoch / checkpoint / genesis はここに載せない(メンバー・サーバー集合に影響しない。
// genesis は deriveReportedView が鍵 FP の追跡込みで畳む)
const OPERATION_FOLDERS: {
  readonly [Op in ProposableEntry["op"]]?: (
    state: FoldState,
    seq: number,
    operation: OperationOf<Op>,
  ) => void;
} = {
  add_member: (state, seq, operation) => applyAddMember(state, seq, operation.payload),
  remove_member: (state, _seq, operation) =>
    void state.members.delete(operation.payload.targetUserId),
  change_role: (state, seq, operation) => applyChangeRole(state, seq, operation.payload),
  grant_server: (state, seq, operation) => applyGrantServer(state, seq, operation.payload),
  revoke_server: (state, _seq, operation) =>
    void state.servers.delete(operation.payload.serverKeyFingerprintHex),
  set_approval_policy: (state, _seq, operation) => {
    state.policy =
      operation.payload.requiredApprovals === 0
        ? null
        : {
            requiredApprovals: operation.payload.requiredApprovals,
            ops: [...new Set(operation.payload.ops)],
          };
  },
};

function applyOperation(state: FoldState, seq: number, operation: ProposableEntry): void {
  const fold = Object.hasOwn(OPERATION_FOLDERS, operation.op)
    ? (OPERATION_FOLDERS[operation.op] as
        | ((s: FoldState, q: number, o: ProposableEntry) => void)
        | undefined)
    : undefined;
  fold?.(state, seq, operation);
}

/** 原則 2 の S = {owner として提案した提案者} ∪ approvals。 */
function signersOf(pending: PendingFold): Vote[] {
  const proposer: Vote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/** 票の FP がその人の束縛済み端末なら、その端末の roleCap が owner か(未束縛なら undefined)。 */
function ownerVoteByDevice(member: MutableMember, fp: string): boolean | undefined {
  const device = member.devices.find((d) => d.keyFingerprintHex === fp);
  return device === undefined ? undefined : device.roleCap === "owner";
}

/** 束縛できなかった署名 FP: その人の未束縛端末が**すべて** roleCap owner のときだけ数える。 */
function ownerVoteByUnbound(member: MutableMember, fp: string): boolean {
  if (!member.unboundSignerFps.has(fp)) return false;
  const unbound = unboundDevicesOf(member);
  return unbound.length > 0 && unbound.every((d) => d.roleCap === "owner");
}

/**
 * 1 票が数えられるか(§6.2 の端末語彙 — K5-2): 投票者が現 owner で、票の FP がその人の
 * 束縛済み端末に一致し、端末の roleCap が owner(実効 role = owner)。束縛できなかった
 * 署名 FP は、その人の未束縛端末が**すべて** roleCap owner のときだけ数える(どの端末でも
 * 結論が同じ)。それ以外は数えない(fail-closed — 同定できない票は数えない)。
 */
function countsAsOwnerVote(state: FoldState, signer: Vote): boolean {
  const member = state.members.get(signer.userId);
  if (member === undefined || member.role !== "owner") return false;
  return (
    ownerVoteByDevice(member, signer.keyFingerprintHex) ??
    ownerVoteByUnbound(member, signer.keyFingerprintHex)
  );
}

/** 票数 = S のうち「現 owner かつ鍵 FP が一致(既知)」の distinct user_id(再集計)。 */
function countedVoters(state: FoldState, signers: ReadonlyArray<Vote>): string[] {
  const counted = signers.filter((signer) => countsAsOwnerVote(state, signer));
  return [...new Set(counted.map((signer) => signer.userId))];
}

function applyPropose(state: FoldState, entry: EntryOf<"propose">, hash: string | undefined): void {
  if (hash === undefined) return;
  state.pending.set(hash, {
    seq: entry.seq,
    proposerUserId: entry.actor.userId,
    proposerKeyFingerprintHex: entry.actor.keyFingerprintHex,
    proposerRoleAtProposal: state.members.get(entry.actor.userId)?.role ?? "unknown",
    inner: entry.payload.inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
}

/**
 * approve: 票を記録し、再集計が現方針の required に達したら内側 op を適用して pending から
 * 外す(§6.2 — approve エントリの seq で適用)。チェーンに載っている approve は受理面で
 * 合意規則を通っている(無効なものは載らない)ので、ここでは票の算術だけを写す。
 */
function applyApprove(state: FoldState, entry: EntryOf<"approve">): void {
  const pending = state.pending.get(entry.payload.proposalHashHex);
  if (pending === undefined) return;
  const vote: Vote = {
    userId: entry.actor.userId,
    keyFingerprintHex: entry.actor.keyFingerprintHex,
  };
  if (!quorumReached(state, [...signersOf(pending), vote])) {
    pending.approvals.push(vote);
    return;
  }
  state.pending.delete(entry.payload.proposalHashHex);
  applyOperation(state, entry.seq, pending.inner);
}

/** 再集計した票数が現方針の required に達したか(方針オフなら達しない)。 */
function quorumReached(state: FoldState, signers: ReadonlyArray<Vote>): boolean {
  const required = state.policy?.requiredApprovals;
  return required !== undefined && countedVoters(state, signers).length >= required;
}

// 内側 op の 1 行要約(識別子は生のまま — 描画側が中和する)
const INNER_SUMMARIES: {
  readonly [Op in ProposableEntry["op"]]?: (operation: OperationOf<Op>) => string;
} = {
  add_member: (o) => `add ${o.payload.targetUserId} as ${o.payload.role}`,
  remove_member: (o) => `remove ${o.payload.targetUserId}`,
  change_role: (o) => `change ${o.payload.targetUserId} to ${o.payload.newRole}`,
  grant_server: (o) => `grant server key ${o.payload.serverKeyFingerprintHex}`,
  revoke_server: (o) => `revoke server key ${o.payload.serverKeyFingerprintHex}`,
  set_approval_policy: (o) =>
    o.payload.requiredApprovals === 0
      ? "turn the approval policy off"
      : `set the approval policy to ${o.payload.requiredApprovals} approvals`,
};

function summarizeInner(operation: ProposableEntry): string {
  const summarize = Object.hasOwn(INNER_SUMMARIES, operation.op)
    ? (INNER_SUMMARIES[operation.op] as ((o: ProposableEntry) => string) | undefined)
    : undefined;
  return summarize === undefined ? operation.op : summarize(operation);
}

function applyGenesis(state: FoldState, entry: EntryOf<"genesis">): void {
  const member = startTenure(
    state,
    entry.actor.userId,
    "owner",
    ALL_SCOPE,
    entry.payload,
    entry.seq,
  );
  const first = member.devices[0];
  if (first !== undefined)
    bindFingerprint(state, member.userId, first, entry.actor.keyFingerprintHex);
}

// ---------------------------------------------------------------------------
// 端末 2 op(K5-1 / K5-4): fold の整合に要る構造規則だけを写し、読めない行は無視する
// ---------------------------------------------------------------------------

function isStringArray(value: unknown): value is ReadonlyArray<string> {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

/** scope の 2 フィールドが読める形か(型は信じず形だけ見る)。 */
function readableScope(payload: Scope): boolean {
  return (
    (payload.scopeKind === "all" || payload.scopeKind === "listed") &&
    isStringArray(payload.scopeEnvironmentIds)
  );
}

/** add_device の payload が読める形か(公開鍵・cap・scope)。 */
function readableAddDevice(payload: EntryOf<"add_device">["payload"]): boolean {
  const keysReadable = [payload.encPubHex, payload.sigPubHex, payload.roleCap].every(
    (field) => typeof field === "string",
  );
  return keysReadable && readableScope(payload);
}

/** 現メンバーの端末のうち同種公開鍵を持つもの(持ち主と端末)。 */
function currentKeyHolder(
  state: FoldState,
  encPubHex: string,
  sigPubHex: string,
): { member: MutableMember; device: MutableDevice } | undefined {
  for (const member of state.members.values()) {
    const device = member.devices.find(
      (d) => d.encPubHex === encPubHex || d.sigPubHex === sigPubHex,
    );
    if (device !== undefined) return { member, device };
  }
  return undefined;
}

/**
 * 同じ鍵が現メンバーの端末に見えるとき、それが曖昧に失効した未束縛端末の残骸かを解く(K5-12):
 * 受理された `add_device` は「その鍵は現在有効でない」(`duplicate-member-key`)を意味するので、
 * 持ち主に unresolved があり、その端末が未束縛なら、その端末こそ失効済みと確定して外す。
 * 解けなければ重複(読めない行)。
 */
function resolveStaleHolder(holder: { member: MutableMember; device: MutableDevice }): boolean {
  const { member, device } = holder;
  if (device.keyFingerprintHex !== null || member.unresolvedRevocations === 0) return false;
  member.devices = member.devices.filter((d) => d !== device);
  member.unresolvedRevocations -= 1;
  return true;
}

/** 新端末の鍵が使えるか: 現メンバーの端末と重複しない、または重複が失効の残骸として解ける。 */
function keyAvailable(state: FoldState, encPubHex: string, sigPubHex: string): boolean {
  const holder = currentKeyHolder(state, encPubHex, sigPubHex);
  return holder === undefined || resolveStaleHolder(holder);
}

/** add_device: actor 自身の端末集合へ新端末を加える(対象 = actor — §6.2)。 */
function applyAddDevice(state: FoldState, entry: EntryOf<"add_device">): void {
  const member = state.members.get(entry.actor.userId);
  const payload = entry.payload;
  if (member === undefined || !readableAddDevice(payload)) return;
  if (!keyAvailable(state, payload.encPubHex, payload.sigPubHex)) return;
  member.devices.push(newDevice(state, member.userId, payload, payload, entry.seq));
}

/** revoke_device の payload が読める形か(FP のリスト: 1 要素以上・重複なし)。 */
function readableRevokeDevice(payload: EntryOf<"revoke_device">["payload"]): boolean {
  const fps = payload.deviceFingerprintsHex;
  return (
    typeof payload.targetUserId === "string" &&
    isStringArray(fps) &&
    fps.length > 0 &&
    new Set(fps).size === fps.length
  );
}

/** 失効の算術(K5-1): 一致した端末・一致しない FP の数・未束縛の残り・読める形か。 */
interface RevocationPlan {
  matched: Set<MutableDevice>;
  unmatched: number;
  unboundRemaining: number;
  /** 一致しない FP が未束縛の残りを超えず、失効後に 1 台以上残る(§6.2 `unknown-device` / `last-device-protected`)。 */
  readable: boolean;
}

function planRevocation(member: MutableMember, fps: ReadonlySet<string>): RevocationPlan {
  const matched = new Set(
    member.devices.filter((d) => d.keyFingerprintHex !== null && fps.has(d.keyFingerprintHex)),
  );
  const unmatched = fps.size - matched.size;
  const unboundRemaining = unboundDevicesOf(member).length - member.unresolvedRevocations;
  const countAfter = member.devices.length - member.unresolvedRevocations - fps.size;
  return {
    matched,
    unmatched,
    unboundRemaining,
    readable: unmatched <= unboundRemaining && countAfter > 0,
  };
}

/** 失効の対象メンバー(payload が読めない・対象が現メンバーでないなら undefined)。 */
function revocationTarget(
  state: FoldState,
  payload: EntryOf<"revoke_device">["payload"],
): MutableMember | undefined {
  return readableRevokeDevice(payload) ? state.members.get(payload.targetUserId) : undefined;
}

/** 一致しない FP を未束縛端末から算術で外す(残り全部なら消し、少なければ unresolved に数える)。 */
function revokeUnbound(member: MutableMember, plan: RevocationPlan): void {
  // 未束縛端末が減る = 未束縛署名 FP の端末が失効したかもしれない → 票の材料を捨てる
  member.unboundSignerFps.clear();
  if (plan.unmatched === plan.unboundRemaining) {
    member.devices = member.devices.filter((d) => d.keyFingerprintHex !== null);
    member.unresolvedRevocations = 0;
  } else {
    member.unresolvedRevocations += plan.unmatched;
  }
}

/**
 * revoke_device: 束縛済み端末に一致する FP はその端末を外し、一致しない FP は未束縛端末の
 * 数だけ算術で外す(K5-1)。未束縛の残り(行数 − unresolved)と一致すれば全部外し、少なければ
 * unresolved に数える(端末数は正確・どれかは不明)。多い / 失効後 0 台 / 対象不明は無視。
 */
function applyRevokeDevice(state: FoldState, entry: EntryOf<"revoke_device">): void {
  const member = revocationTarget(state, entry.payload);
  if (member === undefined) return;
  const plan = planRevocation(member, new Set(entry.payload.deviceFingerprintsHex));
  if (!plan.readable) return;
  member.devices = member.devices.filter((d) => !plan.matched.has(d));
  if (plan.unmatched > 0) revokeUnbound(member, plan);
}

// エントリ自体の畳み込み(genesis・四眼の 4 op・端末の 2 op)。端末の 2 op は提案できない
// (§6.2 `approval-not-required`)ので直接エントリとしてだけ畳む(内側 op としては無視 —
// K5-4)。それ以外の状態を変える op は applyOperation(適用済み op の表 — 完成した approve
// の内側 op と共有)
const ENTRY_FOLDERS: {
  readonly [Op in ChainEntry["op"]]?: (
    state: FoldState,
    entry: EntryOf<Op>,
    hash: string | undefined,
  ) => void;
} = {
  genesis: applyGenesis,
  propose: applyPropose,
  approve: (state, entry) => applyApprove(state, entry),
  withdraw: (state, entry) => void state.pending.delete(entry.payload.proposalHashHex),
  add_device: applyAddDevice,
  revoke_device: applyRevokeDevice,
};

/** 1 エントリの畳み込み。 */
function foldEntry(state: FoldState, entry: ChainEntry, hash: string | undefined): void {
  // Object.hasOwn: 敵対的サーバーの op(例: "__proto__")がプロトタイプ鎖の
  // 値に当たって throw で描画を落とさないための自衛
  if (!Object.hasOwn(ENTRY_KINDS, entry.op)) return;
  const fold = Object.hasOwn(ENTRY_FOLDERS, entry.op)
    ? (ENTRY_FOLDERS[entry.op] as
        | ((s: FoldState, e: ChainEntry, h: string | undefined) => void)
        | undefined)
    : undefined;
  if (fold !== undefined) {
    fold(state, entry, hash);
    return;
  }
  applyOperation(state, entry.seq, entry as ProposableEntry);
}

// 畳み込みに載せる op の閉集合(own-property 判定用)。create_environment / rotate_epoch /
// checkpoint はメンバー・サーバー集合に影響しないため載せない。scope(add_member /
// change_role の末尾 2 フィールド)は K4(2026-09-15 ES — 設計録 K4-D)で、四眼の 4 op は
// K6(設計録 K6-J)で、端末の 2 op は DK K5(設計録 dk-design.md §10)で写す
const ENTRY_KINDS: { readonly [Op in ChainEntry["op"]]?: true } = {
  genesis: true,
  add_member: true,
  remove_member: true,
  change_role: true,
  grant_server: true,
  revoke_server: true,
  set_approval_policy: true,
  propose: true,
  approve: true,
  withdraw: true,
  add_device: true,
  revoke_device: true,
};

/** 可変レコード → 公開の行(票の材料は出さない)。 */
function reportedMemberOf(member: MutableMember): ReportedMember {
  return {
    userId: member.userId,
    role: member.role,
    scopeKind: member.scopeKind,
    scopeEnvironmentIds: member.scopeEnvironmentIds,
    sinceSeq: member.sinceSeq,
    devices: member.devices.map((d) => ({ ...d })),
    unresolvedRevocations: member.unresolvedRevocations,
  };
}

/**
 * 返された順のエントリ列を表示用のメンバー / サーバー集合・方針・pending 提案へ畳み込む。
 * `headHashHex` は末尾エントリの hash(応答の headHashHex — サーバー申告)。
 */
export function deriveReportedView(
  entries: ReadonlyArray<ChainEntry>,
  headHashHex?: string,
): ReportedChainView {
  const state: FoldState = {
    members: new Map(),
    servers: new Map(),
    policy: null,
    pending: new Map(),
    knownFingerprints: new Map(),
  };
  entries.forEach((entry, index) => {
    // 署名した本人の actor FP はそのメンバーの端末の 1 つ(受理面が検証済み — as reported)
    bindActor(state, entry.actor.userId, entry.actor.keyFingerprintHex);
    // エントリ i の hash = エントリ i + 1 の prevHashHex、末尾は headHashHex
    foldEntry(state, entry, entries[index + 1]?.prevHashHex ?? headHashHex);
  });
  const proposals = [...state.pending]
    .map(([hash, pending]) => {
      const voters = countedVoters(state, signersOf(pending));
      return {
        proposalHashHex: hash,
        proposalSeq: pending.seq,
        proposerUserId: pending.proposerUserId,
        proposerRoleAtProposal: pending.proposerRoleAtProposal,
        innerOp: pending.inner.op,
        innerSummary: summarizeInner(pending.inner),
        expiresAtMs: pending.expiresAtMs,
        votes: voters.length,
        voterUserIds: voters,
      };
    })
    .toSorted((a, b) => a.proposalSeq - b.proposalSeq);
  return {
    members: [...state.members.values()].map(reportedMemberOf),
    servers: [...state.servers.values()],
    policy: state.policy,
    proposals,
  };
}
