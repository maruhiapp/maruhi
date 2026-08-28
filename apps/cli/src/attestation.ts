// ヘッドゴシップのクライアント面(CRYPTO_SPEC §6.3 ヘッドゴシップ / §6.6、
// AUTH_SPEC §16-1 — 2026-08-28 PR-M4)。
//
// 照合(reconcileDistributedAttestations): チェーン取得応答に同梱された
// 他メンバーの申告を §6.6 で検証した上で自ビューと照合する。
//   (a) 申告 seq ≤ 自ヘッドでハッシュ不一致 = 分岐(equivocation)または
//       attester 鍵漏洩の**硬い証拠** — 当該同期の成果物の使用を中断して警告し、
//       証拠(申告 + 自ビューのチェーンダイジェスト)を追記専用の非機密ローカル
//       状態へ保存する(§14.2-5 の証拠化 — floor-evidence 様式)
//   (b) 申告 seq > 自ヘッド = 自分のチェーンが古いだけの可能性 — 既存の有界
//       再同期(sync.ts の resyncExtended — 1 回)で延長として解決すれば正常、
//       解決しなければ (a) と同じ扱い
// 検証に失敗した申告(署名・履歴外 attester 等)は**照合材料にしない**(偽申告に
// よる警告誘発 DoS の排除 — §6.6)。現メンバーでない attester の申告も同様
// (§6.6 (1) — サーバーは remove 時に行を削除するはずで、配布自体が逸脱)。
//
// 提出(submitHeadAttestationIfAdvanced): チェーン同期 + 検証の成功後、検証済み
// ヘッドが前回申告より前進していれば署名して提出する(SHOULD — 失敗は非失敗の
// 警告。旧サーバーには PUT が存在しない — SELF_HOSTING.md の更新順)。前回申告の
// 追跡は床の join 格子外の非機密ローカル状態(floor.ts の loadAttestedHead —
// 喪失は同一 seq 再提出でサーバーの冪等 204 が吸収する)。
//
// ci run(lease 経路)はゴシップに参加しない(§6.6 / §14-2 — lease 応答は申告を
// 同梱せず、ワークロードは署名鍵を持たない)。

import { AttestationRegressionError } from "@maruhi/api-schema";
import { SUITE_ID, signHeadAttestation, verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices } from "./context.ts";
import { cliError, type CliError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { formatAttestationEvidence } from "./floor-evidence.ts";
import { type AttestationEvidenceRecord, FloorStore } from "./floor.ts";
import { CliIo } from "./io.ts";
import type { DistributedAttestationWire, VerifiedProject } from "./sync.ts";
import { resyncExtended } from "./sync.ts";

/** 1 申告の照合結果(内部)。 */
type MatchOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "skip" }
  | { readonly kind: "future" }
  | { readonly kind: "mismatch" };

/**
 * 1 申告の §6.6 検証 + 自ビュー照合。検証失敗は skip(照合材料にしない)、
 * ヘッド束縛の 2 種(§6.3-2)だけを future / mismatch として返す。
 */
async function matchAttestation(
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
): Promise<MatchOutcome> {
  // §6.6 (1) 前半: attester(user_id + 鍵 FP)が自ビューの現メンバーであること。
  // 現メンバーでない申告は照合材料にしない(サーバーは remove 時に行を削除する —
  // §6.4。配布されても在籍区間内の過去申告に警告価値はない)
  const current = view.history.memberStateAt(attestation.attesterUserId, view.state.headSeq);
  if (
    current === undefined ||
    current.keyFingerprintHex !== attestation.attesterKeyFingerprintHex
  ) {
    return { kind: "skip" };
  }
  const verified = await verifyDistributedHeadAttestation({
    history: view.history,
    context: {
      suite: attestation.suite,
      projectId: view.projectId,
      attesterUserId: attestation.attesterUserId,
      chainHeadHashHex: attestation.chainHeadHashHex,
      chainHeadSeq: attestation.chainHeadSeq,
    },
    attesterKeyFingerprintHex: attestation.attesterKeyFingerprintHex,
    signatureHex: attestation.signatureHex,
  });
  if (verified.ok) {
    return { kind: "ok" };
  }
  if (verified.error.kind !== "HeadAttestationInvalid") {
    return { kind: "skip" };
  }
  if (verified.error.reason === "chain-head-future") {
    return { kind: "future" };
  }
  if (verified.error.reason === "chain-head-mismatch") {
    // 署名・鍵選択は検証済み(検査順 — §6.6)なので、この不一致は申告自体が
    // 証拠になる(捨てる skip とは区別する)
    return { kind: "mismatch" };
  }
  return { kind: "skip" };
}

interface Classified {
  readonly evidence: DistributedAttestationWire[];
  readonly future: DistributedAttestationWire[];
}

async function classifyAll(
  view: VerifiedProject,
  attestations: readonly DistributedAttestationWire[],
): Promise<Classified> {
  const evidence: DistributedAttestationWire[] = [];
  const future: DistributedAttestationWire[] = [];
  for (const attestation of attestations) {
    const outcome = await matchAttestation(view, attestation);
    if (outcome.kind === "mismatch") {
      evidence.push(attestation);
    } else if (outcome.kind === "future") {
      future.push(attestation);
    }
  }
  return { evidence, future };
}

function evidenceRecordOf(
  view: VerifiedProject,
  attestation: DistributedAttestationWire,
  kind: AttestationEvidenceRecord["kind"],
): AttestationEvidenceRecord {
  return {
    attestation: {
      suite: attestation.suite,
      attesterUserId: attestation.attesterUserId,
      attesterKeyFingerprintHex: attestation.attesterKeyFingerprintHex,
      chainHeadHashHex: attestation.chainHeadHashHex,
      chainHeadSeq: attestation.chainHeadSeq,
      signatureHex: attestation.signatureHex,
    },
    localView: {
      headSeq: view.state.headSeq,
      headHashHex: view.state.headHashHex,
      entryHashAtAttestedSeq: view.history.entryHashAt(attestation.chainHeadSeq) ?? "",
    },
    kind,
    detectedAtMs: Date.now(),
  };
}

/** 証拠の保存(追記専用)+ 警告 + 当該同期の成果物の使用中断(fail)。 */
function failWithEvidence(
  projectId: string,
  view: VerifiedProject,
  records: readonly {
    attestation: DistributedAttestationWire;
    kind: AttestationEvidenceRecord["kind"];
  }[],
): Effect.Effect<never, CliError, CliServices> {
  return Effect.gen(function* () {
    const store = yield* FloorStore;
    const evidence = records.map((record) =>
      evidenceRecordOf(view, record.attestation, record.kind),
    );
    let evidencePath = "(could not be written)";
    for (const record of evidence) {
      // 証拠保存自体の失敗は検出を握り潰さない(警告本文が証拠を含む — 保存は
      // 追加の保全であり、失敗しても中断・警告は変わらない)
      const written = yield* store
        .appendAttestationEvidence(projectId, record)
        .pipe(Effect.catch(() => Effect.succeed(null)));
      if (written !== null) {
        evidencePath = written;
      }
    }
    return yield* Effect.fail(
      cliError(formatAttestationEvidence(projectId, evidence, evidencePath)),
    );
  });
}

/**
 * 配布された申告集合の検証・照合(モジュール冒頭コメントの (a)(b))。future 申告が
 * あれば 1 回だけ有界再同期し(resyncExtended — 延長でなければそこで拒否)、
 * 前進後のビューで自ビューの申告集合 + 未解決分を再照合する。解決しなければ (a)。
 * 成功時は照合済みのビュー(再同期で前進していることがある)を返す。
 */
export function reconcileDistributedAttestations(input: {
  readonly projectId: string;
  readonly view: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
}): Effect.Effect<VerifiedProject, CliError, CliServices> {
  return Effect.gen(function* () {
    const first = yield* Effect.promise(() => classifyAll(input.view, input.view.attestations));
    if (first.evidence.length > 0) {
      return yield* failWithEvidence(
        input.projectId,
        input.view,
        first.evidence.map((attestation) => ({ attestation, kind: "head-mismatch" as const })),
      );
    }
    if (first.future.length === 0) {
      return input.view;
    }
    // (b): 有界再同期(1 回)。延長検査(resyncExtended)は別チェーンへの
    // 差し替えをここで落とす
    const advanced = yield* resyncExtended(input.resync, input.view);
    // 再同期後のビュー自身の申告集合と、未解決だった future 分を再照合する
    // (future 分は新集合で同 attester のより新しい申告に置き換わっているのが
    // 正常形だが、置き換わらず消えた場合も元申告の解決可否で判定する)
    const second = yield* Effect.promise(() =>
      classifyAll(advanced, [...advanced.attestations, ...first.future]),
    );
    if (second.evidence.length > 0 || second.future.length > 0) {
      return yield* failWithEvidence(input.projectId, advanced, [
        ...second.evidence.map((attestation) => ({
          attestation,
          kind: "head-mismatch" as const,
        })),
        ...second.future.map((attestation) => ({
          attestation,
          kind: "unresolved-after-resync" as const,
        })),
      ]);
    }
    return advanced;
  });
}

/**
 * 検証済みヘッドの申告提出(§6.3 ヘッドゴシップ — SHOULD)。前回申告より前進して
 * いる場合のみ署名して PUT し、成功したら追跡を更新する。**いかなる失敗も
 * コマンドを失敗させない**(黙殺はしない — 警告 1 行に落とす): 旧サーバー
 * (PUT 未実装 = 404 等)との併用を壊さないため。409(AttestationRegression)は
 * 自ビューの後退 = 床破損・並行 CLI の徴候として区別して警告する。
 */
export function submitHeadAttestationIfAdvanced(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly view: VerifiedProject;
  readonly attesterUserId: string;
  readonly signingKey: CryptoKey;
}): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const store = yield* FloorStore;
    const head = { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex };
    const attested = yield* store
      .loadAttestedHead(input.projectId)
      .pipe(Effect.catch(() => Effect.succeed(null)));
    if (attested !== null && head.seq <= attested.seq) {
      // 前進していない(同一ヘッドの再申告はサーバー側冪等だが、SHOULD の契機は
      // 「前進していれば」— 提出もレート窓消費も行わない)
      return;
    }
    const signed = yield* Effect.promise(() =>
      signHeadAttestation({
        context: {
          suite: SUITE_ID,
          projectId: input.projectId,
          attesterUserId: input.attesterUserId,
          chainHeadHashHex: head.hashHex,
          chainHeadSeq: head.seq,
        },
        signingKey: input.signingKey,
      }),
    );
    if (!signed.ok) {
      yield* io.logError(
        "Note: could not sign the head attestation for this sync (split-view gossip). This does not affect the current command",
      );
      return;
    }
    // `_tag` 直読みは oxlint が禁止 — 判定は instanceof(failure.ts の規律)、
    // 診断名は internalErrorKind(型名のみ — 応答断片を運ばない)
    const submitted = yield* input.client.membership
      .attest({
        params: { projectId: input.projectId },
        payload: {
          suite: SUITE_ID,
          chainHeadHashHex: head.hashHex,
          chainHeadSeq: head.seq,
          signatureHex: signed.value,
        },
      })
      .pipe(
        Effect.as("submitted" as const),
        Effect.catch((error) =>
          Effect.succeed(
            error instanceof AttestationRegressionError ? "regression" : internalErrorKind(error),
          ),
        ),
      );
    if (submitted === "submitted") {
      yield* store
        .saveAttestedHead(input.projectId, head)
        .pipe(
          Effect.catch(() =>
            io.logError(
              "Note: the head attestation was submitted but its local tracking file could not be written (the next sync may re-submit the same head, which the server treats as an idempotent success)",
            ),
          ),
        );
      return;
    }
    // 提出失敗は非失敗(SHOULD)だが黙殺しない — 1 行の警告に落とす
    if (submitted === "regression") {
      yield* io.logError(
        "Warning: the server rejected this head attestation as a regression (it stores a later attestation from this account). This can indicate local floor damage or a concurrent CLI on another machine that has seen a later chain — run `maruhi project verify` and compare with other members if you do not recognize this",
      );
      return;
    }
    yield* io.logError(
      `Note: could not submit the head attestation for this sync (split-view gossip stays inactive for this account until it succeeds; the server may be running a previous release without PUT /projects/:id/head-attestation). This does not affect the current command (${submitted})`,
    );
  });
}
