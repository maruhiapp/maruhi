"use client";

// ダッシュボード共通部品(裁定 BP の文言一元化 — docs/notes/session-43.md)。
// ユーザー可視文言はすべて英語(ADR-0017)。表示規律(設計文書 §4):
// サーバー申告の言い回しに限り、クライアント側の断定(expired / revoked /
// not a member 等)を含めない。
//
// 空状態 / ローディング / エラーの規律(DP3 裁定 B — docs/notes/web-design-pass.md §5):
// 各リソースの 3 状態は次の 3 部品だけで描く。画面側で Text / Banner を直接組まない。
//   - ローディング = `LoadingRow`(スピナー + 何を読んでいるかの 1 行。role="status")
//   - 空 = `EmptyNotice`(見出し + 「as reported by the server」の説明。件数は出さない)
//   - 失敗 = `FailureNotice`(HTTP 分類ごとの Banner。置き方は 2 種のみ)
//       (a) 置換: リソース本体の代わりに描く。再取得手段があれば onRetry を渡す
//       (b) 追記: 既に描けた本体の下に足す(Load more の失敗・失効の失敗)。
//           行から再操作できる失敗(失効)は onRetry を渡さない
//     13 か所の呼び出しは AuditEventList(2)/ TokensScreen(2)/ DashboardScreen(2)/
//     InvitesTab(2)/ ProjectScreen(4)+ DashboardShell(1)= 置換 9 / 追記 4
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Spinner } from "@astryxdesign/core/Spinner";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import * as stylex from "@stylexjs/stylex";
import type { ReactNode } from "react";

import type { ApiFailure } from "./api.ts";
import { spaPaths } from "./routes.ts";
import type { ChainRole, ForbiddenReason } from "./types.ts";

/**
 * SPA 内の命令的ナビゲーション(ID 直入力の Open 等)。Navigation API が
 * あれば SPA 遷移、なければフルページロードへ劣化(Router の fallback="static"
 * と同じ劣化線)。
 */
export function navigateTo(path: string): void {
  const nav = (window as { navigation?: { navigate: (url: string) => void } }).navigation;
  if (nav) {
    nav.navigate(path);
  } else {
    window.location.assign(path);
  }
}

/** サーバー時刻(ms)の表示形。UTC 明示の ISO 形式(ローカル換算の演出をしない)。 */
export function formatServerTime(ms: number): string {
  const date = new Date(ms);
  return Number.isFinite(date.getTime()) ? date.toISOString() : String(ms);
}

const ROLE_TOKEN_COLOR: Record<ChainRole, "purple" | "blue" | "green" | "gray"> = {
  owner: "purple",
  admin: "blue",
  member: "green",
  reader: "gray",
};

/**
 * チェーン導出 role のサーバー申告値の表示(設計文書 §4 — 検証済みを名乗らない)。
 * Object.hasOwn: 想定外の role 文字列(プロトタイプ鎖の鍵名を含む)は
 * default 色へ落とす(PR #107 pullfrog 指摘)。
 */
export function RoleToken({ role }: { role: string }): ReactNode {
  const color = Object.hasOwn(ROLE_TOKEN_COLOR, role)
    ? ROLE_TOKEN_COLOR[role as ChainRole]
    : ("default" as const);
  return <Token label={role} size="sm" color={color} />;
}

// 比較リテラルを api-schema の閉じた列挙へ型束縛する(裁定 CC): reason 名の
// リネームは「一般文言への無音フォールバック」でなくコンパイルエラーで割れる
const SESSION_NOT_ALLOWED = "session-not-allowed" satisfies ForbiddenReason;

/**
 * 404 文言の対象名詞(裁定 CN の付随具体化 — docs/notes/session-45.md §5)。
 * 一様 404 の意味(他人の・存在しないを区別しない)は変えず、画面の対象に
 * 合わせて名詞だけ替える — 文言の一元化(裁定 BP)は本モジュールが保つ。
 */
export type FailureSubject = "project" | "invitation" | "token";

const NOT_FOUND_DESCRIPTION: Record<FailureSubject, string> = {
  project: "The server reports no such project for your account.",
  invitation: "The server reports no such invitation for this project.",
  token: "The server reports no such token for your account.",
};

/** 403 の表示(reason 別 — session-not-allowed は CLI へ誘導)。 */
function ForbiddenNotice({ reason }: { reason: string | undefined }): ReactNode {
  return reason === SESSION_NOT_ALLOWED ? (
    <Banner
      status="warning"
      title="Not available to browser sessions"
      description="This data is not exposed to browser sessions. Use the maruhi CLI instead."
    />
  ) : (
    <Banner
      status="info"
      title="Not available to your role"
      description="Not available to your role in this project, as reported by the server."
    />
  );
}

function UnreachableNotice({ onRetry }: { onRetry: (() => void) | undefined }): ReactNode {
  return (
    <Banner
      status="error"
      title="Could not reach the server"
      endContent={onRetry ? <Button label="Retry" variant="secondary" onClick={onRetry} /> : null}
    />
  );
}

/**
 * 410 の表示(現状は invite 失効面のみが受ける — サーバー申告の reason を写す)。
 * 名詞は NOT_FOUND_DESCRIPTION と同じく subject から取る(裁定 BP の単一
 * 実装点 — 他の消費面が 410 を持ったとき片方だけ名詞が固定される形を残さない。
 * PR #109 pullfrog 指摘)。
 */
function GoneNotice({
  reason,
  subject,
}: {
  reason: string | undefined;
  subject: FailureSubject;
}): ReactNode {
  return (
    <Banner
      status="info"
      title="No longer active"
      description={
        reason === undefined
          ? `The server reports this ${subject} is no longer active.`
          : `The server reports this ${subject} as ${reason}.`
      }
    />
  );
}

function StatusNotice({
  failure,
  onRetry,
  subject,
}: {
  failure: ApiFailure;
  onRetry: (() => void) | undefined;
  subject: FailureSubject;
}): ReactNode {
  if (failure.kind === "not-found") {
    return <Banner status="info" title="Not found" description={NOT_FOUND_DESCRIPTION[subject]} />;
  }
  if (failure.kind === "unauthorized") {
    return (
      <Banner
        status="warning"
        title="Signed out"
        description="Your session has ended. Sign in again to continue."
        endContent={<Link href={spaPaths.dashboard()}>Go to sign-in</Link>}
      />
    );
  }
  return <UnreachableNotice onRetry={onRetry} />;
}

/** 401 以外の失敗の画面内表示(401 は各画面がログインカードへ差し替える)。 */
export function FailureNotice({
  failure,
  onRetry,
  subject = "project",
}: {
  failure: ApiFailure;
  onRetry?: () => void;
  subject?: FailureSubject;
}): ReactNode {
  if (failure.kind === "forbidden") return <ForbiddenNotice reason={failure.reason} />;
  if (failure.kind === "gone") return <GoneNotice reason={failure.reason} subject={subject} />;
  return <StatusNotice failure={failure} onRetry={onRetry} subject={subject} />;
}

/**
 * ローディング表示(リソース本体の置き換え用)。Spinner が role="status" を持ち
 * label を読み上げる — 見える文言と同じ 1 行にする(裁定 B)。
 */
export function LoadingRow({ label }: { label: string }): ReactNode {
  return (
    <HStack gap={2} align="center">
      <Spinner size="sm" aria-label={label} />
      <Text type="supporting">{label}</Text>
    </HStack>
  );
}

/**
 * 空状態(裁定 B)。説明は既定で「as reported by the server」を含む規定文言 —
 * 件数・不可視クラスの存在を示唆しない(設計文書 §4-4)。`headingLevel` は
 * 置かれる場所の見出し階層に合わせる(ページ h1 → 節 h2 → 空状態 h3 が既定)。
 */
export function EmptyNotice({
  title,
  description = "Nothing to show, as reported by the server.",
  headingLevel = 3,
  testId,
}: {
  title: string;
  description?: string;
  headingLevel?: 2 | 3 | 4;
  testId?: string;
}): ReactNode {
  return (
    <VStack data-testid={testId}>
      <EmptyState title={title} description={description} headingLevel={headingLevel} isCompact />
    </VStack>
  );
}

// 識別子(64 hex の project ID / チェーンハッシュ / 鍵 FP / row_id)の表示。空白を
// 含まない長い文字列は Text の wordBreak だけでは折れない(inline 要素の幅が親の
// flex 項目の min-content を押し広げる)ため、xstyle で anywhere 折りを明示する。
// DP3 で同じ上書きが繰り返し必要になったので本モジュールに 1 定義だけ置き、
// 画面側は HexText を使う(variant / ui.package への昇格は人間の判断 — 裁定 H)
const hexStyles = stylex.create({
  breakable: {
    overflowWrap: "anywhere",
    wordBreak: "break-all",
    minWidth: 0,
  },
});

/** 識別子の短縮形(先頭・末尾 6 桁 — 見出しとサイドバーの子項目用。全文は HexText で並記する)。 */
export function shortId(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-6)}`;
}

/** 識別子の表示(等幅・任意位置で折り返し)。`size` は周囲の密度に合わせる。 */
export function HexText({
  children,
  size = "sm",
  testId,
}: {
  children: string;
  size?: "sm" | "xsm" | "2xs";
  testId?: string;
}): ReactNode {
  return (
    <Text type="code" size={size} xstyle={hexStyles.breakable} data-testid={testId}>
      {children}
    </Text>
  );
}

/**
 * 狭い幅の判定(DP3 裁定 D)。AppShell の mobileNav 既定ブレークポイント `md`
 * (768px、`(max-width: 768px)`)と同じ式にし、ナビのドロワー化と本文の表示形
 * 切替(監査一覧の Table → List)が同じ幅で起きるようにする。他の表は Astryx の
 * Table 自身が横スクロール枠(role="group" の scroll wrapper)を持つのでそのまま。
 */
export const NARROW_VIEWPORT_QUERY = "(max-width: 768px)";

/**
 * 期限の表示(裁定 CQ — docs/notes/session-45.md)。表示の主体は常にサーバー
 * 申告の expiresAtMs(過去判定のみクライアント時計との比較)。null は移行
 * (AUTH_SPEC §6 裁定 CE-c′)前の旧無期限行で、検証側が期限切れとして扱う
 * (fail-closed)ため表示も Expired + no expiry recorded とする — 仕様が定める
 * 挙動の写しであり、クライアントの捏造ではない。
 */
export function ExpiryCell({ expiresAtMs }: { expiresAtMs: number | null }): ReactNode {
  const expired = expiresAtMs === null || expiresAtMs <= Date.now();
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <Text type="supporting" size="sm" hasTabularNumbers>
        {expiresAtMs === null ? "no expiry recorded" : formatServerTime(expiresAtMs)}
      </Text>
      {expired ? <Token label="Expired" size="sm" color="red" /> : null}
    </HStack>
  );
}

/**
 * インライン 2 段階の失効ボタン(裁定 CO — docs/notes/session-45.md)。
 * 武装(armed)状態は親が行単位で管理する(常に 1 行のみ — 別行の武装・
 * Cancel で解除)。確認は destructive バリアント、実行中は isLoading。
 * 失効の帰結の注記は各画面がテーブル下へ常時表示する(武装時だけ出す形より
 * 先に読める)。
 */
export function RevokeControl({
  armed,
  isPending,
  isLocked,
  onArm,
  onCancel,
  onConfirm,
}: {
  armed: boolean;
  isPending: boolean;
  /** 別の行の失効が実行中(PR #109 Bugbot 指摘 — in-flight 中は他行を無効化)。 */
  isLocked: boolean;
  onArm: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}): ReactNode {
  if (!armed) {
    return (
      <Button label="Revoke" variant="ghost" size="sm" onClick={onArm} isDisabled={isLocked} />
    );
  }
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <Button label="Cancel" variant="ghost" size="sm" onClick={onCancel} isDisabled={isPending} />
      <Button
        label="Confirm revoke"
        variant="destructive"
        size="sm"
        onClick={onConfirm}
        isLoading={isPending}
      />
    </HStack>
  );
}

/**
 * 表示規律の但し書き(設計文書 §4-1・§4-2): 全表示はサーバー申告であり、
 * 検証済み表示が要る場面は CLI へ誘導する。
 */
export function ServerReportedNote(): ReactNode {
  return (
    <Text type="supporting" as="p">
      Everything on this page is shown as reported by the server. Integrity verification is the
      CLI's job: run <Text type="code">maruhi project verify</Text> or{" "}
      <Text type="code">maruhi audit verify</Text> on your own machine.
    </Text>
  );
}
