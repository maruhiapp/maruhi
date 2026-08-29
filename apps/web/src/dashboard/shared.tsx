"use client";

// ダッシュボード共通部品(裁定 BP の文言一元化 — docs/notes/session-43.md)。
// ユーザー可視文言はすべて英語(ADR-0017)。表示規律(設計文書 §4):
// サーバー申告の言い回しに限り、クライアント側の断定(expired / revoked /
// not a member 等)を含めない。
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { HStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Spinner } from "@astryxdesign/core/Spinner";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import type { ReactNode } from "react";

import type { ApiFailure } from "./api.ts";
import { spaPaths } from "./routes.ts";
import type { ChainRole } from "./types.ts";

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

/** 403 の表示(reason 別 — session-not-allowed は CLI へ誘導)。 */
function ForbiddenNotice({ reason }: { reason: string | undefined }): ReactNode {
  return reason === "session-not-allowed" ? (
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

/** 401 以外の失敗の画面内表示(401 は各画面がログインカードへ差し替える)。 */
export function FailureNotice({
  failure,
  onRetry,
}: {
  failure: ApiFailure;
  onRetry?: () => void;
}): ReactNode {
  if (failure.kind === "forbidden") return <ForbiddenNotice reason={failure.reason} />;
  if (failure.kind === "not-found") {
    return (
      <Banner
        status="info"
        title="Not found"
        description="The server reports no such project for your account."
      />
    );
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

/** ローディング表示(行の置き換え用)。 */
export function LoadingRow({ label }: { label: string }): ReactNode {
  return (
    <HStack gap={2} align="center">
      <Spinner size="sm" aria-label={label} />
      <Text type="supporting">{label}</Text>
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
