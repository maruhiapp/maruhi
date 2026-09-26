"use client";

// S11 端末登録簿(読み取りのみ — AUTH_SPEC §13-11 / DK K5。設計録 dk-design.md §10 K5-7〜K5-10)。
//
// - 対象は本人の登録簿(user 軸 — S9 と同じ独立ルート /dashboard/devices)。登録簿は
//   **advisory**(表示名・トークンの対応の置き場)であり、端末鍵の真実源は各プロジェクトの
//   チェーン(`maruhi device list` が検証する)。全表示はサーバー申告
// - **登録・削除・要求の承認は置かない**(セッション主体は拒否される API — §13-11。
//   チェーンの `revoke_device` も Web からは行わない — ADR-0018 改訂 2)。置くのは
//   紛失時の導線 = 既存のトークン失効(`DELETE /auth/tokens/:tokenId` — 資格を減らす方向)
// - `tokenId` は `GET /auth/tokens` の一覧と id で突合して名前 + prefix を出す(K5-8)。
//   一覧に無ければ id だけ(失効済み / 期限切れの可能性)。一覧の取得だけ失敗しても
//   登録簿は描く(部分失敗で画面を落とさない)。読込中は何も主張しない(id だけ — K5-14)
// - 表示名 / FP / tokenId はサーバー由来の文字列としてテキストノードにだけ描く。href に
//   埋めるのは `apiPaths.tokenRevoke(tokenId)`(encodeURIComponent)のみ
import { VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback } from "react";

import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { spaPaths } from "./routes.ts";
import {
  Callout,
  EmptyNotice,
  FailureNotice,
  HexText,
  LoadingRow,
  RevokeButton,
  RevocationOutcome,
  SectionBlock,
  ServerTime,
} from "./shared.tsx";
import type { DeviceList, DeviceSummary, TokenList, TokenSummary } from "./types.ts";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

/** 登録簿の行の tokenId が指すトークン(一覧との突合結果 — K5-8)。 */
type LinkedToken =
  | { kind: "none" }
  | { kind: "found"; token: TokenSummary }
  | { kind: "not-listed"; tokenId: string }
  /** トークン一覧をまだ読んでいる(何も主張しない — id だけ出す。K5-14)。 */
  | { kind: "pending"; tokenId: string }
  /** トークン一覧の取得に失敗した(id だけ出し、一覧が無いと言う)。 */
  | { kind: "unresolved"; tokenId: string };

interface DeviceRow extends Record<string, unknown> {
  id: string;
  label: string;
  fingerprint: string;
  createdAtMs: number;
  linked: LinkedToken;
}

/** 取得済みの一覧との突合(あれば found、無ければ not-listed)。 */
function linkedFromList(tokenId: string, tokens: TokenList): LinkedToken {
  const token = tokens.tokens.find((t) => t.id === tokenId);
  return token === undefined ? { kind: "not-listed", tokenId } : { kind: "found", token };
}

/** tokenId → 一覧の行(読込中は pending、取れなければ unresolved — どちらも id だけを出す)。 */
function linkedTokenOf(tokenId: string | undefined, tokens: ResourceState<TokenList>): LinkedToken {
  if (tokenId === undefined) return { kind: "none" };
  if (tokens.kind === "ok") return linkedFromList(tokenId, tokens.value);
  return tokens.kind === "loading" ? { kind: "pending", tokenId } : { kind: "unresolved", tokenId };
}

function toDeviceRow(device: DeviceSummary, tokens: ResourceState<TokenList>): DeviceRow {
  return {
    id: device.keyFingerprintHex,
    label: device.label,
    fingerprint: device.keyFingerprintHex,
    createdAtMs: device.createdAtMs,
    linked: linkedTokenOf(device.tokenId, tokens),
  };
}

/** Token 列: 名前 + prefix(突合できたとき)/ id だけ(一覧に無い・一覧が取れない)/ none。 */
function LinkedTokenCell({ linked }: { linked: LinkedToken }): ReactNode {
  if (linked.kind === "none") {
    return (
      <Text type="supporting" size="sm">
        none linked
      </Text>
    );
  }
  if (linked.kind === "found") {
    return (
      <VStack gap={1}>
        <Text size="sm" wordBreak="break-all">
          {linked.token.name}
        </Text>
        <HexText>{linked.token.tokenPrefix}</HexText>
      </VStack>
    );
  }
  return <UnmatchedTokenCell linked={linked} />;
}

/** 突合できなかった id(読込中は何も主張しない — K5-14)。 */
function UnmatchedTokenCell({
  linked,
}: {
  linked: Extract<LinkedToken, { kind: "not-listed" | "pending" | "unresolved" }>;
}): ReactNode {
  return (
    <VStack gap={1}>
      {linked.kind === "pending" ? null : (
        <Text type="supporting" size="sm">
          {linked.kind === "not-listed"
            ? "not among your tokens (revoked or expired?)"
            : "token list unavailable"}
        </Text>
      )}
      <HexText>{linked.tokenId}</HexText>
    </VStack>
  );
}

function buildDeviceColumns(
  isLocked: boolean,
  onArm: (id: string | undefined) => void,
): TableColumn<DeviceRow>[] {
  return [
    {
      key: "label",
      header: "Label",
      width: proportional(1),
      renderCell: (row: DeviceRow) => (
        <Text size="sm" wordBreak="break-all">
          {row.label}
        </Text>
      ),
    },
    {
      key: "fingerprint",
      header: "Fingerprint",
      width: proportional(1),
      renderCell: (row: DeviceRow) => <HexText>{row.fingerprint}</HexText>,
    },
    {
      key: "createdAtMs",
      header: "Registered",
      width: pixel(220),
      renderCell: (row: DeviceRow) => <ServerTime ms={row.createdAtMs} />,
    },
    {
      key: "linked",
      header: "API token",
      width: proportional(1),
      renderCell: (row: DeviceRow) => <LinkedTokenCell linked={row.linked} />,
    },
    {
      key: "actions",
      header: "Actions",
      width: pixel(160),
      renderCell: (row: DeviceRow) => {
        const linked = row.linked;
        if (linked.kind !== "found") return null;
        return (
          <RevokeButton
            label="Revoke token"
            accessibleName={`Revoke token "${linked.token.name}" of device ${row.label}`}
            onArm={() => onArm(linked.token.id)}
            isLocked={isLocked}
          />
        );
      },
    },
  ];
}

/** 紛失時の導線(CLI の `device revoke` → ここでトークン失効)+ 登録の案内。 */
function DeviceNotes(): ReactNode {
  return (
    <Callout title="Lost a device?" headingLevel={2} testId="device-notes">
      Revoke its key from another device with{" "}
      <Text type="code">maruhi device revoke &lt;fingerprint&gt;</Text>, then revoke its API token
      here (or on the <Link href={spaPaths.tokens()}>API tokens</Link> page). Revoking the token
      stops that device from reaching the API immediately; revoking the key is what removes it from
      the project chains. Registering, approving and removing devices is done from the CLI (
      <Text type="code">maruhi device add</Text> / <Text type="code">maruhi device approve</Text>)
      and is not available in the dashboard.
    </Callout>
  );
}

function DevicesTable({
  devices,
  tokens,
  isLocked,
  onArm,
}: {
  devices: ReadonlyArray<DeviceSummary>;
  tokens: ResourceState<TokenList>;
  isLocked: boolean;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (devices.length === 0) {
    return (
      <EmptyNotice
        title="No devices registered"
        description="Devices you register from the CLI (maruhi device add) appear here, as reported by the server."
        // 一覧の箱は見出し無し(ページ h1 が兼ねる)なので h2
        headingLevel={2}
        testId="device-empty"
      />
    );
  }
  return (
    <Table
      data={devices.map((device) => toDeviceRow(device, tokens))}
      columns={buildDeviceColumns(isLocked, onArm)}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid="device-table"
    />
  );
}

/** 行の Revoke token を無効化するか: 失効の実行中、または失効後の再取得中(直前の値を描いている)。 */
function isRowActionLocked(
  revocation: RevocationState,
  resources: ReadonlyArray<{ readonly kind: string; readonly refreshing?: boolean }>,
): boolean {
  return (
    revocation.pendingId !== undefined || resources.some((resource) => resource.refreshing === true)
  );
}

function DevicesResource({
  state,
  tokens,
  reload,
  revocation,
  onArm,
}: {
  state: ResourceState<DeviceList>;
  tokens: ResourceState<TokenList>;
  reload: () => void;
  revocation: RevocationState;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  // 置換形(裁定 B-a)。404 は旧サーバー(登録簿の無い面)の文言(K5-9)。失効後の
  // 再取得(refreshing — 登録簿・トークン一覧のどちらか)中は直前の表を残し、行の
  // Revoke token は実行中と同じく無効化する(再取得前の行への二重失効を防ぐ)
  if (state.kind === "loading") return <LoadingRow label="Loading devices" />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject="device registry" />;
  }
  return (
    <DevicesTable
      devices={state.value.devices}
      tokens={tokens}
      isLocked={isRowActionLocked(revocation, [state, tokens])}
      onArm={onArm}
    />
  );
}

/** 武装中のトークン(一覧にあれば)。 */
function armedToken(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): TokenSummary | undefined {
  return tokens.kind === "ok" ? tokens.value.tokens.find((t) => t.id === armedId) : undefined;
}

/** 確認ダイアログの見出しに出す対象名(一覧にあれば名前、無ければ "this token")。 */
function armedName(tokens: ResourceState<TokenList>, armedId: string | undefined): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "this token" : `token "${token.name}"`;
}

/** 失効成功の告知文(確認時点の名前 — 再取得後のトークン一覧には残らない)。 */
function revokedMessage(tokens: ResourceState<TokenList>, armedId: string | undefined): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "Token revoked." : `Token "${token.name}" revoked.`;
}

export function DevicesScreen(): ReactNode {
  const devices = useApiResource<DeviceList>(apiPaths.devices());
  const tokens = useApiResource<TokenList>(apiPaths.tokens());
  const reloadDevices = devices.reload;
  const reloadTokens = tokens.reload;
  // 失効後は両方を再取得する(登録簿の tokenId 欄は advisory で残るので、一覧から消えた
  // トークンは「not among your tokens」へ落ちる — K5-8 反例 4)
  const reloadBoth = useCallback(() => {
    reloadDevices();
    reloadTokens();
  }, [reloadDevices, reloadTokens]);
  // 失効状態は一覧リソースの外に持つ(use-revocation.ts のヘッダーコメント)
  const { revocation, arm, confirm } = useRevocation(apiPaths.tokenRevoke, reloadBoth);
  return (
    <DashboardShell
      destination="devices"
      title="Devices"
      intro={
        <Text as="p" type="supporting">
          Your device registry (display names and linked API tokens), as reported by the server. The
          registry is advisory; the project chains are the source of truth —{" "}
          <Text type="code">maruhi device list</Text> verifies them.
        </Text>
      }
    >
      <VStack gap={4} data-testid="device-list">
        <SectionBlock>
          <DevicesResource
            state={devices.state}
            tokens={tokens.state}
            reload={reloadDevices}
            revocation={revocation}
            onArm={arm}
          />
        </SectionBlock>
        {/* 確認はモーダル(AlertDialogAsyncAction テンプレート)。対象名はトークン一覧から引く */}
        <RevocationOutcome
          revocation={revocation}
          title={`Revoke ${armedName(tokens.state, revocation.armedId)}?`}
          description="Any CLI or CI job still using this token is signed out immediately. This does not revoke the device key on the project chains — do that from the CLI."
          successMessage={revokedMessage(tokens.state, revocation.armedId)}
          subject="token"
          arm={arm}
          confirm={confirm}
        />
        <DeviceNotes />
      </VStack>
    </DashboardShell>
  );
}
