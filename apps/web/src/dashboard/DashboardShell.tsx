"use client";

// アプリシェル(DP3 裁定 A 改訂 1 — docs/notes/web-design-pass.md §5)。認証が要る画面
// (S4〜S9)はすべてこのシェルの中に描く。形は Astryx のテンプレートに従う:
//
// - フレーム = `astryx template shell-side-nav` / `AppShellSideNavOnly`: AppShell +
//   SideNav(ヘッダー = ㊙ ロゴ + maruhi、本文 = 到達点、フッター = アカウント〔ユーザー
//   id → Account audit、Sign out〕)。collapsible。モバイル幅(AppShell の md)では
//   SideNav が AppShell 生成のドロワーへ移る(スキップリンク・main ランドマークも AppShell)
// - ページ = `table-page` / `LayoutHeaderWithActions`: Layout(fill)の header スロットに
//   パンくず + h1 + 説明、content スロットに本文。main の内部スクロール
// - サインイン = `astryx template login`: Center(ビューポート全高)+ ロゴ + Card(見出し・説明・主ボタン)
//
// セッション状態(`GET /auth/me`)はシェルが 1 か所で持つ。401 は全画面で同じサインイン
// 画面に落ち、ok のときだけ本文を描く(子のフェッチは me の確認後 — 1 往復の直列化を
// 受け入れて、401 時に本文が一瞬描かれてから消える形を避ける)。ログアウトは
// POST /auth/logout + CSRF ヘッダー(api.ts が一律付与)。表示規律の但し書き
// (ServerReportedNote)はページ末尾にシェルが 1 回置く。文言はすべて英語(ADR-0017)。
import { AppShell } from "@astryxdesign/core/AppShell";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Center } from "@astryxdesign/core/Center";
import { Layout, LayoutContent, LayoutHeader, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { SideNav, SideNavHeading, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Heading, Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, apiPost } from "./api.ts";
import { apiPaths } from "./endpoints.ts";
import {
  ArrowRightStartOnRectangleIcon,
  ClipboardDocumentListIcon,
  FolderIcon,
  KeyIcon,
  UserCircleIcon,
} from "./icons.tsx";
import { markResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
import { FailureNotice, LoadingRow, ServerReportedNote } from "./shared.tsx";
import type { Me } from "./types.ts";

/** サイドバーの到達点(選択状態 = aria-current="page")。project 画面は Projects 配下。 */
type ShellDestination = "projects" | "tokens" | "account";

/** 親階層への戻りリンク(`detail-page` テンプレートの「← All orders」の形)。 */
interface BackLink {
  label: string;
  href: string;
}

// ブランド資産(DP1 — apps/web/public)。反転版 = 朱の円盤に白抜きの「秘」= favicon と同形。
// サイドバー見出しとサインイン画面で同じファイルを使う。色はテーマに追随せず
// 朱で固定(ブラウザのタブの favicon と同じ見え方)
const LOGO_INVERTED_SRC = "/logo-inverted.svg";
// 見出しの文字高(bold 16px)と釣り合う 24px。サインインは見出しの上に置くので 40px
const SIDE_NAV_LOGO_PX = 24;
const SIGN_IN_LOGO_PX = 40;

// 本文の最大幅(全ページ共通の 1 値 — ページごとに変えない)。Astryx の `settings` テンプレートは
// 1440、`detail-page` は 1000。1200 は 1440px のノート(領域 1180)でちょうど満ち、1920px では中央に
// 収まる。監査のインスペクタ(380)を並べても行に 800 弱が残る
const CONTENT_WIDTH = 1200;

/** 開いているプロジェクト(サイドバーの Projects の子項目として現在地を示す)。 */
interface CurrentProject {
  id: string;
  label: string;
}

type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; signedOutNow: boolean }
  | { status: "ok"; me: Me }
  | { status: "failed"; failure: ApiFailure };

// 到達点の目録(表示順)。パスは routes.ts の spaPaths だけを経由する(裁定 CA)
const DESTINATIONS: ReadonlyArray<{
  id: ShellDestination;
  label: string;
  href: string;
  icon: typeof FolderIcon;
}> = [
  { id: "projects", label: "Projects", href: spaPaths.dashboard(), icon: FolderIcon },
  { id: "tokens", label: "API tokens", href: spaPaths.tokens(), icon: KeyIcon },
  {
    id: "account",
    label: "Account audit",
    href: spaPaths.account(),
    icon: ClipboardDocumentListIcon,
  },
];

function NavItems({
  current,
  project,
}: {
  current: ShellDestination;
  project: CurrentProject | undefined;
}): ReactNode {
  return DESTINATIONS.map((d) =>
    d.id === "projects" && project !== undefined ? (
      <SideNavItem key={d.id} label={d.label} icon={d.icon} href={d.href} collapsible>
        <SideNavItem label={project.label} href={spaPaths.project(project.id)} isSelected />
      </SideNavItem>
    ) : (
      <SideNavItem
        key={d.id}
        label={d.label}
        icon={d.icon}
        href={d.href}
        isSelected={d.id === current}
      />
    ),
  );
}

/** サイドバー(`shell-side-nav` テンプレートの形: ヘッダー / 到達点 / アカウントのフッター)。 */
function DashboardSideNav({
  current,
  project,
  me,
  onSignOut,
}: {
  current: ShellDestination;
  project: CurrentProject | undefined;
  me: Me;
  onSignOut: () => void;
}): ReactNode {
  return (
    <SideNav
      collapsible
      header={
        <SideNavHeading
          heading="maruhi"
          icon={
            <img
              src={LOGO_INVERTED_SRC}
              alt=""
              width={SIDE_NAV_LOGO_PX}
              height={SIDE_NAV_LOGO_PX}
            />
          }
          headingHref={spaPaths.dashboard()}
        />
      }
      footer={
        <SideNavSection title="Account" isHeaderHidden>
          {/* 内部 user_id(ULID)の表示。Account audit(本人軸)への到達点を兼ねる */}
          <SideNavItem
            label={me.userId}
            icon={UserCircleIcon}
            href={spaPaths.account()}
            isSelected={current === "account"}
            data-testid="signed-in-user"
          />
          <SideNavItem
            label="Sign out"
            icon={ArrowRightStartOnRectangleIcon}
            onClick={onSignOut}
            data-testid="sign-out"
          />
        </SideNavSection>
      }
    >
      <SideNavSection title="Navigation" isHeaderHidden>
        <NavItems current={current} project={project} />
      </SideNavSection>
    </SideNav>
  );
}

/** サインイン画面(`astryx template login` の形。資格情報は GitHub OAuth のみ)。 */
function SignInScreen({ signedOutNow }: { signedOutNow: boolean }): ReactNode {
  return (
    <Center axis="both" padding={6} minHeight="100dvh">
      <VStack gap={4} align="center" width="100%" maxWidth={400}>
        <VStack gap={2} align="center">
          <img src={LOGO_INVERTED_SRC} alt="" width={SIGN_IN_LOGO_PX} height={SIGN_IN_LOGO_PX} />
          <Text type="body" weight="bold" size="lg">
            maruhi
          </Text>
        </VStack>
        <Card padding={8} width="100%" data-testid="login-card">
          <VStack gap={4} align="stretch">
            <VStack gap={1} align="center">
              <Heading level={1}>Sign in</Heading>
              <Text type="body" color="secondary" size="sm" justify="center">
                A read-only view of your projects, as reported by the server.
              </Text>
            </VStack>
            {signedOutNow ? (
              <Banner status="info" title="You are signed out." container="card" />
            ) : null}
            {/* 復帰マーカー(裁定 BU): OAuth 完了後に S1 経由で /dashboard へ戻る */}
            <Button
              label="Sign in with GitHub"
              variant="primary"
              size="lg"
              href={apiPaths.githubStart()}
              onClick={markResumeToDashboard}
              data-testid="sign-in-link"
            />
            <Text type="supporting" color="secondary" justify="center">
              Secrets never appear here — values live on your own machines and are handled by the
              CLI.
            </Text>
          </VStack>
        </Card>
      </VStack>
    </Center>
  );
}

/**
 * ページ見出し(`detail-page` テンプレートの PageHeader の形): 戻りリンク → h1 → 説明 →
 * タブ。タブは header スロットに置くことで、本文が内部スクロールしても見え続ける。
 */
function PageHeader({
  backLink,
  title,
  intro,
  tabs,
}: {
  backLink: BackLink | undefined;
  title: string;
  intro: ReactNode;
  tabs: ReactNode;
}): ReactNode {
  return (
    <VStack gap={3}>
      <VStack gap={1}>
        {backLink === undefined ? null : (
          <Link href={backLink.href} color="secondary">
            ← {backLink.label}
          </Link>
        )}
        <Heading level={1}>{title}</Heading>
        {intro}
      </VStack>
      {tabs}
    </VStack>
  );
}

/**
 * セッション状態(loading / signed-out / ok / failed)。ok のときだけ me を持つ。
 * サインアウトは成功・401 のどちらでも signed-out(signedOutNow)へ落とす。
 */
function useSession(): { auth: AuthState; reload: () => void; signOut: () => void } {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const reload = useCallback(() => {
    setAuth({ status: "loading" });
    void apiGet<Me>(apiPaths.me()).then((result) => {
      if (result.kind === "ok") {
        setAuth({ status: "ok", me: result.value });
      } else if (result.kind === "unauthorized") {
        setAuth({ status: "signed-out", signedOutNow: false });
      } else {
        setAuth({ status: "failed", failure: result });
      }
    });
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);
  const signOut = useCallback(() => {
    void apiPost(apiPaths.logout()).then((result) => {
      if (result.kind === "ok" || result.kind === "unauthorized") {
        setAuth({ status: "signed-out", signedOutNow: true });
      } else {
        setAuth({ status: "failed", failure: result });
      }
    });
  }, []);
  return { auth, reload, signOut };
}

interface PageProps {
  destination: ShellDestination;
  project?: CurrentProject | undefined;
  backLink?: BackLink;
  title: string;
  intro?: ReactNode;
  /** header スロットの末尾に置くタブ(TabList)。本文の切替は呼び出し側が持つ。 */
  tabs?: ReactNode;
  children: ReactNode;
}

/** サインイン後のフレーム: サイドバー + Layout(header = 見出し、content = 本文)。 */
function SignedInFrame({
  me,
  onSignOut,
  destination,
  project,
  backLink,
  title,
  intro,
  tabs,
  children,
}: PageProps & { me: Me; onSignOut: () => void }): ReactNode {
  return (
    <AppShell
      contentPadding={0}
      sideNav={
        <DashboardSideNav current={destination} project={project} me={me} onSignOut={onSignOut} />
      }
    >
      <Layout
        height="fill"
        contentWidth={CONTENT_WIDTH}
        padding={6}
        header={
          <LayoutHeader hasDivider>
            <PageHeader backLink={backLink} title={title} intro={intro} tabs={tabs} />
          </LayoutHeader>
        }
        content={
          <LayoutContent>
            <VStack gap={8}>
              {children}
              <ServerReportedNote />
            </VStack>
          </LayoutContent>
        }
      />
    </AppShell>
  );
}

/** セッション確認中・失敗時のフレーム(ナビなし — 状態表示だけを中央に置く)。 */
function StatusFrame({ children }: { children: ReactNode }): ReactNode {
  return (
    <Center axis="both" padding={6} minHeight="100dvh">
      <VStack width="100%" maxWidth={480}>
        {children}
      </VStack>
    </Center>
  );
}

/**
 * 認証が要る画面の共通フレーム。`title` はページの h1(AppShell は見出しを描かない
 * ので、header スロットの見出しがページの h1 になる)。`backLink` は親階層への戻り。
 * `intro` は見出し直下の 1〜2 行、`tabs` は header 末尾の TabList。`project` を渡すと
 * サイドバーの Projects の下に現在のプロジェクトが選択状態で並ぶ。
 */
export function DashboardShell(props: PageProps): ReactNode {
  const { auth, reload, signOut } = useSession();
  if (auth.status === "loading") {
    return (
      <StatusFrame>
        <LoadingRow label="Checking your session" />
      </StatusFrame>
    );
  }
  if (auth.status === "signed-out") return <SignInScreen signedOutNow={auth.signedOutNow} />;
  if (auth.status === "failed") {
    return (
      <StatusFrame>
        <FailureNotice failure={auth.failure} onRetry={reload} />
      </StatusFrame>
    );
  }
  return <SignedInFrame {...props} me={auth.me} onSignOut={signOut} />;
}
