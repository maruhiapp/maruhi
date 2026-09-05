"use client";

// アプリシェル(DP3 裁定 A 改訂 1 — docs/notes/web-design-pass.md §5)。認証が要る画面
// (S4〜S9)はすべてこのシェルの中に描く。形は Astryx のテンプレートに従う:
//
// - フレーム = `astryx template shell-side-nav` / `AppShellSideNavOnly`: AppShell +
//   SideNav(ヘッダー = ㊙ ロゴ + maruhi、本文 = 到達点、フッター = アカウント〔ユーザー
//   id → Account audit、Sign out〕)。collapsible。モバイル幅(AppShell の md)では
//   SideNav が AppShell 生成のドロワーへ移る(スキップリンク・main ランドマークも AppShell)
// - ページ = `table-page` / `LayoutHeaderWithActions`: Layout(auto)の header スロットに
//   戻りリンク + h1 + 説明(+ タブ)、content スロットに本文。ページ全体がスクロールする
//   (header は固定しない — DP3 改訂 5: 見出しと本文を分ける線を引かず余白で分ける。固定
//   header は線なしでは本文と重なって読めないので固定もやめる)
// - サインイン = `astryx template login`: Center(ビューポート全高)+ ロゴ + Card(見出し・説明・主ボタン)
//
// セッション状態(`GET /auth/me`)はシェルが 1 か所で持つ。401 は全画面で同じサインイン
// 画面に落ち、ok のときだけ本文を描く(子のフェッチは me の確認後 — 1 往復の直列化を
// 受け入れて、401 時に本文が一瞬描かれてから消える形を避ける)。ログアウトは
// POST /auth/logout + CSRF ヘッダー(api.ts が一律付与)。表示規律の但し書き
// (ServerReportedNote)はページ末尾にシェルが 1 回置く。文言はすべて英語(ADR-0017)。
//
// 2 層構造(DP3 改訂 11 — PR #148 Bugbot 指摘): `DashboardLayout` は pathless の親ルート
// (routes.ts の dashboardShellRoute)の部品で、セッション状態 + AppShell + SideNav を持ち
// `Outlet` に子ルートを描く。画面間の遷移で再マウントされないので、/auth/me の再取得・
// 「Checking your session」の再表示・サイドバーの折りたたみ状態の消失が起きない。
// `DashboardShell` は各画面が使うページの枠(Layout の header = 見出し、content = 本文)。
// サイドバーの現在地とプロジェクトの子項目は各画面が `destination` / `project` で申告し、
// context 経由で親へ上げる(URL から導く `useLocation` は Location の `.hash` を
// バンドルに持ち込み、AUTH_SPEC §15-3 の tripwire〔語 "hash" の禁止〕に当たるため使わない)。
import { AppShell } from "@astryxdesign/core/AppShell";
import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Center } from "@astryxdesign/core/Center";
import { Layout, LayoutContent, LayoutHeader, VStack } from "@astryxdesign/core/Layout";
import { SideNav, SideNavHeading, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Heading, Text } from "@astryxdesign/core/Text";
import { Outlet } from "@funstack/router";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useState,
} from "react";

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
import { SessionExpiredContext } from "./session-expiry.ts";
import { FailureNotice, LoadingRow, SECTION_GAP, ServerReportedNote } from "./shared.tsx";
import type { Me } from "./types.ts";

/** サイドバーの到達点(選択状態 = aria-current="page")。project 画面は Projects 配下。 */
type ShellDestination = "projects" | "tokens" | "account";

/** 親階層(パンくずの先頭。現在地はプロジェクトの短縮 ID か title — 改訂 7 で `Breadcrumbs` に)。 */
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
// 収まる
const CONTENT_WIDTH = 1200;

// 区切りの規律(DP3 改訂 5 — 裁定 O): 見出し・節・本文の境界は線でなく余白(SECTION_GAP)で
// 示す。線は集合の内側(表の行・監査行の hairline)と、タブ行(TabList hasDivider — タブの
// 下線が header と本文の唯一の境界を兼ねる)だけ

/** 開いているプロジェクト(サイドバーの Projects の子項目として現在地を示す)。 */
interface CurrentProject {
  id: string;
  label: string;
}

/** サイドバーの状態(現在地 + 開いているプロジェクト)。各画面が申告し、親のシェルが保持する。 */
interface ShellNav {
  destination: ShellDestination;
  project: CurrentProject | undefined;
}

// 子ルート(画面)→ 親(シェル)への申告経路。値は useState の setter(同一性が安定)
const ShellNavContext = createContext<((nav: ShellNav) => void) | undefined>(undefined);

/**
 * 画面が自分の到達点とプロジェクトをシェルへ申告する。描画前(layout effect)に反映し、
 * 遷移直後の 1 フレームに前の画面の選択状態が残らないようにする。
 */
function useShellNav(destination: ShellDestination, project: CurrentProject | undefined): void {
  const setNav = useContext(ShellNavContext);
  const projectId = project?.id;
  const projectLabel = project?.label;
  useLayoutEffect(() => {
    setNav?.({
      destination,
      project:
        projectId === undefined || projectLabel === undefined
          ? undefined
          : { id: projectId, label: projectLabel },
    });
  }, [setNav, destination, projectId, projectLabel]);
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
 * ページ見出し(`detail-page` テンプレートの PageHeader の形): パンくず → h1 → 説明 →
 * タブ。パンくずは Astryx `Breadcrumbs`(親階層 = リンク、現在地 = aria-current)。
 * タブ(TabList hasDivider)の下線が header と本文の境界を兼ねる(裁定 O)。
 */
function PageHeader({
  backLink,
  crumb,
  title,
  intro,
  tabs,
}: {
  backLink: BackLink | undefined;
  crumb: string;
  title: string;
  intro: ReactNode;
  tabs: ReactNode;
}): ReactNode {
  return (
    <VStack gap={3}>
      <VStack gap={1}>
        {backLink === undefined ? null : (
          <Breadcrumbs variant="supporting">
            <BreadcrumbItem href={backLink.href}>{backLink.label}</BreadcrumbItem>
            <BreadcrumbItem isCurrent>{crumb}</BreadcrumbItem>
          </Breadcrumbs>
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
function useSession(): {
  auth: AuthState;
  reload: () => void;
  signOut: () => void;
  expire: () => void;
} {
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
  // 画面のフェッチが 401 を返した(session-expiry.ts)。サインアウト直後と同じ画面へ
  const expire = useCallback(() => setAuth({ status: "signed-out", signedOutNow: true }), []);
  return { auth, reload, signOut, expire };
}

interface PageProps {
  destination: ShellDestination;
  /** 開いているプロジェクト(サイドバーの子項目 + パンくずの現在地)。 */
  project?: CurrentProject | undefined;
  backLink?: BackLink;
  title: string;
  intro?: ReactNode;
  /** header スロットの末尾に置くタブ(TabList)。本文の切替は呼び出し側が持つ。 */
  tabs?: ReactNode;
  children: ReactNode;
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
 * 認証が要る画面の親(pathless ルート `dashboardShellRoute` の部品)。セッションを確認し、
 * ok のときだけ AppShell + SideNav の中に子ルート(`Outlet`)を描く。signed-out はサインイン
 * 画面、loading / failed は状態フレーム(ナビなし)。画面のフェッチが 401 を返したら
 * (SessionExpiredContext — session-expiry.ts)その場で signed-out へ落とす。
 */
export function DashboardLayout(): ReactNode {
  const { auth, reload, signOut, expire } = useSession();
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
  return (
    <SessionExpiredContext.Provider value={expire}>
      <SignedInFrame me={auth.me} onSignOut={signOut} />
    </SessionExpiredContext.Provider>
  );
}

/** サインイン後のフレーム: サイドバー(現在地は子ルートの申告)+ 子ルート。 */
function SignedInFrame({ me, onSignOut }: { me: Me; onSignOut: () => void }): ReactNode {
  const [nav, setNav] = useState<ShellNav>({ destination: "projects", project: undefined });
  return (
    <ShellNavContext.Provider value={setNav}>
      <AppShell
        contentPadding={0}
        sideNav={
          <DashboardSideNav
            current={nav.destination}
            project={nav.project}
            me={me}
            onSignOut={onSignOut}
          />
        }
      >
        <Outlet />
      </AppShell>
    </ShellNavContext.Provider>
  );
}

/**
 * 画面ごとのページの枠(`DashboardLayout` の Outlet に描かれる)。`title` はページの h1
 * (AppShell は見出しを描かないので、header スロットの見出しがページの h1 になる)。
 * `backLink` は親階層への戻り、`intro` は見出し直下の 1〜2 行、`tabs` は header 末尾の
 * TabList。`destination` / `project` はサイドバーへの申告(useShellNav)。
 */
export function DashboardShell({
  destination,
  project,
  backLink,
  title,
  intro,
  tabs,
  children,
}: PageProps): ReactNode {
  useShellNav(destination, project);
  return (
    <Layout
      height="auto"
      contentWidth={CONTENT_WIDTH}
      padding={6}
      header={
        <LayoutHeader>
          <PageHeader
            backLink={backLink}
            crumb={project?.label ?? title}
            title={title}
            intro={intro}
            tabs={tabs}
          />
        </LayoutHeader>
      }
      content={
        <LayoutContent>
          {/* header との間は線でなく余白(裁定 O): header 自身の下余白 16px + 24px = 40px */}
          <VStack gap={SECTION_GAP} paddingBlockStart={6}>
            {children}
            <ServerReportedNote />
          </VStack>
        </LayoutContent>
      }
    />
  );
}
