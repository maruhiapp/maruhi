// auth.package の公開面(ImportLint 境界)。
//
// 公開するのはサービス構築関数・ミドルウェア実装・クッキー名のみ。GitHub API の
// リクエスト詳細・ハッシュ計算などの内部は境界内に閉じる。

export {
  CLI_FLOW_TTL_MS,
  type CliVerifyParams,
  computeVsig,
  createFlowToken,
  generateUserCode,
  importFlowSigningKey,
  verificationQuery,
  verifyCliVerifyQuery,
  verifyFlowToken,
} from "./cli-flow.ts";
export {
  CLI_PAGE_CSP_HEADER,
  renderApprovalPage,
  renderApprovedPage,
  renderCliErrorPage,
  renderDeniedPage,
  renderSignupGuidancePage,
} from "./cli-pages.ts";
export { GitHubApi, type GitHubApiShape, makeGitHubApi } from "./github.ts";
export {
  renderSignupClosedPage,
  renderSignupInviteInvalidPage,
  renderSignupInviteRequiredPage,
} from "./signup-pages.ts";
export {
  authMiddlewareImpl,
  parseBearerToken,
  SESSION_COOKIE,
  statefulGetCsrfViolated,
} from "./middleware.ts";
export { makeSessionService } from "./session.ts";
export { makeTokenService } from "./token.ts";
