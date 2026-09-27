// The public surface of auth.package (the ImportLint boundary).
//
// Only the service constructors, middleware implementation, and cookie names
// are exposed. Internals such as GitHub API request details and hash
// computation stay inside the boundary.

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
