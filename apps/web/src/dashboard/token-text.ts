// The wording of the token revocation dialog and its announcement, shared
// by the tokens screen and the devices screen.

import type { TokenList, TokenSummary } from "./types.ts";
import type { ResourceState } from "./use-api-resource.ts";

/** The armed token (if still in the list). */
function armedToken(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): TokenSummary | undefined {
  return tokens.kind === "ok" ? tokens.value.tokens.find((t) => t.id === armedId) : undefined;
}

/** The object's name for the confirm dialog's heading (its name if in the list, otherwise "this token"). */
export function armedTokenName(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "this token" : `token "${token.name}"`;
}

/** The announcement text of a successful revocation (the name at the moment of confirmation — it may not remain in the post-refetch list). */
export function tokenRevokedMessage(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "Token revoked." : `Token "${token.name}" revoked.`;
}
