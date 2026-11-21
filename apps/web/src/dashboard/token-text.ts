import type { TokenList, TokenSummary } from "./types.ts";
import type { ResourceState } from "./use-api-resource.ts";

function armedToken(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): TokenSummary | undefined {
  return tokens.kind === "ok" ? tokens.value.tokens.find((t) => t.id === armedId) : undefined;
}

export function armedTokenName(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "this token" : `token "${token.name}"`;
}

export function tokenRevokedMessage(
  tokens: ResourceState<TokenList>,
  armedId: string | undefined,
): string {
  const token = armedToken(tokens, armedId);
  return token === undefined ? "Token revoked." : `Token "${token.name}" revoked.`;
}
