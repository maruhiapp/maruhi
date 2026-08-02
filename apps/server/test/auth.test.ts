// 認証サービス境界(AUTH_SPEC §8 に沿ったスタブ)の形の検証。
// 本実装は認証セッションで行う。ここではスタブが境界のインターフェースを
// 満たすこと(= 後から実装を差し替えられること)だけを固定する。

import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";

import {
  anonymousPrincipal,
  SessionService,
  TokenService,
  unauthenticatedRequestAuth,
} from "../src/auth.ts";
import {
  stubRequestAuth,
  stubSessionService,
  stubTokenService,
  stubUserPrincipal,
} from "./support/auth-stub.ts";

describe("auth service boundary", () => {
  it("production placeholder resolves every request as anonymous", async () => {
    await expect(Effect.runPromise(unauthenticatedRequestAuth.principal)).resolves.toEqual(
      anonymousPrincipal,
    );
  });

  it("test stubs resolve the configured principal through each §8 boundary", async () => {
    const principal = stubUserPrincipal("user-test-0001");
    await expect(Effect.runPromise(stubRequestAuth(principal).principal)).resolves.toEqual(
      principal,
    );

    // SessionService / TokenService はサービスタグ経由で解決できること
    // (後から本実装 Layer に差し替えられる境界であることの検証)
    const viaSession = Effect.gen(function* () {
      const sessions = yield* SessionService;
      return yield* sessions.resolveSession("session-id");
    }).pipe(Effect.provide(Layer.succeed(SessionService, stubSessionService(principal))));
    await expect(Effect.runPromise(viaSession)).resolves.toEqual(principal);

    const viaToken = Effect.gen(function* () {
      const tokens = yield* TokenService;
      return yield* tokens.resolveApiToken("maruhi_pat_dummy");
    }).pipe(Effect.provide(Layer.succeed(TokenService, stubTokenService(principal))));
    await expect(Effect.runPromise(viaToken)).resolves.toEqual(principal);
  });
});
