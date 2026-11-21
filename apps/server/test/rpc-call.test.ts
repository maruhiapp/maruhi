import { Cause, Effect, Formatter } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { RpcCallError, rpcCall } from "../src/worker-env.ts";

const DO_ERROR_TEXT = "dummy DO error text naming a stored row";

const failureOf = (call: () => PromiseLike<unknown>): Promise<RpcCallError> =>
  Effect.runPromise(Effect.flip(rpcCall<unknown>(call)));

describe("rpcCall (worker-env.ts)", () => {
  it("passes a resolved value through", async () => {
    const value = await Effect.runPromise(rpcCall<{ kind: string }>(async () => ({ kind: "ok" })));
    expect(value).toEqual({ kind: "ok" });
  });

  it("maps a rejection to RpcCallError carrying only the error class name", async () => {
    const error = await failureOf(() => Promise.reject(new TypeError(DO_ERROR_TEXT)));
    expect(error).toBeInstanceOf(RpcCallError);
    expect(error).toMatchObject({ _tag: "RpcCallError" });
    expect(error.errorName).toBe("TypeError");
    const renderings = [
      String(error),
      JSON.stringify(error),
      Formatter.format(error),
      Cause.pretty(Cause.fail(error)),
    ];
    for (const rendering of renderings) {
      expect(rendering).not.toContain(DO_ERROR_TEXT);
    }
  });

  it("names a non-Error rejection 'unknown'", async () => {
    const error = await failureOf(() => Promise.reject(DO_ERROR_TEXT));
    expect(error.errorName).toBe("unknown");
  });

  it("maps a synchronous throw before the promise to RpcCallError too", async () => {
    const error = await failureOf(() => {
      throw new RangeError(DO_ERROR_TEXT);
    });
    expect(error.errorName).toBe("RangeError");
  });
});
