// rpcCall (worker-env.ts): a DO RPC's rejection is a typed RpcCallError,
// not a defect, and the error carries only the rejection's error class name
// — the rejection's message (DO error text) never reaches any rendering of
// it. The call sites' outcomes are pinned where a test can make the RPC
// reject: the project-list isolation and the 500 of the orDie sites (chain
// get, callProjectData, requireProjectChainAdmin — project-list.test.ts),
// and the backup sweep's rpc-failed record (ops-backup.test.ts).

import { Cause, Effect, Formatter } from "effect";
import { describe, expect, it } from "vitest";

import { RpcCallError, rpcCall } from "../src/worker-env.ts";

const DO_ERROR_TEXT = "dummy DO error text naming a stored row";

/** The call's RpcCallError (a success or a defect rejects, failing the test). */
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
