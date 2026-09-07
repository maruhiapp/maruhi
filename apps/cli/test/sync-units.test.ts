// `maruhi sync` の部品の単体テスト: リポジトリ設定の検証(sync-config.ts)、
// 宣言的プリセットと呼び出しの組み立て(sync-exec.ts — argv に値が載らない・
// stdin の形式・100 件ごとの分割・削除の表現)、値の制約、ベンダー出力の伏せ字化、
// plan の差分(sync-plan.ts)、レシートの codec(sync-receipt.ts)。

import { Effect, Exit, Redacted } from "effect";
import { describe, expect, it } from "vitest";

import { parseSyncConfig, type SyncTarget, type TargetDriver } from "../src/sync-config.ts";
import {
  buildInvocations,
  checkValueConstraints,
  EXEC_PRESETS,
  scrubVendorOutput,
  type SyncWrite,
} from "../src/sync-exec.ts";
import { computePlan } from "../src/sync-plan.ts";
import { decodeReceipt, encodeReceipt, receiptVariableName } from "../src/sync-receipt.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function write(name: string, value: string): SyncWrite {
  return { name, value: Redacted.make(encoder.encode(value), { label: "variable-value" }) };
}

function baseConfig(target: Record<string, unknown>): string {
  return JSON.stringify({
    version: 1,
    receipts: { environment: "sync-receipts" },
    targets: { t: target },
  });
}

function vercelTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    environment: "prod",
    variables: ["A"],
    options: { environment: "production" },
    ...overrides,
  };
}

function parsed(target: Record<string, unknown>): SyncTarget {
  const config = parseSyncConfig(baseConfig(target), "/repo");
  if (typeof config === "string") {
    throw new Error(config);
  }
  return config.targets.get("t") as SyncTarget;
}

/** exec ドライバの面(cwd / command)。http だったらテストの前提違い。 */
function execOf(target: SyncTarget): Extract<TargetDriver, { kind: "exec" }> {
  if (target.driver.kind !== "exec") {
    throw new Error("expected the exec driver");
  }
  return target.driver;
}

describe("parseSyncConfig", () => {
  it("Vercel の production は既定で production 扱い、preview は違う。明示が勝つ", () => {
    expect(parsed(vercelTarget()).production).toBe(true);
    expect(parsed(vercelTarget({ options: { environment: "preview" } })).production).toBe(false);
    expect(parsed(vercelTarget({ production: false })).production).toBe(false);
    expect(
      parsed(vercelTarget({ options: { environment: "development" }, production: true }))
        .production,
    ).toBe(true);
  });

  it("Workers は名前付き環境なしが production、cwd / command は設定からの相対・上書き", () => {
    const top = parsed({ preset: "cloudflare-workers", environment: "prod", variables: "all" });
    expect(top.production).toBe(true);
    expect(execOf(top).cwd).toBe("/repo");
    expect(execOf(top).command).toBe("wrangler");
    const named = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      cwd: "apps/worker",
      command: "node_modules/.bin/wrangler",
      options: { environment: "staging" },
    });
    expect(named.production).toBe(false);
    expect(execOf(named).cwd).toBe("/repo/apps/worker");
    expect(execOf(named).command).toBe("node_modules/.bin/wrangler");
  });

  it.each([
    ["not json", "not valid JSON"],
    ["[]", "the top level must be an object"],
    [JSON.stringify({ version: 2 }), "unsupported config version"],
    [JSON.stringify({ version: 1, extra: 1 }), "unknown top-level keys (extra)"],
    [JSON.stringify({ version: 1, project: "nope" }), "project must be the project ID"],
    [JSON.stringify({ version: 1 }), "receipts must be an object"],
    [
      JSON.stringify({ version: 1, receipts: { environment: "bad id!" } }),
      "receipts.environment must be a maruhi environment ID",
    ],
    [
      JSON.stringify({ version: 1, receipts: { environment: "r" }, targets: {} }),
      "targets must be an object with at least one target",
    ],
    [
      baseConfig({ preset: "netlify" }),
      "targets.t.preset must be one of cloudflare-workers, vercel",
    ],
    [baseConfig({ preset: "__proto__" }), "targets.t.preset must be one of"],
    [
      baseConfig(vercelTarget({ environment: "no spaces" })),
      "targets.t.environment must be a maruhi environment ID",
    ],
    [
      baseConfig(vercelTarget({ variables: [] })),
      'targets.t.variables must be a non-empty array of variable names, or "all"',
    ],
    [baseConfig(vercelTarget({ variables: ["A", "A"] })), "lists the same name more than once"],
    [
      baseConfig(vercelTarget({ exclude: ["B"] })),
      'targets.t.exclude applies only when variables is "all"',
    ],
    [baseConfig(vercelTarget({ bogus: 1 })), "targets.t has unknown keys (bogus)"],
    [
      baseConfig(vercelTarget({ options: {} })),
      "targets.t.options.environment is required for the vercel preset with the exec driver (one of production, preview, development)",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "prod" } })),
      "targets.t.options.environment must be one of production, preview, development",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "production", sensitive: "no" } })),
      "targets.t.options.sensitive must be true or false",
    ],
    [
      baseConfig(vercelTarget({ options: { environment: "production", value: "x" } })),
      "targets.t.options has unknown keys (value)",
    ],
    [
      baseConfig(vercelTarget({ environment: "sync-receipts" })),
      "targets.t.environment is the receipts environment",
    ],
  ])("拒否する: %s", (content, reason) => {
    const result = parseSyncConfig(content, "/repo");
    expect(typeof result).toBe("string");
    expect(result).toContain(reason);
  });

  it("ターゲット名は環境 ID と同じ字種(レシート変数名の一部になる)", () => {
    const bad = parseSyncConfig(
      JSON.stringify({
        version: 1,
        receipts: { environment: "r" },
        targets: { "bad name": vercelTarget() },
      }),
      "/repo",
    );
    expect(bad).toContain("target names must start with an alphanumeric character");
  });
});

describe("buildInvocations(宣言的プリセット)", () => {
  it("Vercel: 名前ごとに 1 プロセス、値は stdin そのもの、オプションは argv、削除は env rm", () => {
    const target = parsed(
      vercelTarget({
        options: {
          environment: "preview",
          gitBranch: "feature/x",
          project: "my-app",
          scope: "team",
          sensitive: false,
        },
      }),
    );
    const invocations = buildInvocations({
      preset: target.preset.exec,
      command: execOf(target).command,
      cwd: execOf(target).cwd,
      options: target.options,
      writes: [write("A", "value-a"), write("B", "line1\nline2\n")],
      deletes: ["OLD"],
    });
    expect(invocations.map((invocation) => invocation.command)).toEqual([
      [
        "vercel",
        "env",
        "add",
        "A",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--no-sensitive",
        "--force",
        "--non-interactive",
      ],
      [
        "vercel",
        "env",
        "add",
        "B",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--no-sensitive",
        "--force",
        "--non-interactive",
      ],
      [
        "vercel",
        "env",
        "rm",
        "OLD",
        "preview",
        "--git-branch",
        "feature/x",
        "--project",
        "my-app",
        "--scope",
        "team",
        "--yes",
        "--non-interactive",
      ],
    ]);
    expect(
      invocations.map((invocation) => decoder.decode(Redacted.value(invocation.stdin))),
    ).toEqual(["value-a", "line1\nline2\n", ""]);
    expect(invocations.map((invocation) => invocation.kind)).toEqual(["write", "write", "delete"]);
    for (const invocation of invocations) {
      expect(invocation.extraEnv).toEqual({ VERCEL_TELEMETRY_DISABLED: "1" });
      expect(invocation.cwd).toBe("/repo");
      expect(invocation.command.join(" ")).not.toContain("value-a");
    }
  });

  it("Workers: JSON 1 つに書き込みと削除(null)を同居させ、100 件ごとに分割する", () => {
    const target = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      options: { name: "w", environment: "staging", config: "wrangler.jsonc" },
    });
    const writes = Array.from({ length: 150 }, (_, index) => write(`V${index}`, `value ${index}`));
    const invocations = buildInvocations({
      preset: target.preset.exec,
      command: "npx-free/wrangler",
      cwd: "/repo",
      options: target.options,
      writes,
      deletes: ["GONE"],
    });
    expect(invocations).toHaveLength(2);
    for (const invocation of invocations) {
      expect(invocation.command).toEqual([
        "npx-free/wrangler",
        "secret",
        "bulk",
        "--name",
        "w",
        "--env",
        "staging",
        "--config",
        "wrangler.jsonc",
      ]);
      expect(invocation.kind).toBe("write");
    }
    const first = JSON.parse(
      decoder.decode(Redacted.value((invocations[0] as (typeof invocations)[number]).stdin)),
    ) as Record<string, unknown>;
    const second = JSON.parse(
      decoder.decode(Redacted.value((invocations[1] as (typeof invocations)[number]).stdin)),
    ) as Record<string, unknown>;
    expect(Object.keys(first)).toHaveLength(100);
    expect(Object.keys(second)).toHaveLength(51);
    expect(first["V0"]).toBe("value 0");
    expect(second["GONE"]).toBeNull();
    expect(invocations[1]?.names).toContain("GONE");
  });

  it("UTF-8 でない値が届いたら空文字列を黙って書かずに落とす(prepareWork が先に弾く前提の防衛線)", () => {
    const target = parsed({ preset: "cloudflare-workers", environment: "prod", variables: "all" });
    expect(() =>
      buildInvocations({
        preset: target.preset.exec,
        command: execOf(target).command,
        cwd: execOf(target).cwd,
        options: target.options,
        writes: [
          {
            name: "A",
            value: Redacted.make(new Uint8Array([0xff, 0xfe]), { label: "variable-value" }),
          },
        ],
        deletes: [],
      }),
    ).toThrow("not valid UTF-8");
  });

  it("引数テンプレートに値のトークンは存在しない(型で禁止 — 宣言を走査して確かめる)", () => {
    for (const preset of Object.values(EXEC_PRESETS)) {
      const templates = [
        ...preset.writeArgs,
        ...(preset.delete === "json-null" ? [] : preset.delete.args),
      ];
      for (const template of templates) {
        if (typeof template === "string") {
          expect(template).not.toMatch(/value|body/i);
        } else {
          expect(["name", "option", "switch"]).toContain(template.kind);
        }
      }
    }
  });
});

describe("checkValueConstraints", () => {
  const vercel = { constraints: EXEC_PRESETS.vercel.constraints, label: "the vercel CLI" };
  const workers = {
    constraints: EXEC_PRESETS["cloudflare-workers"].constraints,
    label: "the wrangler CLI",
  };

  it("Vercel: 空・16 KiB 超・末尾改行 1 つの 1 行を拒否し、文面は変数名だけ", () => {
    const secret = "s3cr3t-value";
    expect(checkValueConstraints(vercel, "A", encoder.encode(""))?.message).toContain(
      "Variable A is empty",
    );
    const large = checkValueConstraints(vercel, "A", new Uint8Array(16 * 1024 + 1));
    expect(large?.message).toContain("16385 bytes, above the 16384-byte limit");
    expect(checkValueConstraints(vercel, "A", new Uint8Array(16 * 1024))).toBeNull();
    const newline = checkValueConstraints(vercel, "A", encoder.encode(`${secret}\n`));
    expect(newline?.message).toContain("single line ending with a newline");
    expect(newline?.message).not.toContain(secret);
    expect(checkValueConstraints(vercel, "A", encoder.encode(`${secret}\r\n`))).not.toBeNull();
    // 複数行は末尾改行があっても残る(Vercel CLI が落とさない)ので通す
    expect(checkValueConstraints(vercel, "A", encoder.encode("a\nb\n"))).toBeNull();
    expect(checkValueConstraints(vercel, "A", encoder.encode(secret))).toBeNull();
  });

  it("Workers: 制約なし(空も改行もそのまま JSON に載る)", () => {
    expect(checkValueConstraints(workers, "A", encoder.encode(""))).toBeNull();
    expect(checkValueConstraints(workers, "A", encoder.encode("x\n"))).toBeNull();
    expect(checkValueConstraints(workers, "A", new Uint8Array(70_000))).toBeNull();
  });
});

describe("scrubVendorOutput", () => {
  it("JSON に逃がされた形の値(wrangler の本文 echo)も伏せる", () => {
    const values = [write("A", 'quo"te\\back\nnext'), write("B", "plain")];
    const echoed = `Error: body was ${JSON.stringify({ A: 'quo"te\\back\nnext', B: "plain" })}`;
    const scrubbed = scrubVendorOutput(echoed, values).join("\n");
    expect(scrubbed).not.toContain("quo");
    expect(scrubbed).not.toContain("back");
    expect(scrubbed).not.toContain("next");
    expect(scrubbed).not.toContain("plain");
    expect(scrubbed).toContain('{"A":"[redacted]","B":"[redacted]"}');
  });

  it("上限を超える出力でも、切る前に伏せる(切れ目にかかった値の後半を残さない)", () => {
    // Security Agent 指摘: 伏せる前に末尾 64 K 文字で切ると、切れ目をまたいだ値の
    // 後半が断片に一致せず、そのまま表示された。値の 20 文字目に切れ目が来る長さ
    const value = "S".repeat(40);
    const values = [write("A", value)];
    const tail = "\nError: request failed";
    const filler = "f".repeat(64 * 1024 + 20 - value.length - tail.length);
    const scrubbed = scrubVendorOutput(`${value}${filler}${tail}`, values);
    expect(scrubbed).toHaveLength(2);
    expect(scrubbed.join("\n")).not.toContain("SSSSSSSSSS");
    expect(scrubbed[0]?.length).toBeLessThan(64 * 1024);
    expect(scrubbed[1]).toBe("Error: request failed");
  });

  it("値と複数行値の各行を伏せ、制御文字を中和し、末尾 20 行だけを残す", () => {
    const values = [write("A", "top-secret"), write("B", "first line\nsecond line")];
    const lines = Array.from({ length: 30 }, (_, index) => `line ${index}`);
    const output = [
      ...lines,
      "wrote top-secret ok[31m",
      "saw second line and first line\nfirst line",
    ].join("\n");
    const scrubbed = scrubVendorOutput(output, values);
    expect(scrubbed).toHaveLength(20);
    expect(scrubbed.join("\n")).not.toContain("top-secret");
    expect(scrubbed.join("\n")).not.toContain("second line");
    expect(scrubbed.join("\n")).not.toContain("");
    expect(scrubbed[scrubbed.length - 3]).toBe("wrote [redacted] ok�[31m");
    expect(scrubbed[scrubbed.length - 2]).toBe("saw [redacted] and [redacted]");
    expect(scrubbed[scrubbed.length - 1]).toBe("[redacted]");
  });
});

describe("computePlan", () => {
  const target = parsed(vercelTarget({ variables: ["A", "B", "C"] }));

  function plan(input: {
    readonly source: readonly {
      name: string;
      version: number;
      byteLength?: number;
      required?: boolean;
    }[];
    readonly receipt: Record<string, number> | null;
    readonly declared?: readonly { name: string; required: boolean }[];
    readonly targetOverride?: SyncTarget;
  }) {
    return Effect.runSync(
      computePlan({
        target: input.targetOverride ?? target,
        source: input.source.map((entry) => ({
          name: entry.name,
          version: entry.version,
          byteLength: entry.byteLength ?? 10,
          required: entry.required ?? false,
        })),
        declared: (input.declared ?? []).map((entry) => ({
          variableId: `id-${entry.name}`,
          name: entry.name,
          required: entry.required,
          varType: "",
        })),
        receipt:
          input.receipt === null
            ? null
            : {
                version: 1,
                target: "t",
                preset: "vercel",
                syncedAt: "2026-09-06T00:00:00.000Z",
                variables: input.receipt,
              },
      }),
    );
  }

  it("add / update / unchanged / delete を名前順に出す", () => {
    const result = plan({
      source: [
        { name: "C", version: 1 },
        { name: "A", version: 3 },
        { name: "B", version: 2 },
      ],
      receipt: { A: 2, B: 2, Z: 9 },
    });
    expect(result.entries).toEqual([
      { action: "update", name: "A", version: 3, previousVersion: 2 },
      { action: "unchanged", name: "B", version: 2 },
      { action: "add", name: "C", version: 1 },
      { action: "delete", name: "Z", previousVersion: 9 },
    ]);
  });

  it("declared のみの変数は運ぶものが無く、required なら止める材料になる", () => {
    const result = plan({
      source: [
        { name: "A", version: 1 },
        { name: "B", version: 1 },
      ],
      receipt: null,
      declared: [{ name: "C", required: true }],
    });
    expect(result.entries.map((entry) => entry.name)).toEqual(["A", "B"]);
    expect(result.declaredRequired.map((entry) => entry.name)).toEqual(["C"]);
  });

  it("選択に無い required の active を数え、レシートにあって選択から外れた名前は delete", () => {
    const narrow = parsed(vercelTarget({ variables: ["A"] }));
    const result = plan({
      targetOverride: narrow,
      source: [
        { name: "A", version: 1 },
        { name: "B", version: 1, required: true },
      ],
      receipt: { A: 1, B: 1 },
    });
    expect(result.requiredNotSelected).toEqual(["B"]);
    expect(result.entries).toEqual([
      { action: "unchanged", name: "A", version: 1 },
      { action: "delete", name: "B", previousVersion: 1 },
    ]);
  });

  it("all + exclude: 除外名は運ばず、maruhi から消えた名前は delete、`__proto__` も普通の名前", () => {
    const all = parsed({
      preset: "cloudflare-workers",
      environment: "prod",
      variables: "all",
      exclude: ["PUBLIC"],
    });
    const result = plan({
      targetOverride: all,
      source: [
        { name: "PUBLIC", version: 1 },
        { name: "__proto__", version: 2 },
      ],
      // オブジェクトリテラルの `__proto__:` はプロトタイプ指定になるので JSON から作る
      receipt: JSON.parse('{"REMOVED":1,"__proto__":1}') as Record<string, number>,
    });
    expect(result.entries).toEqual([
      { action: "delete", name: "REMOVED", previousVersion: 1 },
      { action: "update", name: "__proto__", version: 2, previousVersion: 1 },
    ]);
  });

  it("明示リストに無い名前は失敗(値の名前だけを言う)", () => {
    const exit = Effect.runSyncExit(
      computePlan({
        target,
        source: [{ name: "A", version: 1, byteLength: 1, required: false }],
        declared: [],
        receipt: null,
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain("do not exist in environment prod: B, C");
  });
});

describe("receipt codec", () => {
  it("往復し、名前順で決定論的にエンコードする", () => {
    const encoded = encodeReceipt({
      version: 1,
      target: "web",
      preset: "vercel",
      syncedAt: "2026-09-06T00:00:00.000Z",
      variables: { B: 2, A: 1 },
    });
    expect(decoder.decode(encoded)).toBe(
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"2026-09-06T00:00:00.000Z","variables":{"A":1,"B":2}}',
    );
    const decoded = decodeReceipt(decoder.decode(encoded), "web");
    expect(decoded).toMatchObject({ target: "web", variables: { A: 1, B: 2 } });
    expect(receiptVariableName("web")).toBe("sync-receipt:web");
  });

  it.each([
    ["nope", "not valid JSON"],
    ["[]", "the top level must be an object"],
    ['{"version":2}', "unsupported receipt version"],
    ['{"version":1,"target":"other"}', "the receipt names a different target"],
    ['{"version":1,"target":"web","preset":"x"}', "unknown preset"],
    ['{"version":1,"target":"web","preset":"vercel","syncedAt":1}', "syncedAt must be a string"],
    [
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"t","variables":[]}',
      "variables must be an object",
    ],
    [
      '{"version":1,"target":"web","preset":"vercel","syncedAt":"t","variables":{"A":0}}',
      "positive integer versions",
    ],
  ])("拒否する: %s", (text, reason) => {
    expect(decodeReceipt(text, "web")).toContain(reason);
  });
});
