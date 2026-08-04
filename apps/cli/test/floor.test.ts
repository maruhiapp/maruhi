// ローカル床(CRYPTO_SPEC §6.3)のテスト。
//
// 前半: 床ストア(floor.ts)の単体 — スキーマの厳格デコード・fail-open の
// 読み込み分類・マージ規則(ヘッド前進のみ・変数床の後退禁止)・原子更新。
// 後半(結線テスト)は floor-detection.test.ts(セッションを跨ぐ検出)。

import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import {
  decodeProjectFloor,
  type EnvironmentFloor,
  type FloorStoreShape,
  makeFileFloorStore,
  type ProjectFloor,
} from "../src/floor.ts";

const PROJECT_ID = "ab".repeat(32);
const HASH_A = "11".repeat(32);
const HASH_B = "22".repeat(32);
const HASH_C = "33".repeat(32);

function envFloor(overrides?: Partial<EnvironmentFloor>): EnvironmentFloor {
  return {
    pullEpoch: 2,
    metaVersion: 1,
    metaSigHashHex: HASH_A,
    variables: {
      va: {
        status: "active",
        version: 3,
        epoch: 2,
        valueSigHashHex: HASH_B,
        metaVersion: 1,
        metaSigHashHex: HASH_C,
      },
      vb: { status: "deleted", metaVersion: 2, metaSigHashHex: HASH_C },
    },
    ...overrides,
  };
}

function sampleFloor(): ProjectFloor {
  return {
    v: 1,
    chainHead: { seq: 3, hashHex: HASH_A },
    environments: { prod: envFloor() },
  };
}

describe("decodeProjectFloor(スキーマの厳格デコード)", () => {
  it("エンコードしたものを byte-exact に読み戻せる", () => {
    const floor = sampleFloor();
    expect(decodeProjectFloor(JSON.stringify(floor))).toEqual(floor);
  });

  it.each([
    ["JSON でない", "not-json"],
    ["配列", "[]"],
    ["スキーマバージョン不一致", JSON.stringify({ ...sampleFloor(), v: 2 })],
    ["チェーンヘッド欠落", JSON.stringify({ v: 1, environments: {} })],
    [
      "hash が hex64 でない",
      JSON.stringify({ v: 1, chainHead: { seq: 1, hashHex: "zz" }, environments: {} }),
    ],
    [
      "seq が正整数でない",
      JSON.stringify({ v: 1, chainHead: { seq: 0, hashHex: HASH_A }, environments: {} }),
    ],
    [
      "変数床の一部が壊れている(部分読みしない)",
      JSON.stringify({
        v: 1,
        chainHead: { seq: 1, hashHex: HASH_A },
        environments: {
          prod: { ...envFloor(), variables: { va: { status: "active", version: -1 } } },
        },
      }),
    ],
    [
      "active 変数に valueSigHashHex がない",
      JSON.stringify({
        v: 1,
        chainHead: { seq: 1, hashHex: HASH_A },
        environments: {
          prod: {
            ...envFloor(),
            variables: {
              va: {
                status: "active",
                version: 1,
                epoch: 1,
                metaVersion: 1,
                metaSigHashHex: HASH_A,
              },
            },
          },
        },
      }),
    ],
  ])("破損として全体拒否する: %s", (_label, json) => {
    expect(decodeProjectFloor(json)).toBeNull();
  });

  it("deleted 変数は value 系フィールドなしで有効", () => {
    const floor: ProjectFloor = {
      v: 1,
      chainHead: { seq: 1, hashHex: HASH_A },
      environments: {
        prod: envFloor({
          variables: { vx: { status: "deleted", metaVersion: 3, metaSigHashHex: HASH_B } },
        }),
      },
    };
    expect(decodeProjectFloor(JSON.stringify(floor))).toEqual(floor);
  });
});

describe("makeFileFloorStore(fail-open 読み込みと原子コミット)", () => {
  let dir: string;
  let store: FloorStoreShape;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "maruhi-floor-test-"));
    store = makeFileFloorStore(dir);
  });

  const load = () => Effect.runPromise(store.load(PROJECT_ID));

  it("ファイル不在 = missing(初回)、破損 = corrupt を区別する", async () => {
    expect(await load()).toEqual({ floor: null, state: "missing" });
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    expect((await load()).state).toBe("loaded");
    await writeFile(join(dir, `${PROJECT_ID}.json`), "{broken");
    expect(await load()).toEqual({ floor: null, state: "corrupt" });
  });

  it("commitHead はヘッドを前進のみさせる(seq 後退は書き込まない)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 3, hashHex: HASH_B }));
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_A });
  });

  it("commitPull は環境床の置き換えとヘッド前進を 1 ファイル書き込みで行う", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 4, hashHex: HASH_B },
        environmentId: "dev",
        environment: envFloor({ pullEpoch: 1, variables: {} }),
      }),
    );
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
    // 別環境の床は保持される(環境単位のマージ)
    expect(Object.keys(result.floor?.environments ?? {}).toSorted()).toEqual(["dev", "prod"]);
    expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
  });

  it("commitPush は変数床を前進させ、pullEpoch(規則 (c) 基準)は動かさない", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({ pullEpoch: 2 }),
      }),
    );
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: {
          status: "active",
          version: 4,
          epoch: 3,
          valueSigHashHex: HASH_C,
          metaVersion: 1,
          metaSigHashHex: HASH_C,
        },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.pullEpoch).toBe(2);
    expect(environment?.variables["va"]).toMatchObject({ version: 4, epoch: 3 });
    // 他の変数床は保持される
    expect(environment?.variables["vb"]).toMatchObject({ status: "deleted" });
  });

  it("commitPull のマージは単調(並行プロセスが確立した新しい床を古いコミットが後退させない)", async () => {
    // プロセス B が新世代(pullEpoch 3・va v5)をコミット済み
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 5, hashHex: HASH_B },
        environmentId: "prod",
        environment: envFloor({
          pullEpoch: 3,
          metaVersion: 2,
          variables: {
            va: {
              status: "active",
              version: 5,
              epoch: 3,
              valueSigHashHex: HASH_B,
              metaVersion: 2,
              metaSigHashHex: HASH_B,
            },
          },
        }),
      }),
    );
    // プロセス A の古い pull(pullEpoch 2・va v3・vb の tombstone 込み)が後に着地
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    // pullEpoch(規則 (c) 基準)・メタ・変数床は後退しない。片側にしかない
    // 変数(vb)は union で保持される
    expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_B });
    expect(environment?.pullEpoch).toBe(3);
    expect(environment?.metaVersion).toBe(2);
    expect(environment?.variables["va"]).toMatchObject({ version: 5, epoch: 3 });
    expect(environment?.variables["vb"]).toMatchObject({ status: "deleted" });
  });

  it("マージは deleted(終端状態)を active で上書きしない(commitPush の窓)", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    // vb は床上 deleted(終端)。並行 push の遅延コミットが active を書こうと
    // しても保持される(削除の無断取り消しの検出材料を失わない)
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "vb",
        variable: {
          status: "active",
          version: 9,
          epoch: 2,
          valueSigHashHex: HASH_B,
          metaVersion: 9,
          metaSigHashHex: HASH_B,
        },
      }),
    );
    const result = await load();
    expect(result.floor?.environments["prod"]?.variables["vb"]).toEqual({
      status: "deleted",
      metaVersion: 2,
      metaSigHashHex: HASH_C,
    });
  });

  it("commitPush は並行プロセスが先に進めた変数床を後退させない", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: {
          status: "active",
          version: 2,
          epoch: 1,
          valueSigHashHex: HASH_C,
          metaVersion: 1,
          metaSigHashHex: HASH_C,
        },
      }),
    );
    const result = await load();
    expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({
      version: 3,
      valueSigHashHex: HASH_B,
    });
  });

  it("commitPush は環境床がない場合に規則 (c) 基準を捏造しない(ヘッド前進のみ)", async () => {
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 2, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: { status: "deleted", metaVersion: 1, metaSigHashHex: HASH_A },
      }),
    );
    const result = await load();
    expect(result.floor?.chainHead.seq).toBe(2);
    expect(result.floor?.environments["prod"]).toBeUndefined();
  });

  it("破損した床ファイルへのコミットは退避(quarantine)してから作り直す", async () => {
    await writeFile(join(dir, `${PROJECT_ID}.json`), "{broken");
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    const result = await load();
    expect(result.state).toBe("loaded");
    expect(result.floor?.chainHead).toEqual({ seq: 1, hashHex: HASH_A });
    // 破損の形自体もフォレンジック材料 — 上書きで消さず .corrupt-* へ退避する
    const entries = await readdir(dir);
    const quarantined = entries.find((name) => name.startsWith(`${PROJECT_ID}.json.corrupt-`));
    expect(quarantined).toBeDefined();
    expect(await readFile(join(dir, quarantined as string), "utf8")).toBe("{broken");
  });

  it("missing は ENOENT のみ: それ以外の読み取りエラーは初回と同一視しない", async () => {
    // 床ファイルのパスにディレクトリを置く(readFile → EISDIR)
    await mkdir(join(dir, `${PROJECT_ID}.json`));
    await expect(Effect.runPromise(store.load(PROJECT_ID))).rejects.toThrow("読み取れません");
    // 書き込み経路も空からの作り直しをせず中断する(床の無警告全消去を防ぐ)
    await expect(
      Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A })),
    ).rejects.toThrow("書き込めません");
  });

  it("書き込みは temp + rename(コミット後のファイルは常に完全な JSON)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    const raw = await readFile(join(dir, `${PROJECT_ID}.json`), "utf8");
    expect(decodeProjectFloor(raw)).not.toBeNull();
    expect(raw.endsWith("\n")).toBe(true);
  });

  it("プロジェクト ID の形式(hex 64)をパス組み立て前に強制する", async () => {
    await expect(Effect.runPromise(store.load("../escape"))).rejects.toThrow();
  });
});
