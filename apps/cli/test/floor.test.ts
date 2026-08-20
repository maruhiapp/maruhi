// ローカル床(CRYPTO_SPEC §6.3 — 追記専用観測ログ + fold)のテスト。
//
// 前半: 床ストア(floor-log.ts)の単体 — 追記 + fold の単調 join・typed
// conflict(同座標・異ハッシュの両証拠保存)・破損末尾レコードの自己回復・
// スナップショットレコードのコンパクション・intent / resolution(3-F)・
// 旧保存形からの移行。session-31 §3 M1-A5 の固定テスト(3-E 読み替え)は
// 「2 ストアインスタンスの並行追記で両観測がログに残り、同版異 hash が
// 両証拠付き typed conflict になり、異なる変数の並行 commit は union される」
// 形で固定する。後半(結線テスト)は floor-detection.test.ts。

import { appendFile, mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Effect } from "effect";
import { beforeEach, describe, expect, it } from "vitest";

import { cliError } from "../src/errors.ts";
import { makeFloorHandle } from "../src/floor-check.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { EnvironmentFloor, FloorStoreShape } from "../src/floor.ts";

const PROJECT_ID = "ab".repeat(32);
const HASH_A = "11".repeat(32);
const HASH_B = "22".repeat(32);
const HASH_C = "33".repeat(32);
const HASH_D = "44".repeat(32);

function envFloor(overrides?: Partial<EnvironmentFloor>): EnvironmentFloor {
  return {
    pullEpoch: 2,
    observedEpoch: 2,
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

describe("makeFileFloorStore(追記専用ログ + fold)", () => {
  let dir: string;
  let store: FloorStoreShape;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "maruhi-floor-test-"));
    store = makeFileFloorStore(dir);
  });

  const load = () => Effect.runPromise(store.load(PROJECT_ID));
  const logPath = () => join(dir, `${PROJECT_ID}.jsonl`);

  it("ファイル不在 = missing(初回)、解読可能レコードゼロの非空ファイル = corrupt を区別する", async () => {
    expect(await load()).toEqual({ floor: null, state: "missing", droppedRecords: 0 });
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    expect((await load()).state).toBe("loaded");
    await writeFile(logPath(), "{broken\nnot-json-either\n");
    expect(await load()).toEqual({ floor: null, state: "corrupt", droppedRecords: 2 });
  });

  it("部分的に解読できない行は droppedRecords として数える(呼び出し側の警告材料)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A }));
    await appendFile(logPath(), "\n{torn-line-without-newline");
    const result = await load();
    expect(result.state).toBe("loaded");
    expect(result.droppedRecords).toBe(1);
    expect(result.floor?.chainHead).toEqual({ seq: 1, hashHex: HASH_A });
  });

  it("commitHead はヘッドを前進のみさせる(seq 後退の観測は join で負ける)", async () => {
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
    await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 3, hashHex: HASH_B }));
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_A });
  });

  it("commitPull は環境床の join とヘッド前進を 1 レコードの追記で行う", async () => {
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
        environment: envFloor({ pullEpoch: 1, observedEpoch: 1, variables: {} }),
      }),
    );
    const result = await load();
    expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
    // 別環境の床は保持される(環境単位の join)
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

  it("commitPush は環境床がなくても規則 (c) 基準を捏造しない(変数床のみの部分観測)", async () => {
    await Effect.runPromise(
      store.commitPush(PROJECT_ID, {
        chainHead: { seq: 2, hashHex: HASH_A },
        environmentId: "prod",
        variableId: "va",
        variable: { status: "deleted", metaVersion: 1, metaSigHashHex: HASH_A },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(result.floor?.chainHead?.seq).toBe(2);
    // 各座標は独立な半束: pull 基準・環境メタは bottom のまま、変数床だけが立つ
    expect(environment?.pullEpoch).toBe(0);
    expect(environment?.metaVersion).toBe(0);
    expect(environment?.variables["va"]).toMatchObject({ status: "deleted" });
  });

  it("commitMetadata は環境水準のみ join する(M1-A3 — 値床を捏造せず pull 基準も動かさない)", async () => {
    await Effect.runPromise(
      store.commitMetadata(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        observedEpoch: 4,
        metaVersion: 2,
        metaSigHashHex: HASH_B,
        manifest: { manifestVersion: 3, epoch: 4, manifestSigHashHex: HASH_C },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.pullEpoch).toBe(0);
    expect(environment?.observedEpoch).toBe(4);
    expect(environment?.metaVersion).toBe(2);
    expect(environment?.manifest).toEqual({
      manifestVersion: 3,
      epoch: 4,
      manifestSigHashHex: HASH_C,
    });
    expect(environment?.variables).toEqual({});
  });

  it("commitManifest はマニフェスト床と環境水準エポック観測(座標 (ii))だけを前進させる", async () => {
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({
          pullEpoch: 2,
          observedEpoch: 2,
          manifest: { manifestVersion: 1, epoch: 2, manifestSigHashHex: HASH_A },
        }),
      }),
    );
    await Effect.runPromise(
      store.commitManifest(PROJECT_ID, {
        chainHead: { seq: 4, hashHex: HASH_B },
        environmentId: "prod",
        manifest: { manifestVersion: 2, epoch: 3, manifestSigHashHex: HASH_B },
      }),
    );
    const result = await load();
    const environment = result.floor?.environments["prod"];
    expect(environment?.manifest).toMatchObject({ manifestVersion: 2, epoch: 3 });
    // マニフェストの epoch は座標 (ii)(observedEpoch)へも join される
    expect(environment?.observedEpoch).toBe(3);
    // 規則 (c) の pull 基準は動かない(チェーン同期・受理確認単独で前進させない)
    expect(environment?.pullEpoch).toBe(2);
    // 変数床は不変
    expect(environment?.variables["va"]).toMatchObject({ version: 3 });
  });

  describe("並行 2 ストアインスタンス(= 2 プロセス相当)の追記(M1-A5 の 3-E 読み替え)", () => {
    it("異なる変数の並行 commit は union され、どちらの観測も失われない", async () => {
      // 2 プロセスが同じ古い床から出発して独立に commit する形
      const storeA = makeFileFloorStore(dir);
      const storeB = makeFileFloorStore(dir);
      await Effect.runPromise(
        storeA.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: {
            status: "active",
            version: 1,
            epoch: 1,
            valueSigHashHex: HASH_A,
            metaVersion: 1,
            metaSigHashHex: HASH_A,
          },
        }),
      );
      await Effect.runPromise(
        storeB.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "vb",
          variable: {
            status: "active",
            version: 2,
            epoch: 1,
            valueSigHashHex: HASH_B,
            metaVersion: 1,
            metaSigHashHex: HASH_B,
          },
        }),
      );
      const result = await load();
      const environment = result.floor?.environments["prod"];
      expect(environment?.variables["va"]).toMatchObject({ version: 1 });
      expect(environment?.variables["vb"]).toMatchObject({ version: 2 });
      expect(result.floor?.conflicts).toEqual([]);
    });

    it("同版異 hash の並行 commit は両観測がログに残り、両証拠付きの typed conflict になる", async () => {
      const storeA = makeFileFloorStore(dir);
      const storeB = makeFileFloorStore(dir);
      const variable = (hash: string) =>
        ({
          status: "active",
          version: 3,
          epoch: 1,
          valueSigHashHex: hash,
          metaVersion: 1,
          metaSigHashHex: HASH_A,
        }) as const;
      await Effect.runPromise(
        storeA.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: variable(HASH_C),
        }),
      );
      // 後から着地した同版異 hash は「後勝ち」にならず typed conflict で失敗する
      // (証拠の上書きが保存形として表現不能 — 追記のみ)
      await expect(
        Effect.runPromise(
          storeB.commitPush(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: variable(HASH_D),
          }),
        ),
      ).rejects.toThrow("contradict each other");
      // 両観測はログに残っている(追記専用 — 先の証拠は消えない)
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain(HASH_C);
      expect(raw).toContain(HASH_D);
      // fold は両証拠付きの typed conflict を表面化する
      const result = await load();
      expect(result.floor?.conflicts).toHaveLength(1);
      const conflict = result.floor?.conflicts[0];
      expect(conflict).toMatchObject({ kind: "value", environmentId: "prod", variableId: "va" });
      expect([conflict?.firstHashHex, conflict?.secondHashHex].toSorted()).toEqual(
        [HASH_C, HASH_D].toSorted(),
      );
    });

    it("同一 manifestVersion への異なる hash も typed conflict(規則 (b) のマージ意味論)", async () => {
      await Effect.runPromise(
        store.commitManifest(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          manifest: { manifestVersion: 2, epoch: 1, manifestSigHashHex: HASH_C },
        }),
      );
      await expect(
        Effect.runPromise(
          store.commitManifest(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            manifest: { manifestVersion: 2, epoch: 1, manifestSigHashHex: HASH_D },
          }),
        ),
      ).rejects.toThrow("manifestVersion");
      const result = await load();
      expect(result.floor?.conflicts[0]).toMatchObject({ kind: "manifest" });
    });

    it("同一 seq への異なるチェーンヘッド hash は分岐の typed conflict", async () => {
      await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
      await expect(
        Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_B })),
      ).rejects.toThrow("fork");
      const result = await load();
      expect(result.floor?.conflicts[0]).toMatchObject({ kind: "chain-head" });
    });

    it("deleted(終端)より進んだ metaVersion の active 観測は undeletion の typed conflict", async () => {
      await Effect.runPromise(
        store.commitPush(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          variableId: "va",
          variable: { status: "deleted", metaVersion: 2, metaSigHashHex: HASH_A },
        }),
      );
      await expect(
        Effect.runPromise(
          store.commitPush(PROJECT_ID, {
            chainHead: { seq: 3, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: {
              status: "active",
              version: 1,
              epoch: 1,
              valueSigHashHex: HASH_B,
              metaVersion: 3,
              metaSigHashHex: HASH_B,
            },
          }),
        ),
      ).rejects.toThrow("undeletion");
      // 代表は deleted のまま(終端状態は active で上書きされない)
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({
        status: "deleted",
      });
    });

    it("古い pull の遅延着地は単調 join で負けるだけで、証拠は何も失われない", async () => {
      // プロセス B が新世代(pullEpoch 3・va v5)をコミット済み
      await Effect.runPromise(
        store.commitPull(PROJECT_ID, {
          chainHead: { seq: 5, hashHex: HASH_B },
          environmentId: "prod",
          environment: envFloor({
            pullEpoch: 3,
            observedEpoch: 3,
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
      expect(result.floor?.chainHead).toEqual({ seq: 5, hashHex: HASH_B });
      expect(environment?.pullEpoch).toBe(3);
      expect(environment?.metaVersion).toBe(2);
      expect(environment?.variables["va"]).toMatchObject({ version: 5, epoch: 3 });
      // 片側にしかない変数(vb)は union で保持される
      expect(environment?.variables["vb"]).toMatchObject({ status: "deleted" });
      expect(result.floor?.conflicts).toEqual([]);
    });
  });

  describe("破損末尾レコードの自己回復(3-E — ロック回復テストの置き換え)", () => {
    it("torn 行(クラッシュした書きかけ)は fold が無視し、後続の追記を壊さない", async () => {
      await Effect.runPromise(
        store.commitPull(PROJECT_ID, {
          chainHead: { seq: 3, hashHex: HASH_A },
          environmentId: "prod",
          environment: envFloor(),
        }),
      );
      // 並行プロセスが書きかけでクラッシュした形(末尾に改行のない部分行)
      await appendFile(logPath(), '{"r":"pull","head":{"seq":9');
      const afterTear = await load();
      expect(afterTear.state).toBe("loaded");
      expect(afterTear.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
      // 次の追記は改行を前置して torn 行を隔離する — 新しい観測は正しく載る
      await Effect.runPromise(
        store.commitPush(PROJECT_ID, {
          chainHead: { seq: 4, hashHex: HASH_B },
          environmentId: "prod",
          variableId: "va",
          variable: {
            status: "active",
            version: 4,
            epoch: 2,
            valueSigHashHex: HASH_D,
            metaVersion: 1,
            metaSigHashHex: HASH_C,
          },
        }),
      );
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 4 });
      expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
    });
  });

  describe("intent / resolution(3-F — journal-before-send)", () => {
    const intentInput = {
      op: "rotate_epoch" as const,
      environmentId: "prod",
      epoch: 2,
      dekCommitmentHex: HASH_C,
      variableId: null,
      manifestVersion: 2,
      manifestSigHashHex: HASH_D,
      declaredHead: { seq: 3, hashHex: HASH_A },
    };

    it("未解決 intent は fold が「要照合」として表面化し、resolution が閉じる", async () => {
      const id = await Effect.runPromise(store.appendIntent(PROJECT_ID, intentInput));
      let result = await load();
      expect(result.floor?.intents).toHaveLength(1);
      expect(result.floor?.intents[0]).toMatchObject({
        id,
        op: "rotate_epoch",
        environmentId: "prod",
        epoch: 2,
        dekCommitmentHex: HASH_C,
      });
      await Effect.runPromise(store.resolveIntent(PROJECT_ID, id, "accepted"));
      result = await load();
      expect(result.floor?.intents).toEqual([]);
    });

    it("intent は join の格子に入らない(床の観測座標を一切動かさない)", async () => {
      await Effect.runPromise(store.appendIntent(PROJECT_ID, intentInput));
      const result = await load();
      expect(result.floor?.chainHead).toBeNull();
      expect(result.floor?.environments).toEqual({});
    });
  });

  describe("コンパクション(スナップショットレコードの追記 — 書き直さない)", () => {
    it("閾値超過でスナップショットが追記され、fold 結果は不変・conflict の証拠も畳まれても消えない", async () => {
      const compacting = makeFileFloorStore(dir, { compactionThreshold: 4 });
      // conflict を 1 件作る(証拠がスナップショットを跨いで残ることの固定)
      await Effect.runPromise(compacting.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_A }));
      await expect(
        Effect.runPromise(compacting.commitHead(PROJECT_ID, { seq: 5, hashHex: HASH_B })),
      ).rejects.toThrow("fork");
      // 閾値(4 レコード)を超えるまで観測を積む(conflict 済みの床への commit は
      // 失敗し続けるが、追記自体は行われる — 証拠は増える方向にしか動かない)
      for (let index = 0; index < 5; index += 1) {
        await Effect.runPromise(
          Effect.ignore(compacting.commitHead(PROJECT_ID, { seq: 6 + index, hashHex: HASH_C })),
        );
      }
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain('"r":"snapshot"');
      // スナップショット追記後も fold の意味論は不変(conflict は消えない)
      const result = await load();
      expect(result.floor?.conflicts.some((conflict) => conflict.kind === "chain-head")).toBe(true);
      // 物理回収はしない(追記のみ): torn な書き直しが起きていないことの代替検査
      // として、スナップショット後もログに全レコードが残っていることを見る
      expect(raw).toContain(HASH_B);
    });

    it("スナップショット以降だけを fold しても状態が等しい(位置基準 + 冪等な join)", async () => {
      const compacting = makeFileFloorStore(dir, { compactionThreshold: 2 });
      for (let index = 0; index < 4; index += 1) {
        await Effect.runPromise(
          compacting.commitPush(PROJECT_ID, {
            chainHead: { seq: index + 1, hashHex: HASH_A },
            environmentId: "prod",
            variableId: "va",
            variable: {
              status: "active",
              version: index + 1,
              epoch: 1,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          }),
        );
      }
      const result = await load();
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 4 });
      expect(result.floor?.chainHead?.seq).toBe(4);
    });
  });

  describe("旧保存形(単一 JSON スナップショット)からの移行", () => {
    const legacy = {
      v: 1,
      chainHead: { seq: 3, hashHex: HASH_A },
      environments: {
        prod: {
          pullEpoch: 2,
          metaVersion: 1,
          metaSigHashHex: HASH_A,
          manifest: { manifestVersion: 1, epoch: 2, manifestSigHashHex: HASH_B },
          variables: {
            va: {
              status: "active",
              version: 3,
              epoch: 2,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          },
        },
      },
    };

    it("旧ファイルを互換読みし(observedEpoch は既知の検証済み事実から導出)、最初の追記でログへ移行する", async () => {
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), JSON.stringify(legacy));
      const loaded = await load();
      expect(loaded.state).toBe("loaded");
      expect(loaded.floor?.environments["prod"]).toMatchObject({
        pullEpoch: 2,
        observedEpoch: 2,
        metaVersion: 1,
      });
      // 最初の追記が旧状態をスナップショットレコードとしてログへ移行する
      await Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 4, hashHex: HASH_B }));
      const raw = await readFile(logPath(), "utf8");
      expect(raw).toContain('"r":"snapshot"');
      const result = await load();
      expect(result.floor?.chainHead).toEqual({ seq: 4, hashHex: HASH_B });
      expect(result.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
      // 旧ファイルはフォレンジック材料として残る(追記専用の規律 — 消さない)
      const entries = await readdir(dir);
      expect(entries).toContain(`${PROJECT_ID}.json`);
    });

    it("旧ファイルの破損は corrupt として区別する", async () => {
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), "{broken");
      expect(await load()).toEqual({ floor: null, state: "corrupt", droppedRecords: 0 });
    });

    it("空の .jsonl(open と write の間で落ちた残骸)は有効な旧形式を隠さない", async () => {
      // open(\"a\") はファイルを即座に作るため、直後のクラッシュで 0 byte の
      // ログが残りうる。これを missing(初回)へ潰すと、有効な旧床がある run が
      // 床なし(fail-open)で走り、事実と違う first sync 通知が出る
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, `${PROJECT_ID}.json`), JSON.stringify(legacy));
      await writeFile(join(dir, `${PROJECT_ID}.jsonl`), "");
      const loaded = await load();
      expect(loaded.state).toBe("loaded");
      expect(loaded.floor?.environments["prod"]?.variables["va"]).toMatchObject({ version: 3 });
    });
  });

  it("missing は ENOENT のみ: それ以外の読み取りエラーは初回と同一視しない", async () => {
    // 床ログのパスにディレクトリを置く(readFile → EISDIR)
    await mkdir(logPath(), { recursive: true });
    await expect(Effect.runPromise(store.load(PROJECT_ID))).rejects.toThrow(
      "Cannot read the local floor log",
    );
    // 書き込み経路も中断する(床の無警告な機能停止を作らない)
    await expect(
      Effect.runPromise(store.commitHead(PROJECT_ID, { seq: 1, hashHex: HASH_A })),
    ).rejects.toThrow("Cannot write the local floor log");
  });

  it("プロジェクト ID の形式(hex 64)をパス組み立て前に強制する", async () => {
    await expect(Effect.runPromise(store.load("../escape"))).rejects.toThrow();
  });
});

describe("FloorHandle(プロセス内キャッシュと intent の窓口)", () => {
  let dir: string;
  let store: FloorStoreShape;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "maruhi-floor-handle-test-"));
    store = makeFileFloorStore(dir);
  });

  it("コミットごとに fold 済みの床へ同期する(並行プロセスの検出材料を取りこぼさない)", async () => {
    // 兄弟プロセスが vb の tombstone を確立済み(自プロセスの openProject 後)
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 3, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor({ pullEpoch: 3, observedEpoch: 3 }),
      }),
    );
    // 自プロセスのハンドルは古いスナップショット(床なし)から開始
    const handle = makeFloorHandle({
      store,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: null,
    });
    await Effect.runPromise(
      handle.commitPull(
        envFloor({
          pullEpoch: 2,
          observedEpoch: 2,
          variables: {
            va: {
              status: "active",
              version: 1,
              epoch: 2,
              valueSigHashHex: HASH_B,
              metaVersion: 1,
              metaSigHashHex: HASH_C,
            },
          },
        }),
        { seq: 3, hashHex: HASH_A },
      ),
    );
    // 送信スナップショット(va v1・pullEpoch 2)でなく fold 済み床が採用される:
    // 兄弟の tombstone(vb)・より新しい va(v3)・高い方の基準(pullEpoch 3)を
    // 同一コマンド内の後続検査が引き継ぐ
    const current = handle.current();
    expect(current?.pullEpoch).toBe(3);
    expect(current?.variables["vb"]).toMatchObject({ status: "deleted" });
    expect(current?.variables["va"]).toMatchObject({ version: 3 });
  });

  it("commitManifest はディスク書き込みが失敗してもプロセス内の基準を同じ join で前進させる", async () => {
    const failing: FloorStoreShape = {
      ...store,
      commitManifest: () => Effect.fail(cliError("injected floor write failure")),
    };
    const handle = makeFloorHandle({
      store: failing,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: envFloor({ manifest: { manifestVersion: 1, epoch: 1, manifestSigHashHex: HASH_A } }),
    });
    await expect(
      Effect.runPromise(
        handle.commitManifest(
          { manifestVersion: 2, epoch: 2, manifestSigHashHex: HASH_B },
          { seq: 4, hashHex: HASH_B },
        ),
      ),
    ).rejects.toThrow();
    expect(handle.current()?.manifest).toMatchObject({ manifestVersion: 2 });
    // 座標 (ii) も同じ join で前進する
    expect(handle.current()?.observedEpoch).toBe(2);
  });

  it("intent は環境スコープで保持され、resolveIntent は冪等に閉じる", async () => {
    const handle = makeFloorHandle({
      store,
      projectId: PROJECT_ID,
      environmentId: "prod",
      initial: null,
    });
    const id = await Effect.runPromise(
      handle.appendIntent({
        op: "meta-op",
        environmentId: "prod",
        epoch: 1,
        dekCommitmentHex: null,
        variableId: "va",
        manifestVersion: 2,
        manifestSigHashHex: HASH_A,
        declaredHead: { seq: 3, hashHex: HASH_B },
      }),
    );
    expect(handle.unresolvedIntents()).toHaveLength(1);
    await Effect.runPromise(handle.resolveIntent(id, "accepted"));
    expect(handle.unresolvedIntents()).toEqual([]);
    // 二重 resolution は no-op(ログにも余計な resolution を積まない)
    await Effect.runPromise(handle.resolveIntent(id, "accepted"));
    const loaded = await Effect.runPromise(store.load(PROJECT_ID));
    expect(loaded.floor?.intents).toEqual([]);
  });
});

describe("床ログの非機密性(ディスクレス不変条件)", () => {
  it("ProjectFloor の shape に平文値・名前のフィールドが存在しない(型レベルの固定はここでは値検査)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "maruhi-floor-shape-test-"));
    const store = makeFileFloorStore(dir);
    await Effect.runPromise(
      store.commitPull(PROJECT_ID, {
        chainHead: { seq: 1, hashHex: HASH_A },
        environmentId: "prod",
        environment: envFloor(),
      }),
    );
    const raw = await readFile(join(dir, `${PROJECT_ID}.jsonl`), "utf8");
    // 追記は隔離用の改行を前置する — 最初の非空行がレコード
    const line = raw.split("\n").find((candidate) => candidate.trim() !== "") as string;
    const record: unknown = JSON.parse(line);
    // 保存されるのはハッシュ・連番・op 種別のみ(§6.3)
    expect(JSON.stringify(record)).not.toContain("name");
  });
});
