// 復元 worker(運営専用・非 HTTP・非常設) — docs/notes/hosted-ops.md §2-E / §5-2。
//
// `wrangler deploy -c wrangler.restore.jsonc` で復元作業のときだけデプロイし、終わったら
// `wrangler delete -c wrangler.restore.jsonc` で消す。HTTP ハンドラを持たない: 起動は
// 毎分の cron で、仕事は退避バケットの `restore/jobs/<name>.json` を列挙して実行し、
// `restore/results/<name>.json` に結果(静的コード + 検証値)を書くことだけ。ジョブを
// 置けるのは R2 への書き込み権限を持つ運営のみ。
//
// target:
// - `production`: 本番 worker の DO 名前空間(`script_name` で束縛)。受け側 RPC
//   (chain-do.ts の opsRestore)は**空の DO にのみ**書く — 上書き経路は存在しない
// - `drill`: 本 worker 自身の DO クラス(RestoreDrillDO — ProjectChainDO と同じ実装)。
//   演習(hosted-ops.md §5-3)は本番名前空間に触れない
//
// DO 名(= プロジェクト ID)はジョブに書かず、退避物のチェーン genesis(seq 1 の
// entry_hash_hex)から導出する(キー・ジョブ・結果に capability を載せない)。

import type { OpsRestoreOutcome, ProjectChainDO } from "./chain-do.ts";
import { ProjectChainDO as ProjectChainDOClass } from "./chain-do.ts";

/** 演習用の名前空間(本 worker 内の別クラス名 — 本番名前空間と交わらない)。 */
export class RestoreDrillDO extends ProjectChainDOClass {}

export interface RestoreEnv {
  readonly OPS_BACKUP_BUCKET: R2Bucket;
  /** 本番 worker の名前空間(wrangler.restore.jsonc の script_name 束縛)。 */
  readonly PRODUCTION_PROJECT_CHAIN?: DurableObjectNamespace<ProjectChainDO>;
  readonly DRILL_PROJECT_CHAIN?: DurableObjectNamespace<RestoreDrillDO>;
}

const JOBS_PREFIX = "restore/jobs/";
const RESULTS_PREFIX = "restore/results/";

interface RestoreJob {
  readonly objectKey: string;
  readonly target: "production" | "drill";
}

export type RestoreJobResult =
  | {
      readonly status: "ok";
      readonly target: RestoreJob["target"];
      readonly verification: Extract<OpsRestoreOutcome, { kind: "restored" }>;
    }
  | {
      readonly status: "failed";
      /** 静的コードのみ(例外メッセージは書かない) */
      readonly code:
        | "job-malformed"
        | "target-unavailable"
        | "snapshot-missing"
        | "genesis-missing"
        | "rpc-failed"
        | Extract<OpsRestoreOutcome, { kind: "refused" }>["code"]
        | "no-bucket";
    };

function parseJob(text: string): RestoreJob | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return null;
  }
  const job = parsed as { objectKey?: unknown; target?: unknown };
  if (
    typeof job.objectKey !== "string" ||
    (job.target !== "production" && job.target !== "drill")
  ) {
    return null;
  }
  return { objectKey: job.objectKey, target: job.target };
}

/**
 * 退避物からプロジェクト ID(genesis エントリのハッシュ)を読む。gzip NDJSON を
 * 先頭から流し、chain_entries の seq 1 の行に達したら止める(chain_entries は最後の
 * 表なので実質全走査 — 復元自体が全走査であり、一回性の運用操作として受容)。
 */
export async function projectIdFromSnapshot(body: ReadableStream): Promise<string | null> {
  const reader = body
    .pipeThrough(new DecompressionStream("gzip"))
    .pipeThrough(new TextDecoderStream())
    .getReader();
  const scanner = new GenesisScanner();
  let carry = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return carry === "" ? null : scanner.consider(carry);
    }
    carry += value;
    let index = carry.indexOf("\n");
    while (index !== -1) {
      const found = scanner.consider(carry.slice(0, index));
      if (found !== null) {
        await reader.cancel();
        return found;
      }
      carry = carry.slice(index + 1);
      index = carry.indexOf("\n");
    }
  }
}

interface ScannedLine {
  readonly kind: string;
  readonly table?: string;
  readonly columns?: readonly string[];
  readonly values?: readonly unknown[];
}

/** chain_entries の列名を覚え、seq 1 の行の entry_hash_hex(= プロジェクト ID)を拾う。 */
class GenesisScanner {
  #chainColumns: readonly string[] | null = null;

  consider(line: string): string | null {
    if (line === "") {
      return null;
    }
    const parsed = JSON.parse(line) as ScannedLine;
    if (parsed.kind === "table" && parsed.table === "chain_entries") {
      this.#chainColumns = parsed.columns ?? null;
      return null;
    }
    if (parsed.kind !== "row" || parsed.table !== "chain_entries" || this.#chainColumns === null) {
      return null;
    }
    return genesisHashOf(parsed.values ?? [], this.#chainColumns);
  }
}

function genesisHashOf(values: readonly unknown[], columns: readonly string[]): string | null {
  const hash = values[columns.indexOf("entry_hash_hex")];
  return values[columns.indexOf("seq")] === 1 && typeof hash === "string" ? hash : null;
}

function toJobResult(outcome: OpsRestoreOutcome, target: RestoreJob["target"]): RestoreJobResult {
  switch (outcome.kind) {
    case "restored":
      return { status: "ok", target, verification: outcome };
    case "refused":
      return { status: "failed", code: outcome.code };
    case "no-bucket":
      return { status: "failed", code: "no-bucket" };
  }
}

async function runJob(env: RestoreEnv, job: RestoreJob): Promise<RestoreJobResult> {
  const namespace =
    job.target === "production" ? env.PRODUCTION_PROJECT_CHAIN : env.DRILL_PROJECT_CHAIN;
  if (namespace === undefined) {
    return { status: "failed", code: "target-unavailable" };
  }
  const object = await env.OPS_BACKUP_BUCKET.get(job.objectKey);
  if (object === null) {
    return { status: "failed", code: "snapshot-missing" };
  }
  const projectId = await projectIdFromSnapshot(object.body);
  if (projectId === null) {
    return { status: "failed", code: "genesis-missing" };
  }
  const stub = namespace.get(namespace.idFromName(projectId));
  try {
    // workers-types の RPC スタブ型は union 戻り値を分配するため、宣言どおりの型へ戻す
    // (worker-env.ts の rpcCall と同じ理由。復元 worker は Effect ランタイムを持たない)
    return toJobResult(
      await (stub.opsRestore(job.objectKey) as Promise<OpsRestoreOutcome>),
      job.target,
    );
  } catch (error) {
    console.warn("restore RPC failed", error instanceof Error ? error.name : "unknown");
    return { status: "failed", code: "rpc-failed" };
  }
}

/** ジョブを列挙して順に実行し、結果を書いてジョブを消す(1 ジョブ = 1 結果)。 */
export async function processRestoreJobs(env: RestoreEnv): Promise<readonly string[]> {
  const listed = await env.OPS_BACKUP_BUCKET.list({ prefix: JOBS_PREFIX });
  const processed: string[] = [];
  for (const object of listed.objects) {
    // ジョブ名 = キーの basename から .json を除いたもの(結果は同名の .json)
    const name = object.key.slice(JOBS_PREFIX.length).replace(/\.json$/, "");
    if (name === "") {
      continue;
    }
    const body = await env.OPS_BACKUP_BUCKET.get(object.key);
    const job = body === null ? null : parseJob(await body.text());
    const result: RestoreJobResult =
      job === null ? { status: "failed", code: "job-malformed" } : await runJob(env, job);
    await env.OPS_BACKUP_BUCKET.put(
      `${RESULTS_PREFIX}${name}.json`,
      JSON.stringify(result, null, 2),
      {
        httpMetadata: { contentType: "application/json" },
      },
    );
    await env.OPS_BACKUP_BUCKET.delete(object.key);
    processed.push(name);
  }
  return processed;
}

export default {
  // HTTP ハンドラは持たない(fetch 未定義 = 404)。起動は cron のみ
  async scheduled(_controller, env, _ctx): Promise<void> {
    await processRestoreJobs(env);
  },
} satisfies ExportedHandler<RestoreEnv>;
