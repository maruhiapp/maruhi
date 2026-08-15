// ビルド後に Workers Static Assets 用の _headers を生成する。
// funstack-static はブートストラップとしてインライン <script id="_R_"> を index.html に埋め込む
// (RSC ペイロードのマニフェスト設定 + エントリの動的 import)。内容はビルドごとに変わる
// (ペイロードのコンテンツハッシュを含む)ため、CSP は 'unsafe-inline' ではなく
// そのスクリプトの SHA-256 ハッシュのみを許可する。これで「実質 script-src 'self'」を保つ。
// 検証メモ: docs/notes/spike-a.md
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const publicDir = join(import.meta.dirname, "..", "dist", "public");
const html = readFileSync(join(publicDir, "index.html"), "utf8");

const inlineScripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1] ?? "")
  .filter((body) => body.length > 0);

if (inlineScripts.length !== 1) {
  throw new Error(
    `expected exactly 1 inline bootstrap script, found ${inlineScripts.length}. ` +
      "funstack-static の出力形式が変わった可能性がある。CSP 生成ロジックを見直すこと",
  );
}

const hashes = inlineScripts.map(
  (body) => `'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`,
);

const csp = [
  "default-src 'none'",
  `script-src 'self' ${hashes.join(" ")}`,
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// HSTS(セキュリティレビュー L-5): workers.dev はプリロード済みだが、routes で
// custom domain を割り当てた場合の初回接続ダウングレードを塞ぐ。includeSubDomains
// は付けない(_headers はこのアプリの応答にしか効かず、デプロイ先ゾーンの
// サブドメイン構成はセルフホスト側の管轄のため、越権のリスクだけがある)
const headers = `/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000
`;

writeFileSync(join(publicDir, "_headers"), headers);
console.log(`_headers written (${hashes.length} inline script hash)`);
