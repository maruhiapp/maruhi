// ビルド後に Workers Static Assets 用の _headers を生成する。
// funstack-static はブートストラップとしてインライン <script id="_R_"> を index.html に埋め込む
// (RSC ペイロードのマニフェスト設定 + エントリの動的 import)。内容はビルドごとに変わる
// (ペイロードのコンテンツハッシュを含む)ため、CSP は 'unsafe-inline' ではなく
// そのスクリプトの SHA-256 ハッシュのみを許可する。これで「実質 script-src 'self'」を保つ。
// 検証メモ: docs/notes/spike-a.md
//
// あわせて /invite(招待リンク着地ページ — AUTH_SPEC §15-3 / ADR-0018 改訂 2・5 項)の
// 不変条件「スクリプトを一切持たない・フラグメントを解釈しない」を、
//   (1) 配信物 invite.html への機械検査(script ゼロ・外部リソース読み込みなし)
//   (2) per-path CSP `script-src 'none'` の _headers への書き込みと最終成果物の確認
// で構成として固定する。違反はビルド失敗(throw)にする — 検査は品質ゲート
// (CI の web ビルドステップ)の経路に載る。裁定の経緯は docs/notes/session-41.md。
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

// ---- /invite: 配信物の機械検査(固定検査 1) ----
// 検査対象はソースでなくビルド出力(dist/public/invite.html)。配信されるバイトに
// script が紛れ込む経路(ビルド変換・コピー漏れ)ごと検査する。
// 配信バイト全体を検査する(HTML コメントも除去しない — コメント内の字面も含めて
// script 開始タグをゼロに保つ。e2e 側の検査と同じ強度)
const inviteHtml = readFileSync(join(publicDir, "invite.html"), "utf8");

if (/<script/i.test(inviteHtml)) {
  throw new Error(
    "invite.html に <script> がある。/invite はスクリプトを一切持たない(AUTH_SPEC §15-3)",
  );
}
if (/\bon[a-z]+\s*=\s*["']/i.test(inviteHtml)) {
  throw new Error("invite.html にインラインイベントハンドラ属性がある(AUTH_SPEC §15-3)");
}
if (/javascript:/i.test(inviteHtml)) {
  throw new Error("invite.html に javascript: URL がある(AUTH_SPEC §15-3)");
}
// 外部リソース読み込みなし(全アセット自己配信)。href 属性に限り、自リポジトリの
// GitHub(CLI 導入への導線のナビゲーションリンク)を許可する。実行時の強制は CSP
// (default-src 'none' 基調)が担い、この検査はビルド時に早く落とすための二重化
// (プロトコル相対 `//` はルート相対と区別して弾く — pullfrog レビュー反映)
const allowedExternalNavPrefix = "https://github.com/maruhiapp/maruhi";
for (const [, attr, url] of inviteHtml.matchAll(/\b(src|href)="([^"]*)"/g)) {
  const ok =
    url !== undefined &&
    ((url.startsWith("/") && !url.startsWith("//")) ||
      url.startsWith("#") ||
      (attr === "href" && url.startsWith(allowedExternalNavPrefix)));
  if (!ok) {
    throw new Error(`invite.html が外部リソース/URL を参照している: ${attr}="${url}"`);
  }
}
// スタイルシートの実体もビルド出力に存在すること(コピー漏れの検出)
readFileSync(join(publicDir, "invite.css"));

// /invite の per-path CSP: script-src 'none' で「フラグメントを解釈しない」を構成で強制。
// ページが使うのは自己配信スタイルのみ。それ以外は全面 'none'
const inviteCsp = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

// HSTS(セキュリティレビュー L-5): workers.dev はプリロード済みだが、routes で
// custom domain を割り当てた場合の初回接続ダウングレードを塞ぐ。includeSubDomains
// は付けない(_headers はこのアプリの応答にしか効かず、デプロイ先ゾーンの
// サブドメイン構成はセルフホスト側の管轄のため、越権のリスクだけがある)
//
// /invite ブロック: `! Content-Security-Policy` で /* の CSP をデタッチしてから
// 置き換える(デタッチしないと 2 本の CSP が併記され、どちらも強制される —
// 安全側だが意図が読めない)。/* の他ヘッダー(nosniff / Referrer-Policy / HSTS)は
// /invite にもそのまま効く。html_handling 既定(auto-trailing-slash)により
// /invite.html・/invite/ へのリクエストは /invite へ正規化されるため、
// per-path ルールは /invite の 1 本でよい(配信挙動は e2e で固定)
const headers = `/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000

/invite
  ! Content-Security-Policy
  Content-Security-Policy: ${inviteCsp}
`;

writeFileSync(join(publicDir, "_headers"), headers);

// ---- _headers の最終成果物確認(固定検査 2) ----
// 「_headers に /invite の per-path CSP が存在する」を書き込み後の実ファイルで確認する
// (この script の将来の編集で書き込みが落ちた場合もビルドが失敗する)
const written = readFileSync(join(publicDir, "_headers"), "utf8");
const inviteBlock = written.split(/^(?=\/)/m).find((block) => block.startsWith("/invite\n"));
if (inviteBlock === undefined || !inviteBlock.includes("script-src 'none'")) {
  throw new Error("_headers に /invite の per-path CSP(script-src 'none')が無い");
}

console.log(`_headers written (${hashes.length} inline script hash + /invite per-path CSP)`);
