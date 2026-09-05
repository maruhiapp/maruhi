// ビルド後に Workers Static Assets 用の _headers を生成する。
// funstack-static はブートストラップとしてインライン <script id="_R_"> を index.html に埋め込む
// (RSC ペイロードのマニフェスト設定 + エントリの動的 import)。内容はビルドごとに変わる
// (ペイロードのコンテンツハッシュを含む)ため、CSP は 'unsafe-inline' ではなく
// そのスクリプトの SHA-256 ハッシュのみを許可する。これで「実質 script-src 'self'」を保つ。
// 検証メモ: docs/notes/spike-a.md
//
// あわせて /invite(招待リンク着地ページ — AUTH_SPEC §15-3 / ADR-0018 改訂 2・5 項)の
// 不変条件「スクリプトを一切持たない・フラグメントを解釈しない」を、
//   (1) 配信物 invite.html への機械検査(script ゼロ・meta CSP あり・外部リソースなし)
//   (2) per-path CSP `script-src 'none'` の _headers への書き込みと最終成果物の確認
//   (3) near-miss パス(大小変種・深いパス)を /invite へ正規化する _redirects の生成
// で構成として固定する。違反はビルド失敗(throw)にする — 検査は品質ゲート
// (CI の web ビルドステップ)の経路に載る。裁定の経緯は docs/notes/session-41.md。
//
// スクリプトなしページ(/invite + サーバー配信の儀式ページ — DP4)の共通スタイルは
// public/pages.css(自己配信)で、ブランド値は theme/maruhi.css(`astryx theme build` の
// 生成物 = ブランドの正の生成物)を **無変換で /theme.css として同梱**して var() で読む
// (裁定 DP4-B — docs/notes/web-design-pass.md §5。生成スクリプトも写しも持たない:
// 配信物 = テーマファイルそのもの)。同梱は本スクリプトが行い、バイト等価を検査する。
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const publicDir = join(import.meta.dirname, "..", "dist", "public");
const themeSource = join(import.meta.dirname, "..", "theme", "maruhi.css");

// ---- /theme.css: ブランドテーマの無変換同梱(DP4 裁定 B) ----
// vite は theme/maruhi.css を SPA の CSS バンドル(コンテンツハッシュ名)に取り込むため、
// 静的 HTML / サーバー描画 HTML から安定して参照できる名前が無い。同じ生成物を
// 固定名で置く(二重管理ではなく同一バイトの複製 — 下の等価検査で固定する)
writeFileSync(join(publicDir, "theme.css"), readFileSync(themeSource));
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
// meta CSP(配信バイト内蔵の強制)が存在し script-src 'none' を含むこと。
// _headers の per-path CSP(配信層)と独立に効く二重化であり、配信層の挙動差
// (デタッチ構文の production 実装等)に依らずスクリプト実行ゼロを保つ
const metaCspMatch = inviteHtml.match(
  /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i,
);
if (metaCspMatch?.[1] === undefined || !metaCspMatch[1].includes("script-src 'none'")) {
  throw new Error("invite.html に meta CSP(script-src 'none')が無い(AUTH_SPEC §15-3)");
}
// 外部リソース読み込みなし(全アセット自己配信 — スタイルシート / ロゴ SVG / favicon は
// ルート相対)。href 属性に限り、自リポジトリの GitHub(CLI 導入への導線のナビゲーション
// リンク)を許可する。実行時の強制は CSP(default-src 'none' 基調)が担い、この検査は
// ビルド時に早く落とすための二重化
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
// 複製忠実性(裁定 BH): vite publicDir のコピーが無変換であること(= レビューした
// ソースの字面がそのまま配信バイトであること)をバイト等価で固定する。将来の
// ビルドプラグインが HTML/CSS を変換し始めた場合に最速で検知する。/theme.css も
// 同じ契約(配信バイト = theme/maruhi.css)
const sourceDir = join(import.meta.dirname, "..", "public");
for (const [source, asset] of [
  [join(sourceDir, "invite.html"), "invite.html"],
  [join(sourceDir, "pages.css"), "pages.css"],
  [themeSource, "theme.css"],
] as const) {
  if (readFileSync(source, "utf8") !== readFileSync(join(publicDir, asset), "utf8")) {
    throw new Error(
      `${asset} がソースとビルド出力で一致しない(publicDir の無変換コピーの前提が破れた)`,
    );
  }
}

// ---- SPA バンドルのフラグメント非読取検査(裁定 BG) ----
// near-miss 正規化(下の _redirects)から漏れる語中タイポ(/invte 等)は SPA シェルに
// 落ちる。その無害性の根拠「SPA はフラグメントを読まない」を、規約でなく配信物への
// 機械検査にする: 配信される全 JS + index.html(インラインブートストラップ含む)に
// **識別子・プロパティ・文字列としての語 `hash` が一切現れない**ことを要求する
// (location.hash / {hash} 分割代入 / ["hash"] の全字面形を被覆。現行バンドルで 0 件)。
// これは字面のトリップワイヤであり、対象はドリフト(将来の機能追加でフラグメント
// 読取が紛れ込むこと)。`location.href` の手動 `#` パースや難読化(charCodeAt(35) 等)
// は検知対象外 — `#` 系の字面検査は正当用途(色パーサの startsWith(`#`)・Intl 数値
// パターン・RSC ランタイムのモジュール参照 "path#export" の分割)と原理的に区別
// できず誤検知するため棄却した(実測は session-41 裁定 BG)。正当な `hash` 利用が
// 将来必要になったら、この検査が落ちて明示的な裁定を強制する(「インライン script は
// 厳密に 1 本」検査と同じ、上流変化で意図的に割れる型)
// 走査は publicDir 全体の再帰列挙(pullfrog レビュー反映): assets/ 直下・非再帰に
// 固定すると、ビルドの出力レイアウト変更(サブディレクトリ・.mjs 化)で検査が
// 落ちずに被覆だけ縮む。再帰なら被覆が自己維持される
const bundleFiles = [
  join(publicDir, "index.html"),
  ...readdirSync(publicDir, { recursive: true, encoding: "utf8" })
    .filter((name) => name.endsWith(".js") || name.endsWith(".mjs"))
    .map((name) => join(publicDir, name)),
];
for (const file of bundleFiles) {
  const content = readFileSync(file, "utf8");
  if (/\bhash\b/i.test(content)) {
    throw new Error(
      `${file} が語 "hash" を含む。SPA バンドルはフラグメントを読まない(AUTH_SPEC §15-3 — ` +
        "正当な利用を足す場合は docs/notes/session-41.md 裁定 BG を改訂すること)",
    );
  }
}

// /invite の per-path CSP: script-src 'none' で「フラグメントを解釈しない」を構成で強制。
// ページが使うのは自己配信のスタイル(/theme.css + /pages.css)とロゴ SVG のみ。
// それ以外は全面 'none'(サーバー配信の儀式ページの CSP — cli-pages.ts — と同じ形)
const inviteCsp = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
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

// ---- _redirects: near-miss パスの /invite への正規化 ----
// 資産キー照合は大文字小文字を区別するため、`/Invite` 等の大小変種はアセットに一致せず
// SPA フォールバック(script を持つシェル)へ落ちる。系統的な発生源(モバイルの
// 自動大文字化・貼り付け時の末尾ゴミ〔小文字パスに落ちる — pullfrog 指摘〕)を含む
// 「大小変種 × 任意の末尾続き」のクラス全体を、機械生成した _redirects で /invite へ
// 301 正規化して閉じる(フラグメントはブラウザがリダイレクト越しに保持する)。
//
// 構成(先勝ちマッチを利用): ① 正規パスの 200 リライト(自分自身へのリライト =
// 素通し)を盾として前置 → ② 大小変種 63 本の末尾スプラット
// `/{Variant}* /invite 301` → ③ 小文字総取り `/invite* /invite 301` を最後に。
// 盾が先にあるため ③ が正規パス自身(自己ループ)に誤爆しない(スタイルシートは
// DP4 で /pages.css へ移り /invite* の外に出たため、旧 /invite.css の盾は不要)。
// 全ルールが動的扱いで上限 100 本(超過行は黙って落ちる — 実測)のため
// 計 65 本に収める。想定外の失敗モードは「盾だけ落ちて ③ が残る」= /invite の
// リダイレクトループ(可用性の喪失。秘匿には影響せず、開けば即分かる)だが、
// wrangler dev と production は同一のアセットワーカー実装であり選択的欠落の根拠は
// 無い。挙動全体は e2e が固定する。残余は語中タイポ(/invte 等)のみ = 任意の
// 404 パスと同じクラス(SPA 側に fragment を読むコードは無い)
const inviteRedirectRules: string[] = ["/invite /invite 200"];
for (let bits = 1; bits < 1 << "invite".length; bits++) {
  let variant = "";
  for (let i = 0; i < "invite".length; i++) {
    const ch = "invite".charAt(i);
    variant += (bits >> i) & 1 ? ch.toUpperCase() : ch;
  }
  inviteRedirectRules.push(`/${variant}* /invite 301`);
}
inviteRedirectRules.push("/invite* /invite 301");
writeFileSync(join(publicDir, "_redirects"), `${inviteRedirectRules.join("\n")}\n`);

// 固定検査: 書き出した _redirects に正規化ルールが実在し、かつ盾(200 リライト)が
// 総取り(/invite*)より前にあること(先勝ちマッチのループ安全性の順序不変条件)
const writtenRedirects = readFileSync(join(publicDir, "_redirects"), "utf8");
for (const required of ["/invite /invite 200", "/Invite* /invite 301", "/invite* /invite 301"]) {
  if (!writtenRedirects.includes(required)) {
    throw new Error(`_redirects に正規化ルールが無い: ${required}`);
  }
}
if (
  writtenRedirects.indexOf("/invite /invite 200") > writtenRedirects.indexOf("/invite* /invite 301")
) {
  throw new Error("_redirects の順序が壊れている: 200 リライトの盾が /invite* 総取りより後にある");
}

console.log(
  `_headers written (${hashes.length} inline script hash + /invite per-path CSP), ` +
    `_redirects written (${inviteRedirectRules.length} rules), theme.css + pages.css verified`,
);
