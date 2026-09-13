// パスキー PRF 取得のローカルリスナー(CRYPTO_SPEC §8.2 / ADR-0018 決定 2 /
// integration-options.md 補足 20 裁定 A・B)。**CLI 初の TCP リスナー**。
//
// 127.0.0.1 の乱数ポートで `node:http` を聞き(`agent.ts` の `node:net` と同じく
// vitest〔Node〕で実リスナーを検査できる)、CLI 同梱のページ(passkey-page.ts)を配って
// PRF 出力を 1 POST で受け取る。URL は `http://localhost:<port>/<token>/`(rpId =
// `localhost` のため、bind は 127.0.0.1 でもホスト名は localhost)。
//
// 認証(裁定 A — 人間レビュー箇所):
//   - URL パスのワンタイムトークン(32 バイト乱数の base64url)。ページ資産の GET も
//     POST も同じトークンで閉じる(他の localhost ページはこちらの画面を列挙できない)
//   - `Host` 完全一致(`localhost:<port>` — DNS リバインディングは Host が違う)
//   - POST は `Origin` 完全一致(`http://localhost:<port>` — 別ポートの localhost
//     ページは Origin が違う。JSON の POST は preflight になり OPTIONS も 404 で落ちる)
//   - 1 回限りの消費: 最初の正しい POST で結果を確定し、以後は 404
//   - 失敗は理由を出さない一様 404(トークン・Origin・本文の何が違うかを外へ返さない)
//   - 本文は `application/json` かつ 4 KiB まで。形は passkey-page.ts の PrfPagePost
// 有効期間はリスナーの寿命(呼び出し側の `Effect.timeout`)。close は開いている接続を
// 切ってから `server.close`(keep-alive が close を遅らせる — agent.ts と同じ先例)。
//
// 値・鍵素材の扱い: PRF 出力は受け取った Promise の値としてだけ存在し、ログ・エラー・
// ページの DOM に出ない。トークンはリスナーと同寿命。

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";

import {
  PRF_PAGE_CSS,
  PRF_PAGE_ERROR_CODES,
  PRF_PAGE_HTML,
  PRF_PAGE_JS,
  type PrfPageConfig,
  type PrfPagePost,
} from "./passkey-page.ts";

/** ページ資産の CSP(script-src 'self' 基調。inline・eval・第三者を許さない)。 */
export const PRF_PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** POST 本文の上限(PRF hex 64 + credential id hex ≤ 2048 + JSON の器で十分)。 */
const MAX_BODY_BYTES = 4 * 1024;
const TOKEN_BYTES = 32;
const PRF_HEX_PATTERN = /^[0-9a-f]{64}$/;
const CREDENTIAL_ID_HEX_PATTERN = /^(?:[0-9a-f]{2}){1,1024}$/;

/** A running PRF listener (one ceremony; closes itself after the first accepted POST). */
export interface PrfListener {
  /** The URL to open in a browser (`http://localhost:<port>/<token>/`). */
  readonly url: string;
  readonly port: number;
  /** Resolves with the page's single POST. Never rejects; close() before it resolves leaves it pending. */
  readonly outcome: Promise<PrfPagePost>;
  /** Stops listening and destroys open connections (idempotent). */
  readonly close: () => Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parses the page's POST body; null when malformed (the request is then answered 404). */
export function parsePrfPost(text: string): PrfPagePost | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(value)) {
    return null;
  }
  const error = value["error"];
  if (typeof error === "string") {
    const code = PRF_PAGE_ERROR_CODES.find((known) => known === error);
    return code === undefined || Object.keys(value).length !== 1 ? null : { error: code };
  }
  const credentialIdHex = value["credentialIdHex"];
  const prfHex = value["prfHex"];
  if (
    typeof credentialIdHex !== "string" ||
    typeof prfHex !== "string" ||
    !CREDENTIAL_ID_HEX_PATTERN.test(credentialIdHex) ||
    !PRF_HEX_PATTERN.test(prfHex) ||
    Object.keys(value).length !== 2
  ) {
    return null;
  }
  return { credentialIdHex, prfHex };
}

function newToken(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES))).toString("base64url");
}

/** 全応答に共通のヘッダ(キャッシュ・スニッフ・Referer を閉じる)。 */
const COMMON_HEADERS: Readonly<Record<string, string>> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  connection: "close",
};

function reply(
  response: ServerResponse,
  status: number,
  body: string,
  headers: Readonly<Record<string, string>> = {},
): void {
  response.writeHead(status, { ...COMMON_HEADERS, "content-type": "text/plain", ...headers });
  response.end(body);
}

/** 理由を出さない一様 404。 */
function notFound(response: ServerResponse): void {
  reply(response, 404, "not found");
}

/** 静的資産(トークン配下の GET)。 */
function serveAsset(name: string, config: PrfPageConfig, response: ServerResponse): void {
  switch (name) {
    case "":
      reply(response, 200, PRF_PAGE_HTML, {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": PRF_PAGE_CSP,
      });
      return;
    case "app.js":
      reply(response, 200, PRF_PAGE_JS, { "content-type": "text/javascript; charset=utf-8" });
      return;
    case "style.css":
      reply(response, 200, PRF_PAGE_CSS, { "content-type": "text/css; charset=utf-8" });
      return;
    case "config.json":
      reply(response, 200, JSON.stringify(config), {
        "content-type": "application/json; charset=utf-8",
      });
      return;
    default:
      notFound(response);
  }
}

/** 本文を上限つきで読む(超過は接続を切る)。 */
function readBody(request: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        request.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", () => {
      resolve(null);
    });
  });
}

/**
 * Starts the PRF listener on 127.0.0.1 with a fresh one-time token and serves
 * the passkey page for `config`. The returned `outcome` resolves with the first
 * accepted POST, after which every further request is answered 404.
 */
export function startPrfListener(config: PrfPageConfig): Promise<PrfListener> {
  const token = newToken();
  const connections = new Set<Socket>();
  let settled = false;
  // Promise の外から確定させる(executor は同期に走るので代入は必ず済む)
  let resolveOutcome!: (post: PrfPagePost) => void;
  const outcome = new Promise<PrfPagePost>((resolve) => {
    resolveOutcome = resolve;
  });
  let expectedHost = "";

  const handlePost = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (settled || request.headers.origin !== `http://${expectedHost}`) {
      notFound(response);
      return;
    }
    const contentType = request.headers["content-type"] ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      notFound(response);
      return;
    }
    const text = await readBody(request);
    const post = text === null ? null : parsePrfPost(text);
    // 読み終わるまでに別の POST が確定していたら、こちらは捨てる(1 回限り)
    if (post === null || settled) {
      notFound(response);
      return;
    }
    settled = true;
    reply(response, 204, "");
    resolveOutcome(post);
  };

  const server: Server = createServer({ keepAlive: false }, (request, response) => {
    if (request.headers.host !== expectedHost) {
      notFound(response);
      return;
    }
    const path = (request.url ?? "/").split("?")[0] ?? "/";
    const segments = path.split("/").filter((segment) => segment.length > 0);
    if (segments[0] !== token) {
      notFound(response);
      return;
    }
    const rest = segments.slice(1).join("/");
    if (request.method === "GET") {
      serveAsset(rest, config, response);
      return;
    }
    if (request.method === "POST" && rest === "prf") {
      void handlePost(request, response);
      return;
    }
    notFound(response);
  });
  server.on("connection", (socket) => {
    connections.add(socket);
    socket.once("close", () => {
      connections.delete(socket);
    });
  });

  let closing: Promise<void> | null = null;
  const close = (): Promise<void> => {
    closing ??= new Promise<void>((done) => {
      server.close(() => {
        done();
      });
      for (const socket of connections) {
        socket.destroy();
      }
    });
    return closing;
  };

  return new Promise<PrfListener>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error("listener has no TCP address"));
        return;
      }
      expectedHost = `localhost:${address.port}`;
      resolve({
        url: `http://${expectedHost}/${token}/`,
        port: address.port,
        outcome,
        close,
      });
    });
  });
}
