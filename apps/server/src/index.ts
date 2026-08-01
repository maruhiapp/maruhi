// @maruhi/server — Workers + DO + D1。Effect HttpApi(実装は Phase 1 で)。
// サーバーコードは Web 標準 + Workers API のみ。Bun 固有 API(bun:*)は使用禁止。
export default {
  fetch(): Response {
    return new Response("maruhi", { status: 200 });
  },
} satisfies ExportedHandler;
