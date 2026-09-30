import { defineWranglerConfig } from "wrangler/experimental-config";

// Bundler shim evaluated by the local wrangler build that `cf deploy` /
// `cf dev` delegate to. The asset directory lives here (cloudflare.config.ts
// has no assets.directory field); mode handling must mirror that file.
export default defineWranglerConfig((ctx) => {
  switch (ctx.mode) {
    case "restore": {
      // The ops-only restore worker has no static assets.
      return {};
    }
    default: {
      return {
        assetsDirectory: "../web/dist/public",
      };
    }
  }
});
