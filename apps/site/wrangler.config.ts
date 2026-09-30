import { defineWranglerConfig } from "wrangler/experimental-config";

// Bundler shim evaluated by the local wrangler build that `cf deploy` /
// `cf dev` delegate to. The asset directory lives here (cloudflare.config.ts
// has no assets.directory field).
export default defineWranglerConfig({
  assetsDirectory: "./dist",
});
