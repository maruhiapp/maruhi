import { defineWranglerConfig } from "wrangler/experimental-config";

export default defineWranglerConfig((ctx) => {
  switch (ctx.mode) {
    case "restore": {
      return {};
    }
    default: {
      return {
        assetsDirectory: "../web/dist/public",
      };
    }
  }
});
