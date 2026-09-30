import { defineConfig } from "cf/config";

export default defineConfig({
  worker: {
    name: "maruhi-site",
    compatibilityDate: "2026-07-01",
    workersDev: false,
    previewUrls: false,
    assets: {
      htmlHandling: "drop-trailing-slash",
      notFoundHandling: "404-page",
    },
    domains: ["maruhi.app"],
  },
});
