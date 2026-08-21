import { defineConfig } from "deepsec/config";
import { generatedMatchersPlugin } from "./generated-matchers.js";

export default defineConfig({
  projects: [
    {
      id: "maruhi",
      root: "..",
      githubUrl: "https://github.com/maruhiapp/maruhi/blob/main",
      priorityPaths: [
        "packages/crypto/",
        "packages/api-schema/",
        "apps/server/",
        "apps/cli/",
        "apps/web/scripts/",
      ],
      promptAppend:
        "Plaintext secrets must never appear on the server API, disk, or logs. " +
        "API values are EncryptedPayload only. Membership/audit actors are internal user_id + key fingerprint. " +
        "Do not invent crypto primitives. Hosted web must not ship a decryptor.",
    },
    // <deepsec:projects-insert-above>
  ],
  plugins: [generatedMatchersPlugin],
});
