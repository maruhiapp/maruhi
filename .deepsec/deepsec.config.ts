import { defineConfig } from "deepsec/config";
import { generatedMatchersPlugin } from "./generated-matchers.js";

export default defineConfig({
  defaultThinkingLevel: "medium", // <deepsec:default-thinking-level>
  defaultModel: "claude-opus-5", // <deepsec:default-model>
  defaultAgent: "claude-agent-sdk", // <deepsec:default-agent>
  ai: {"mode":"local","provider":"local"}, // <deepsec:model-route>
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
