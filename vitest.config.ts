import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ACCESS_TEAM_DOMAIN: "test.cloudflareaccess.com",
          ACCESS_AUD: "test-aud",
          // On in tests so we can prove it only applies to localhost.
          DEV_BYPASS_ACCESS: "true",
        },
      },
    }),
  ],
});
