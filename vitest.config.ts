import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => ({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: { bindings: { SIGHTING_KEY: "test-sighting-key", TEST_MIGRATIONS: await readD1Migrations("./migrations") } },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
}));
