// Browser smoke test against a running stack (make up). Not part of `npm test`.
//   PX_UI_URL=http://localhost:5173 npx playwright test
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 20 * 60 * 1000,
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  expect: { timeout: 30_000 },
  outputDir: "./test-results",
  use: {
    baseURL: process.env.PX_UI_URL || "http://localhost:5173",
    browserName: "chromium",
    headless: true,
    trace: "retain-on-failure",
    actionTimeout: 30_000,
  },
});
