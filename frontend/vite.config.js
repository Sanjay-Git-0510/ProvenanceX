import { configDefaults, defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// API_PROXY_TARGET lets docker-compose point the dev proxy at the api service.
const apiTarget = process.env.API_PROXY_TARGET || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: { "/api": { target: apiTarget, changeOrigin: true } },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.js"],
    // Playwright browser tests run separately: npm run e2e (needs a running stack).
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
