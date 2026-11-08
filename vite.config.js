import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The React app lives in client/ and builds into dist/, which the
// Cloudflare Worker serves as static assets (see wrangler.toml).
export default defineConfig({
  root: "client",
  envDir: "..", // load .env.production from the repo root
  plugins: [react()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
  },
  test: {
    root: ".",
    include: ["tests/**/*.test.mjs"],
  },
});
