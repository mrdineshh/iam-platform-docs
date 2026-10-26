import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Pure static SPA build -- no server of its own (BUILD_PLAN.md's tech
// choice for this service). See docs/specs/iam-admin-console-SPEC.md
// Section 0 for what that tradeoff costs (session token in sessionStorage,
// no server-side real-IP capture).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
  },
});
