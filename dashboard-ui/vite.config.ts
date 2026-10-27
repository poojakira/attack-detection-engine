import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the backend via /api and /health; in dev these are
// proxied to the FastAPI service. In production (Docker Compose) the frontend
// is served statically and the same paths are reverse-proxied to the backend.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
      "/readiness": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
  build: { outDir: "dist" },
});
