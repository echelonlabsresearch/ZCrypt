import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed dev port. For `tauri ios dev` on a simulator or a phone the CLI
// sets TAURI_DEV_HOST so the device can reach the dev server over the LAN.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    host: host || false,
    port: 1420,
    strictPort: true,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
  },
  build: {
    target: "esnext",
    outDir: "dist",
  },
});
