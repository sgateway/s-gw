import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: "src/console-ui",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src/console-ui/src")
    }
  },
  build: {
    outDir: "../../dist/console-ui",
    emptyOutDir: true
  },
  server: {
    host: "127.0.0.1",
    port: 8720
  }
});
