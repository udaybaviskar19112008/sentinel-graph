import { fileURLToPath, URL } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The FastAPI backend (`uvicorn app.main:app`) listens here in development.
const BACKEND = '127.0.0.1:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    // The lazily loaded CyberCanvas chunk is three.js (~900 kB) and cannot shrink below
    // Vite's 500 kB default; it loads after the dashboard is already interactive.
    chunkSizeWarningLimit: 1000,
  },
  server: {
    // Cloudflare quick tunnels (`cloudflared tunnel --url http://localhost:5173`) arrive with this Host.
    allowedHosts: ['.trycloudflare.com'],
    proxy: {
      '/api': { target: `http://${BACKEND}`, changeOrigin: true },
      // Analysis stream: /ws/api/v1/stream-analysis
      '/ws': { target: `ws://${BACKEND}`, ws: true },
    },
  },
})
