import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies to the HUB (3100), never to an agent — the browser
// has no direct relationship with a monitored server in this architecture.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:3100',
        changeOrigin: true,
      },
    },
  },
})
