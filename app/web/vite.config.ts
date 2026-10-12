/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
    },
  },
  build: {
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks: (id: string) => {
          if (/node_modules\/(echarts|zrender)\//.test(id)) return 'echarts'
          if (/node_modules\/(@codemirror|@lezer|crelt|style-mod|w3c-keyname)\//.test(id)) return 'codemirror'
          if (/node_modules\/(react|react-dom|scheduler|react-router|react-router-dom|@tanstack)\//.test(id)) return 'vendor'
          return undefined
        },
      },
    },
  },
  test: { environment: 'jsdom', include: ['src/**/*.test.ts', 'src/**/*.test.tsx'] },
})
