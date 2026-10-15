/// <reference types="vitest/config" />
import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), 'VITE_'), ...process.env }
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, './src'),
      },
    },
    // Same-origin API in development: the Flask backend (python app.py) listens on :5000.
    // The proxy also carries the SSE stream (/api/v1/stream/live) and the session cookie.
    server: {
      proxy: {
        '/api': { target: env.VITE_BACKEND_URL ?? 'http://127.0.0.1:5000', changeOrigin: true },
      },
    },
    test: {
      environment: 'jsdom',
      include: ['src/**/*.test.{ts,tsx}'],
      restoreMocks: true,
      setupFiles: ['src/test/setup.ts'],
    },
  }
})
