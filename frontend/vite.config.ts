import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  // Same-origin API in development: the Flask backend (python app.py) listens on :5000.
  server: {
    proxy: {
      '/api': { target: process.env.VITE_BACKEND_URL ?? 'http://127.0.0.1:5000', changeOrigin: true },
    },
  },
})
