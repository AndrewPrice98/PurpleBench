import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard calls /api/*; in development Vite forwards that to FastAPI.
// PURPLEBENCH_API_URL points the proxy at another port when 8000 is taken.
const target = process.env.PURPLEBENCH_API_URL || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': target },
  },
  preview: {
    proxy: { '/api': target },
  },
})
