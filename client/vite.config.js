import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite settings: React support, and send /api calls to the Express server during development
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Stop with an error if 5173 is busy, instead of quietly moving to 5174.
    // 5174 isn't in ALLOWED_ORIGINS, so Clerk's token would be refused ("Please sign in").
    strictPort: true,
    proxy: {
      '/api': 'http://localhost:3000',
      '/healthz': 'http://localhost:3000',
    },
  },
});
