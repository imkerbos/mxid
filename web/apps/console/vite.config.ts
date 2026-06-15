import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// console SPA serves at /admin/ in both dev and prod. nginx sits in front,
// routes /admin/* here and forwards /api /protocol to the backend.
// HMR client tells the browser to dial back through nginx (port 3500),
// otherwise it would try to reach the vite-internal port 5173 and fail.
export default defineConfig(() => ({
  base: '/admin/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    host: '0.0.0.0',
    strictPort: true,
    // Vite 5+ rejects unknown Host headers as a DNS-rebinding precaution.
    // When fronted by nginx the inbound Host is whatever the user typed,
    // so allow everything in dev.
    allowedHosts: true as const,
    watch: {
      usePolling: true,
      interval: 300,
    },
    // Bind HMR ws to the nginx-exposed port so the browser can find it
    // when the SPA is served behind /admin/.
    hmr: {
      clientPort: 3500,
      path: '/admin/',
    },
    // /api and /protocol proxies kept for standalone `pnpm dev` (no
    // docker / nginx). When running inside the dev stack nginx handles
    // these and this proxy is a no-op.
    proxy: {
      '/api': {
        target: 'http://mxid:10050',
        changeOrigin: true,
        xfwd: true,
      },
      '/protocol': {
        target: 'http://mxid:10050',
        changeOrigin: true,
        xfwd: true,
      },
    },
  },
}))
