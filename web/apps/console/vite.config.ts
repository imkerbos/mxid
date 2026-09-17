import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// console SPA serves at /admin/ in both dev and prod. nginx sits in front,
// routes /admin/* here and forwards /api /protocol to the backend.
// HMR client tells the browser to dial back through nginx (port 3500),
// otherwise it would try to reach the vite-internal port 5173 and fail.
// The browser reaches vite through a front door whose port the container
// cannot discover. MXID_DEV_HMR_PORT says which:
//   unset  → nginx on 3500, the compose stack's front door (unchanged default)
//   ""     → follow the page's own port (a proxy serving both http and https)
//   "N"    → a fixed port
// "Follow the page" exists because a fixed port is right for only one scheme:
// behind a proxy serving http on 80 and https on 443, a client pinned to :80 on
// an https page attempts TLS against plaintext (net::ERR_SSL_PROTOCOL_ERROR) —
// HMR dies silently while the page itself loads fine, and browsers upgrade to
// https on their own. Leaving clientPort unset makes vite's client fall back to
// location.port, which is right for both schemes and has no port to keep in
// sync with the proxy.
const hmrClientPortEnv = process.env.MXID_DEV_HMR_PORT
const hmrClientPort =
  hmrClientPortEnv === undefined ? 3500 : hmrClientPortEnv === '' ? undefined : Number(hmrClientPortEnv)

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
      clientPort: hmrClientPort,
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
