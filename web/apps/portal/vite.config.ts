import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

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
  base: '/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5174,
    host: '0.0.0.0',
    strictPort: true,
    allowedHosts: true as const,
    watch: {
      usePolling: true,
      interval: 300,
    },
    // HMR client connects through nginx :3500. Default vite HMR would try
    // to dial back through the internal vite port and fail behind nginx.
    hmr: {
      clientPort: hmrClientPort,
      path: '/',
    },
    proxy: {
      '/api': {
        target: 'http://mxid:10050',
        changeOrigin: true,
        // xfwd: true makes http-proxy append the original client IP to
        // X-Forwarded-For. The backend trusts this header for the dev
        // private subnets (see internal/bootstrap/router.go), so the
        // /security/sessions list shows the real browser IP instead of
        // the vite container's docker subnet IP.
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
