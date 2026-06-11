import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

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
      clientPort: 3500,
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
