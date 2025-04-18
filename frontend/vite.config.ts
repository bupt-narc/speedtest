import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [
    vue(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    host: "0.0.0.0",  // 在容器环境中，Vite 应该监听所有网络接口
    port: 5173,
    open: false,
    proxy: {
      '^/backend': {
        target: process.env.VITE_BACKEND_URL || 'http://localhost:8080',  // 读取环境变量
        changeOrigin: true
      }
    }
  }
})

