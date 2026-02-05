/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 */

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: false, // <--- THÊM DÒNG NÀY: Ngăn Vite xóa thư mục dist
  },
})
