import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
import fs from 'node:fs'
import path from 'node:path'

// Records build date/time (and package version) into dist/build-info.json so every
// packaged build can be traced to when it was produced.
function buildTimestamp() {
  const fmt = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
  return fmt.format(new Date())
}

// Writes dist/build-info.json at the end of each production build with the build
// date/time, so packaged artifacts carry an auditable build timestamp.
function buildInfoWritePlugin() {
  let outDir = 'dist'
  let buildMode = 'web'
  return {
    name: 'build-info-write',
    configResolved(config) {
      outDir = config.build.outDir
      buildMode = config.mode || 'web'
    },
    writeBundle() {
      const info = {
        app: 'security-toolbox-desktop',
        version: '0.2.0',
        buildDate: buildTimestamp(),
        mode: buildMode,
      }
      fs.mkdirSync(outDir, { recursive: true })
      fs.writeFileSync(
        path.join(outDir, 'build-info.json'),
        JSON.stringify(info, null, 2),
        'utf-8',
      )
    },
  }
}

export default defineConfig(({ mode }) => ({
  base: mode === 'desktop' ? './' : '/',
  plugins: [
    vue(),
    Components({
      dts: false,
      resolvers: [ElementPlusResolver({ importStyle: 'css' })],
    }),
    buildInfoWritePlugin(),
  ],
  server: {
    port: 5173,
    watch: {
      ignored: ['**/desktop-release/**'],
    },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
}))
