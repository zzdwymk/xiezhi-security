import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

export default defineConfig({
  // Electron loads the production renderer through file://, so bundled assets
  // must be relative to dist/index.html instead of rooted at /assets.
  base: './',
  plugins: [
    vue(),
    Components({
      dts: false,
      resolvers: [ElementPlusResolver({ importStyle: 'css' })],
    }),
  ],
  server: {
    port: 5173,
    watch: {
      // Desktop packaging creates a large, briefly locked ZIP below this tree.
      // Watching it can terminate Vite with EBUSY while the browser app is running.
      ignored: ['**/desktop-release/**'],
    },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
