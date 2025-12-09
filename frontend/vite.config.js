import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    headers: {
      // Required for WASM SharedArrayBuffer support
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp'
    },
    port: 3000
  },
  build: {
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: {
          'wasm-core': ['./src/wasm/wasm_core.js']
        }
      }
    }
  },
  assetsInclude: ['**/*.wasm'],
  optimizeDeps: {
    exclude: ['./src/wasm/wasm_core.js']
  }
});
