import {defineConfig} from 'vite';

export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    watch: {
      // Rust build artifacts change constantly and Windows can hold locks on
      // them. Watching src-tauri makes the dev server crash with EBUSY.
      ignored: ['**/src-tauri/**', '**/dist/**']
    }
  },
  clearScreen: false,
  build: {
    // ECharts and Cytoscape are bundled locally so the forensic workbench
    // never fetches a charting or graph library at runtime. The desktop
    // installer carries these vendor chunks; the size warning is raised
    // accordingly instead of hiding a real network dependency.
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/echarts') || id.includes('node_modules/zrender')) return 'echarts';
          if (id.includes('node_modules/cytoscape')) return 'cytoscape';
          return undefined;
        }
      }
    }
  }
});
