import { defineConfig } from 'vite';
import { resolve } from 'path';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig(({ mode }) => ({
  root: 'src',
  // Load .env files (e.g. .env.development) from the extension directory,
  // since `root` is set to 'src'
  envDir: '..',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    sourcemap: mode === 'development',
    minify: mode === 'production' ? 'esbuild' : false,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        'content/gmail': resolve(__dirname, 'src/content/gmail/index.ts'),
        'content/outlook': resolve(__dirname, 'src/content/outlook/index.ts'),
        popup: resolve(__dirname, 'src/popup/popup.html'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: '[name].js',
        assetFileNames: '[name].[ext]',
      },
    },
  },
  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: 'manifest.json',
          dest: '',
          // Allow the local backend host in development builds only.
          // Production builds copy the manifest unchanged.
          transform: mode === 'development'
            ? (content: string) => {
                const manifest = JSON.parse(content);
                if (!manifest.host_permissions.includes('http://127.0.0.1:8080/*')) {
                  manifest.host_permissions.push('http://127.0.0.1:8080/*');
                }
                return JSON.stringify(manifest, null, 2);
              }
            : undefined,
        },
        { src: 'styles/badge.css', dest: '' },
        { src: '../public/*', dest: '' },
      ],
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  test: {
    root: resolve(__dirname),
  },
}));