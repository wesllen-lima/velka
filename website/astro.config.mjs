// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://wesllen-lima.github.io',
  base: '/velka',
  outDir: '../docs',
  vite: {
    plugins: [tailwindcss()],
  },
});
