import { build } from 'esbuild';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';

// Only the checked-in application entrypoint is bundled; no input globbing,
// dev server, plugin execution, or user-upload processing is part of this path.
await rm('dist', { recursive: true, force: true });
await mkdir('dist/assets', { recursive: true });
await build({entryPoints: ['src/main.tsx'], bundle: true, outfile: 'dist/assets/app.js',
  minify: true, sourcemap: true, target: ['es2020'], format: 'esm',
  define: {'process.env.NODE_ENV': '"production"'}, jsx: 'automatic'});
const html = await readFile('index.html', 'utf8');
await writeFile('dist/index.html', html.replace('<script type="module" src="/src/main.tsx"></script>',
  '<link rel="stylesheet" href="/assets/app.css" /><script type="module" src="/assets/app.js"></script>'));
