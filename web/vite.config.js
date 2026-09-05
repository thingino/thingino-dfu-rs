import { defineConfig } from 'vite'
import { execSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { refuseStubEngine } from './build/stub-guard.mjs'

// Short commit sha, shown in the footer when the engine did not load (the engine
// reports its own version and commit when it did). 'dev' where there is no git.
let gitSha = 'dev'
try {
  gitSha = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim()
} catch { /* no git available - keep 'dev' */ }

// GitHub Pages project sites serve from a subpath
// (https://<user>.github.io/<repo>/), so allow the base href to be set at
// build time via PAGES_BASE. Defaults to '/' for root hosting / local dev.
//
// There is no cache-busting plugin any more. It existed for /wasm/tdfu.js and
// tdfu.wasm, which were fixed names outside the bundle - a stale cached copy of
// the glue demonstrably survived a redeploy in the field. The engine is now an
// ES module imported by src/tdfu.js, so vite content-hashes it into /assets/
// like everything else and a changed build is a changed URL.
export default defineConfig({
  base: process.env.PAGES_BASE || '/',
  // The one build-time check that is not the xtask's: `npm run build` on its own
  // will happily bundle the seam stub into a page that looks shippable and has
  // no engine.
  plugins: [refuseStubEngine(fileURLToPath(new URL('./src/wasm/tdfu_wasm.js', import.meta.url)))],
  define: {
    __GIT_SHA__: JSON.stringify(gitSha),
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
