import { defineConfig } from 'tsdown'

const PLUGIN_ID = 'dsh-auto-review-approval'

/**
 * Packages the Host process supplies at runtime. They must stay external so
 * the plugin shares the Host's single instance of each service, and the
 * profile resolver is the only thing that has to locate them.
 */
const HOST_PACKAGES = [
  /^@deepseek-ai\/cordis(?:\/|$)/,
  /^@deepseek-ai\/dsh-/,
]

/**
 * The plugin's own libraries are bundled into `lib/index.js`. A profile
 * installs this package with a `link:`/directory dependency, and pnpm does not
 * install the dependencies of a linked package. Keeping these imports in the
 * emitted file made activation depend on a local `node_modules` directory that
 * may be missing or stale, which surfaced as
 *
 *   failed to import: Cannot find package '...@deepseek-ai/schemastery...'
 *
 * Bundling them makes the emitted Host code self-contained: the only remaining
 * runtime imports are Node builtins and Host packages.
 */
const BUNDLED_PACKAGES = [
  '@deepseek-ai/schemastery',
  '@standard-schema/spec',
  'cosmokit',
  'zod',
]

export default defineConfig([
  {
    name: PLUGIN_ID,
    entry: ['src/index.ts'],
    outDir: 'lib',
    format: ['esm'],
    platform: 'node',
    target: 'es2024',
    fixedExtension: false,
    dts: true,
    clean: true,
    sourcemap: true,
    deps: {
      neverBundle: HOST_PACKAGES,
      alwaysBundle: BUNDLED_PACKAGES,
      /* Bundling packages that also appear in `dependencies` is intended here. */
      onlyBundle: false,
      /* Keep the type-only imports in `lib/index.d.ts` readable instead of
       * inlining zod's CommonJS locale declarations. */
      dts: { neverBundle: ['zod'] },
    },
  },
  {
    name: `${PLUGIN_ID}/client`,
    entry: { client: 'src/client/index.ts' },
    outDir: 'lib',
    format: ['cjs'],
    platform: 'browser',
    target: 'es2023',
    dts: false,
    clean: false,
    sourcemap: true,
    deps: {
      neverBundle: ['react', 'react/jsx-runtime'],
    },
    outputOptions: {
      entryFileNames: 'client.js',
      banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify(PLUGIN_ID)}, factory: (require) => {`,
      footer: 'return module.exports; } });',
      intro: 'var module = { exports: {} }; var exports = module.exports;',
    },
  },
])
