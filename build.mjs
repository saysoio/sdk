// Builds the publishable package: TypeScript → dist/*.js + dist/*.d.ts, then adds ".js" to the relative imports
// (the sources leave the extension off so bundlers can read them directly; Node needs it in the built files).
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const dist = join(here, 'dist')
rmSync(dist, { recursive: true, force: true })
execFileSync(process.execPath, [createRequire(import.meta.url).resolve('typescript/bin/tsc'), '-p', join(here, 'tsconfig.build.json')], { stdio: 'inherit' })
let rewritten = 0
for (const name of readdirSync(dist)) {
  if (!/\.(js|d\.ts)$/.test(name)) continue
  const file = join(dist, name)
  const out = readFileSync(file, 'utf8').replace(/(\b(?:from|import)\s*\(?\s*['"])(\.\.?\/[^'"]+?)(['"])/g, (m, a, spec, c) => (/\.(js|json)$/.test(spec) ? m : (rewritten++, `${a}${spec}.js${c}`)))
  writeFileSync(file, out)
}
console.log(`built ${readdirSync(dist).length} files into dist/ (${rewritten} relative imports given their .js extension)`)
