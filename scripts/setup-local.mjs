import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const major = Number(process.versions.node.split('.')[0])
if (major !== 22) {
  console.error(`StockPair requires Node.js 22.x. Current: ${process.version}`)
  process.exit(1)
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const root = fileURLToPath(new URL('../', import.meta.url))
const web = fileURLToPath(new URL('../apps/web/', import.meta.url))

function run(command, args, cwd = root) {
  console.log(`> ${command} ${args.join(' ')}`)
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', env: process.env, shell: false })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status ?? result.signal ?? 'unknown status'}`)
}

try {
  run(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'])
  run(npm, ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], web)
  run(process.execPath, ['scripts/validate-artifacts.mjs'])
  run(process.execPath, ['--test', 'scripts/ui-contract.test.mjs'], web)
  console.log('\nSetup complete.')
  console.log('Run `npm run local` and open http://127.0.0.1:5173')
  console.log('Use `npm run local:fresh` only after intentionally changing Solidity sources.')
} catch (error) {
  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
}
