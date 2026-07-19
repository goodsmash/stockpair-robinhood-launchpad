import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import crypto from 'node:crypto'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const required = [
  'README.md', 'AGENTS.md', 'SECURITY.md', 'CHANGELOG.md', 'vercel.json', '.vercelignore', '.nvmrc',
  '.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/dependabot.yml',
  'docs/AGENT_HANDOFF.md', 'docs/LOCAL_DEVELOPMENT.md', 'docs/VERCEL_DEPLOYMENT.md',
  'docs/GITHUB_HANDOFF.md', 'docs/ENVIRONMENT_REFERENCE.md', 'docs/USER_ACCEPTANCE_TESTS.md',
  'apps/web/public/manifest.webmanifest', 'apps/web/scripts/validate-env.mjs', 'scripts/validate-artifacts.mjs',
  'artifacts/solc/_build-info.json', 'docs/RELEASE_NOTES_v0.6.0.md', 'docs/V0.6.0_SECURITY_REVIEW.md', 'docs/UI_SECURITY_MODEL.md',
  'deploy/indexer/Dockerfile', 'deploy/indexer/README.md'
]
const errors = []
for (const file of required) if (!fs.existsSync(path.join(root, file))) errors.push(`Missing ${file}`)
for (const file of ['package.json', 'apps/web/package.json']) {
  const json = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'))
  if (json.version !== '0.6.0') errors.push(`${file} version must be 0.6.0`)
}
const vercel = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'))
if (vercel.outputDirectory !== 'apps/web/dist') errors.push('vercel.json outputDirectory must be apps/web/dist')
const main = fs.readFileSync(path.join(root, 'apps/web/src/main.ts'), 'utf8')
if (!main.includes("VITE_ENABLE_OPERATIONS ?? 'false'")) errors.push('Public operations default is missing')
if (!main.includes('authorizeWrite')) errors.push('Browser write authorization gate is missing')
if (!main.includes('reviewTransaction')) errors.push('Decoded transaction review is missing')
if (!main.includes('normalizeLaunch')) errors.push('Runtime API normalization is missing')
if (!main.includes('expectedPoolProtocolVersion')) errors.push('Pool protocol provenance verification is missing')
if (!main.includes('allowance === amount')) errors.push('Exact allowance equality check is missing')
const security = fs.readFileSync(path.join(root, 'apps/web/src/lib/security.ts'), 'utf8')
if (!security.includes('safeExplorerUrl')) errors.push('Safe explorer URL validation is missing')
const forbiddenNames = ['.env.local', 'deployments/local.json']
for (const name of forbiddenNames) if (fs.existsSync(path.join(root, name))) errors.push(`Release tree contains local state: ${name}`)
const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\b(?:sk_live|ghp_|github_pat_|AKIA)[A-Za-z0-9_=-]{12,}/,
  /\b(?:PRIVATE_KEY|DEPLOYER_PRIVATE_KEY|SECRET_KEY)\s*=\s*0x[0-9a-fA-F]{64}\b/,
  /\b(?:MNEMONIC|SEED_PHRASE)\s*=\s*["']?(?:[a-z]{3,}\s+){11,23}[a-z]{3,}/i
]
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', 'dist', 'artifacts', 'qa'].includes(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (entry.isFile() && fs.statSync(full).size < 2_000_000) {
      const text = fs.readFileSync(full, 'utf8')
      if (secretPatterns.some((pattern) => pattern.test(text))) errors.push(`Potential secret pattern in ${path.relative(root, full)}`)
    }
  }
}
walk(root)
if (errors.length) {
  console.error('Release check failed:')
  for (const error of [...new Set(errors)]) console.error(`- ${error}`)
  process.exit(1)
}
const digest = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'package-lock.json'))).digest('hex')
console.log(JSON.stringify({ ok: true, version: '0.6.0', requiredFiles: required.length, packageLockSha256: digest, checkedAt: new Date().toISOString() }, null, 2))
