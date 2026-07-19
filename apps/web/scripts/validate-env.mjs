import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadEnv } from 'vite'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const mode = process.env.VERCEL_ENV === 'production' || process.argv.includes('--production') ? 'production' : 'development'
const env = { ...loadEnv(mode, root, ''), ...process.env }
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`
const ZERO_HASH = `0x${'0'.repeat(64)}`
const errors = []
const warnings = []

function requireValue(name) {
  const value = String(env[name] ?? '').trim()
  if (!value) errors.push(`${name} is required`)
  return value
}
function checkUrl(name, { allowBlank = false, originOnly = false } = {}) {
  const value = String(env[name] ?? '').trim()
  if (!value && allowBlank) return ''
  if (!value) { errors.push(`${name} is required`); return '' }
  try {
    const url = new URL(value)
    if (mode === 'production' && url.protocol !== 'https:') errors.push(`${name} must use https in production`)
    if (url.username || url.password) errors.push(`${name} must not contain embedded credentials`)
    if (mode === 'production' && /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(url.hostname)) errors.push(`${name} must not target localhost in production`)
    if (originOnly && (url.pathname !== '/' || url.search || url.hash)) errors.push(`${name} must be an origin only, without path, query or fragment`)
    return url.origin
  } catch { errors.push(`${name} must be a valid URL`); return '' }
}
function checkAddress(name) {
  const value = requireValue(name)
  if (value && !/^0x[0-9a-fA-F]{40}$/.test(value)) errors.push(`${name} must be a 20-byte EVM address`)
  if (mode === 'production' && value.toLowerCase() === ZERO_ADDRESS) errors.push(`${name} must not be the zero address in production`)
}
function checkHash(name) {
  const value = requireValue(name)
  if (value && !/^0x[0-9a-fA-F]{64}$/.test(value)) errors.push(`${name} must be a 32-byte hex value`)
  if (mode === 'production' && value.toLowerCase() === ZERO_HASH) errors.push(`${name} must not be zero in production`)
}

const chainId = Number(env.VITE_CHAIN_ID)
if (!Number.isSafeInteger(chainId) || chainId <= 0) errors.push('VITE_CHAIN_ID must be a positive integer')
requireValue('VITE_CHAIN_NAME')
checkUrl('VITE_RPC_URL')
checkUrl('VITE_EXPLORER_URL', { originOnly: true })
checkUrl('VITE_INDEXER_URL', { allowBlank: mode !== 'production', originOnly: true })
checkAddress('VITE_LAUNCHPAD_ADDRESS')
checkHash('VITE_LAUNCHPAD_CODE_HASH')
checkHash('VITE_LAUNCHPAD_PROTOCOL_VERSION')
if (String(env.VITE_ENABLE_OPERATIONS ?? 'false') !== 'false') errors.push('VITE_ENABLE_OPERATIONS must be false for the public Vercel build')
if (mode === 'production' && String(env.VITE_DEPLOYMENT_ACK ?? '') !== 'I_HAVE_VERIFIED_THE_FACTORY') errors.push('VITE_DEPLOYMENT_ACK must equal I_HAVE_VERIFIED_THE_FACTORY for production builds')

if (errors.length) {
  console.error('StockPair environment validation failed:')
  for (const error of errors) console.error(`- ${error}`)
  process.exit(1)
}
for (const warning of warnings) console.warn(`Warning: ${warning}`)
console.log(JSON.stringify({ ok: true, mode, chainId, rpcOrigin: new URL(env.VITE_RPC_URL).origin, indexerOrigin: env.VITE_INDEXER_URL ? new URL(env.VITE_INDEXER_URL).origin : 'same-origin', operationsEnabled: false }, null, 2))
