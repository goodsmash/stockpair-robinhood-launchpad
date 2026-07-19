import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineChain, getAddress, isAddress, zeroAddress } from 'viem'

const moduleDir = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(moduleDir, '../../..')
const ZERO_HASH = `0x${'0'.repeat(64)}`

function intEnv(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(process.env[name] ?? fallback)
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name} must be an integer between ${min} and ${max}`)
  return parsed
}

function boolEnv(name, fallback = false) {
  const value = process.env[name]
  if (value === undefined) return fallback
  if (value === 'true') return true
  if (value === 'false') return false
  throw new Error(`${name} must be true or false`)
}

function safeUrl(value, name, protocols = ['http:', 'https:']) {
  const parsed = new URL(value)
  if (!protocols.includes(parsed.protocol)) throw new Error(`${name} must use ${protocols.join(' or ')}`)
  if (parsed.username || parsed.password) throw new Error(`${name} must not contain embedded credentials`)
  return value.replace(/\/$/, '')
}

function safeOrigin(value, name) {
  const parsed = new URL(value)
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`${name} must use http or https`)
  if (parsed.username || parsed.password) throw new Error(`${name} must not contain embedded credentials`)
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error(`${name} must be an origin without a path, query or fragment`)
  return parsed.origin
}

function isLoopbackOrigin(origin) {
  const host = new URL(origin).hostname.toLowerCase()
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost')
}

function bytes32Env(name, fallback = ZERO_HASH) {
  const value = String(process.env[name] ?? fallback).toLowerCase()
  if (!/^0x[0-9a-f]{64}$/.test(value)) throw new Error(`${name} must be a 32-byte hex value`)
  return value
}

function readJsonFile(filename, fallback) {
  if (!filename) return fallback
  const resolved = path.isAbsolute(filename) ? filename : path.resolve(root, filename)
  if (!fs.existsSync(resolved)) return fallback
  return JSON.parse(fs.readFileSync(resolved, 'utf8'))
}

function parseJsonEnv(name, fallback) {
  const raw = process.env[name]
  return raw ? JSON.parse(raw) : fallback
}

function normalizeScoutChains(primary) {
  const fileRows = readJsonFile(process.env.SCOUT_CHAINS_FILE ?? 'config/scout-chains.example.json', [])
  const envRows = parseJsonEnv('SCOUT_CHAINS_JSON', null)
  const source = Array.isArray(envRows) ? envRows : Array.isArray(fileRows) && fileRows.length ? fileRows : [primary]
  const seen = new Set()
  const rows = []
  for (const item of source) {
    const chainId = Number(item.chainId)
    if (!Number.isSafeInteger(chainId) || chainId <= 0 || seen.has(chainId)) continue
    const rpcUrl = safeUrl(String(item.rpcUrl), `Scout RPC for chain ${chainId}`)
    const explorerUrl = item.explorerUrl ? safeUrl(String(item.explorerUrl), `Scout explorer for chain ${chainId}`) : null
    const wsUrl = item.wsUrl ? safeUrl(String(item.wsUrl), `Scout WebSocket for chain ${chainId}`, ['ws:', 'wss:']) : null
    seen.add(chainId)
    rows.push({
      chainId,
      name: String(item.name ?? `Chain ${chainId}`).slice(0, 80),
      rpcUrl,
      explorerUrl,
      wsUrl,
      nativeCurrencyName: String(item.nativeCurrencyName ?? 'Ether').slice(0, 32),
      nativeCurrencySymbol: String(item.nativeCurrencySymbol ?? 'ETH').slice(0, 12)
    })
  }
  if (!rows.some((item) => item.chainId === primary.chainId)) rows.unshift(primary)
  return rows
}

function isPublicSharedRpc(url) {
  const hostname = new URL(url).hostname.toLowerCase()
  return hostname === 'rpc.mainnet.chain.robinhood.com' || hostname === 'rpc.testnet.chain.robinhood.com'
}

export function loadConfig() {
  const chainId = intEnv('RH_CHAIN_ID', 46630, { min: 1 })
  const network = process.env.RH_CHAIN_NAME ?? (chainId === 4663 ? 'Robinhood Chain' : 'Robinhood Chain Testnet')
  const rpcUrl = safeUrl(process.env.RH_RPC_URL ?? (chainId === 4663
    ? 'https://rpc.mainnet.chain.robinhood.com'
    : 'https://rpc.testnet.chain.robinhood.com'), 'RH_RPC_URL')
  const explorerUrl = safeUrl(process.env.RH_EXPLORER_URL ?? (chainId === 4663
    ? 'https://robinhoodchain.blockscout.com'
    : 'https://explorer.testnet.chain.robinhood.com'), 'RH_EXPLORER_URL')
  const wsUrl = process.env.RH_WS_URL ? safeUrl(process.env.RH_WS_URL, 'RH_WS_URL', ['ws:', 'wss:']) : null
  const rawLaunchpad = process.env.LAUNCHPAD_ADDRESS ?? zeroAddress
  const launchpadAddress = isAddress(rawLaunchpad) ? getAddress(rawLaunchpad) : zeroAddress
  const launchpadCodeHash = bytes32Env('LAUNCHPAD_CODE_HASH')
  const protocolVersion = bytes32Env('LAUNCHPAD_PROTOCOL_VERSION')
  const productionTradingEnabled = boolEnv('PRODUCTION_TRADING_ENABLED', false)
  const localDemoMode = process.env.LOCAL_DEMO_ACK === 'I_UNDERSTAND_THIS_IS_DISPOSABLE'
  const port = intEnv('PORT', 8787, { min: 1, max: 65_535 })
  const host = String(process.env.HOST ?? '127.0.0.1').trim()
  if (!/^(127\.0\.0\.1|0\.0\.0\.0|::1|::)$/.test(host)) throw new Error('HOST must be a loopback or wildcard bind address')
  const rawAllowedOrigins = (process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173')
    .split(',').map((item) => item.trim()).filter(Boolean)
  if (rawAllowedOrigins.includes('*')) throw new Error('ALLOWED_ORIGINS must not contain *')
  const allowedOrigins = [...new Set(rawAllowedOrigins.map((item, index) => safeOrigin(item, `ALLOWED_ORIGINS[${index}]`)))]

  if (localDemoMode) {
    if (chainId !== 31337 || !isLoopbackOrigin(new URL(rpcUrl).origin) || allowedOrigins.some((origin) => !isLoopbackOrigin(origin))) {
      throw new Error('LOCAL_DEMO_ACK is valid only for chain 31337 with loopback RPC and browser origins')
    }
  }
  if (productionTradingEnabled) {
    if (launchpadAddress === zeroAddress) throw new Error('Production trading requires LAUNCHPAD_ADDRESS')
    if (launchpadCodeHash === ZERO_HASH) throw new Error('Production trading requires LAUNCHPAD_CODE_HASH')
    if (protocolVersion === ZERO_HASH) throw new Error('Production trading requires LAUNCHPAD_PROTOCOL_VERSION')
    if (!localDemoMode && isPublicSharedRpc(rpcUrl)) throw new Error('Production trading requires a dedicated authenticated RPC/archive endpoint')
    if (!localDemoMode && allowedOrigins.some((origin) => new URL(origin).protocol !== 'https:' || isLoopbackOrigin(origin))) throw new Error('Production trading requires HTTPS non-loopback ALLOWED_ORIGINS')
  }

  const chain = defineChain({
    id: chainId,
    name: network,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
    blockExplorers: { default: { name: 'Robinhood Explorer', url: explorerUrl } }
  })

  const primaryScoutChain = { chainId, name: network, rpcUrl, explorerUrl, wsUrl }
  const scoutLabelsFile = path.resolve(root, process.env.SCOUT_LABELS_FILE ?? 'config/scout-labels.example.json')
  const trustedProxyIps = new Set((process.env.TRUSTED_PROXY_IPS ?? '127.0.0.1,::1')
    .split(',').map((item) => item.trim()).filter(Boolean))

  return {
    host,
    port,
    chain,
    chainId,
    network,
    rpcUrl,
    explorerUrl,
    launchpadAddress,
    launchpadCodeHash,
    protocolVersion,
    allowedOrigins,
    productionTradingEnabled,
    localDemoMode,
    requireExplorerVerification: boolEnv('REQUIRE_EXPLORER_VERIFICATION', true),
    trustProxy: boolEnv('TRUST_PROXY', false),
    trustedProxyIps,
    maxSseConnections: intEnv('MAX_SSE_CONNECTIONS', 100, { min: 1, max: 10_000 }),
    maxSsePerIp: intEnv('MAX_SSE_PER_IP', 3, { min: 1, max: 100 }),
    eventLookbackBlocks: intEnv('EVENT_LOOKBACK_BLOCKS', 25_000, { min: 100, max: 1_000_000 }),
    requestLimitPerMinute: intEnv('REQUEST_LIMIT_PER_MINUTE', 120, { min: 10, max: 10_000 }),
    scoutEnabled: boolEnv('SCOUT_ENABLED', true),
    scoutPendingEnabled: boolEnv('SCOUT_PENDING_ENABLED', false),
    scoutPollIntervalMs: intEnv('SCOUT_POLL_INTERVAL_MS', 12_000, { min: 2_000, max: 300_000 }),
    scoutInitialLookback: intEnv('SCOUT_INITIAL_LOOKBACK', 25, { min: 1, max: 5_000 }),
    scoutMaxBlocksPerPoll: intEnv('SCOUT_MAX_BLOCKS_PER_POLL', 25, { min: 1, max: 500 }),
    scoutMaxRecords: intEnv('SCOUT_MAX_RECORDS', 5_000, { min: 100, max: 100_000 }),
    scoutLabelsFile,
    scoutDexFactories: parseJsonEnv('SCOUT_DEX_FACTORIES_JSON', []),
    scoutChains: normalizeScoutChains(primaryScoutChain)
  }
}
