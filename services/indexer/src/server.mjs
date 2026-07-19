import http from 'node:http'
import { isIP } from 'node:net'
import { isAddress } from 'viem'
import { loadConfig } from './config.mjs'
import { createIndexer } from './indexer.mjs'
import { createChainScout } from './scout.mjs'

const config = loadConfig()
const indexer = createIndexer(config)
const scout = createChainScout(config)
const buckets = new Map()
const cache = new Map()
const streams = new Set()
const streamsByIp = new Map()
const MAX_CACHE_ENTRIES = 5_000

function securityHeaders(contentType = 'application/json; charset=utf-8') {
  return {
    'content-type': contentType,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'cross-origin',
    'x-stockpair-api-version': '0.6.0',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  }
}

function corsHeaders(req) {
  const origin = req.headers.origin
  if (!origin || !config.allowedOrigins.includes(origin)) return {}
  return { 'access-control-allow-origin': origin, vary: 'Origin', 'access-control-allow-methods': 'GET,OPTIONS', 'access-control-allow-headers': 'content-type,last-event-id' }
}

function send(req, res, status, data, extra = {}) {
  if (status === 204) {
    res.writeHead(status, { ...securityHeaders(), ...corsHeaders(req), ...extra })
    return res.end()
  }
  const body = JSON.stringify(data, (_, value) => typeof value === 'bigint' ? value.toString() : value)
  res.writeHead(status, { ...securityHeaders(), ...corsHeaders(req), 'content-length': Buffer.byteLength(body), ...extra })
  res.end(body)
}

let lastBucketSweep = Date.now()
function normalizeIp(value) {
  return String(value ?? 'unknown').replace(/^::ffff:/, '')
}

function clientIp(req) {
  const remote = normalizeIp(req.socket.remoteAddress)
  if (!config.trustProxy || !config.trustedProxyIps.has(remote)) return remote
  const chain = String(req.headers['x-forwarded-for'] ?? '').split(',').map((item) => normalizeIp(item.trim())).filter((item) => isIP(item))
  if (!chain.length) return remote
  let candidate = remote
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    if (!config.trustedProxyIps.has(candidate)) break
    candidate = chain[index]
  }
  return candidate
}

function originAllowed(req) {
  const origin = req.headers.origin
  return !origin || config.allowedOrigins.includes(origin)
}

function rateLimited(req) {
  const now = Date.now()
  if (now - lastBucketSweep > 60_000) {
    const activeMinute = Math.floor(now / 60_000)
    for (const [key, value] of buckets) if (value.minute < activeMinute - 1) buckets.delete(key)
    lastBucketSweep = now
  }
  const ip = clientIp(req)
  const minute = Math.floor(now / 60_000)
  const current = buckets.get(ip)
  if (!current || current.minute !== minute) {
    buckets.set(ip, { minute, count: 1 })
    return false
  }
  current.count += 1
  return current.count > config.requestLimitPerMinute
}

function pruneCache() {
  const now = Date.now()
  for (const [key, value] of cache) if (value.expires <= now) cache.delete(key)
  while (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value)
}

async function cached(key, ttlMs, loader) {
  const current = cache.get(key)
  if (current && current.expires > Date.now()) return current.value
  const value = await loader()
  if (cache.size >= MAX_CACHE_ENTRIES) pruneCache()
  cache.set(key, { expires: Date.now() + ttlMs, value })
  return value
}

function queryObject(url) {
  return {
    limit: url.searchParams.get('limit') ?? '100',
    chainId: url.searchParams.get('chainId') ?? undefined,
    status: url.searchParams.get('status') ?? undefined,
    q: url.searchParams.get('q') ?? undefined
  }
}

function removeStream(client) {
  if (!client || !streams.delete(client)) return
  const remaining = Math.max(0, (streamsByIp.get(client.ip) ?? 1) - 1)
  if (remaining === 0) streamsByIp.delete(client.ip)
  else streamsByIp.set(client.ip, remaining)
  if (!client.res.writableEnded) client.res.end()
}

function writeStream(client, payload) {
  try {
    if (client.res.writableEnded || !client.res.write(payload)) {
      removeStream(client)
      return false
    }
    return true
  } catch {
    removeStream(client)
    return false
  }
}

function openStream(req, res) {
  if (!originAllowed(req)) return send(req, res, 403, { error: 'Origin not allowed' })
  const ip = clientIp(req)
  const currentForIp = streamsByIp.get(ip) ?? 0
  if (streams.size >= config.maxSseConnections || currentForIp >= config.maxSsePerIp) {
    return send(req, res, 429, { error: 'SSE connection limit exceeded' }, { 'retry-after': '30' })
  }
  res.writeHead(200, {
    ...securityHeaders('text/event-stream; charset=utf-8'),
    ...corsHeaders(req),
    connection: 'keep-alive',
    'cache-control': 'no-cache, no-transform',
    'x-accel-buffering': 'no'
  })
  const client = { res, ip }
  if (!res.write(`event: ready\ndata: ${JSON.stringify(scout.summary())}\n\n`)) return res.end()
  streams.add(client)
  streamsByIp.set(ip, currentForIp + 1)
  const heartbeat = setInterval(() => {
    if (!res.writableEnded) writeStream(client, ': heartbeat\n\n')
  }, 20_000)
  heartbeat.unref?.()
  req.on('close', () => {
    clearInterval(heartbeat)
    removeStream(client)
  })
}

const removeScoutListener = scout.onEvent((event) => {
  const payload = `id: ${event.id}\nevent: scout\ndata: ${JSON.stringify(event)}\n\n`
  for (const client of [...streams]) writeStream(client, payload)
})

const server = http.createServer(async (req, res) => {
  if (!originAllowed(req)) return send(req, res, 403, { error: 'Origin not allowed' })
  if (req.method === 'OPTIONS') return send(req, res, 204, null)
  if (req.method !== 'GET') return send(req, res, 405, { error: 'Method not allowed' }, { allow: 'GET,OPTIONS' })
  if (rateLimited(req)) return send(req, res, 429, { error: 'Rate limit exceeded' })
  if ((req.url?.length ?? 0) > 2_048) return send(req, res, 414, { error: 'Request URI too long' })

  const url = new URL(req.url ?? '/', 'http://localhost')
  try {
    if (url.pathname === '/health') {
      const state = await cached('network', 3_000, () => indexer.network())
      return send(req, res, 200, { ok: true, service: 'stockpair-indexer', version: '0.6.0', scout: scout.summary(), ...state })
    }
    if (url.pathname === '/api/config') {
      const factoryTrust = await cached('factory-trust', 3_000, () => indexer.factoryTrust())
      return send(req, res, 200, {
        chainId: config.chainId,
        network: config.network,
        explorerUrl: config.explorerUrl,
        launchpadAddress: config.launchpadAddress,
        launchpadCodeHash: config.launchpadCodeHash,
        protocolVersion: config.protocolVersion,
        factoryTrust,
        productionTradingEnabled: config.productionTradingEnabled && factoryTrust.trusted,
        requireExplorerVerification: config.requireExplorerVerification,
        scoutEnabled: config.scoutEnabled,
        scoutCoverage: scout.summary().coverage
      })
    }
    if (url.pathname === '/api/stream') return openStream(req, res)
    if (url.pathname === '/api/network') return send(req, res, 200, await cached('network', 3_000, () => indexer.network()))
    if (url.pathname === '/api/launchpad') return send(req, res, 200, await cached('launchpad', 3_000, () => indexer.launchpadState()))
    if (url.pathname === '/api/stocks') return send(req, res, 200, await cached('stocks', 15_000, () => indexer.stocks()))
    if (url.pathname === '/api/launches') {
      const limit = Math.max(1, Math.min(100, Number(url.searchParams.get('limit') ?? 40)))
      return send(req, res, 200, await cached(`launches:${limit}`, 5_000, () => indexer.launches(limit)))
    }
    if (url.pathname === '/api/activity') {
      const blocks = Math.max(100, Math.min(250_000, Number(url.searchParams.get('blocks') ?? config.eventLookbackBlocks)))
      return send(req, res, 200, await cached(`activity:${blocks}`, 5_000, () => indexer.activity(blocks)))
    }
    if (url.pathname.startsWith('/api/scan/')) {
      const token = decodeURIComponent(url.pathname.slice('/api/scan/'.length))
      if (!isAddress(token)) return send(req, res, 400, { error: 'Invalid token address' })
      return send(req, res, 200, await cached(`scan:${token.toLowerCase()}`, 30_000, () => indexer.scanToken(token)))
    }
    if (url.pathname.startsWith('/api/portfolio/')) {
      const wallet = decodeURIComponent(url.pathname.slice('/api/portfolio/'.length))
      if (!isAddress(wallet)) return send(req, res, 400, { error: 'Invalid wallet address' })
      return send(req, res, 200, await cached(`portfolio:${wallet.toLowerCase()}`, 5_000, () => indexer.portfolio(wallet)))
    }

    if (url.pathname === '/api/scout/summary') return send(req, res, 200, scout.summary())
    if (url.pathname === '/api/scout/contracts') return send(req, res, 200, scout.contracts(queryObject(url)))
    if (url.pathname === '/api/scout/tokens') return send(req, res, 200, scout.tokens(queryObject(url)))
    if (url.pathname === '/api/scout/pools') return send(req, res, 200, scout.pools(queryObject(url)))
    if (url.pathname === '/api/scout/swaps') return send(req, res, 200, scout.swaps(queryObject(url)))
    if (url.pathname === '/api/scout/events') return send(req, res, 200, scout.events(queryObject(url)))
    if (url.pathname === '/api/scout/labels') return send(req, res, 200, scout.labels())
    if (url.pathname.startsWith('/api/scout/deployer/')) {
      const parts = url.pathname.split('/').filter(Boolean)
      const chainId = Number(parts[3])
      const address = decodeURIComponent(parts[4] ?? '')
      if (!Number.isSafeInteger(chainId) || !isAddress(address)) return send(req, res, 400, { error: 'Invalid chain or deployer address' })
      const result = scout.deployer(chainId, address)
      return send(req, res, result ? 200 : 404, result ?? { error: 'Deployer not indexed' })
    }
    if (url.pathname.startsWith('/api/scout/code/')) {
      const hash = decodeURIComponent(url.pathname.slice('/api/scout/code/'.length)).toLowerCase()
      if (!/^0x[0-9a-f]{64}$/.test(hash)) return send(req, res, 400, { error: 'Invalid code hash' })
      const result = scout.codeFamily(hash)
      return send(req, res, result ? 200 : 404, result ?? { error: 'Code family not indexed' })
    }

    // v0.7.0 Launch Radar endpoints
    if (url.pathname === '/api/radar/sources') {
      return send(req, res, 200, {
        sources: [
          { id: 'robinhood-testnet-scout', adapter: 'generic-evm-scout', chainId: config.chainId, enabled: true, addresses: {}, trust: { requireRuntimeHash: false, requireProtocolVersion: false, requireExplorerVerification: true } },
        ],
        version: '0.7.0'
      })
    }
    if (url.pathname === '/api/radar/candidates') {
      const contracts = await scout.contracts({ limit: String(Math.max(1, Math.min(50, Number(url.searchParams.get('limit') ?? 20)))) }) || []
      const head = (scout.summary()?.coverage?.[0]?.head) ? Number(scout.summary().coverage[0].head) : 1
      const candidates = (Array.isArray(contracts) ? contracts : (contracts?.contracts || [])).map((c, i) => ({
        id: `scout-${c.address || i}`,
        chainId: config.chainId,
        address: c.address,
        token: c.token || c.address,
        deploymentBlock: c.blockNumber,
        deployer: c.deployer,
        transactionHash: c.transactionHash,
        codeHash: c.codeHash,
        source: 'robinhood-testnet-scout',
        createdAt: c.timestamp ? new Date(c.timestamp * 1000).toISOString() : new Date().toISOString(),
        scores: {
          safety: Math.max(0, 100 - ((c.risk?.score || 0) * 2)),
          liquidity: 0,
          traction: Math.min(80, ((c.evidence?.length || 0)) * 10),
          freshness: c.blockNumber ? Math.max(0, Math.min(100, 100 - ((head - Number(c.blockNumber)) / 1000))) : 50,
          provenance: (c.risk?.status === 'LOW') ? 80 : 40
        },
        riskScore: c.risk?.score || 30,
        status: (c.risk?.status === 'LOW') ? 'verified' : 'unverified',
        verifiedPools: (c.risk?.status === 'LOW') ? 1 : 0,
        swaps: c.evidence?.length || 0,
        executionReview: {
          autoExecutionAllowed: false, userSignatureRequired: true, privateKeyStorageAllowed: false,
          frontRunningAllowed: false, sandwichingAllowed: false, antiBotBypassAllowed: false,
          blockers: (c.risk?.status === 'LOW') ? [] : ['Unverified contract — manual review required'],
          requiredSteps: ['Verify source code', 'Review deployer history', 'Check LP lock']
        }
      }))
      return send(req, res, 200, { candidates, total: candidates.length, version: '0.7.0' })
    }
    if (url.pathname === '/api/radar/alerts') {
      const contracts = await scout.contracts({ limit: '20' }) || []
      const list = Array.isArray(contracts) ? contracts : (contracts?.contracts || [])
      const triggered = list.filter(c => (c.risk?.status !== 'LOW') && (c.evidence?.length > 0)).map(c => ({
        alertId: `unverified-${c.address?.slice(2,10)}`, candidateId: `scout-${c.address}`,
        ruleId: 'manual-review-new-token', timestamp: new Date().toISOString(),
        chainId: config.chainId, address: c.address,
        reason: `Unverified contract ${c.address?.slice(0,10)}... with ${c.evidence?.length || 0} evidence records`
      }))
      return send(req, res, 200, {
        rules: [{ id: 'manual-review-new-token', enabled: true, chainIds: [config.chainId], minScore: 45, maxRiskScore: 40, minVerifiedPools: 0, minSwaps: 0, maxAgeMinutes: 30, requirePublicEvidence: false, actions: ['ui'] }],
        alerts: triggered,
        version: '0.7.0'
      })
    }
    return send(req, res, 404, { error: 'Not found' })
  } catch (error) {
    console.error(error instanceof Error ? error.message : error)
    return send(req, res, 500, { error: 'Internal error' })
  }
})

server.requestTimeout = 20_000
server.headersTimeout = 10_000
server.keepAliveTimeout = 5_000
server.maxRequestsPerSocket = 1_000
server.listen(config.port, config.host, () => {
  scout.start()
  console.log(`StockPair indexer listening on http://${config.host}:${config.port}`)
})

function shutdown() {
  scout.stop()
  removeScoutListener()
  for (const client of [...streams]) removeStream(client)
  streams.clear()
  streamsByIp.clear()
  server.close(() => process.exit(0))
  setTimeout(() => process.exit(1), 5_000).unref()
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
