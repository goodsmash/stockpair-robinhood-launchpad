import fs from 'node:fs'
import path from 'node:path'
import { EventEmitter } from 'node:events'
import {
  createPublicClient,
  decodeEventLog,
  defineChain,
  getAddress,
  http,
  isAddress,
  keccak256,
  parseAbi,
  parseAbiItem,
  zeroAddress
} from 'viem'
import { analyzeBytecode } from './risk.mjs'

const ERC20_PROBE_ABI = parseAbi([
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function decimals() view returns (uint8)',
  'function totalSupply() view returns (uint256)',
  'function owner() view returns (address)',
  'function paused() view returns (bool)'
])

const PAIR_CREATED_V2 = parseAbiItem('event PairCreated(address indexed token0,address indexed token1,address pair,uint256)')
const POOL_CREATED_V3 = parseAbiItem('event PoolCreated(address indexed token0,address indexed token1,uint24 indexed fee,int24 tickSpacing,address pool)')
const SWAP_V2 = parseAbiItem('event Swap(address indexed sender,uint256 amount0In,uint256 amount1In,uint256 amount0Out,uint256 amount1Out,address indexed to)')
const SWAP_V3 = parseAbiItem('event Swap(address indexed sender,address indexed recipient,int256 amount0,int256 amount1,uint160 sqrtPriceX96,uint128 liquidity,int24 tick)')
const TRANSFER_EVENT = parseAbiItem('event Transfer(address indexed from,address indexed to,uint256 value)')

const TOPICS = {
  pairV2: keccak256(Buffer.from('PairCreated(address,address,address,uint256)')),
  poolV3: keccak256(Buffer.from('PoolCreated(address,address,uint24,int24,address)')),
  swapV2: keccak256(Buffer.from('Swap(address,uint256,uint256,uint256,uint256,address)')),
  swapV3: keccak256(Buffer.from('Swap(address,address,int256,int256,uint160,uint128,int24)')),
  transfer: keccak256(Buffer.from('Transfer(address,address,uint256)'))
}

function asNumber(value, fallback = 0) {
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) ? parsed : fallback
}

function boundedPush(list, value, max) {
  list.unshift(value)
  if (list.length > max) list.length = max
}

function safeJsonFile(filename, fallback) {
  try {
    if (!filename || !fs.existsSync(filename)) return fallback
    return JSON.parse(fs.readFileSync(filename, 'utf8'))
  } catch (error) {
    console.error(`Failed to read ${filename}:`, error instanceof Error ? error.message : error)
    return fallback
  }
}

function normalizeAddress(value) {
  try { return isAddress(value) ? getAddress(value) : null } catch { return null }
}

function sanitizeText(value, max = 120) {
  if (typeof value !== 'string') return null
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, '').trim()
  return cleaned ? cleaned.slice(0, max) : null
}

function publicRpcLabel(url) {
  try {
    const parsed = new URL(url)
    return `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}`
  } catch { return 'configured endpoint' }
}

function parseLabels(filename) {
  const source = safeJsonFile(filename, { entities: [] })
  const entities = Array.isArray(source.entities) ? source.entities : []
  const addressIndex = new Map()
  for (const entity of entities) {
    if (!entity || typeof entity !== 'object') continue
    const normalized = {
      id: sanitizeText(entity.id, 80) ?? `entity-${addressIndex.size + 1}`,
      name: sanitizeText(entity.name, 100) ?? 'Publicly labeled entity',
      kind: sanitizeText(entity.kind, 40) ?? 'project',
      website: sanitizeText(entity.website, 300),
      sources: Array.isArray(entity.sources) ? entity.sources.filter((item) => typeof item === 'string').slice(0, 10) : [],
      addresses: []
    }
    for (const item of Array.isArray(entity.addresses) ? entity.addresses : []) {
      const address = normalizeAddress(item?.address)
      const chainId = asNumber(item?.chainId)
      if (!address || !chainId) continue
      const evidence = {
        chainId,
        address,
        role: sanitizeText(item.role, 80) ?? 'publicly labeled address',
        source: sanitizeText(item.source, 300),
        confidence: ['verified', 'high', 'medium', 'low'].includes(item.confidence) ? item.confidence : 'medium'
      }
      normalized.addresses.push(evidence)
      addressIndex.set(`${chainId}:${address.toLowerCase()}`, { entity: normalized, evidence })
    }
  }
  return { entities, addressIndex }
}

function chainFromRecord(record) {
  return defineChain({
    id: record.chainId,
    name: record.name,
    nativeCurrency: { name: record.nativeCurrencyName ?? 'Ether', symbol: record.nativeCurrencySymbol ?? 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [record.rpcUrl] } },
    blockExplorers: record.explorerUrl ? { default: { name: `${record.name} Explorer`, url: record.explorerUrl } } : undefined
  })
}

function decodeKnownLog(log) {
  const topic0 = log.topics?.[0]?.toLowerCase()
  try {
    if (topic0 === TOPICS.pairV2.toLowerCase()) {
      const decoded = decodeEventLog({ abi: [PAIR_CREATED_V2], data: log.data, topics: log.topics, strict: false })
      return { kind: 'pool', standard: 'uniswap-v2', args: decoded.args }
    }
    if (topic0 === TOPICS.poolV3.toLowerCase()) {
      const decoded = decodeEventLog({ abi: [POOL_CREATED_V3], data: log.data, topics: log.topics, strict: false })
      return { kind: 'pool', standard: 'uniswap-v3', args: decoded.args }
    }
    if (topic0 === TOPICS.swapV2.toLowerCase()) {
      const decoded = decodeEventLog({ abi: [SWAP_V2], data: log.data, topics: log.topics, strict: false })
      return { kind: 'swap', standard: 'uniswap-v2', args: decoded.args }
    }
    if (topic0 === TOPICS.swapV3.toLowerCase()) {
      const decoded = decodeEventLog({ abi: [SWAP_V3], data: log.data, topics: log.topics, strict: false })
      return { kind: 'swap', standard: 'uniswap-v3', args: decoded.args }
    }
  } catch { return null }
  return null
}

async function safeRead(client, request) {
  try { return await client.readContract(request) } catch { return undefined }
}

async function probeToken(client, address) {
  const [name, symbol, decimals, totalSupply, owner, paused] = await Promise.all([
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'name' }),
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'symbol' }),
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'decimals' }),
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'totalSupply' }),
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'owner' }),
    safeRead(client, { address, abi: ERC20_PROBE_ABI, functionName: 'paused' })
  ])
  const tokenLike = typeof symbol === 'string' && typeof decimals === 'number' && typeof totalSupply === 'bigint'
  return {
    tokenLike,
    name: sanitizeText(name, 96),
    symbol: sanitizeText(symbol, 32),
    decimals: typeof decimals === 'number' ? decimals : null,
    totalSupply: typeof totalSupply === 'bigint' ? totalSupply.toString() : null,
    owner: typeof owner === 'string' && isAddress(owner) ? getAddress(owner) : null,
    paused: typeof paused === 'boolean' ? paused : null
  }
}

function parseFactoryLabels(raw = []) {
  const labels = new Map()
  for (const item of raw) {
    const address = normalizeAddress(item?.address)
    const chainId = asNumber(item?.chainId)
    if (!address || !chainId) continue
    labels.set(`${chainId}:${address.toLowerCase()}`, sanitizeText(item.name, 80) ?? 'Configured DEX factory')
  }
  return labels
}

export function createChainScout(config) {
  const emitter = new EventEmitter()
  emitter.setMaxListeners(200)
  const maxRecords = config.scoutMaxRecords
  const chains = config.scoutChains.map((item) => ({
    ...item,
    chain: chainFromRecord(item),
    client: createPublicClient({ chain: chainFromRecord(item), transport: http(item.rpcUrl, { timeout: 12_000, retryCount: 1 }) })
  }))
  const labels = parseLabels(config.scoutLabelsFile)
  const factoryLabels = parseFactoryLabels(config.scoutDexFactories)
  const heads = new Map()
  const polling = new Set()
  const seen = new Set()
  let timer
  let running = false
  let lastError = null
  let startedAt = null

  const state = {
    contracts: [],
    tokens: [],
    pools: [],
    swaps: [],
    events: [],
    codeFamilies: new Map(),
    deployers: new Map()
  }

  function labelFor(chainId, address) {
    return labels.addressIndex.get(`${chainId}:${String(address).toLowerCase()}`) ?? null
  }

  function addEvidence(record, address, role) {
    const label = labelFor(record.chainId, address)
    if (!label) return []
    return [{
      type: 'public-label',
      entityId: label.entity.id,
      entityName: label.entity.name,
      entityKind: label.entity.kind,
      address: getAddress(address),
      role: label.evidence.role ?? role,
      source: label.evidence.source,
      confidence: label.evidence.confidence
    }]
  }

  function emit(kind, record) {
    const event = { id: `${kind}:${record.chainId}:${record.transactionHash ?? record.address ?? Date.now()}:${record.logIndex ?? ''}`, kind, at: new Date().toISOString(), ...record }
    boundedPush(state.events, event, maxRecords)
    emitter.emit('event', event)
  }

  function rememberDeployer(contract) {
    const key = `${contract.chainId}:${contract.deployer.toLowerCase()}`
    const current = state.deployers.get(key) ?? {
      chainId: contract.chainId,
      chain: contract.chain,
      address: contract.deployer,
      firstSeenBlock: contract.blockNumber,
      lastSeenBlock: contract.blockNumber,
      contracts: 0,
      tokens: 0,
      pools: 0,
      codeHashes: new Set(),
      evidence: addEvidence(contract, contract.deployer, 'deployer')
    }
    current.contracts += 1
    current.tokens += contract.token?.tokenLike ? 1 : 0
    current.firstSeenBlock = String(BigInt(current.firstSeenBlock) < BigInt(contract.blockNumber) ? current.firstSeenBlock : contract.blockNumber)
    current.lastSeenBlock = String(BigInt(current.lastSeenBlock) > BigInt(contract.blockNumber) ? current.lastSeenBlock : contract.blockNumber)
    current.codeHashes.add(contract.codeHash)
    state.deployers.set(key, current)
  }

  function rememberCodeFamily(contract) {
    const current = state.codeFamilies.get(contract.codeHash) ?? { codeHash: contract.codeHash, deployments: [] }
    current.deployments.unshift({
      chainId: contract.chainId,
      chain: contract.chain,
      address: contract.address,
      deployer: contract.deployer,
      blockNumber: contract.blockNumber,
      transactionHash: contract.transactionHash,
      token: contract.token?.tokenLike ? { name: contract.token.name, symbol: contract.token.symbol } : null
    })
    if (current.deployments.length > 100) current.deployments.length = 100
    state.codeFamilies.set(contract.codeHash, current)
  }

  async function inspectContract(record, tx, receipt) {
    const address = normalizeAddress(receipt.contractAddress)
    const deployer = normalizeAddress(tx.from)
    if (!address || !deployer) return
    const id = `${record.chainId}:${address.toLowerCase()}`
    if (seen.has(id)) return
    seen.add(id)

    const bytecode = await record.client.getBytecode({ address }).catch(() => '0x')
    if (!bytecode || bytecode === '0x') return
    const token = await probeToken(record.client, address)
    const staticRisk = analyzeBytecode(bytecode, { tokenAddress: address })
    const evidence = [
      ...addEvidence(record, address, 'contract'),
      ...addEvidence(record, deployer, 'deployer')
    ]
    const contract = {
      chainId: record.chainId,
      chain: record.name,
      explorerUrl: record.explorerUrl,
      address,
      deployer,
      transactionHash: receipt.transactionHash,
      blockNumber: receipt.blockNumber.toString(),
      timestamp: record.timestamp,
      codeHash: keccak256(bytecode),
      codeSize: Math.max(0, (bytecode.length - 2) / 2),
      risk: { status: staticRisk.status, score: staticRisk.score, findings: staticRisk.findings.slice(0, 20) },
      token: token.tokenLike ? token : null,
      evidence
    }
    rememberDeployer(contract)
    rememberCodeFamily(contract)
    boundedPush(state.contracts, contract, maxRecords)
    emit('contract-created', contract)
    if (token.tokenLike) {
      boundedPush(state.tokens, contract, maxRecords)
      emit('token-detected', contract)
    }
  }

  async function processLog(record, log) {
    const decoded = decodeKnownLog(log)
    if (!decoded) return
    const id = `${record.chainId}:${log.transactionHash}:${log.logIndex}`
    if (seen.has(id)) return
    seen.add(id)
    const factoryKey = `${record.chainId}:${log.address.toLowerCase()}`
    const factoryName = factoryLabels.get(factoryKey) ?? null
    if (decoded.kind === 'pool') {
      const token0 = normalizeAddress(decoded.args.token0)
      const token1 = normalizeAddress(decoded.args.token1)
      const pool = normalizeAddress(decoded.args.pair ?? decoded.args.pool)
      if (!token0 || !token1 || !pool) return
      const [token0Meta, token1Meta] = await Promise.all([probeToken(record.client, token0), probeToken(record.client, token1)])
      const item = {
        chainId: record.chainId,
        chain: record.name,
        explorerUrl: record.explorerUrl,
        standard: decoded.standard,
        factory: getAddress(log.address),
        factoryName,
        verifiedFactory: Boolean(factoryName),
        token0,
        token1,
        token0Meta: token0Meta.tokenLike ? token0Meta : null,
        token1Meta: token1Meta.tokenLike ? token1Meta : null,
        pool,
        fee: decoded.args.fee === undefined ? null : Number(decoded.args.fee),
        tickSpacing: decoded.args.tickSpacing === undefined ? null : Number(decoded.args.tickSpacing),
        transactionHash: log.transactionHash,
        blockNumber: log.blockNumber.toString(),
        logIndex: Number(log.logIndex),
        timestamp: record.timestamp,
        evidence: [
          ...addEvidence(record, log.address, 'factory'),
          ...addEvidence(record, token0, 'token0'),
          ...addEvidence(record, token1, 'token1')
        ]
      }
      boundedPush(state.pools, item, maxRecords)
      emit('pool-created', item)
      return
    }
    const item = {
      chainId: record.chainId,
      chain: record.name,
      explorerUrl: record.explorerUrl,
      standard: decoded.standard,
      pool: getAddress(log.address),
      transactionHash: log.transactionHash,
      blockNumber: log.blockNumber.toString(),
      logIndex: Number(log.logIndex),
      timestamp: record.timestamp,
      sender: normalizeAddress(decoded.args.sender),
      recipient: normalizeAddress(decoded.args.recipient ?? decoded.args.to),
      amounts: Object.fromEntries(Object.entries(decoded.args).filter(([key]) => key.startsWith('amount')).map(([key, value]) => [key, typeof value === 'bigint' ? value.toString() : String(value)])),
      sqrtPriceX96: decoded.args.sqrtPriceX96?.toString?.() ?? null,
      liquidity: decoded.args.liquidity?.toString?.() ?? null,
      tick: decoded.args.tick === undefined ? null : Number(decoded.args.tick),
      pair: (() => { const known = state.pools.find((pool) => pool.chainId === record.chainId && pool.pool.toLowerCase() === log.address.toLowerCase()); return known ? { token0: known.token0, token1: known.token1, token0Meta: known.token0Meta, token1Meta: known.token1Meta } : null })(),
      evidence: addEvidence(record, log.address, 'pool')
    }
    boundedPush(state.swaps, item, maxRecords)
    emit('swap-observed', item)
  }

  async function processRange(record, fromBlock, toBlock) {
    const logsPromise = record.client.getLogs({ fromBlock, toBlock }).catch((error) => {
      console.error(`Scout logs ${record.name}:`, error instanceof Error ? error.message : error)
      return []
    })
    for (let number = fromBlock; number <= toBlock; number += 1n) {
      const block = await record.client.getBlock({ blockNumber: number, includeTransactions: true }).catch(() => null)
      if (!block) continue
      const timestamp = Number(block.timestamp)
      for (const tx of block.transactions) {
        if (typeof tx === 'string' || tx.to !== null) continue
        const receipt = await record.client.getTransactionReceipt({ hash: tx.hash }).catch(() => null)
        if (receipt?.contractAddress) await inspectContract({ ...record, timestamp }, tx, receipt)
      }
    }
    const logs = await logsPromise
    const blockTimestamps = new Map()
    for (const log of logs) {
      let timestamp = blockTimestamps.get(log.blockNumber.toString())
      if (timestamp === undefined) {
        const block = await record.client.getBlock({ blockNumber: log.blockNumber }).catch(() => null)
        timestamp = block ? Number(block.timestamp) : null
        blockTimestamps.set(log.blockNumber.toString(), timestamp)
      }
      await processLog({ ...record, timestamp }, log)
    }
  }

  async function pollChain(record) {
    if (polling.has(record.chainId)) return
    polling.add(record.chainId)
    try {
      const current = await record.client.getBlockNumber()
      const previous = heads.get(record.chainId)
      let fromBlock = previous === undefined
        ? (current > BigInt(config.scoutInitialLookback) ? current - BigInt(config.scoutInitialLookback) + 1n : 0n)
        : previous + 1n
      if (fromBlock > current) return
      while (fromBlock <= current) {
        const toBlock = fromBlock + BigInt(config.scoutMaxBlocksPerPoll - 1) > current
          ? current
          : fromBlock + BigInt(config.scoutMaxBlocksPerPoll - 1)
        await processRange(record, fromBlock, toBlock)
        heads.set(record.chainId, toBlock)
        fromBlock = toBlock + 1n
      }
      lastError = null
    } catch (error) {
      lastError = `${record.name}: ${error instanceof Error ? error.message : error}`
      console.error('Scout poll failed:', lastError)
    } finally {
      polling.delete(record.chainId)
    }
  }

  async function poll() {
    if (!config.scoutEnabled) return
    await Promise.allSettled(chains.map((chain) => pollChain(chain)))
  }

  function start() {
    if (!config.scoutEnabled || running) return
    running = true
    startedAt = new Date().toISOString()
    void poll()
    timer = setInterval(() => void poll(), config.scoutPollIntervalMs)
    timer.unref?.()
  }

  function stop() {
    if (timer) clearInterval(timer)
    timer = undefined
    running = false
  }

  function filter(items, query = {}) {
    let output = [...items]
    if (query.chainId) output = output.filter((item) => item.chainId === Number(query.chainId))
    if (query.status) output = output.filter((item) => item.risk?.status?.toLowerCase() === String(query.status).toLowerCase())
    if (query.q) {
      const needle = String(query.q).toLowerCase()
      output = output.filter((item) => JSON.stringify(item).toLowerCase().includes(needle))
    }
    return output.slice(0, Math.max(1, Math.min(500, Number(query.limit ?? 100))))
  }

  function summary() {
    return {
      enabled: config.scoutEnabled,
      running,
      startedAt,
      lastError,
      pollIntervalMs: config.scoutPollIntervalMs,
      coverage: chains.map((record) => ({
        chainId: record.chainId,
        name: record.name,
        explorerUrl: record.explorerUrl,
        rpc: publicRpcLabel(record.rpcUrl),
        head: heads.get(record.chainId)?.toString() ?? null,
        pendingFeed: Boolean(record.wsUrl && config.scoutPendingEnabled)
      })),
      counts: {
        contracts: state.contracts.length,
        tokens: state.tokens.length,
        pools: state.pools.length,
        swaps: state.swaps.length,
        deployers: state.deployers.size,
        codeFamilies: state.codeFamilies.size,
        publicLabels: labels.addressIndex.size
      },
      limitation: 'Coverage is complete only for configured RPC/archive endpoints and indexed block ranges. Public labels are evidence records, not private identity claims. Pending visibility requires a provider that exposes pending transactions.'
    }
  }

  function deployer(chainId, address) {
    const normalized = normalizeAddress(address)
    if (!normalized) return null
    const record = state.deployers.get(`${Number(chainId)}:${normalized.toLowerCase()}`)
    if (!record) return {
      chainId: Number(chainId),
      address: normalized,
      contracts: 0,
      tokens: 0,
      pools: 0,
      codeHashes: [],
      evidence: addEvidence({ chainId: Number(chainId) }, normalized, 'deployer'),
      deployments: []
    }
    return {
      ...record,
      codeHashes: [...record.codeHashes],
      deployments: state.contracts.filter((item) => item.chainId === Number(chainId) && item.deployer.toLowerCase() === normalized.toLowerCase()).slice(0, 100)
    }
  }

  function codeFamily(hash) {
    return state.codeFamilies.get(String(hash).toLowerCase()) ?? null
  }

  return {
    start,
    stop,
    poll,
    onEvent: (listener) => { emitter.on('event', listener); return () => emitter.off('event', listener) },
    summary,
    contracts: (query) => filter(state.contracts, query),
    tokens: (query) => filter(state.tokens, query),
    pools: (query) => filter(state.pools, query),
    swaps: (query) => filter(state.swaps, query),
    events: (query) => filter(state.events, query),
    deployer,
    codeFamily,
    labels: () => ({ entities: labels.entities, indexedAddresses: labels.addressIndex.size })
  }
}
