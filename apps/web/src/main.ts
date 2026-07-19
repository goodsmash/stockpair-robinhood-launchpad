import './style.css'
import {
  createPublicClient,
  createWalletClient,
  custom,
  formatUnits,
  getAddress,
  http,
  isAddress,
  keccak256,
  parseUnits,
  toBytes,
  zeroAddress,
  type Abi,
  type Address,
  type EIP1193Provider
} from 'viem'
import { launchpadAbi, poolAbi, erc20Abi } from './abi/contracts'
import { robinhoodChain } from './lib/chain'
import { boundedText, isRecord, normalizeRiskStatus, safeAddress, safeBoolean, safeExplorerUrl, safeHash, safeInteger, safeNumericString, safeShortHex } from './lib/security'

declare global {
  interface Window { ethereum?: EIP1193Provider }
}

type View = 'discover' | 'scout' | 'radar' | 'trade' | 'launch' | 'portfolio' | 'scanner' | 'activity' | 'settings' | 'admin'
type RiskStatus = 'TRUSTED' | 'LOW' | 'CAUTION' | 'DANGER' | 'BLOCKED'

type LaunchView = {
  launchId: string
  creator: Address
  coinToken: Address
  stockToken: Address
  pool: Address
  createdAt: number
  liquidityUnlockAt: number
  feeBps: number
  liquidityLockId: string
  creatorVestingId: string
  metadataHash: string
  coin: { name: string | null; symbol: string | null; totalSupply: string | null }
  stock: { name: string | null; symbol: string | null }
  state: null | {
    reserveCoin: string
    reserveStock: string
    lastUpdated: number
    lpSupply: string
    swaps: string
    cumulativeCoinVolume: string
    cumulativeStockVolume: string
    spotCoinPerStock: string | null
  }
  security: {
    stockEnabled: boolean
    stockEmergencyBlocked: boolean
    poolEmergencyBlocked: boolean
    codeMatches: boolean
    liquidityLocked: boolean
    tradeAllowed: boolean
    reason: string | null
  }
}

type ActivityItem = {
  event: string
  address: Address
  blockNumber: string
  transactionHash: string
  args: Record<string, string | boolean>
}

type ScanResult = {
  address: Address
  scannedAt: string
  status: RiskStatus
  score: number
  codeHash: string
  tradeAllowed: boolean
  metadata: { name: string | null; symbol: string | null; decimals: number | null; totalSupply: string | null; owner: Address | null; paused: boolean | null }
  proxy: { implementation?: Address; admin?: Address; beacon?: Address }
  explorer: { verified: boolean | null; changedBytecode: boolean | null; implementation: Address | null; holdersCount: string | null; transfersCount: string | null; holderConcentration: number | null }
  registry: null | { enabled: boolean; emergencyBlocked: boolean; approvedCodeHash: string; priceFeed: Address; maxOracleAge: number; requireFreshOracleForSwaps: boolean }
  findings: Array<{ code: string; severity: string; detail: string; signature?: string }>
  limitation: string
}

type NetworkState = {
  chainId: number
  network: string
  blockNumber: string
  gasPriceWei: string
  configured: boolean
  productionTradingEnabled: boolean
  factoryTrust?: FactoryTrust
}

type FactoryTrust = { trusted: boolean; actualCodeHash: string | null; expectedCodeHash?: string; protocolVersion: string | null; expectedProtocolVersion?: string; codeHashMatches?: boolean; versionMatches?: boolean; reason: string | null }
type IndexerConfig = { chainId: number; launchpadAddress: Address; launchpadCodeHash: string; protocolVersion: string; productionTradingEnabled: boolean; factoryTrust: FactoryTrust }
type VerifiedPool = { pool: Address; launchId: bigint; coin: Address; stock: Address; record: Awaited<ReturnType<typeof readLaunchRecord>>; feeBps: number }

type ScoutEvidence = { type: string; entityId?: string; entityName?: string; entityKind?: string; role?: string; source?: string | null; confidence?: string }
type ScoutRisk = { status: RiskStatus; score: number; findings: Array<{ code: string; severity: string; detail: string }> }
type ScoutContract = {
  chainId: number; chain: string; explorerUrl?: string | null; address: Address; deployer: Address; transactionHash: string; blockNumber: string; timestamp?: number | null;
  codeHash: string; codeSize: number; risk: ScoutRisk; token: null | { name: string | null; symbol: string | null; decimals: number | null; totalSupply: string | null; owner: Address | null; paused: boolean | null };
  evidence: ScoutEvidence[]
}
type ScoutTokenMeta = { name: string | null; symbol: string | null; decimals: number | null; totalSupply: string | null; owner: Address | null; paused: boolean | null }
type ScoutPool = { chainId: number; chain: string; explorerUrl?: string | null; standard: string; factory: Address; factoryName: string | null; verifiedFactory: boolean; token0: Address; token1: Address; token0Meta?: ScoutTokenMeta | null; token1Meta?: ScoutTokenMeta | null; pool: Address; fee: number | null; transactionHash: string; blockNumber: string; timestamp?: number | null; evidence: ScoutEvidence[] }
type ScoutSwap = { chainId: number; chain: string; explorerUrl?: string | null; standard: string; pool: Address; transactionHash: string; blockNumber: string; timestamp?: number | null; sender: Address | null; recipient: Address | null; amounts: Record<string, string>; evidence: ScoutEvidence[] }
type ScoutSummary = { enabled: boolean; running: boolean; startedAt: string | null; lastError: string | null; pollIntervalMs: number; coverage: Array<{ chainId: number; name: string; explorerUrl?: string | null; rpc: string; head: string | null; pendingFeed: boolean }>; counts: { contracts: number; tokens: number; pools: number; swaps: number; deployers: number; codeFamilies: number; publicLabels: number }; limitation: string }


function normalizeEvidence(value: unknown): ScoutEvidence[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, 20).filter(isRecord).map((item) => ({
    type: boundedText(item.type, 48),
    entityId: boundedText(item.entityId, 160) || undefined,
    entityName: boundedText(item.entityName, 120) || undefined,
    entityKind: boundedText(item.entityKind, 48) || undefined,
    role: boundedText(item.role, 64) || undefined,
    source: boundedText(item.source, 300) || null,
    confidence: boundedText(item.confidence, 32) || undefined
  }))
}

function normalizeScoutRisk(value: unknown): ScoutRisk {
  const row = isRecord(value) ? value : {}
  const findings = Array.isArray(row.findings) ? row.findings.slice(0, 100).filter(isRecord).map((item) => ({
    code: boundedText(item.code, 80), severity: boundedText(item.severity, 24), detail: boundedText(item.detail, 500)
  })) : []
  return { status: normalizeRiskStatus(row.status), score: safeInteger(row.score, 100, 0, 100), findings }
}

function normalizeTokenMeta(value: unknown): ScoutTokenMeta | null {
  if (!isRecord(value)) return null
  return {
    name: boundedText(value.name, 96) || null,
    symbol: boundedText(value.symbol, 24) || null,
    decimals: value.decimals === null || value.decimals === undefined ? null : safeInteger(value.decimals, 0, 0, 255),
    totalSupply: value.totalSupply === null || value.totalSupply === undefined ? null : safeNumericString(value.totalSupply),
    owner: safeAddress(value.owner),
    paused: typeof value.paused === 'boolean' ? value.paused : null
  }
}

function normalizeLaunch(value: unknown): LaunchView | null {
  if (!isRecord(value)) return null
  const creator = safeAddress(value.creator), coinToken = safeAddress(value.coinToken), stockToken = safeAddress(value.stockToken), pool = safeAddress(value.pool)
  const metadataHash = safeHash(value.metadataHash)
  if (!creator || !coinToken || !stockToken || !pool || !metadataHash) return null
  const coin = isRecord(value.coin) ? value.coin : {}
  const stock = isRecord(value.stock) ? value.stock : {}
  const security = isRecord(value.security) ? value.security : {}
  const stateRow = isRecord(value.state) ? value.state : null
  return {
    launchId: safeNumericString(value.launchId), creator, coinToken, stockToken, pool,
    createdAt: safeInteger(value.createdAt), liquidityUnlockAt: safeInteger(value.liquidityUnlockAt), feeBps: safeInteger(value.feeBps, 0, 0, 10_000),
    liquidityLockId: safeNumericString(value.liquidityLockId), creatorVestingId: safeNumericString(value.creatorVestingId), metadataHash,
    coin: { name: boundedText(coin.name, 96) || null, symbol: boundedText(coin.symbol, 24) || null, totalSupply: coin.totalSupply === null || coin.totalSupply === undefined ? null : safeNumericString(coin.totalSupply) },
    stock: { name: boundedText(stock.name, 96) || null, symbol: boundedText(stock.symbol, 24) || null },
    state: stateRow ? {
      reserveCoin: safeNumericString(stateRow.reserveCoin), reserveStock: safeNumericString(stateRow.reserveStock), lastUpdated: safeInteger(stateRow.lastUpdated),
      lpSupply: safeNumericString(stateRow.lpSupply), swaps: safeNumericString(stateRow.swaps), cumulativeCoinVolume: safeNumericString(stateRow.cumulativeCoinVolume),
      cumulativeStockVolume: safeNumericString(stateRow.cumulativeStockVolume), spotCoinPerStock: typeof stateRow.spotCoinPerStock === 'string' && /^\d+(?:\.\d+)?$/.test(stateRow.spotCoinPerStock) ? stateRow.spotCoinPerStock : null
    } : null,
    security: {
      stockEnabled: safeBoolean(security.stockEnabled), stockEmergencyBlocked: safeBoolean(security.stockEmergencyBlocked), poolEmergencyBlocked: safeBoolean(security.poolEmergencyBlocked),
      codeMatches: safeBoolean(security.codeMatches), liquidityLocked: safeBoolean(security.liquidityLocked), tradeAllowed: safeBoolean(security.tradeAllowed),
      reason: boundedText(security.reason, 300) || null
    }
  }
}

function normalizeActivity(value: unknown): ActivityItem | null {
  if (!isRecord(value)) return null
  const address = safeAddress(value.address), transactionHash = safeHash(value.transactionHash)
  if (!address || !transactionHash) return null
  const args = isRecord(value.args) ? Object.fromEntries(Object.entries(value.args).slice(0, 30).map(([key, item]) => [boundedText(key, 64), typeof item === 'boolean' ? item : boundedText(item, 200)])) : {}
  return { event: boundedText(value.event, 80), address, blockNumber: safeNumericString(value.blockNumber), transactionHash, args }
}

function normalizeScoutContract(value: unknown): ScoutContract | null {
  if (!isRecord(value)) return null
  const address = safeAddress(value.address), deployer = safeAddress(value.deployer), transactionHash = safeHash(value.transactionHash), codeHash = safeHash(value.codeHash)
  if (!address || !deployer || !transactionHash || !codeHash) return null
  return { chainId: safeInteger(value.chainId, 0, 1), chain: boundedText(value.chain, 80), explorerUrl: boundedText(value.explorerUrl, 300) || null, address, deployer, transactionHash,
    blockNumber: safeNumericString(value.blockNumber), timestamp: value.timestamp === null || value.timestamp === undefined ? null : safeInteger(value.timestamp), codeHash, codeSize: safeInteger(value.codeSize, 0, 0, 50_000_000),
    risk: normalizeScoutRisk(value.risk), token: normalizeTokenMeta(value.token), evidence: normalizeEvidence(value.evidence) }
}

function normalizeScoutPool(value: unknown): ScoutPool | null {
  if (!isRecord(value)) return null
  const factory = safeAddress(value.factory), token0 = safeAddress(value.token0), token1 = safeAddress(value.token1), pool = safeAddress(value.pool), transactionHash = safeHash(value.transactionHash)
  if (!factory || !token0 || !token1 || !pool || !transactionHash) return null
  return { chainId: safeInteger(value.chainId, 0, 1), chain: boundedText(value.chain, 80), explorerUrl: boundedText(value.explorerUrl, 300) || null, standard: boundedText(value.standard, 24), factory,
    factoryName: boundedText(value.factoryName, 100) || null, verifiedFactory: safeBoolean(value.verifiedFactory), token0, token1, token0Meta: normalizeTokenMeta(value.token0Meta), token1Meta: normalizeTokenMeta(value.token1Meta),
    pool, fee: value.fee === null || value.fee === undefined ? null : safeInteger(value.fee, 0, 0, 1_000_000), transactionHash, blockNumber: safeNumericString(value.blockNumber),
    timestamp: value.timestamp === null || value.timestamp === undefined ? null : safeInteger(value.timestamp), evidence: normalizeEvidence(value.evidence) }
}

function normalizeScoutSwap(value: unknown): ScoutSwap | null {
  if (!isRecord(value)) return null
  const pool = safeAddress(value.pool), transactionHash = safeHash(value.transactionHash)
  if (!pool || !transactionHash) return null
  const amounts = isRecord(value.amounts) ? Object.fromEntries(Object.entries(value.amounts).slice(0, 12).map(([key, item]) => [boundedText(key, 40), safeNumericString(item)])) : {}
  return { chainId: safeInteger(value.chainId, 0, 1), chain: boundedText(value.chain, 80), explorerUrl: boundedText(value.explorerUrl, 300) || null, standard: boundedText(value.standard, 24), pool, transactionHash,
    blockNumber: safeNumericString(value.blockNumber), timestamp: value.timestamp === null || value.timestamp === undefined ? null : safeInteger(value.timestamp), sender: safeAddress(value.sender), recipient: safeAddress(value.recipient), amounts, evidence: normalizeEvidence(value.evidence) }
}

function normalizeScoutSummary(value: unknown): ScoutSummary | null {
  if (!isRecord(value)) return null
  const counts = isRecord(value.counts) ? value.counts : {}
  const coverage = Array.isArray(value.coverage) ? value.coverage.slice(0, 50).filter(isRecord).map((item) => ({
    chainId: safeInteger(item.chainId, 0, 1), name: boundedText(item.name, 80), explorerUrl: boundedText(item.explorerUrl, 300) || null,
    rpc: boundedText(item.rpc, 160), head: item.head === null || item.head === undefined ? null : safeNumericString(item.head), pendingFeed: safeBoolean(item.pendingFeed)
  })) : []
  return {
    enabled: safeBoolean(value.enabled), running: safeBoolean(value.running), startedAt: boundedText(value.startedAt, 64) || null,
    lastError: boundedText(value.lastError, 500) || null, pollIntervalMs: safeInteger(value.pollIntervalMs, 12_000, 2_000, 300_000), coverage,
    counts: { contracts: safeInteger(counts.contracts, 0, 0), tokens: safeInteger(counts.tokens, 0, 0), pools: safeInteger(counts.pools, 0, 0), swaps: safeInteger(counts.swaps, 0, 0), deployers: safeInteger(counts.deployers, 0, 0), codeFamilies: safeInteger(counts.codeFamilies, 0, 0), publicLabels: safeInteger(counts.publicLabels, 0, 0) },
    limitation: boundedText(value.limitation, 800)
  }
}

type ScoutDeployerView = { address: Address; chainId: number; contracts: number; tokens: number; codeHashes: string[]; evidence: ScoutEvidence[]; deployments: ScoutContract[] }
function normalizeScoutDeployer(value: unknown): ScoutDeployerView | null {
  if (!isRecord(value)) return null
  const address = safeAddress(value.address)
  if (!address) return null
  const codeHashes = Array.isArray(value.codeHashes) ? value.codeHashes.map(safeHash).filter((item): item is string => Boolean(item)).slice(0, 500) : []
  const deployments = Array.isArray(value.deployments) ? value.deployments.map(normalizeScoutContract).filter((item): item is ScoutContract => item !== null).slice(0, 200) : []
  return { address, chainId: safeInteger(value.chainId, 0, 1), contracts: safeInteger(value.contracts, deployments.length, 0), tokens: safeInteger(value.tokens, 0, 0), codeHashes, evidence: normalizeEvidence(value.evidence), deployments }
}

function normalizeNetworkState(value: unknown): NetworkState | undefined {
  if (!isRecord(value)) return undefined
  const trust = isRecord(value.factoryTrust) ? value.factoryTrust : undefined
  return { chainId: safeInteger(value.chainId, robinhoodChain.id, 1), network: boundedText(value.network, 80), blockNumber: safeNumericString(value.blockNumber), gasPriceWei: safeNumericString(value.gasPriceWei),
    configured: safeBoolean(value.configured), productionTradingEnabled: safeBoolean(value.productionTradingEnabled), factoryTrust: trust ? {
      trusted: safeBoolean(trust.trusted), actualCodeHash: safeHash(trust.actualCodeHash), expectedCodeHash: safeHash(trust.expectedCodeHash) ?? undefined,
      protocolVersion: safeHash(trust.protocolVersion), expectedProtocolVersion: safeHash(trust.expectedProtocolVersion) ?? undefined,
      codeHashMatches: safeBoolean(trust.codeHashMatches), versionMatches: safeBoolean(trust.versionMatches), reason: boundedText(trust.reason, 300) || null
    } : undefined }
}

function normalizeIndexerConfig(value: unknown): IndexerConfig | undefined {
  if (!isRecord(value)) return undefined
  const address = safeAddress(value.launchpadAddress), hash = safeHash(value.launchpadCodeHash), version = safeHash(value.protocolVersion)
  const trust = normalizeNetworkState({ chainId: value.chainId, network: '', blockNumber: '0', gasPriceWei: '0', configured: true, productionTradingEnabled: value.productionTradingEnabled, factoryTrust: value.factoryTrust })?.factoryTrust
  if (!address || !hash || !version || !trust) return undefined
  return { chainId: safeInteger(value.chainId, 0, 1), launchpadAddress: address, launchpadCodeHash: hash, protocolVersion: version, productionTradingEnabled: safeBoolean(value.productionTradingEnabled), factoryTrust: trust }
}

function normalizeScanResult(value: unknown): ScanResult | undefined {
  if (!isRecord(value)) return undefined
  const address = safeAddress(value.address), codeHash = safeHash(value.codeHash)
  if (!address || !codeHash) return undefined
  const metadata = isRecord(value.metadata) ? value.metadata : {}, proxy = isRecord(value.proxy) ? value.proxy : {}, explorerRow = isRecord(value.explorer) ? value.explorer : {}, registryRow = isRecord(value.registry) ? value.registry : null
  const findings = Array.isArray(value.findings) ? value.findings.slice(0, 100).filter(isRecord).map((item) => ({ code: boundedText(item.code, 80), severity: boundedText(item.severity, 24), detail: boundedText(item.detail, 500), signature: boundedText(item.signature, 120) || undefined })) : []
  return { address, scannedAt: boundedText(value.scannedAt, 64), status: normalizeRiskStatus(value.status), score: safeInteger(value.score, 100, 0, 100), codeHash, tradeAllowed: safeBoolean(value.tradeAllowed),
    metadata: { name: boundedText(metadata.name, 96) || null, symbol: boundedText(metadata.symbol, 24) || null, decimals: metadata.decimals === null || metadata.decimals === undefined ? null : safeInteger(metadata.decimals, 0, 0, 255), totalSupply: metadata.totalSupply === null || metadata.totalSupply === undefined ? null : safeNumericString(metadata.totalSupply), owner: safeAddress(metadata.owner), paused: typeof metadata.paused === 'boolean' ? metadata.paused : null },
    proxy: { implementation: safeAddress(proxy.implementation) ?? undefined, admin: safeAddress(proxy.admin) ?? undefined, beacon: safeAddress(proxy.beacon) ?? undefined },
    explorer: { verified: typeof explorerRow.verified === 'boolean' ? explorerRow.verified : null, changedBytecode: typeof explorerRow.changedBytecode === 'boolean' ? explorerRow.changedBytecode : null, implementation: safeAddress(explorerRow.implementation), holdersCount: explorerRow.holdersCount === null || explorerRow.holdersCount === undefined ? null : safeNumericString(explorerRow.holdersCount), transfersCount: explorerRow.transfersCount === null || explorerRow.transfersCount === undefined ? null : safeNumericString(explorerRow.transfersCount), holderConcentration: typeof explorerRow.holderConcentration === 'number' && Number.isFinite(explorerRow.holderConcentration) ? Math.max(0, Math.min(1, explorerRow.holderConcentration)) : null },
    registry: registryRow ? { enabled: safeBoolean(registryRow.enabled), emergencyBlocked: safeBoolean(registryRow.emergencyBlocked), approvedCodeHash: safeHash(registryRow.approvedCodeHash) ?? `0x${'0'.repeat(64)}`, priceFeed: safeAddress(registryRow.priceFeed) ?? zeroAddress, maxOracleAge: safeInteger(registryRow.maxOracleAge), requireFreshOracleForSwaps: safeBoolean(registryRow.requireFreshOracleForSwaps) } : null,
    findings, limitation: boundedText(value.limitation, 800)
  }
}

const launchpadAddress = (import.meta.env.VITE_LAUNCHPAD_ADDRESS ?? zeroAddress) as Address
const expectedLaunchpadCodeHash = String(import.meta.env.VITE_LAUNCHPAD_CODE_HASH ?? `0x${'0'.repeat(64)}`).toLowerCase()
const expectedProtocolVersion = String(import.meta.env.VITE_LAUNCHPAD_PROTOCOL_VERSION ?? keccak256(toBytes('STOCKPAIR_LAUNCHPAD_V0.6.0'))).toLowerCase()
const expectedPoolProtocolVersion = keccak256(toBytes('STOCKPAIR_POOL_V0.6.0')).toLowerCase()
const expectedLaunchTokenProtocolVersion = keccak256(toBytes('STOCKPAIR_LAUNCH_TOKEN_V0.6.0')).toLowerCase()
const enableOperations = String(import.meta.env.VITE_ENABLE_OPERATIONS ?? 'false') === 'true'
const indexerUrl = String(import.meta.env.VITE_INDEXER_URL ?? '').replace(/\/$/, '')
const publicClient = createPublicClient({ chain: robinhoodChain, transport: http(undefined, { timeout: 10_000 }) })
const ZERO_HASH = `0x${'0'.repeat(64)}`
let account: Address | undefined
let walletClient: ReturnType<typeof createWalletClient> | undefined
let activeView: View = 'discover'
let selectedPool: Address | undefined
let launches: LaunchView[] = []
let activities: ActivityItem[] = []
let networkState: NetworkState | undefined
let indexerConfig: IndexerConfig | undefined
let directFactoryTrust: FactoryTrust | undefined
let trustCheckedAt = 0
let scanResult: ScanResult | undefined
let scoutSummary: ScoutSummary | undefined
let scoutContracts: ScoutContract[] = []
let scoutPools: ScoutPool[] = []
let scoutSwaps: ScoutSwap[] = []
let scoutFilter = 'all'
let scoutQuery = ''
let radarCandidates: RadarCandidate[] = []
type RadarScores = { safety: number; liquidity: number; traction: number; freshness: number; provenance: number }
type RadarCandidate = { id: string; chainId: number; address: string; deploymentBlock: string; deployer: string; transactionHash: string; codeHash: string; scores: RadarScores; riskScore: number; status: string; verifiedPools: number; swaps: number; executionReview: { blockers: string[]; requiredSteps: string[] } }
let eventSource: EventSource | undefined
const watchlist = new Set<string>(safeStoredArray('stockpair-watchlist'))
let searchQuery = ''
let riskFilter = 'all'
let pollingTimer: number | undefined

const app = document.querySelector<HTMLDivElement>('#app')!
app.innerHTML = `
  <div class="app-shell">
    <aside class="sidebar" id="sidebar" aria-label="Application sidebar">
      <div class="sidebar-top">
        <a class="brand" href="#discover" aria-label="StockPair home">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 40 40" role="img"><path d="M7 24.5 18.2 13l5.4 5.4L33 9v9.1l-9.4 9.4-5.4-5.4L7 33.3Z"/><path d="M27 9h6v6"/></svg>
          </span>
          <span><strong>StockPair</strong><small>Robinhood Chain</small></span>
          <span class="version-pill">v0.6</span>
        </a>
        <div class="sidebar-environment" id="sidebar-environment">
          <div class="environment-title"><span>Deployment posture</span><i id="environment-dot"></i></div>
          <strong id="environment-label">Checking trust anchors</strong>
          <small id="environment-detail">Writes stay locked until chain verification completes.</small>
        </div>
      </div>
      <nav class="main-nav" aria-label="Primary navigation">
        <span class="nav-label">Markets</span>
        ${navButton('discover', '⌁', 'Discover')}
        ${navButton('trade', '⇄', 'Trade')}
        ${navButton('launch', '↗', 'Launch')}
        ${navButton('portfolio', '◫', 'Portfolio')}
        <span class="nav-label">Intelligence</span>
        ${navButton('radar', '◈', 'Launch Radar')}
        ${navButton('scout', '◉', 'Chain Scout')}
        ${navButton('scanner', '⌾', 'Risk Scanner')}
        ${navButton('activity', '≋', 'Activity')}
        <span class="nav-label">System</span>
        ${navButton('settings', '⚙', 'Settings')}
        ${enableOperations ? navButton('admin', '◇', 'Operations') : ''}
      </nav>
      <div class="sidebar-foot">
        <div class="network-chip"><i id="network-dot"></i><span id="network-name">Robinhood Chain</span></div>
        <div class="sidebar-links"><a target="_blank" rel="noopener noreferrer" href="${escapeAttr(robinhoodChain.blockExplorers?.default.url ?? '#')}">Explorer ↗</a><a href="#settings">Help & deployment</a></div>
        <small>Independent application. Not affiliated with or endorsed by Robinhood. Verify every transaction in your wallet.</small>
      </div>
    </aside>

    <div class="workspace">
      <header class="topbar">
        <button class="icon-button mobile-only" id="menu-button" aria-label="Open menu">☰</button>
        <div class="topbar-context"><span id="page-kicker">Markets</span><strong id="page-title">Discover</strong></div>
        <div class="global-search">
          <span aria-hidden="true">⌕</span>
          <input id="global-search" autocomplete="off" placeholder="Search markets, contracts or deployers" aria-label="Global market search" />
          <kbd>/</kbd>
        </div>
        <div class="top-actions">
          <div class="live-block" title="Indexer stream status"><i id="stream-dot"></i><span id="stream-label">Connecting</span><strong id="block-number">—</strong></div>
          <button class="button icon-ghost" id="refresh-all" title="Refresh all data" aria-label="Refresh all data">↻</button>
          <button class="button wallet-button" id="connect-wallet"><span class="wallet-indicator"></span><span id="wallet-label">Connect wallet</span></button>
        </div>
      </header>

      <div class="incident-banner hidden" id="incident-banner" role="alert">
        <div class="incident-icon">!</div><div><strong>Execution is locked</strong><span>On-chain trust anchors or emergency controls do not permit new risk. Self-directed LP exits remain available.</span></div>
      </div>
      <div class="incident-banner degraded hidden" id="data-banner" role="status">
        <div class="incident-icon">i</div><div><strong>Discovery data is degraded</strong><span>The indexer is unavailable or does not match this build. Direct wallet writes still require independent on-chain verification.</span></div>
      </div>

      <main id="view-root" tabindex="-1"></main>
      <footer class="app-footer"><span>StockPair v0.6.0</span><span>Factory-only markets · exact approvals · fail-closed verification</span><a href="#settings">Deployment status</a></footer>
    </div>
  </div>
  <nav class="mobile-nav" aria-label="Mobile navigation">
    ${navButton('discover', '⌁', 'Markets')}
    ${navButton('trade', '⇄', 'Trade')}
    ${navButton('launch', '＋', 'Launch')}
    ${navButton('portfolio', '◫', 'Portfolio')}
    ${navButton('scout', '◉', 'Scout')}
  </nav>
  <div id="toast-root" class="toast-root" aria-live="polite"></div>
  <div id="modal-root"></div>
`

function safeStoredArray(key: string): string[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) ?? '[]')
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string').slice(0, 500) : []
  } catch { return [] }
}

function navButton(view: View, icon: string, label: string) {
  return `<a href="#${view}" class="nav-item" data-view="${view}"><span>${icon}</span>${label}</a>`
}

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
}

function escapeAttr(value: unknown): string { return escapeHtml(value) }
function shortAddress(value?: string | null): string { return value ? safeShortHex(value) : '—' }
function explorer(path: string): string { return `${robinhoodChain.blockExplorers?.default.url ?? ''}/${path}` }
function nowSeconds(): number { return Math.floor(Date.now() / 1000) }
function deadline(): bigint { return BigInt(nowSeconds() + 1_200) }

function errorMessage(error: unknown): string {
  if (error instanceof Error) return (error as Error & { shortMessage?: string }).shortMessage ?? error.message
  return String(error)
}

function formatToken(value?: string | bigint | null, decimals = 18, max = 4): string {
  if (value === null || value === undefined) return '—'
  try {
    const text = formatUnits(BigInt(value), decimals)
    const number = Number(text)
    if (!Number.isFinite(number)) return text
    return new Intl.NumberFormat('en-US', { maximumFractionDigits: max, notation: Math.abs(number) >= 1_000_000 ? 'compact' : 'standard' }).format(number)
  } catch { return '—' }
}

function formatDate(seconds?: number): string {
  if (!seconds) return '—'
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(seconds * 1000)
}

function timeRemaining(seconds: number): string {
  const delta = seconds - nowSeconds()
  if (delta <= 0) return 'Unlocked'
  const days = Math.floor(delta / 86_400)
  const hours = Math.floor((delta % 86_400) / 3_600)
  return days > 0 ? `${days}d ${hours}h remaining` : `${hours}h remaining`
}

function riskFor(launch: LaunchView): RiskStatus {
  if (!launch.security.stockEnabled || launch.security.stockEmergencyBlocked || launch.security.poolEmergencyBlocked || !launch.security.codeMatches) return 'BLOCKED'
  if (!launch.security.liquidityLocked) return 'CAUTION'
  return launch.security.tradeAllowed ? 'TRUSTED' : 'LOW'
}

function badge(status: RiskStatus): string {
  const safe = normalizeRiskStatus(status)
  return `<span class="risk-badge ${safe.toLowerCase()}"><i></i>${safe}</span>`
}

function toast(message: string, kind: 'success' | 'error' | 'info' = 'info') {
  const root = document.querySelector<HTMLDivElement>('#toast-root')!
  const node = document.createElement('div')
  node.className = `toast ${kind}`
  node.textContent = message
  root.append(node)
  window.setTimeout(() => node.remove(), 5_000)
}

async function copyText(value: string, success = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(value)
    toast(success, 'success')
  } catch {
    const textarea = document.createElement('textarea')
    textarea.value = value
    textarea.style.position = 'fixed'
    textarea.style.opacity = '0'
    document.body.append(textarea)
    textarea.select()
    document.execCommand('copy')
    textarea.remove()
    toast(success, 'success')
  }
}

async function api<T>(path: string): Promise<T> {
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), 8_000)
  try {
    const response = await fetch(`${indexerUrl}${path}`, { headers: { accept: 'application/json', 'cache-control': 'no-store' }, signal: controller.signal, credentials: 'omit', referrerPolicy: 'no-referrer' })
    if (!response.ok) throw new Error(`Indexer returned ${response.status}`)
    const contentType = response.headers.get('content-type') ?? ''
    if (!contentType.toLowerCase().includes('application/json')) throw new Error('Indexer returned an unexpected content type')
    const declared = Number(response.headers.get('content-length') ?? 0)
    if (Number.isFinite(declared) && declared > 2_000_000) throw new Error('Indexer response exceeded the 2 MB safety limit')
    const text = await response.text()
    if (text.length > 2_000_000) throw new Error('Indexer response exceeded the 2 MB safety limit')
    return JSON.parse(text) as T
  } finally { window.clearTimeout(timer) }
}

function ensureConfigured(): Address {
  if (!isAddress(launchpadAddress) || launchpadAddress === zeroAddress) throw new Error('Set VITE_LAUNCHPAD_ADDRESS to the deployed launchpad address')
  if (!/^0x[0-9a-f]{64}$/.test(expectedLaunchpadCodeHash) || expectedLaunchpadCodeHash === ZERO_HASH) throw new Error('Writes disabled: VITE_LAUNCHPAD_CODE_HASH is not pinned')
  return getAddress(launchpadAddress)
}

async function readLaunchRecord(factory: Address, launchId: bigint) {
  return publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'launchAt', args: [launchId] })
}

async function verifyFactory(force = false): Promise<FactoryTrust> {
  if (!force && directFactoryTrust && Date.now() - trustCheckedAt < 5_000) {
    if (!directFactoryTrust.trusted) throw new Error(directFactoryTrust.reason ?? 'Factory trust check failed')
    return directFactoryTrust
  }
  const factory = ensureConfigured()
  const [chainId, bytecode, protocolVersion] = await Promise.all([
    publicClient.getChainId(),
    publicClient.getBytecode({ address: factory }),
    publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'PROTOCOL_VERSION' }).catch(() => null)
  ])
  const actualCodeHash = bytecode ? keccak256(bytecode).toLowerCase() : null
  const codeHashMatches = actualCodeHash === expectedLaunchpadCodeHash
  const versionMatches = typeof protocolVersion === 'string' && protocolVersion.toLowerCase() === expectedProtocolVersion
  const chainMatches = chainId === robinhoodChain.id
  directFactoryTrust = {
    trusted: Boolean(chainMatches && codeHashMatches && versionMatches), actualCodeHash, protocolVersion,
    expectedCodeHash: expectedLaunchpadCodeHash, expectedProtocolVersion, codeHashMatches, versionMatches,
    reason: !chainMatches ? `Wrong chain: expected ${robinhoodChain.id}, received ${chainId}` : !codeHashMatches ? 'Factory bytecode hash does not match the hard-coded deployment trust anchor' : !versionMatches ? 'Factory protocol version does not match the hard-coded release' : null
  }
  trustCheckedAt = Date.now()
  if (!directFactoryTrust.trusted) throw new Error(directFactoryTrust.reason ?? 'Factory trust check failed')
  return directFactoryTrust
}

async function verifyStockToken(stock: Address) {
  const factory = ensureConfigured()
  await verifyFactory()
  const [stockConfig, code] = await Promise.all([
    publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'stockConfigs', args: [stock] }),
    publicClient.getBytecode({ address: stock })
  ])
  if (!stockConfig[0] || stockConfig[2]) throw new Error('Stock token is not enabled or is emergency-blocked')
  if (!code || keccak256(code).toLowerCase() !== stockConfig[7].toLowerCase()) throw new Error('Stock runtime code hash does not match the registry')
  await publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'assertOracleHealthy', args: [stock] })
  return stockConfig
}

async function verifyPool(pool: Address, expectedCoin?: Address, expectedStock?: Address, allowIncidentExit = false): Promise<VerifiedPool> {
  const factory = ensureConfigured()
  await verifyFactory()
  const [registered, poolFactory, coin, stock, poolProtocolVersion, initialized, poolFeeBps] = await Promise.all([
    publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'isPool', args: [pool] }),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'factory' }),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'coinToken' }),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'stockToken' }),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'PROTOCOL_VERSION' }).catch(() => null),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'initialized' }).catch(() => false),
    publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'feeBps' }).catch(() => 65_535)
  ])
  if (!registered || poolFactory.toLowerCase() !== factory.toLowerCase()) throw new Error('Pool is not a factory-created StockPair market')
  if (typeof poolProtocolVersion !== 'string' || poolProtocolVersion.toLowerCase() !== expectedPoolProtocolVersion) throw new Error('Pool protocol version does not match this release')
  if (!initialized) throw new Error('Pool is not initialized')
  const launchLookup = await publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'launchIdForPool', args: [pool] })
  if (!launchLookup[0]) throw new Error('Pool has no immutable launch record')
  const launchId = launchLookup[1]
  const record = await readLaunchRecord(factory, launchId)
  if (record.pool.toLowerCase() !== pool.toLowerCase() || record.coinToken.toLowerCase() !== coin.toLowerCase() || record.stockToken.toLowerCase() !== stock.toLowerCase()) throw new Error('Pool registry record is inconsistent')
  if (Number(poolFeeBps) !== Number(record.feeBps) || Number(poolFeeBps) > 100) throw new Error('Pool fee does not match the immutable launch record')
  if (expectedCoin && coin.toLowerCase() !== expectedCoin.toLowerCase()) throw new Error('Pool coin does not match the selected market')
  if (expectedStock && stock.toLowerCase() !== expectedStock.toLowerCase()) throw new Error('Pool stock token does not match the selected market')
  const [trustedPair, issuer, launchTokenVersion, tokenMetadataHash, blocked] = await Promise.all([
    publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'isTrustedPool', args: [pool, coin, stock] }),
    publicClient.readContract({ address: coin, abi: erc20Abi, functionName: 'issuer' }).catch(() => zeroAddress),
    publicClient.readContract({ address: coin, abi: erc20Abi, functionName: 'PROTOCOL_VERSION' }).catch(() => null),
    publicClient.readContract({ address: coin, abi: erc20Abi, functionName: 'metadataHash' }).catch(() => null),
    publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'poolEmergencyBlocked', args: [pool] })
  ])
  if (!trustedPair || issuer.toLowerCase() !== factory.toLowerCase()) throw new Error('Pool or launch coin failed immutable factory provenance checks')
  if (typeof launchTokenVersion !== 'string' || launchTokenVersion.toLowerCase() !== expectedLaunchTokenProtocolVersion) throw new Error('Launch-token protocol version does not match this release')
  if (typeof tokenMetadataHash !== 'string' || tokenMetadataHash.toLowerCase() !== record.metadataHash.toLowerCase()) throw new Error('Launch-token metadata commitment does not match the factory record')
  if (blocked && !allowIncidentExit) throw new Error('Pool is emergency-blocked')
  if (!allowIncidentExit) await verifyStockToken(stock)
  return { pool, launchId, coin, stock, record, feeBps: Number(poolFeeBps) }
}

function serverTrustMatchesBuild(config?: IndexerConfig): boolean {
  return Boolean(config && config.chainId === robinhoodChain.id && config.launchpadAddress.toLowerCase() === launchpadAddress.toLowerCase() && config.launchpadCodeHash.toLowerCase() === expectedLaunchpadCodeHash && config.protocolVersion.toLowerCase() === expectedProtocolVersion && config.factoryTrust?.trusted)
}

async function readLaunchesDirect(limit = 40): Promise<LaunchView[]> {
  const factory = ensureConfigured()
  const count = await publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'launchCount' })
  const start = count > BigInt(limit) ? count - BigInt(limit) : 0n
  const rows: LaunchView[] = []
  for (let i = count; i > start; i -= 1n) {
    const launchId = i - 1n
    const record = await readLaunchRecord(factory, launchId)
    const [poolState, coinName, coinSymbol, coinSupply, stockName, stockSymbol, stockConfig, poolBlocked] = await Promise.all([
      publicClient.readContract({ address: record.pool, abi: poolAbi, functionName: 'getPoolState' }),
      publicClient.readContract({ address: record.coinToken, abi: erc20Abi, functionName: 'name' }).catch(() => null),
      publicClient.readContract({ address: record.coinToken, abi: erc20Abi, functionName: 'symbol' }).catch(() => null),
      publicClient.readContract({ address: record.coinToken, abi: erc20Abi, functionName: 'totalSupply' }).catch(() => null),
      publicClient.readContract({ address: record.stockToken, abi: erc20Abi, functionName: 'name' }).catch(() => null),
      publicClient.readContract({ address: record.stockToken, abi: erc20Abi, functionName: 'symbol' }).catch(() => null),
      publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'stockConfigs', args: [record.stockToken] }),
      publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'poolEmergencyBlocked', args: [record.pool] })
    ])
    const code = await publicClient.getBytecode({ address: record.stockToken })
    const codeMatches = Boolean(code && keccak256(code).toLowerCase() === stockConfig[7].toLowerCase())
    rows.push({
      launchId: launchId.toString(), creator: record.creator, coinToken: record.coinToken, stockToken: record.stockToken, pool: record.pool,
      createdAt: Number(record.createdAt), liquidityUnlockAt: Number(record.liquidityUnlockAt), feeBps: Number(record.feeBps),
      liquidityLockId: record.liquidityLockId.toString(), creatorVestingId: record.creatorVestingId.toString(), metadataHash: record.metadataHash,
      coin: { name: coinName, symbol: coinSymbol, totalSupply: coinSupply?.toString() ?? null }, stock: { name: stockName, symbol: stockSymbol },
      state: { reserveCoin: poolState[0].toString(), reserveStock: poolState[1].toString(), lastUpdated: Number(poolState[2]), lpSupply: poolState[3].toString(), swaps: poolState[4].toString(), cumulativeCoinVolume: poolState[5].toString(), cumulativeStockVolume: poolState[6].toString(), spotCoinPerStock: poolState[1] > 0n ? formatUnits(poolState[0] * 10n ** 18n / poolState[1], 18) : null },
      security: { stockEnabled: stockConfig[0], stockEmergencyBlocked: stockConfig[2], poolEmergencyBlocked: poolBlocked, codeMatches, liquidityLocked: Number(record.liquidityUnlockAt) > nowSeconds(), tradeAllowed: false, reason: 'Direct RPC fallback does not assert production gate' }
    })
  }
  return rows
}

async function refreshData(showToast = false) {
  const configResult = await Promise.allSettled([api<IndexerConfig>('/api/config')])
  if (configResult[0].status === 'fulfilled') indexerConfig = normalizeIndexerConfig(configResult[0].value)
  await verifyFactory(true).catch(() => undefined)
  const results = await Promise.allSettled([
    api<NetworkState>('/api/network'),
    api<LaunchView[]>('/api/launches?limit=100'),
    api<ActivityItem[]>('/api/activity'),
    api<ScoutSummary>('/api/scout/summary'),
    api<ScoutContract[]>('/api/scout/contracts?limit=150'),
    api<ScoutPool[]>('/api/scout/pools?limit=100'),
    api<ScoutSwap[]>('/api/scout/swaps?limit=100')
  ])
  if (results[0].status === 'fulfilled') networkState = normalizeNetworkState(results[0].value)
  else {
    const blockNumber = await publicClient.getBlockNumber().catch(() => 0n)
    networkState = { chainId: robinhoodChain.id, network: robinhoodChain.name, blockNumber: blockNumber.toString(), gasPriceWei: '0', configured: launchpadAddress !== zeroAddress, productionTradingEnabled: false }
  }
  if (results[1].status === 'fulfilled' && Array.isArray(results[1].value)) launches = results[1].value.map(normalizeLaunch).filter((item): item is LaunchView => item !== null)
  else launches = await readLaunchesDirect(100).catch(() => [])
  activities = results[2].status === 'fulfilled' && Array.isArray(results[2].value) ? results[2].value.map(normalizeActivity).filter((item): item is ActivityItem => item !== null) : []
  scoutSummary = results[3].status === 'fulfilled' ? (normalizeScoutSummary(results[3].value) ?? scoutSummary) : scoutSummary
  scoutContracts = results[4].status === 'fulfilled' && Array.isArray(results[4].value) ? results[4].value.map(normalizeScoutContract).filter((item): item is ScoutContract => item !== null) : scoutContracts
  scoutPools = results[5].status === 'fulfilled' && Array.isArray(results[5].value) ? results[5].value.map(normalizeScoutPool).filter((item): item is ScoutPool => item !== null) : scoutPools
  scoutSwaps = results[6].status === 'fulfilled' && Array.isArray(results[6].value) ? results[6].value.map(normalizeScoutSwap).filter((item): item is ScoutSwap => item !== null) : scoutSwaps
  await fetchRadar()
  updateChrome()
  renderView()
  if (showToast) toast('Live chain data refreshed', 'success')
}

const pageMeta: Record<View, { group: string; title: string }> = {
  discover: { group: 'Markets', title: 'Discover' },
  trade: { group: 'Markets', title: 'Trade' },
  launch: { group: 'Markets', title: 'Launch' },
  portfolio: { group: 'Markets', title: 'Portfolio' },
  scout: { group: 'Intelligence', title: 'Chain Scout' },
  radar: { group: 'Intelligence', title: 'Launch Radar' },
  scanner: { group: 'Intelligence', title: 'Risk Scanner' },
  activity: { group: 'Intelligence', title: 'Activity' },
  settings: { group: 'System', title: 'Settings' },
  admin: { group: 'System', title: 'Operations' }
}

function updateChrome() {
  document.querySelector('#block-number')!.textContent = networkState?.blockNumber ? Number(networkState.blockNumber).toLocaleString() : '—'
  document.querySelector('#network-name')!.textContent = networkState?.network ?? robinhoodChain.name
  document.querySelector('#network-dot')?.classList.toggle('offline', !networkState)
  const streamOpen = Boolean(eventSource && eventSource.readyState === EventSource.OPEN)
  document.querySelector('#stream-dot')?.classList.toggle('offline', !streamOpen)
  const streamLabel = document.querySelector('#stream-label'); if (streamLabel) streamLabel.textContent = streamOpen ? 'Live' : 'Polling'
  const executionTrustFailure = !directFactoryTrust?.trusted
  const indexerDegraded = !indexerConfig || !serverTrustMatchesBuild(indexerConfig)
  const emergencyIssue = launches.some((item) => item.security.reason?.toLowerCase().includes('pause'))
  const executionLocked = executionTrustFailure || emergencyIssue
  document.querySelector('#incident-banner')?.classList.toggle('hidden', !executionLocked)
  const incidentText = document.querySelector('#incident-banner div span')
  if (incidentText) incidentText.textContent = executionTrustFailure ? (directFactoryTrust?.reason ?? 'On-chain deployment trust anchors do not match this build. All writes are disabled.') : 'An on-chain pause or emergency control blocks new risk. Self-directed exits remain available.'
  document.querySelector('#data-banner')?.classList.toggle('hidden', !indexerDegraded)
  const dataText = document.querySelector('#data-banner div span')
  if (dataText) dataText.textContent = directFactoryTrust?.trusted ? 'Indexer data is unavailable or mismatched. Discovery may be incomplete; every wallet write still performs direct on-chain verification.' : 'Indexer data is unavailable or mismatched. Wallet writes are also blocked because direct on-chain trust is not established.'
  const environmentDot = document.querySelector('#environment-dot')
  environmentDot?.classList.toggle('ok', !executionTrustFailure)
  environmentDot?.classList.toggle('bad', executionTrustFailure)
  const environmentLabel = document.querySelector('#environment-label')
  const environmentDetail = document.querySelector('#environment-detail')
  if (environmentLabel) environmentLabel.textContent = executionTrustFailure ? 'Read-only safety mode' : indexerDegraded ? 'Verified execution · degraded discovery' : 'Verified deployment'
  if (environmentDetail) environmentDetail.textContent = executionTrustFailure ? 'Wallet writes are blocked until direct chain, factory hash and protocol checks pass.' : indexerDegraded ? 'Direct writes are independently verified; indexer-fed discovery is degraded.' : 'Factory, code hash, protocol version and indexer deployment match this build.'
  const meta = pageMeta[activeView]
  const pageKicker = document.querySelector('#page-kicker'); if (pageKicker) pageKicker.textContent = meta.group
  const pageTitle = document.querySelector('#page-title'); if (pageTitle) pageTitle.textContent = meta.title
  const walletLabel = document.querySelector('#wallet-label'); if (walletLabel) walletLabel.textContent = account ? shortAddress(account) : 'Connect wallet'
  document.querySelector('#connect-wallet')?.classList.toggle('connected', Boolean(account))
  document.querySelectorAll<HTMLElement>('[data-view]').forEach((item) => {
    const active = item.dataset.view === activeView
    item.classList.toggle('active', active)
    if (active) item.setAttribute('aria-current', 'page')
    else item.removeAttribute('aria-current')
  })
}

function setView(view: View) {
  activeView = view
  window.location.hash = view
  document.querySelector('#sidebar')?.classList.remove('open')
  updateChrome()
  renderView()
  document.querySelector<HTMLElement>('#view-root')?.focus({ preventScroll: true })
}

function pageHeader(eyebrow: string, title: string, description: string, action = ''): string {
  return `<div class="page-head"><div><span class="eyebrow">${escapeHtml(eyebrow)}</span><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></div>${action}</div>`
}

function emptyState(title: string, text: string, action = ''): string {
  return `<div class="empty-state"><div class="empty-icon">⌁</div><h3>${escapeHtml(title)}</h3><p>${escapeHtml(text)}</p>${action}</div>`
}

function filteredLaunches(): LaunchView[] {
  const query = searchQuery.toLowerCase()
  return launches.filter((item) => {
    const haystack = [item.coin.name, item.coin.symbol, item.stock.name, item.stock.symbol, item.pool, item.coinToken, item.stockToken, item.creator].join(' ').toLowerCase()
    const matchesQuery = !query || haystack.includes(query)
    const matchesRisk = riskFilter === 'all' || riskFor(item).toLowerCase() === riskFilter
    return matchesQuery && matchesRisk
  })
}

function launchCard(item: LaunchView): string {
  const status = riskFor(item)
  const coinSymbol = item.coin.symbol ?? 'COIN'
  const stockSymbol = item.stock.symbol ?? 'STOCK'
  const liquidity = item.state ? `${formatToken(item.state.reserveCoin)} ${coinSymbol} + ${formatToken(item.state.reserveStock)} ${stockSymbol}` : 'Unavailable'
  return `<article class="market-card" data-pool="${escapeAttr(item.pool)}">
    <div class="market-card-head">
      <div class="pair-avatar"><span>${escapeHtml(coinSymbol.slice(0, 2))}</span><small>${escapeHtml(stockSymbol.slice(0, 2))}</small></div>
      <div><h3>${escapeHtml(coinSymbol)} <em>/</em> ${escapeHtml(stockSymbol)}</h3><p>${escapeHtml(item.coin.name ?? 'Launch coin')} paired with ${escapeHtml(item.stock.name ?? 'approved stock token')}</p></div>
      ${badge(status)}
    </div>
    <div class="price-line"><strong>${item.state?.spotCoinPerStock ? formatToken(parseUnits(item.state.spotCoinPerStock, 18)) : '—'}</strong><span>${escapeHtml(coinSymbol)} per ${escapeHtml(stockSymbol)}</span></div>
    <div class="market-stats">
      <div><span>Pool reserves</span><strong>${escapeHtml(liquidity)}</strong></div>
      <div><span>Swaps</span><strong>${Number(item.state?.swaps ?? 0).toLocaleString()}</strong></div>
      <div><span>Fee</span><strong>${(item.feeBps / 100).toFixed(2)}%</strong></div>
      <div><span>Initial LP</span><strong class="${item.security.liquidityLocked ? 'positive' : 'warning-text'}">${escapeHtml(timeRemaining(item.liquidityUnlockAt))}</strong></div>
    </div>
    <div class="market-card-foot">
      <span>Created ${escapeHtml(formatDate(item.createdAt))}</span>
      <button class="text-button" data-open-pool="${escapeAttr(item.pool)}">Open market →</button>
    </div>
  </article>`
}


function saveWatchlist() { localStorage.setItem('stockpair-watchlist', JSON.stringify([...watchlist])) }
function watched(address: string): boolean { return watchlist.has(address.toLowerCase()) }
function toggleWatch(address: string) { const key = address.toLowerCase(); watched(key) ? watchlist.delete(key) : watchlist.add(key); saveWatchlist(); renderView() }
function scoutExplorer(base: string | null | undefined, kind: 'address' | 'tx', value: string): string { return safeExplorerUrl(base, robinhoodChain.blockExplorers?.default.url ?? '', kind, value) }
function evidencePills(evidence: ScoutEvidence[]): string { return evidence.length ? `<div class="evidence-row">${evidence.slice(0, 3).map((item) => `<span class="evidence-pill" title="${escapeAttr(item.source ?? '')}">${escapeHtml(item.entityName ?? item.type)} · ${escapeHtml(item.confidence ?? 'evidence')}</span>`).join('')}</div>` : '<span class="muted">No public attribution evidence</span>' }
function scoutRiskBadge(risk?: ScoutRisk): string { return risk ? badge(risk.status) : badge('CAUTION') }
function timeAgo(seconds?: number | null): string { if (!seconds) return 'time unavailable'; const delta = Math.max(0, nowSeconds() - seconds); if (delta < 60) return `${delta}s ago`; if (delta < 3600) return `${Math.floor(delta/60)}m ago`; if (delta < 86400) return `${Math.floor(delta/3600)}h ago`; return `${Math.floor(delta/86400)}d ago` }
async function fetchRadar(): Promise<void> {
  try {
    const res = await fetch(`${indexerUrl}/api/radar/candidates?limit=50`, { headers: { accept: 'application/json' } })
    if (!res.ok) return
    const data = await res.json()
    if (Array.isArray(data?.candidates)) radarCandidates = data.candidates
  } catch { /* indexer may be unavailable */ }
}

function renderRadar(): string {
  const rows = radarCandidates
  const scoringBar = (v: number) => `<span class="score-bar" style="width:${Math.max(0,Math.min(100,v))}%"></span>`
  return `<section class="section-block">
    <div class="section-heading"><div><h2>◈ Launch Radar</h2><p>Live Robinhood Chain testnet. Scores never authorize execution — every candidate requires review.</p></div></div>
    <div class="scout-grid">${rows.length ? rows.map(c => {
      const s = c.scores || { safety:50, liquidity:0, traction:0, freshness:50, provenance:30 }
      return `<article class="card-surface radar-card">
        <div class="radar-header"><h3>${escapeHtml(c.address?.slice(0,14) || c.id)}</h3><span class="risk-badge ${c.riskScore <= 20 ? 'low' : c.riskScore <= 40 ? 'caution' : 'danger'}">risk ${c.riskScore}/100</span></div>
        <div class="score-grid">
          <div><label>Safety ${Math.round(s.safety)}</label>${scoringBar(s.safety)}</div>
          <div><label>Provenance ${Math.round(s.provenance)}</label>${scoringBar(s.provenance)}</div>
          <div><label>Freshness ${Math.round(s.freshness)}</label>${scoringBar(s.freshness)}</div>
          <div><label>Traction ${Math.round(s.traction)}</label>${scoringBar(s.traction)}</div>
        </div>
        <div class="radar-meta">
          <span>Block #${Number(c.deploymentBlock).toLocaleString()}</span>
          <span>Deployer ${escapeHtml(c.deployer?.slice(0,12) || '?')}...</span>
          <span>${escapeHtml(c.status || 'unverified')}</span>
        </div>
        ${c.executionReview?.blockers?.length ? `<div class="callout danger">⛔ ${c.executionReview.blockers.map(escapeHtml).join('; ')}</div>` : ''}
      </article>`
    }).join('') : emptyState('No candidates yet', 'The Launch Radar refreshes as the Chain Scout discovers new contracts. Ensure the indexer is connected to a live RPC endpoint.')}</div>
    <div class="callout info">◈ Powered by StockPair Launch Intelligence v0.7.0. ${rows.length} candidates indexed.</div>
  </section>`
}

function renderScoutContract(item: ScoutContract): string {
  const name = item.token?.symbol ?? 'CONTRACT'
  const subtitle = item.token ? `${item.token.name ?? 'ERC-20-like token'} · ${item.token.decimals ?? '?'} decimals` : `${item.codeSize.toLocaleString()} byte runtime`
  return `<article class="scout-card"><div class="scout-card-top"><div class="contract-glyph">${escapeHtml(name.slice(0, 2))}</div><div class="grow"><div class="title-line"><h3>${escapeHtml(name)}</h3>${scoutRiskBadge(item.risk)}</div><p>${escapeHtml(subtitle)}</p></div><button class="watch-button ${watched(item.address) ? 'active' : ''}" data-watch="${escapeAttr(item.address)}" aria-label="Toggle watchlist">${watched(item.address) ? '★' : '☆'}</button></div><dl class="mini-facts"><div><dt>Chain</dt><dd>${escapeHtml(item.chain)}</dd></div><div><dt>Deployer</dt><dd><button class="link-button mono" data-deployer="${item.chainId}:${escapeAttr(item.deployer)}">${shortAddress(item.deployer)}</button></dd></div><div><dt>Code family</dt><dd class="mono">${shortAddress(item.codeHash)}</dd></div><div><dt>Created</dt><dd>${escapeHtml(timeAgo(item.timestamp))}</dd></div></dl>${evidencePills(item.evidence)}<div class="card-actions"><a target="_blank" rel="noopener noreferrer" href="${escapeAttr(scoutExplorer(item.explorerUrl, 'address', item.address))}">Explorer ↗</a><button data-scan-token="${escapeAttr(item.address)}">Deep scan</button></div></article>`
}
function renderScoutPool(item: ScoutPool): string { const token0=item.token0Meta?.symbol ?? shortAddress(item.token0); const token1=item.token1Meta?.symbol ?? shortAddress(item.token1); return `<article class="tape-card"><div><span class="event-kicker">NEW ${escapeHtml(item.standard.toUpperCase())} POOL</span><h3>${escapeHtml(token0)} / ${escapeHtml(token1)}</h3><p>${item.verifiedFactory ? escapeHtml(item.factoryName ?? 'Verified configured factory') : 'Unverified factory signature match'}</p></div><div class="tape-meta"><span>${escapeHtml(item.chain)}</span><span>#${Number(item.blockNumber).toLocaleString()}</span><span>${escapeHtml(timeAgo(item.timestamp))}</span></div><a target="_blank" rel="noopener noreferrer" href="${escapeAttr(scoutExplorer(item.explorerUrl, 'tx', item.transactionHash))}">Inspect transaction ↗</a></article>` }
function renderScoutSwap(item: ScoutSwap): string { const amount = Object.entries(item.amounts).map(([k,v]) => `${k.replace('amount','')} ${formatToken(v)}`).join(' · '); return `<article class="swap-tick"><i></i><div><strong>${escapeHtml(item.standard)} swap</strong><span>${escapeHtml(item.chain)} · ${shortAddress(item.pool)}</span></div><div><strong>${escapeHtml(amount || 'Amounts indexed')}</strong><span>${escapeHtml(timeAgo(item.timestamp))}</span></div><a target="_blank" rel="noopener noreferrer" href="${escapeAttr(scoutExplorer(item.explorerUrl, 'tx', item.transactionHash))}">↗</a></article>` }
function filteredScoutContracts(): ScoutContract[] { const q=scoutQuery.toLowerCase(); return scoutContracts.filter((item) => { const matchesType=scoutFilter==='all'||(scoutFilter==='tokens' ? Boolean(item.token) : item.risk.status.toLowerCase()===scoutFilter); const matchesQuery=!q||JSON.stringify(item).toLowerCase().includes(q); return matchesType&&matchesQuery }) }
function renderScout(): string {
  const rows=filteredScoutContracts(); const watchedRows=scoutContracts.filter((item)=>watched(item.address));
  return `${pageHeader('Robinhood Chain intelligence', 'Chain Scout', 'See new contracts, ERC-20-like tokens, DEX pools, swaps, code-family reuse and evidence-backed deployer links as configured chains advance.', '<button class="button primary" id="scout-refresh">Scan latest blocks</button>')}
  <section class="scout-hero"><article class="radar-panel"><div class="radar"><i></i><i></i><i></i><span></span></div><div><span class="live-pill"><i></i>${scoutSummary?.running ? 'SCOUT ACTIVE' : 'SCOUT OFFLINE'}</span><h2>Every configured block. Every top-level deployment.</h2><p>Factory events and swap signatures are streamed alongside contract creation. Public builder labels and matching runtime code are shown as evidence, never as private identity claims.</p><div class="coverage-chips">${(scoutSummary?.coverage ?? []).map((chain)=>`<span>${escapeHtml(chain.name)} · #${chain.head ? Number(chain.head).toLocaleString() : 'syncing'}</span>`).join('')}</div></div></article><article class="scout-stats">${metricCard('New contracts', String(scoutSummary?.counts.contracts ?? 0), 'Current bounded index')}${metricCard('Token contracts', String(scoutSummary?.counts.tokens ?? 0), 'ERC-20 interface detected')}${metricCard('DEX pools', String(scoutSummary?.counts.pools ?? 0), 'Pair/pool creation signatures')}${metricCard('Swap ticks', String(scoutSummary?.counts.swaps ?? 0), 'Observed pool events')}</article></section>
  <section class="section-block"><div class="section-heading"><div><h2>Deployment firehose</h2><p>Filter discoveries by risk, token interface or public evidence.</p></div><div class="filter-row"><input id="scout-search" placeholder="Search symbol, address, deployer or code hash" value="${escapeAttr(scoutQuery)}"><select id="scout-filter"><option value="all">All deployments</option><option value="tokens">Tokens only</option><option value="trusted">Trusted</option><option value="low">Low risk</option><option value="caution">Caution</option><option value="danger">Danger</option><option value="blocked">Blocked</option></select></div></div><div class="scout-grid">${rows.length ? rows.map(renderScoutContract).join('') : emptyState('No matching deployments', 'The scout will populate as configured chain heads advance. Dedicated archive/RPC infrastructure is required for complete historical coverage.')}</div></section>
  <section class="split-feed"><article class="card-surface"><div class="section-heading compact"><div><h2>New DEX pools</h2><p>Factory signature matches; configured factories are marked verified.</p></div></div><div class="tape-list">${scoutPools.length ? scoutPools.slice(0,20).map(renderScoutPool).join('') : '<p class="muted">No pool creation events in the indexed window.</p>'}</div></article><article class="card-surface"><div class="section-heading compact"><div><h2>Live swap tape</h2><p>Raw on-chain swap events. No invented USD values.</p></div></div><div class="swap-list">${scoutSwaps.length ? scoutSwaps.slice(0,30).map(renderScoutSwap).join('') : '<p class="muted">No swap events in the indexed window.</p>'}</div></article></section>
  <section class="section-block"><div class="section-heading"><div><h2>Your watchlist</h2><p>Stored only in this browser. No wallet signature or server account.</p></div></div><div class="scout-grid">${watchedRows.length ? watchedRows.map(renderScoutContract).join('') : emptyState('Watchlist is empty', 'Star a newly detected contract to pin it here and receive live in-app updates.')}</div></section><div class="callout warning">${escapeHtml(scoutSummary?.limitation ?? 'Scout coverage depends on configured RPC and archive endpoints.')}</div>`
}

function renderDiscover(): string {
  const rows = filteredLaunches()
  const approved = launches.filter((item) => item.security.stockEnabled && item.security.codeMatches).length
  const blocked = launches.filter((item) => riskFor(item) === 'BLOCKED').length
  const totalSwaps = launches.reduce((sum, item) => sum + Number(item.state?.swaps ?? 0), 0)
  return `
    ${pageHeader('Live on-chain discovery', 'Robinhood Chain markets', 'Track factory-created coin/stock-token pools, liquidity locks, contract integrity and protocol events in one place.', '<button class="button primary" data-go="launch">Launch a market</button>')}
    <section class="hero-grid">
      <article class="hero-panel">
        <div class="hero-copy"><span class="live-pill"><i></i> LIVE CHAIN DATA</span><h2>Discover markets built around approved tokenized stocks.</h2><p>Every executable market is factory-created. Stock contracts are allowlisted, pinned by runtime code hash, oracle-checked and subject to emergency controls.</p><div class="hero-actions"><button class="button primary" data-go="trade">Trade a verified pool</button><button class="button ghost" data-go="scanner">Scan a contract</button></div></div>
        <div class="chain-orbit" aria-hidden="true"><div class="orbit one"></div><div class="orbit two"></div><div class="orbit-core">RH<br><small>CHAIN</small></div><span class="node n1"></span><span class="node n2"></span><span class="node n3"></span></div>
      </article>
      <article class="security-panel"><div class="panel-title"><span>Execution gate</span>${networkState?.productionTradingEnabled ? badge('TRUSTED') : badge('CAUTION')}</div><h3>${networkState?.productionTradingEnabled ? 'Production execution enabled' : 'Testnet / review mode'}</h3><p>${networkState?.productionTradingEnabled ? 'The indexer production flag is enabled. Contract policy checks still apply to every transaction.' : 'The read-side production gate is disabled. Use testnet until audit, legal approval and canonical addresses are complete.'}</p><ul class="check-list"><li>Factory pools only</li><li>Approved stock contract only</li><li>Code-hash and incident checks</li><li>Self-exit preserved during pause</li></ul></article>
    </section>
    <section class="metric-grid">
      ${metricCard('Markets indexed', launches.length.toLocaleString(), 'Factory launch records')}
      ${metricCard('Approved contracts', approved.toLocaleString(), 'Code hash currently matches')}
      ${metricCard('Recorded swaps', totalSwaps.toLocaleString(), 'Across indexed pools')}
      ${metricCard('Blocked markets', blocked.toLocaleString(), blocked ? 'Requires operator review' : 'No active incident flags')}
    </section>
    <section class="chain-pulse-strip"><div><span class="eyebrow">Chain pulse</span><strong>${scoutSummary?.counts.tokens ?? 0} token contracts</strong><small>${scoutSummary?.counts.pools ?? 0} new DEX pools · ${scoutSummary?.counts.swaps ?? 0} swaps indexed</small></div><button class="button ghost" data-go="scout">Open Chain Scout →</button></section>
    <section class="section-block">
      <div class="section-heading"><div><h2>Market feed</h2><p>Newest factory launches first. No arbitrary token listings.</p></div><div class="filter-row"><select id="risk-filter"><option value="all">All risk states</option><option value="trusted">Trusted</option><option value="low">Low</option><option value="caution">Caution</option><option value="blocked">Blocked</option></select><button class="button ghost small" id="feed-refresh">Refresh feed</button></div></div>
      <div class="market-grid">${rows.length ? rows.map(launchCard).join('') : emptyState('No matching markets', launchpadAddress === zeroAddress ? 'Configure a deployed launchpad address to begin indexing factory pools.' : 'Try another search or risk filter.', '<button class="button primary" data-go="launch">Open launch wizard</button>')}</div>
    </section>`
}

function metricCard(label: string, value: string, detail: string): string {
  return `<article class="metric-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></article>`
}

function selectedLaunch(): LaunchView | undefined {
  return launches.find((item) => item.pool.toLowerCase() === selectedPool?.toLowerCase()) ?? launches[0]
}

function renderTrade(): string {
  const item = selectedLaunch()
  if (!item) return `${pageHeader('Execution', 'Trade', 'Swap only through a factory-created, policy-controlled pool.')}${emptyState('No market selected', 'Create or index a market before trading.', '<button class="button primary" data-go="discover">Browse markets</button>')}`
  selectedPool = item.pool
  const coin = item.coin.symbol ?? 'COIN'
  const stock = item.stock.symbol ?? 'STOCK'
  const status = riskFor(item)
  return `
    ${pageHeader('Verified execution', `${escapeHtml(coin)} / ${escapeHtml(stock)}`, 'Review contract integrity, liquidity and minimum output before signing.', `<a class="button ghost" target="_blank" rel="noopener noreferrer" href="${escapeAttr(explorer(`address/${item.pool}`))}">Pool on explorer ↗</a>`)}
    <div class="trade-layout">
      <section class="trade-main card-surface">
        <div class="trade-tabs"><button class="active" data-trade-tab="swap">Swap</button><button data-trade-tab="add">Add liquidity</button><button data-trade-tab="remove">Remove liquidity</button></div>
        <div id="trade-form-root">${swapForm(item)}</div>
      </section>
      <aside class="trade-side">
        <article class="card-surface security-card">
          <div class="panel-title"><span>Market security</span>${badge(status)}</div>
          <div class="security-score"><strong>${status === 'TRUSTED' ? 'Pass' : status}</strong><span>Execution verdict</span></div>
          <div class="security-rows">
            ${securityRow('Factory pool', true, shortAddress(item.pool))}
            ${securityRow('Stock allowlisted', item.security.stockEnabled, shortAddress(item.stockToken))}
            ${securityRow('Runtime code pinned', item.security.codeMatches, item.security.codeMatches ? 'Exact match' : 'Mismatch')}
            ${securityRow('Pool incident block', !item.security.poolEmergencyBlocked, item.security.poolEmergencyBlocked ? 'Blocked' : 'Clear')}
            ${securityRow('Initial LP lock', item.security.liquidityLocked, timeRemaining(item.liquidityUnlockAt))}
          </div>
          ${item.security.reason ? `<div class="callout danger">${escapeHtml(item.security.reason)}</div>` : ''}
          <button class="button ghost full" data-scan-token="${escapeAttr(item.stockToken)}">Open stock-token scan</button>
        </article>
        <article class="card-surface pool-card"><h3>Pool snapshot</h3><dl><div><dt>Coin reserve</dt><dd>${formatToken(item.state?.reserveCoin)} ${escapeHtml(coin)}</dd></div><div><dt>Stock reserve</dt><dd>${formatToken(item.state?.reserveStock)} ${escapeHtml(stock)}</dd></div><div><dt>LP supply</dt><dd>${formatToken(item.state?.lpSupply)}</dd></div><div><dt>Fee</dt><dd>${(item.feeBps / 100).toFixed(2)}%</dd></div><div><dt>Last sync</dt><dd>${formatDate(item.state?.lastUpdated)}</dd></div></dl></article>
      </aside>
    </div>`
}

function securityRow(label: string, pass: boolean, detail: string): string {
  return `<div><span><i class="${pass ? 'pass' : 'fail'}">${pass ? '✓' : '!'}</i>${escapeHtml(label)}</span><strong>${escapeHtml(detail)}</strong></div>`
}

function swapForm(item: LaunchView): string {
  const coin = item.coin.symbol ?? 'COIN'
  const stock = item.stock.symbol ?? 'STOCK'
  return `<form id="swap-form" class="transaction-form">
    <input type="hidden" name="pool" value="${escapeAttr(item.pool)}" />
    <div class="form-top"><span>You pay</span><button type="button" class="text-button" id="swap-direction">Switch direction ⇅</button></div>
    <div class="token-input"><input name="amount" inputmode="decimal" value="1" aria-label="Input amount" /><select name="direction" aria-label="Swap direction"><option value="stockToCoin">${escapeHtml(stock)}</option><option value="coinToStock">${escapeHtml(coin)}</option></select></div>
    <div class="balance-line"><span>Wallet balance</span><strong id="input-balance">Connect wallet</strong></div>
    <div class="swap-arrow">↓</div>
    <div class="form-top"><span>You receive at least</span><span>Slippage <input class="inline-input" name="slippage" value="30" inputmode="numeric" /> bps</span></div>
    <div class="token-input output"><output id="quote-output">—</output><strong id="output-symbol">${escapeHtml(coin)}</strong></div>
    <div class="quote-details" id="quote-details"><div><span>Pool fee</span><strong>${(item.feeBps / 100).toFixed(2)}%</strong></div><div><span>Price impact</span><strong id="price-impact">—</strong></div><div><span>Transaction deadline</span><strong>20 minutes</strong></div></div>
    <div class="callout ${item.security.tradeAllowed ? 'success' : 'warning'}">${escapeHtml(item.security.tradeAllowed ? 'All mandatory read-side execution checks currently pass.' : item.security.reason ?? 'Production trade gate is not enabled. Testnet transactions may still be used for validation.')}</div>
    <button class="button primary xl full" type="submit" ${riskFor(item) === 'BLOCKED' ? 'disabled' : ''}>${account ? 'Review and swap' : 'Connect wallet to trade'}</button>
    <p class="form-status" id="swap-status"></p>
  </form>`
}

function addLiquidityForm(item: LaunchView): string {
  return `<form id="add-form" class="transaction-form">
    <input type="hidden" name="pool" value="${escapeAttr(item.pool)}" />
    <label>Coin amount<div class="token-input"><input name="coin" value="100" inputmode="decimal" /><strong>${escapeHtml(item.coin.symbol ?? 'COIN')}</strong></div></label>
    <label>Stock amount<div class="token-input"><input name="stock" value="0.01" inputmode="decimal" /><strong>${escapeHtml(item.stock.symbol ?? 'STOCK')}</strong></div></label>
    <label>Slippage tolerance<div class="compact-field"><input name="slippage" value="30" inputmode="numeric" /><span>basis points</span></div></label>
    <div class="callout info">The contract takes only the optimal ratio and rejects fee-on-transfer behavior. Exact token approvals are used.</div>
    <button class="button primary xl full" type="submit" ${riskFor(item) === 'BLOCKED' ? 'disabled' : ''}>Add liquidity</button><p class="form-status" id="add-status"></p>
  </form>`
}

function removeLiquidityForm(item: LaunchView): string {
  return `<form id="remove-form" class="transaction-form">
    <input type="hidden" name="pool" value="${escapeAttr(item.pool)}" />
    <label>LP token amount<div class="token-input"><input name="liquidity" value="1" inputmode="decimal" /><strong>LP</strong></div></label>
    <label>Slippage tolerance<div class="compact-field"><input name="slippage" value="30" inputmode="numeric" /><span>basis points (max 100)</span></div></label><div class="callout info">Minimum outputs are calculated directly from the verified pool preview. They cannot be manually set to zero.</div>
    <div class="callout success">Self-directed withdrawals remain available during protocol pause, stock delisting, code-hash mismatch or pool emergency block.</div>
    <button class="button primary xl full" type="submit">Remove liquidity</button><p class="form-status" id="remove-status"></p>
  </form>`
}

function renderLaunch(): string {
  return `
    ${pageHeader('Factory issuance', 'Launch a coin / stock-token market', 'Create a fixed-supply coin and seed it against an operator-approved Robinhood Stock Token. Initial LP is locked by the protocol.', '<button class="button ghost" data-go="discover">View existing markets</button>')}
    <div class="wizard-layout">
      <form id="launch-form" class="card-surface wizard-form">
        <div class="step-head"><span>01</span><div><h2>Coin identity</h2><p>Names and symbols are immutable after deployment.</p></div></div>
        <div class="two-fields"><label>Coin name<input name="name" maxlength="64" value="Agent Launch Coin" required /></label><label>Symbol<input name="symbol" maxlength="12" value="ALC" required /></label></div>
        <label>Metadata URI or canonical descriptor<input name="metadata" value="ipfs://replace-me" required /><small>Only the keccak256 hash is stored on-chain.</small></label>
        <div class="step-head"><span>02</span><div><h2>Approved stock pair</h2><p>The address must be enabled in the launchpad registry and report 18 decimals.</p></div></div>
        <label>Stock token contract<input name="stock" placeholder="0x..." required /><small><button type="button" class="text-button" id="preflight-stock">Run preflight scan</button></small></label>
        <div id="stock-preflight"></div>
        <div class="step-head"><span>03</span><div><h2>Supply and liquidity</h2><p>Creator allocation is capped at 10% and vests for one year after a 90-day cliff. Initial LP lock is 365 days to 4 years.</p></div></div>
        <div class="three-fields"><label>Total supply<input name="total" value="1000000" inputmode="decimal" required /></label><label>Pool allocation<input name="poolCoin" value="900000" inputmode="decimal" required /></label><label>Creator allocation<input name="creatorCoin" value="100000" inputmode="decimal" required /></label></div>
        <div class="three-fields"><label>Stock seed amount<input name="stockAmount" value="1" inputmode="decimal" required /></label><label>Pool fee (bps)<input name="fee" value="30" inputmode="numeric" required /></label><label>LP lock (days)<input name="lockDays" value="365" inputmode="numeric" required /></label></div>
        <div class="allocation-bar"><span style="width:90%">Pool 90%</span><span>Creator 10%</span></div>
        <div class="launch-review"><div>${securityRow('Fixed supply; no mint hook', true, 'Factory LaunchToken')}</div><div>${securityRow('Initial LP custody', true, 'Immutable locker')}</div><div>${securityRow('Stock runtime pin', true, 'Checked at every action')}</div><div>${securityRow('Emergency exits', true, 'Self-directed')}</div></div>
        <button class="button primary xl full" type="submit">Preflight, approve exact amount and launch</button><p class="form-status" id="launch-status"></p>
      </form>
      <aside class="wizard-side card-surface"><span class="eyebrow">Launch policy</span><h3>Hard constraints</h3><ul class="policy-list"><li><strong>10%</strong><span>Maximum creator allocation with one-year vesting</span></li><li><strong>100 bps</strong><span>Maximum pool fee</span></li><li><strong>365 days</strong><span>Minimum initial LP lock</span></li><li><strong>18 decimals</strong><span>Required stock-token precision</span></li></ul><div class="callout warning">A creator chooses the initial exchange ratio. The launch price is not an appraisal or a representation of fair value.</div><p class="fine-print">Mainnet deployment requires legal review for securities/RWA distribution, sanctions and eligibility controls, canonical stock-token addresses, an external audit, monitoring and an incident-response process.</p></aside>
    </div>`
}

function renderPortfolio(): string {
  return `
    ${pageHeader('Wallet intelligence', 'Portfolio', 'See coin, stock-token and LP positions across factory markets.', account ? `<button class="button ghost" id="refresh-portfolio">Refresh ${shortAddress(account)}</button>` : '<button class="button primary" id="portfolio-connect">Connect wallet</button>')}
    <div id="portfolio-root">${account ? '<div class="loading-panel">Loading on-chain positions…</div>' : emptyState('Connect a wallet', 'Portfolio reads are address-based and never require a signature.', '<button class="button primary" id="empty-connect">Connect wallet</button>')}</div>`
}

function renderScanner(): string {
  return `
    ${pageHeader('Contract intelligence', 'Token risk scanner', 'Inspect runtime code, proxy slots, privileged selectors, explorer verification, holder concentration and launchpad approval.', '')}
    <section class="scanner-hero card-surface"><div><span class="eyebrow">Fail-closed execution</span><h2>Scan before interaction.</h2><p>The scanner is a defense-in-depth signal. It never automatically lists a token. Executable pools remain restricted to factory records and operator-approved stock contracts.</p></div><form id="scanner-form"><input name="token" placeholder="0x token contract" value="${escapeAttr(scanResult?.address ?? '')}" required /><button class="button primary" type="submit">Run full scan</button></form></section>
    <div id="scan-root">${scanResult ? scanReport(scanResult) : `<section class="scan-grid"><article class="card-surface"><h3>Runtime checks</h3><p>Code existence, code hash, common privileged controls, minimal proxy bytecode and EIP-1967 implementation/admin/beacon storage.</p></article><article class="card-surface"><h3>Registry checks</h3><p>Approved stock status, emergency block, pinned runtime hash and 18-decimal compatibility.</p></article><article class="card-surface"><h3>Explorer checks</h3><p>Source verification, changed-bytecode flags, implementation metadata, transfer count and sampled holder concentration.</p></article></section>`}</div>`
}

function scanReport(result: ScanResult): string {
  return `<section class="scan-report">
    <article class="scan-score card-surface"><div class="score-ring ${result.status.toLowerCase()}"><strong>${result.score}</strong><span>/100 risk</span></div><div><span class="eyebrow">Scanner verdict</span><h2>${escapeHtml(result.status)}</h2><p>${escapeHtml(result.metadata.name ?? 'Unknown token')} · ${escapeHtml(result.metadata.symbol ?? 'No symbol')} · ${shortAddress(result.address)}</p>${badge(result.status)}</div><div class="execution-verdict ${result.tradeAllowed ? 'allow' : 'block'}"><strong>${result.tradeAllowed ? 'EXECUTION ALLOWED' : 'EXECUTION BLOCKED'}</strong><span>${result.tradeAllowed ? 'All mandatory protocol checks pass.' : 'The UI will not route this token into a trade.'}</span></div></article>
    <div class="scan-columns">
      <article class="card-surface"><h3>Contract profile</h3><dl class="detail-list"><div><dt>Address</dt><dd><a target="_blank" rel="noopener noreferrer" href="${escapeAttr(explorer(`address/${result.address}`))}">${shortAddress(result.address)} ↗</a></dd></div><div><dt>Decimals</dt><dd>${result.metadata.decimals ?? 'Unreadable'}</dd></div><div><dt>Source verified</dt><dd>${result.explorer.verified === true ? 'Yes' : result.explorer.verified === false ? 'No' : 'Unknown'}</dd></div><div><dt>Code hash</dt><dd class="mono">${shortAddress(result.codeHash)}</dd></div><div><dt>Proxy implementation</dt><dd>${shortAddress(result.proxy.implementation ?? result.explorer.implementation)}</dd></div><div><dt>Top-holder sample</dt><dd>${result.explorer.holderConcentration === null ? 'Unavailable' : `${(result.explorer.holderConcentration * 100).toFixed(2)}%`}</dd></div></dl></article>
      <article class="card-surface"><div class="section-heading compact"><div><h3>Findings</h3><p>${result.findings.length} detector signals</p></div></div><div class="finding-list">${result.findings.length ? result.findings.map((finding) => `<div class="finding ${escapeAttr(finding.severity)}"><span>${escapeHtml(finding.severity)}</span><div><strong>${escapeHtml(finding.signature ?? finding.code)}</strong><p>${escapeHtml(finding.detail)}</p></div></div>`).join('') : '<div class="finding info"><span>info</span><div><strong>No heuristic flags</strong><p>No configured detector matched this bytecode.</p></div></div>'}</div></article>
    </div><div class="callout warning">${escapeHtml(result.limitation)}</div>
  </section>`
}

function renderActivity(): string {
  return `
    ${pageHeader('Protocol tape', 'Live activity', 'Launches, swaps, liquidity changes and emergency controls from the configured contract set.', '<button class="button ghost" id="activity-refresh">Refresh events</button>')}
    <section class="card-surface activity-table-wrap"><div class="table-head"><span>Event</span><span>Market / address</span><span>Block</span><span>Transaction</span></div>${activities.length ? activities.map(activityRow).join('') : emptyState('No indexed events', 'The indexer returns events after a launchpad is configured and activity occurs on-chain.')}</section>`
}

function activityRow(item: ActivityItem): string {
  const label = item.event.replace(/([a-z])([A-Z])/g, '$1 $2')
  const detail = item.args.pool ?? item.args.tokenIn ?? item.args.stockToken ?? item.address
  return `<a class="activity-row" target="_blank" rel="noopener noreferrer" href="${escapeAttr(explorer(`tx/${item.transactionHash}`))}"><span><i class="event-dot ${escapeAttr(item.event.toLowerCase())}"></i><strong>${escapeHtml(label)}</strong></span><span class="mono">${shortAddress(String(detail))}</span><span>#${Number(item.blockNumber).toLocaleString()}</span><span class="mono">${shortAddress(item.transactionHash)} ↗</span></a>`
}

function renderSettings(): string {
  const trust = directFactoryTrust
  const configured = launchpadAddress !== zeroAddress && expectedLaunchpadCodeHash !== ZERO_HASH && expectedProtocolVersion !== ZERO_HASH
  const indexerConnected = Boolean(indexerConfig)
  const streamConnected = Boolean(eventSource && eventSource.readyState === EventSource.OPEN)
  const checks = [
    ['Chain configured', Number.isSafeInteger(robinhoodChain.id) && robinhoodChain.id > 0, `${robinhoodChain.name} · ${robinhoodChain.id}`],
    ['Factory trust anchors', configured, configured ? shortAddress(launchpadAddress) : 'Missing production values'],
    ['Factory bytecode verified', Boolean(trust?.codeHashMatches), trust?.actualCodeHash ? shortAddress(trust.actualCodeHash) : 'Not verified'],
    ['Protocol version verified', Boolean(trust?.versionMatches), trust?.protocolVersion ? shortAddress(trust.protocolVersion) : 'Not verified'],
    ['Read-only indexer', indexerConnected, indexerConnected ? 'API configuration loaded' : 'Unavailable; direct RPC fallback'],
    ['Live event stream', streamConnected, streamConnected ? 'SSE connected' : 'Polling fallback'],
    ['Operations isolated', !enableOperations, enableOperations ? 'Enabled on this origin' : 'Disabled in public build']
  ] as const
  const readyCount = checks.filter(([, pass]) => pass).length
  return `
    ${pageHeader('Environment and support', 'Settings', 'Inspect the exact deployment posture, local browser data and production configuration without exposing administrative keys.', '<button class="button ghost" id="settings-refresh">Re-run verification</button>')}
    <section class="settings-hero card-surface">
      <div class="readiness-score ${readyCount === checks.length ? 'ready' : 'review'}"><strong>${readyCount}/${checks.length}</strong><span>runtime checks</span></div>
      <div><span class="eyebrow">Current browser build</span><h2>${readyCount === checks.length ? 'Verified and connected' : 'Safe review mode'}</h2><p>${readyCount === checks.length ? 'The configured chain, factory code and protocol version match. Contract-level checks still run before every signature.' : 'One or more deployment checks are unavailable or mismatched. Wallet writes remain fail-closed.'}</p></div>
      <div class="settings-actions"><button class="button primary" id="copy-diagnostics">Copy diagnostics</button><a class="button ghost" target="_blank" rel="noopener noreferrer" href="${escapeAttr(robinhoodChain.blockExplorers?.default.url ?? '#')}">Open explorer ↗</a></div>
    </section>
    <div class="settings-grid">
      <article class="card-surface settings-card"><div class="section-heading compact"><div><h2>Runtime verification</h2><p>Live checks from this browser session.</p></div></div><div class="verification-list">${checks.map(([label, pass, detail]) => `<div><i class="${pass ? 'pass' : 'fail'}">${pass ? '✓' : '!'}</i><span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></span></div>`).join('')}</div></article>
      <article class="card-surface settings-card"><div class="section-heading compact"><div><h2>Trust anchors</h2><p>These values are baked into the deployed frontend.</p></div></div><dl class="detail-list technical"><div><dt>Chain ID</dt><dd>${robinhoodChain.id}</dd></div><div><dt>Factory</dt><dd class="mono copyable">${escapeHtml(launchpadAddress)}</dd></div><div><dt>Expected code hash</dt><dd class="mono copyable">${escapeHtml(expectedLaunchpadCodeHash)}</dd></div><div><dt>Protocol version</dt><dd class="mono copyable">${escapeHtml(expectedProtocolVersion)}</dd></div><div><dt>Indexer origin</dt><dd class="mono copyable">${escapeHtml(indexerUrl || 'same origin')}</dd></div></dl></article>
      <article class="card-surface settings-card"><div class="section-heading compact"><div><h2>Privacy and local data</h2><p>No StockPair account is required.</p></div></div><ul class="plain-list"><li>Watchlists stay in this browser's local storage.</li><li>Portfolio reads use the connected public address.</li><li>Transactions are sent directly through the injected wallet.</li><li>The public indexer is read-only and has no signing key.</li></ul><div class="button-row"><button class="button ghost" id="clear-watchlist">Clear watchlist</button><button class="button danger" id="reset-local-data">Reset local data</button></div></article>
      <article class="card-surface settings-card"><div class="section-heading compact"><div><h2>Deployment resources</h2><p>Included in the repository handoff.</p></div></div><div class="resource-links"><a href="/docs/VERCEL_DEPLOYMENT.md" data-doc-link><span>Vercel deployment</span><small>Frontend build, environment and CSP</small></a><a href="/docs/LOCAL_DEVELOPMENT.md" data-doc-link><span>Local launch guide</span><small>One-command demo and troubleshooting</small></a><a href="/docs/AGENT_HANDOFF.md" data-doc-link><span>Agent handoff</span><small>Architecture, guardrails and workflow</small></a><a href="/docs/INCIDENT_RESPONSE.md" data-doc-link><span>Incident response</span><small>Pause, evidence and user protection</small></a></div><div class="callout info">Markdown documentation is available in the GitHub repository. Static Vercel builds intentionally do not expose repository files as public routes.</div></article>
    </div>
    <section class="card-surface support-strip"><div><span class="eyebrow">Need to report a security issue?</span><h2>Do not disclose an active exploit in a public issue.</h2><p>Use the private security contact configured in SECURITY.md and include transaction hashes, chain ID, affected addresses and timestamps.</p></div><button class="button ghost" id="copy-security-checklist">Copy evidence checklist</button></section>`
}

function renderAdmin(): string {
  if (!enableOperations) return `${pageHeader('Restricted', 'Operations disabled', 'Administrative controls are intentionally excluded from this public build.')}<div class="callout danger">Use the separately reviewed multisig/timelock operations console. Never expose administrator controls on the public trading origin.</div>`
  const item = selectedLaunch()
  return `
    ${pageHeader('Guardian and owner controls', 'Operations console', 'Read protocol posture and execute explicit emergency controls from an authorized wallet.', '')}
    <div class="ops-grid">
      <article class="card-surface ops-status"><h2>Protocol posture</h2><div class="big-status ${networkState?.productionTradingEnabled ? 'green' : 'amber'}"><i></i><div><strong>${networkState?.productionTradingEnabled ? 'Production gate enabled' : 'Test / review gate'}</strong><span>Indexer-side execution verdict</span></div></div><dl class="detail-list"><div><dt>Chain</dt><dd>${escapeHtml(networkState?.network ?? robinhoodChain.name)} (${robinhoodChain.id})</dd></div><div><dt>Launchpad</dt><dd class="mono">${shortAddress(launchpadAddress)}</dd></div><div><dt>Indexed markets</dt><dd>${launches.length}</dd></div><div><dt>Connected operator</dt><dd>${escapeHtml(account)}</dd></div></dl><div class="callout warning">Guardian actions can block activity but cannot unpause or clear blocks. Those recovery actions are owner-only.</div></article>
      <article class="card-surface ops-actions"><h2>Emergency controls</h2><div class="button-stack"><button class="button danger" data-admin-action="pause">Pause protocol</button><button class="button ghost" data-admin-action="unpause">Unpause protocol</button></div><hr><label>Selected pool<select id="admin-pool">${launches.map((launch) => `<option value="${escapeAttr(launch.pool)}" ${item?.pool === launch.pool ? 'selected' : ''}>${escapeHtml(launch.coin.symbol ?? 'COIN')}/${escapeHtml(launch.stock.symbol ?? 'STOCK')} · ${shortAddress(launch.pool)}</option>`).join('')}</select></label><div class="button-stack"><button class="button danger" data-admin-action="block-pool">Emergency-block pool</button><button class="button ghost" data-admin-action="clear-pool">Clear pool block</button></div><div class="button-stack"><button class="button danger" data-admin-action="block-stock">Emergency-block stock</button><button class="button ghost" data-admin-action="clear-stock">Clear stock block</button></div><p class="form-status" id="admin-status"></p></article>
      <article class="card-surface ops-checklist"><h2>Mainnet release gates</h2><ul class="release-list"><li class="done">Contracts compile below EIP-170 size limit</li><li class="done">Factory-only tokens and pools</li><li class="done">Initial LP lock and creator cap</li><li class="done">Per-stock and per-pool emergency blocks</li><li class="done">Read-only scanner and indexer</li><li>Independent smart-contract audit</li><li>Legal and securities/RWA review</li><li>Production RPC, archive indexing and alerting</li><li>Multisig/timelock owner deployment</li><li>Runbook tabletop and monitored canary release</li></ul></article>
    </div>`
}

function renderView() {
  const root = document.querySelector<HTMLElement>('#view-root')!
  const renderers: Record<View, () => string> = { discover: renderDiscover, scout: renderScout, radar: renderRadar, trade: renderTrade, launch: renderLaunch, portfolio: renderPortfolio, scanner: renderScanner, activity: renderActivity, settings: renderSettings, admin: renderAdmin }
  root.innerHTML = renderers[activeView]()
  bindViewEvents()
  if (activeView === 'portfolio' && account) void loadPortfolio()
  if (activeView === 'trade') void updateSwapQuote()
}

function bindNavigationEvents(scope: ParentNode = document) {
  scope.querySelectorAll<HTMLElement>('[data-go]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.go as View)))
  scope.querySelectorAll<HTMLElement>('[data-open-pool]').forEach((button) => button.addEventListener('click', () => { selectedPool = getAddress(button.dataset.openPool!); setView('trade') }))
}

function bindTradeFormEvents() {
  document.querySelector('#swap-direction')?.addEventListener('click', () => {
    const select = document.querySelector<HTMLSelectElement>('#swap-form select[name="direction"]')
    if (select) { select.value = select.value === 'stockToCoin' ? 'coinToStock' : 'stockToCoin'; void updateSwapQuote() }
  })
  document.querySelector('#swap-form')?.addEventListener('input', debounce(() => void updateSwapQuote(), 250))
  document.querySelector<HTMLFormElement>('#swap-form')?.addEventListener('submit', submitSwap)
  document.querySelector<HTMLFormElement>('#add-form')?.addEventListener('submit', submitAddLiquidity)
  document.querySelector<HTMLFormElement>('#remove-form')?.addEventListener('submit', submitRemoveLiquidity)
}

function bindViewEvents() {
  bindNavigationEvents()
  document.querySelector('#feed-refresh')?.addEventListener('click', () => void refreshData(true))
  const filter = document.querySelector<HTMLSelectElement>('#risk-filter')
  if (filter) { filter.value = riskFilter; filter.addEventListener('change', () => { riskFilter = filter.value; renderView() }) }
  document.querySelectorAll<HTMLElement>('[data-trade-tab]').forEach((tab) => tab.addEventListener('click', () => switchTradeTab(tab.dataset.tradeTab!)))
  bindTradeFormEvents()
  document.querySelector<HTMLFormElement>('#launch-form')?.addEventListener('submit', submitLaunch)
  document.querySelector('#preflight-stock')?.addEventListener('click', () => void preflightStock())
  document.querySelector<HTMLFormElement>('#scanner-form')?.addEventListener('submit', submitScan)
  document.querySelectorAll<HTMLElement>('[data-scan-token]').forEach((button) => button.addEventListener('click', () => { void scanToken(button.dataset.scanToken!); setView('scanner') }))
  document.querySelector('#activity-refresh')?.addEventListener('click', () => void refreshData(true))
  document.querySelector('#scout-refresh')?.addEventListener('click', () => void refreshData(true))
  const scoutSelect = document.querySelector<HTMLSelectElement>('#scout-filter'); if (scoutSelect) { scoutSelect.value = scoutFilter; scoutSelect.addEventListener('change', () => { scoutFilter = scoutSelect.value; renderView() }) }
  document.querySelector<HTMLInputElement>('#scout-search')?.addEventListener('input', debounce((event: Event) => { scoutQuery = (event.currentTarget as HTMLInputElement).value; renderView() }, 180))
  document.querySelectorAll<HTMLElement>('[data-watch]').forEach((button) => button.addEventListener('click', () => toggleWatch(button.dataset.watch!)))
  document.querySelectorAll<HTMLElement>('[data-deployer]').forEach((button) => button.addEventListener('click', () => { const [chainId,address] = button.dataset.deployer!.split(':'); void showDeployer(Number(chainId), address!) }))
  for (const id of ['portfolio-connect', 'empty-connect']) document.querySelector(`#${id}`)?.addEventListener('click', () => void connectWallet())
  document.querySelector('#refresh-portfolio')?.addEventListener('click', () => void loadPortfolio())
  document.querySelectorAll<HTMLElement>('[data-admin-action]').forEach((button) => button.addEventListener('click', () => void adminAction(button.dataset.adminAction!)))
  document.querySelector('#settings-refresh')?.addEventListener('click', () => void refreshData(true))
  document.querySelector('#copy-diagnostics')?.addEventListener('click', () => void copyText(JSON.stringify({
    appVersion: '0.6.0', chainId: robinhoodChain.id, chainName: robinhoodChain.name, launchpadAddress,
    expectedLaunchpadCodeHash, expectedProtocolVersion, directFactoryTrust, indexerConfig,
    networkState, streamConnected: Boolean(eventSource && eventSource.readyState === EventSource.OPEN),
    userAgent: navigator.userAgent, capturedAt: new Date().toISOString()
  }, null, 2), 'Diagnostics copied'))
  document.querySelector('#clear-watchlist')?.addEventListener('click', () => { watchlist.clear(); saveWatchlist(); toast('Watchlist cleared', 'success'); renderView() })
  document.querySelector('#reset-local-data')?.addEventListener('click', () => { localStorage.removeItem('stockpair-watchlist'); watchlist.clear(); toast('Local StockPair data reset', 'success'); renderView() })
  document.querySelector('#copy-security-checklist')?.addEventListener('click', () => void copyText(`Security report checklist:\n- Chain ID\n- Transaction hash(es)\n- Affected wallet and contract addresses\n- Exact timestamp and timezone\n- Browser build/version\n- Screenshots or wallet prompts\n- Whether approvals were granted\n- Any DNS/CDN or repository alerts`, 'Evidence checklist copied'))
  document.querySelectorAll<HTMLElement>('[data-doc-link]').forEach((link) => link.addEventListener('click', (event) => { event.preventDefault(); toast('Open this guide from the repository docs folder.', 'info') }))
}

function switchTradeTab(tab: string) {
  const item = selectedLaunch()
  if (!item) return
  document.querySelectorAll('[data-trade-tab]').forEach((node) => node.classList.toggle('active', (node as HTMLElement).dataset.tradeTab === tab))
  const root = document.querySelector<HTMLDivElement>('#trade-form-root')!
  root.innerHTML = tab === 'add' ? addLiquidityForm(item) : tab === 'remove' ? removeLiquidityForm(item) : swapForm(item)
  bindTradeFormEvents()
  if (tab === 'swap') void updateSwapQuote()
}

function formValue(form: HTMLFormElement, name: string): string {
  const element = form.elements.namedItem(name)
  if (!(element instanceof HTMLInputElement) && !(element instanceof HTMLSelectElement)) throw new Error(`Missing ${name}`)
  return element.value.trim()
}

function addressValue(value: string, label: string): Address {
  if (!isAddress(value)) throw new Error(`${label} is not a valid EVM address`)
  return getAddress(value)
}

function requireWallet() {
  if (!account || !walletClient) throw new Error('Connect a wallet first')
  return { account, walletClient }
}

async function connectWallet() {
  if (!window.ethereum) throw new Error('No injected EVM wallet found')
  const chainId = `0x${robinhoodChain.id.toString(16)}`
  try { await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }) }
  catch (error) {
    if ((error as { code?: number }).code !== 4902) throw error
    await window.ethereum.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainName: robinhoodChain.name, nativeCurrency: robinhoodChain.nativeCurrency, rpcUrls: robinhoodChain.rpcUrls.default.http, blockExplorerUrls: [robinhoodChain.blockExplorers?.default.url] }] })
  }
  const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' }) as string[]
  account = addressValue(accounts[0] ?? '', 'Wallet')
  walletClient = createWalletClient({ chain: robinhoodChain, transport: custom(window.ethereum) })
  const walletLabel = document.querySelector('#wallet-label'); if (walletLabel) walletLabel.textContent = shortAddress(account)
  toast(`Connected ${shortAddress(account)}`, 'success')
  renderView()
}

async function exactApprove(token: Address, spender: Address, amount: bigint) {
  if (amount < 0n) throw new Error('Approval amount cannot be negative')
  const wallet = requireWallet()
  let allowance = await publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [wallet.account, spender] })
  if (allowance === amount) return
  if (allowance > 0n) await send(token, erc20Abi, 'approve', [spender, 0n])
  if (amount > 0n) await send(token, erc20Abi, 'approve', [spender, amount])
  allowance = await publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [wallet.account, spender] })
  if (allowance !== amount) throw new Error('Token did not set the exact requested allowance')
}

function reviewValue(value: unknown): string {
  if (typeof value === 'bigint') return value.toString()
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) return value.map(reviewValue).join(', ')
  if (value && typeof value === 'object') return Object.entries(value as Record<string, unknown>).map(([key, item]) => `${key}: ${reviewValue(item)}`).join(' · ')
  return String(value ?? '')
}

function transactionPurpose(functionName: string): string {
  const purposes: Record<string, string> = {
    approve: 'Set an exact token allowance for the verified spender',
    swapExactCoinForStock: 'Swap launch coin for stock token', swapExactStockForCoin: 'Swap stock token for launch coin',
    addLiquidity: 'Add liquidity to a verified factory pool', removeLiquidity: 'Withdraw your LP position to your own wallet',
    launch: 'Create a new factory market with locked initial liquidity'
  }
  return purposes[functionName] ?? 'Execute an explicitly allowlisted protocol action'
}

function transactionPolicy(functionName: string, args: readonly unknown[]): string {
  const deadlineArg = ['swapExactCoinForStock', 'swapExactStockForCoin', 'addLiquidity', 'removeLiquidity'].includes(functionName) ? args.at(-1) : functionName === 'launch' && isRecord(args[0]) ? args[0].deadline : null
  const deadlineText = typeof deadlineArg === 'bigint' ? ` · expires ${formatDate(Number(deadlineArg))}` : ''
  const slippageText = functionName.includes('swap') ? ' · on-chain minimum output and ≤3% slippage looseness enforced' : ['addLiquidity', 'removeLiquidity'].includes(functionName) ? ' · on-chain ≤1% liquidity slippage looseness enforced' : ''
  return `30-minute maximum deadline enforced on-chain${deadlineText}${slippageText}`
}

function activateModal(root: HTMLElement, initialSelector: string, onEscape: () => void): () => void {
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
  const dialog = root.querySelector<HTMLElement>('[role="dialog"]')
  const focusableSelector = 'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  const onKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') { event.preventDefault(); onEscape(); return }
    if (event.key !== 'Tab' || !dialog) return
    const focusable = [...dialog.querySelectorAll<HTMLElement>(focusableSelector)].filter((node) => node.offsetParent !== null)
    if (!focusable.length) { event.preventDefault(); dialog.focus(); return }
    const first = focusable[0]!
    const last = focusable.at(-1)!
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
  }
  document.addEventListener('keydown', onKeydown)
  window.requestAnimationFrame(() => (root.querySelector<HTMLElement>(initialSelector) ?? dialog)?.focus())
  return () => { document.removeEventListener('keydown', onKeydown); previous?.focus({ preventScroll: true }) }
}

function reviewTransaction(address: Address, functionName: string, args: readonly unknown[]): Promise<boolean> {
  return new Promise((resolve) => {
    const root = document.querySelector<HTMLDivElement>('#modal-root')!
    let settled = false
    let deactivate = () => {}
    const finish = (approved: boolean) => {
      if (settled) return
      settled = true
      deactivate()
      root.innerHTML = ''
      resolve(approved)
    }
    root.innerHTML = `<div class="modal-backdrop"><section class="modal-card" role="dialog" aria-modal="true" aria-labelledby="tx-review-title" aria-describedby="tx-review-purpose" tabindex="-1"><span class="eyebrow">Wallet transaction review</span><h2 id="tx-review-title">Review before signing</h2><p class="review-purpose" id="tx-review-purpose">${escapeHtml(transactionPurpose(functionName))}</p><dl class="detail-list"><div><dt>Network</dt><dd>${escapeHtml(robinhoodChain.name)} (${robinhoodChain.id})</dd></div><div><dt>Contract</dt><dd class="mono">${escapeHtml(address)}</dd></div><div><dt>Function</dt><dd class="mono">${escapeHtml(functionName)}</dd></div><div><dt>Sender</dt><dd class="mono">${escapeHtml(account)}</dd></div></dl><div class="decoded-call"><strong>Decoded arguments</strong>${args.map((item, index) => `<div><span>${index + 1}</span><code>${escapeHtml(reviewValue(item))}</code></div>`).join('')}</div><div class="callout policy"><strong>Protocol-enforced safety</strong><span>${escapeHtml(transactionPolicy(functionName, args))}</span></div><div class="callout warning">Confirm the wallet shows the same chain, contract and function. StockPair never asks for a seed phrase or private key.</div><div class="modal-actions"><button class="button ghost" id="tx-cancel">Cancel</button><button class="button primary" id="tx-confirm">Continue to wallet</button></div></section></div>`
    root.querySelector('#tx-cancel')?.addEventListener('click', () => finish(false))
    root.querySelector('#tx-confirm')?.addEventListener('click', () => finish(true))
    deactivate = activateModal(root, '#tx-cancel', () => finish(false))
  })
}

async function assertWalletReady(expectedAccount: Address) {
  if (!window.ethereum) throw new Error('Injected wallet disconnected')
  const [chainHex, accounts] = await Promise.all([
    window.ethereum.request({ method: 'eth_chainId' }) as Promise<string>,
    window.ethereum.request({ method: 'eth_accounts' }) as Promise<string[]>
  ])
  if (Number.parseInt(chainHex, 16) !== robinhoodChain.id) throw new Error(`Wallet changed networks. Switch back to chain ${robinhoodChain.id}.`)
  if (!accounts[0] || getAddress(accounts[0]).toLowerCase() !== expectedAccount.toLowerCase()) throw new Error('Wallet account changed before submission')
}

async function authorizeWrite(address: Address, functionName: string, args: readonly unknown[], sender: Address) {
  const factory = ensureConfigured()
  if (address.toLowerCase() === factory.toLowerCase()) {
    await verifyFactory(true)
    const publicFunctions = new Set(['launch'])
    const operationsFunctions = new Set(['pause', 'emergencyBlockPool', 'emergencyBlockStock', 'scheduleAdminAction', 'cancelAdminAction', 'unpause', 'clearPoolEmergencyBlock', 'clearStockEmergencyBlock'])
    if (publicFunctions.has(functionName)) return
    if (!enableOperations || !operationsFunctions.has(functionName)) throw new Error(`Factory function ${functionName} is not allowed by this build`)
    const [owner, guardian] = await Promise.all([
      publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'owner' }),
      publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'guardian' })
    ])
    if (sender.toLowerCase() !== owner.toLowerCase() && sender.toLowerCase() !== guardian.toLowerCase()) throw new Error('Connected wallet is not an authorized protocol operator')
    return
  }

  if (functionName === 'approve') {
    const spender = addressValue(String(args[0] ?? ''), 'Approval spender')
    const amount = typeof args[1] === 'bigint' ? args[1] : BigInt(String(args[1] ?? '0'))
    if (amount < 0n) throw new Error('Approval amount cannot be negative')
    if (amount > 0n) {
      const balance = await publicClient.readContract({ address, abi: erc20Abi, functionName: 'balanceOf', args: [sender] })
      if (amount > balance) throw new Error('Approval amount exceeds the connected wallet balance')
    }
    if (spender.toLowerCase() === factory.toLowerCase()) {
      await verifyStockToken(address)
      return
    }
    const verified = await verifyPool(spender)
    if (address.toLowerCase() !== verified.coin.toLowerCase() && address.toLowerCase() !== verified.stock.toLowerCase()) throw new Error('Approval token is not part of the verified pool')
    return
  }

  const poolFunctions = new Set(['swapExactCoinForStock', 'swapExactStockForCoin', 'addLiquidity', 'removeLiquidity'])
  if (!poolFunctions.has(functionName)) throw new Error(`Contract function ${functionName} is not allowed by this build`)
  const allowIncidentExit = functionName === 'removeLiquidity'
  await verifyPool(address, undefined, undefined, allowIncidentExit)
  const recipientIndex = functionName === 'addLiquidity' ? 5 : functionName === 'removeLiquidity' ? 3 : 2
  const recipient = addressValue(String(args[recipientIndex] ?? ''), 'Recipient')
  if (recipient.toLowerCase() !== sender.toLowerCase()) throw new Error('Recipient must be the connected wallet')
}

async function send(address: Address, abi: Abi, functionName: string, args: readonly unknown[]) {
  const wallet = requireWallet()
  await assertWalletReady(wallet.account)
  await authorizeWrite(address, functionName, args, wallet.account)
  const simulation = await publicClient.simulateContract({ account: wallet.account, address, abi, functionName, args } as never)
  if (!(await reviewTransaction(address, functionName, args))) throw new Error('Transaction cancelled before wallet signature')
  await assertWalletReady(wallet.account)
  await authorizeWrite(address, functionName, args, wallet.account)
  const hash = await wallet.walletClient.writeContract(simulation.request as never)
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 })
  if (receipt.status !== 'success') throw new Error('Transaction reverted')
  return hash
}

async function bestEffortRevoke(token: Address, spender: Address) {
  if (!account) return
  try {
    const allowance = await publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'allowance', args: [account, spender] })
    if (allowance > 0n) await send(token, erc20Abi, 'approve', [spender, 0n])
  } catch (error) {
    toast(`Residual approval could not be revoked automatically: ${errorMessage(error)}`, 'info')
  }
}

async function poolTokens(pool: Address) {
  const verified = await verifyPool(pool)
  return { coin: verified.coin, stock: verified.stock }
}

async function updateSwapQuote() {
  const form = document.querySelector<HTMLFormElement>('#swap-form')
  if (!form) return
  try {
    const pool = addressValue(formValue(form, 'pool'), 'Pool')
    const { coin, stock } = await poolTokens(pool)
    const direction = formValue(form, 'direction')
    const tokenIn = direction === 'stockToCoin' ? stock : coin
    const tokenOut = direction === 'stockToCoin' ? coin : stock
    const amountIn = parseUnits(formValue(form, 'amount') || '0', 18)
    const quote = await publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'quoteExactInput', args: [tokenIn, amountIn] })
    const slippage = BigInt(formValue(form, 'slippage') || '50')
    if (slippage < 0n || slippage > 300n) throw new Error('Swap slippage must be 0–300 bps')
    const minimum = quote * (10_000n - slippage) / 10_000n
    const [inputSymbol, outputSymbol, reserves, balance] = await Promise.all([
      publicClient.readContract({ address: tokenIn, abi: erc20Abi, functionName: 'symbol' }),
      publicClient.readContract({ address: tokenOut, abi: erc20Abi, functionName: 'symbol' }),
      publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'getReserves' }),
      account ? publicClient.readContract({ address: tokenIn, abi: erc20Abi, functionName: 'balanceOf', args: [account] }) : Promise.resolve(null)
    ])
    const reserveIn = direction === 'stockToCoin' ? reserves[1] : reserves[0]
    const reserveOut = direction === 'stockToCoin' ? reserves[0] : reserves[1]
    const executionPrice = quote > 0n ? Number(formatUnits(amountIn * 10n ** 18n / quote, 18)) : 0
    const midPrice = reserveOut > 0n ? Number(formatUnits(reserveIn * 10n ** 18n / reserveOut, 18)) : 0
    const impact = midPrice > 0 && executionPrice > 0 ? Math.max(0, (executionPrice / midPrice - 1) * 100) : 0
    const output = document.querySelector<HTMLOutputElement>('#quote-output')
    if (output) output.value = formatToken(minimum)
    const symbolNode = document.querySelector('#output-symbol'); if (symbolNode) symbolNode.textContent = outputSymbol
    const balanceNode = document.querySelector('#input-balance'); if (balanceNode) balanceNode.textContent = balance === null ? 'Connect wallet' : `${formatToken(balance)} ${inputSymbol}`
    const impactNode = document.querySelector('#price-impact'); if (impactNode) { impactNode.textContent = `${impact.toFixed(2)}%`; impactNode.className = impact > 5 ? 'negative' : impact > 1 ? 'warning-text' : 'positive' }
    form.dataset.tokenIn = tokenIn
    form.dataset.amountIn = amountIn.toString()
    form.dataset.minimum = minimum.toString()
    form.dataset.direction = direction
    form.dataset.priceImpact = impact.toString()
  } catch (error) {
    const output = document.querySelector<HTMLOutputElement>('#quote-output'); if (output) output.value = '—'
    const status = document.querySelector('#swap-status'); if (status) status.textContent = errorMessage(error)
  }
}

async function submitSwap(event: SubmitEvent) {
  event.preventDefault()
  const form = event.currentTarget as HTMLFormElement
  const status = document.querySelector('#swap-status')!
  let approval: { token: Address; spender: Address } | null = null
  try {
    if (!account) return await connectWallet()
    await updateSwapQuote()
    const pool = addressValue(formValue(form, 'pool'), 'Pool')
    const tokenIn = addressValue(form.dataset.tokenIn ?? '', 'Input token')
    const amountIn = BigInt(form.dataset.amountIn ?? 0)
    const minimum = BigInt(form.dataset.minimum ?? 0)
    if (amountIn <= 0n || minimum <= 0n) throw new Error('Enter an amount that produces a non-zero quote')
    if (Number(form.dataset.priceImpact ?? '100') > 5) throw new Error('Price impact exceeds the 5% browser safety cap')
    await verifyPool(pool)
    status.textContent = 'Approving exact input amount…'
    await exactApprove(tokenIn, pool, amountIn)
    approval = { token: tokenIn, spender: pool }
    status.textContent = 'Submitting swap…'
    const fn = form.dataset.direction === 'stockToCoin' ? 'swapExactStockForCoin' : 'swapExactCoinForStock'
    const hash = await send(pool, poolAbi, fn, [amountIn, minimum, account, deadline()])
    status.innerHTML = `Confirmed: <a target="_blank" rel="noopener noreferrer" href="${escapeAttr(explorer(`tx/${hash}`))}">${shortAddress(hash)} ↗</a>`
    toast('Swap confirmed', 'success')
    await refreshData()
  } catch (error) { status.textContent = errorMessage(error); toast(errorMessage(error), 'error') }
  finally { if (approval) await bestEffortRevoke(approval.token, approval.spender) }
}

async function submitAddLiquidity(event: SubmitEvent) {
  event.preventDefault()
  const form = event.currentTarget as HTMLFormElement
  const status = document.querySelector('#add-status')!
  const approvals: Array<{ token: Address; spender: Address }> = []
  try {
    if (!account) return await connectWallet()
    const pool = addressValue(formValue(form, 'pool'), 'Pool')
    const { coin, stock } = await poolTokens(pool)
    const coinDesired = parseUnits(formValue(form, 'coin'), 18)
    const stockDesired = parseUnits(formValue(form, 'stock'), 18)
    const slippage = BigInt(formValue(form, 'slippage'))
    if (slippage < 0n || slippage > 100n) throw new Error('Liquidity slippage must be 0–100 bps')
    const preview = await publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'previewAddLiquidity', args: [coinDesired, stockDesired] })
    if (preview[2] === 0n) throw new Error('Deposit is too small or pool is unavailable')
    status.textContent = 'Approving exact optimal amounts…'
    await exactApprove(coin, pool, preview[0]); approvals.push({ token: coin, spender: pool })
    await exactApprove(stock, pool, preview[1]); approvals.push({ token: stock, spender: pool })
    await verifyPool(pool, coin, stock)
    const hash = await send(pool, poolAbi, 'addLiquidity', [coinDesired, stockDesired, preview[0] * (10_000n - slippage) / 10_000n, preview[1] * (10_000n - slippage) / 10_000n, preview[2] * (10_000n - slippage) / 10_000n, account, deadline()])
    status.textContent = `Confirmed ${shortAddress(hash)}`; toast('Liquidity added', 'success'); await refreshData()
  } catch (error) { status.textContent = errorMessage(error); toast(errorMessage(error), 'error') }
  finally { for (const approval of approvals) await bestEffortRevoke(approval.token, approval.spender) }
}

async function submitRemoveLiquidity(event: SubmitEvent) {
  event.preventDefault()
  const form = event.currentTarget as HTMLFormElement
  const status = document.querySelector('#remove-status')!
  try {
    if (!account) return await connectWallet()
    const pool = addressValue(formValue(form, 'pool'), 'Pool')
    const liquidity = parseUnits(formValue(form, 'liquidity'), 18)
    const slippage = BigInt(formValue(form, 'slippage'))
    if (slippage < 0n || slippage > 100n) throw new Error('Liquidity slippage must be 0–100 bps')
    await verifyPool(pool, undefined, undefined, true)
    const preview = await publicClient.readContract({ address: pool, abi: poolAbi, functionName: 'previewRemoveLiquidity', args: [liquidity] })
    const coinMin = preview[0] * (10_000n - slippage) / 10_000n
    const stockMin = preview[1] * (10_000n - slippage) / 10_000n
    const hash = await send(pool, poolAbi, 'removeLiquidity', [liquidity, coinMin, stockMin, account, deadline()])
    status.textContent = `Confirmed ${shortAddress(hash)}`; toast('Liquidity removed', 'success'); await refreshData()
  } catch (error) { status.textContent = errorMessage(error); toast(errorMessage(error), 'error') }
}

async function preflightStock() {
  const form = document.querySelector<HTMLFormElement>('#launch-form')!
  const root = document.querySelector<HTMLDivElement>('#stock-preflight')!
  try {
    const stock = addressValue(formValue(form, 'stock'), 'Stock token')
    root.innerHTML = '<div class="loading-panel small">Running registry and bytecode checks…</div>'
    const result = normalizeScanResult(await api<unknown>(`/api/scan/${stock}`))
    if (!result) throw new Error('Indexer returned an invalid scan response')
    root.innerHTML = `<div class="preflight ${result.tradeAllowed ? 'pass' : 'fail'}">${badge(result.status)}<div><strong>${escapeHtml(result.metadata.symbol ?? shortAddress(stock))}</strong><span>${result.tradeAllowed ? 'Mandatory checks pass' : escapeHtml(result.findings[0]?.detail ?? 'Execution blocked')}</span></div></div>`
  } catch (error) { root.innerHTML = `<div class="callout danger">${escapeHtml(errorMessage(error))}</div>` }
}

async function submitLaunch(event: SubmitEvent) {
  event.preventDefault()
  const form = event.currentTarget as HTMLFormElement
  const status = document.querySelector('#launch-status')!
  let approval: { token: Address; spender: Address } | null = null
  try {
    if (!account) return await connectWallet()
    const factory = ensureConfigured()
    const stock = addressValue(formValue(form, 'stock'), 'Stock token')
    status.textContent = 'Checking registry, runtime hash and oracle…'
    await verifyFactory(true)
    await verifyStockToken(stock)
    const total = parseUnits(formValue(form, 'total'), 18)
    const poolCoin = parseUnits(formValue(form, 'poolCoin'), 18)
    const creatorCoin = parseUnits(formValue(form, 'creatorCoin'), 18)
    if (poolCoin + creatorCoin !== total) throw new Error('Pool plus creator allocation must equal total supply')
    if (creatorCoin * 10_000n > total * 1_000n) throw new Error('Creator allocation exceeds the 10% protocol cap')
    const stockAmount = parseUnits(formValue(form, 'stockAmount'), 18)
    const lockDays = Number(formValue(form, 'lockDays'))
    if (!Number.isInteger(lockDays) || lockDays < 365 || lockDays > 1460) throw new Error('LP lock must be 365–1460 days')
    status.textContent = 'Approving exact stock seed…'
    await exactApprove(stock, factory, stockAmount)
    approval = { token: stock, spender: factory }
    const hash = await send(factory, launchpadAbi, 'launch', [{
      name: formValue(form, 'name'), symbol: formValue(form, 'symbol').toUpperCase(), metadataHash: keccak256(toBytes(formValue(form, 'metadata'))), stockToken: stock,
      totalCoinSupply: total, poolCoinAmount: poolCoin, creatorCoinAmount: creatorCoin, stockAmount, feeBps: Number(formValue(form, 'fee')),
      liquidityLockDuration: lockDays * 86_400, minInitialLiquidity: 1n, deadline: deadline()
    }])
    status.textContent = `Launch confirmed ${shortAddress(hash)}`; toast('Market launched', 'success'); await refreshData(); setView('discover')
  } catch (error) { status.textContent = errorMessage(error); toast(errorMessage(error), 'error') }
  finally { if (approval) await bestEffortRevoke(approval.token, approval.spender) }
}

async function submitScan(event: SubmitEvent) {
  event.preventDefault()
  const form = event.currentTarget as HTMLFormElement
  await scanToken(formValue(form, 'token'))
}

async function scanToken(value: string) {
  try {
    const token = addressValue(value, 'Token')
    const root = document.querySelector('#scan-root'); if (root) root.innerHTML = '<div class="loading-panel">Inspecting runtime code, registry, explorer and holder signals…</div>'
    const parsed = normalizeScanResult(await api<unknown>(`/api/scan/${token}`))
    if (!parsed) throw new Error('Indexer returned an invalid scan response')
    scanResult = parsed
    if (activeView === 'scanner') renderView()
  } catch (error) { toast(errorMessage(error), 'error') }
}

async function loadPortfolio() {
  const root = document.querySelector<HTMLDivElement>('#portfolio-root')
  if (!root || !account) return
  try {
    const raw = await api<unknown>(`/api/portfolio/${account}`)
    const rows = isRecord(raw) && Array.isArray(raw.positions) ? raw.positions.map((entry) => {
      if (!isRecord(entry) || !isRecord(entry.balances)) return null
      const launch = normalizeLaunch(entry)
      return launch ? { ...launch, balances: { coin: safeNumericString(entry.balances.coin), stock: safeNumericString(entry.balances.stock), lp: safeNumericString(entry.balances.lp) } } : null
    }).filter((item): item is LaunchView & { balances: { coin: string; stock: string; lp: string } } => item !== null) : []
    root.innerHTML = rows.length ? `<div class="portfolio-grid">${rows.map((item) => `<article class="position-card card-surface"><div class="market-card-head"><div class="pair-avatar"><span>${escapeHtml((item.coin.symbol ?? 'CO').slice(0, 2))}</span><small>${escapeHtml((item.stock.symbol ?? 'ST').slice(0, 2))}</small></div><div><h3>${escapeHtml(item.coin.symbol ?? 'COIN')} / ${escapeHtml(item.stock.symbol ?? 'STOCK')}</h3><p>${shortAddress(item.pool)}</p></div>${badge(riskFor(item))}</div><div class="position-balances"><div><span>Launch coin</span><strong>${formatToken(item.balances.coin)}</strong></div><div><span>Stock token</span><strong>${formatToken(item.balances.stock)}</strong></div><div><span>LP position</span><strong>${formatToken(item.balances.lp)}</strong></div></div><button class="button ghost full" data-open-pool="${escapeAttr(item.pool)}">Manage position</button></article>`).join('')}</div>` : emptyState('No positions found', 'This wallet has no non-zero coin, stock-token or LP balances in indexed factory markets.', '<button class="button ghost" data-go="discover">Browse markets</button>')
    bindNavigationEvents(root)
  } catch (error) { root.innerHTML = `<div class="callout danger">${escapeHtml(errorMessage(error))}</div>` }
}

async function adminAction(action: string) {
  const status = document.querySelector('#admin-status')
  try {
    if (!account) return await connectWallet()
    const factory = ensureConfigured()
    await verifyFactory()
    if (!enableOperations) throw new Error('Operations are disabled in this public build')
    const [owner, guardian] = await Promise.all([publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'owner' }), publicClient.readContract({ address: factory, abi: launchpadAbi, functionName: 'guardian' })])
    if (account.toLowerCase() !== owner.toLowerCase() && account.toLowerCase() !== guardian.toLowerCase()) throw new Error('Connected wallet is not an authorized owner or guardian')
    const pool = addressValue(document.querySelector<HTMLSelectElement>('#admin-pool')?.value ?? '', 'Pool')
    const launch = launches.find((item) => item.pool.toLowerCase() === pool.toLowerCase())
    let fn: string; let args: readonly unknown[] = []
    if (action === 'pause') fn = 'pause'
    else if (action === 'unpause') fn = 'unpause'
    else if (action === 'block-pool') { fn = 'emergencyBlockPool'; args = [pool] }
    else if (action === 'clear-pool') { fn = 'clearPoolEmergencyBlock'; args = [pool] }
    else if (action === 'block-stock') { fn = 'emergencyBlockStock'; args = [launch?.stockToken ?? zeroAddress] }
    else if (action === 'clear-stock') { fn = 'clearStockEmergencyBlock'; args = [launch?.stockToken ?? zeroAddress] }
    else throw new Error('Unknown operation')
    if (status) status.textContent = `Submitting ${fn}…`
    const hash = await send(factory, launchpadAbi, fn, args)
    if (status) status.textContent = `Confirmed ${shortAddress(hash)}`
    toast('Operations transaction confirmed', 'success'); await refreshData()
  } catch (error) { if (status) status.textContent = errorMessage(error); toast(errorMessage(error), 'error') }
}


async function showDeployer(chainId: number, address: string) {
  try {
    const result = normalizeScoutDeployer(await api<unknown>(`/api/scout/deployer/${chainId}/${address}`))
    if (!result) throw new Error('Indexer returned an invalid deployer response')
    const root = document.querySelector<HTMLDivElement>('#modal-root')!
    let deactivate = () => {}
    const close = () => { deactivate(); root.innerHTML = '' }
    root.innerHTML = `<div class="modal-backdrop" data-close-modal><section class="modal-card wide" role="dialog" aria-modal="true" aria-labelledby="deployer-graph-title" tabindex="-1"><button class="modal-close" data-close-modal aria-label="Close deployer graph">×</button><span class="eyebrow">Evidence-backed deployer graph</span><h2 id="deployer-graph-title">${shortAddress(result.address)}</h2><div class="metric-grid compact">${metricCard('Contracts', String(result.contracts), 'Indexed deployments')}${metricCard('Tokens', String(result.tokens), 'ERC-20-like')}${metricCard('Code families', String(result.codeHashes.length), 'Distinct runtime hashes')}</div>${evidencePills(result.evidence)}<div class="deployment-list">${result.deployments.slice(0,20).map((item)=>`<a target="_blank" rel="noopener noreferrer" href="${escapeAttr(scoutExplorer(item.explorerUrl,'address',item.address))}"><strong>${escapeHtml(item.token?.symbol ?? 'Contract')}</strong><span>${shortAddress(item.address)}</span><small>#${Number(item.blockNumber).toLocaleString()}</small></a>`).join('') || '<p>No deployments in the bounded index.</p>'}</div><div class="callout warning">Connections are based only on same deployer, exact runtime code reuse and configured public labels. They do not prove common beneficial ownership.</div></section></div>`
    deactivate = activateModal(root, '.modal-close', close)
    root.querySelectorAll('[data-close-modal]').forEach((node)=>node.addEventListener('click',(event)=>{ if(event.target===node) close() }))
  } catch (error) { toast(errorMessage(error),'error') }
}

function connectScoutStream() {
  if (!('EventSource' in window) || eventSource) return
  eventSource = new EventSource(`${indexerUrl}/api/stream`)
  eventSource.addEventListener('open', () => updateChrome())
  eventSource.addEventListener('scout', (raw) => {
    try {
      const payload = (raw as MessageEvent).data
      if (typeof payload !== 'string' || payload.length > 256_000) throw new Error('Invalid stream payload')
      const event = JSON.parse(payload) as unknown
      if (!isRecord(event)) throw new Error('Invalid stream event')
      const kind = boundedText(event.kind, 40)
      if (kind === 'contract-created' || kind === 'token-detected') { const item = normalizeScoutContract(event); if (!item) throw new Error('Invalid contract stream event'); scoutContracts = [item, ...scoutContracts.filter((row)=>row.address.toLowerCase()!==item.address.toLowerCase())].slice(0,150); if (item.evidence.length) toast(`Publicly labeled builder activity: ${item.token?.symbol ?? shortAddress(item.address)}`, 'info') }
      if (kind === 'pool-created') { const item = normalizeScoutPool(event); if (!item) throw new Error('Invalid pool stream event'); scoutPools = [item, ...scoutPools].slice(0,100); if (watched(item.token0) || watched(item.token1) || watched(item.pool)) toast('Watchlist alert: new pool relationship detected', 'info') }
      if (kind === 'swap-observed') { const item = normalizeScoutSwap(event); if (!item) throw new Error('Invalid swap stream event'); scoutSwaps = [item, ...scoutSwaps].slice(0,100); if (watched(item.pool)) toast('Watchlist alert: swap observed', 'info') }
      if (activeView === 'scout' || activeView === 'radar' || activeView === 'discover') renderView()
    } catch { /* malformed stream item is ignored */ }
  })
  eventSource.onerror = () => updateChrome()
}

function debounce<T extends (...args: never[]) => void>(fn: T, wait: number) {
  let timer: number | undefined
  return (...args: Parameters<T>) => { window.clearTimeout(timer); timer = window.setTimeout(() => fn(...args), wait) }
}

document.querySelector('#connect-wallet')!.addEventListener('click', () => void connectWallet().catch((error) => toast(errorMessage(error), 'error')))
document.querySelector('#refresh-all')!.addEventListener('click', () => void refreshData(true))
document.querySelector('#menu-button')!.addEventListener('click', () => document.querySelector('#sidebar')?.classList.toggle('open'))
document.querySelector<HTMLInputElement>('#global-search')!.addEventListener('input', (event) => { searchQuery = (event.currentTarget as HTMLInputElement).value; if (activeView !== 'discover') setView('discover'); else renderView() })
document.addEventListener('keydown', (event) => { if (event.key === '/' && document.activeElement?.tagName !== 'INPUT') { event.preventDefault(); document.querySelector<HTMLInputElement>('#global-search')?.focus() } })
window.addEventListener('hashchange', () => { const value = window.location.hash.slice(1) as View; if (['discover', 'scout', 'trade', 'launch', 'portfolio', 'scanner', 'activity', 'settings'].includes(value) || (enableOperations && value === 'admin')) setView(value) })

if (window.ethereum) {
  window.ethereum.on?.('accountsChanged', (value: unknown) => {
    const values = value as string[]
    account = values[0] && isAddress(values[0]) ? getAddress(values[0]) : undefined
    const walletLabel = document.querySelector('#wallet-label'); if (walletLabel) walletLabel.textContent = account ? shortAddress(account) : 'Connect wallet'
    renderView()
  })
  window.ethereum.on?.('chainChanged', () => window.location.reload())
}
window.addEventListener('hashchange', () => { const value = window.location.hash.slice(1) as View; if (['discover', 'scout', 'radar', 'trade', 'launch', 'portfolio', 'scanner', 'activity', 'settings'].includes(value) || (enableOperations && value === 'admin')) setView(value) })
const initialHash = window.location.hash.slice(1) as View
if (['discover', 'scout', 'radar', 'trade', 'launch', 'portfolio', 'scanner', 'activity', 'settings'].includes(initialHash) || (enableOperations && initialHash === 'admin')) activeView = initialHash
renderView()
connectScoutStream()
void refreshData()
pollingTimer = window.setInterval(() => void refreshData(), 15_000)
window.addEventListener('beforeunload', () => { if (pollingTimer) window.clearInterval(pollingTimer); eventSource?.close() })
