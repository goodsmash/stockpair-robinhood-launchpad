import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import ganache from 'ganache'
import { deployLocalNode } from './deploy-local-node.mjs'

const host = '127.0.0.1'
const rpcPort = 8545
const rpcUrl = `http://${host}:${rpcPort}`
const server = ganache.server({
  logging: { quiet: true },
  wallet: { deterministic: true, totalAccounts: 10 },
  chain: { chainId: 31337, hardfork: 'shanghai' },
  miner: { blockGasLimit: 40_000_000 }
})

const children = []
function child(command, args, options = {}) {
  const process = spawn(command, args, { stdio: 'inherit', ...options })
  children.push(process)
  process.on('exit', (code) => { if (code && code !== 0) console.error(`${command} exited with ${code}`) })
  return process
}

async function stop() {
  for (const process of children) process.kill('SIGTERM')
  await server.close().catch(() => undefined)
}

process.on('SIGINT', async () => { await stop(); process.exit(0) })
process.on('SIGTERM', async () => { await stop(); process.exit(0) })

try {
  await server.listen(rpcPort, host)
  console.log(`Local Robinhood-compatible EVM running at ${rpcUrl}`)
  const initial = server.provider.getInitialAccounts()
  const first = Object.values(initial)[0]
  const deployment = await deployLocalNode({ rpcUrl, chainId: 31337, privateKey: first.secretKey })
  console.log(`Launchpad: ${deployment.launchpad}`)
  console.log(`Demo pool: ${deployment.pool}`)
  console.log(`Funded unlocked test account: ${deployment.fundedTrader}`)
  child(process.execPath, ['services/indexer/src/server.mjs'], {
    env: { ...process.env, PORT: '8787', RH_CHAIN_ID: '31337', RH_CHAIN_NAME: 'StockPair Local', RH_RPC_URL: rpcUrl, RH_EXPLORER_URL: 'http://127.0.0.1:8545', LAUNCHPAD_ADDRESS: deployment.launchpad, LAUNCHPAD_CODE_HASH: deployment.launchpadCodeHash, LAUNCHPAD_PROTOCOL_VERSION: deployment.protocolVersion, PRODUCTION_TRADING_ENABLED: 'true', LOCAL_DEMO_ACK: 'I_UNDERSTAND_THIS_IS_DISPOSABLE', REQUIRE_EXPLORER_VERIFICATION: 'false', SCOUT_CHAINS_JSON: JSON.stringify([{ chainId: 31337, name: 'StockPair Local', rpcUrl, explorerUrl: 'http://127.0.0.1:8545' }]), SCOUT_INITIAL_LOOKBACK: '50', SCOUT_MAX_BLOCKS_PER_POLL: '50' }
  })
  child('npm', ['run', 'dev', '--', '--host', host], { cwd: fileURLToPath(new URL('../apps/web/', import.meta.url)), env: process.env })
  console.log('Web UI: http://127.0.0.1:5173')
  console.log('Indexer: http://127.0.0.1:8787/health')
} catch (error) {
  console.error(error)
  await stop()
  process.exit(1)
}
