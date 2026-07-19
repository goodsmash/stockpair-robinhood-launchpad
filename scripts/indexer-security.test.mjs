import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'

const server = fs.readFileSync(new URL('../services/indexer/src/server.mjs', import.meta.url), 'utf8')
const config = fs.readFileSync(new URL('../services/indexer/src/config.mjs', import.meta.url), 'utf8')

test('indexer enforces bounded streams and cross-origin API isolation', () => {
  assert.match(server, /cross-origin-resource-policy': 'cross-origin'/)
  assert.match(server, /x-stockpair-api-version': '0\.6\.0'/)
  assert.match(server, /function removeStream/)
  assert.match(server, /function writeStream/)
  assert.match(server, /!client\.res\.write\(payload\)/)
  assert.match(server, /isIP\(item\)/)
})

test('production config rejects local, credentialed or path origins', () => {
  assert.match(config, /safeOrigin/)
  assert.match(config, /Production trading requires HTTPS non-loopback ALLOWED_ORIGINS/)
  const base = {
    ...process.env,
    PRODUCTION_TRADING_ENABLED: 'true',
    LAUNCHPAD_ADDRESS: '0x1111111111111111111111111111111111111111',
    LAUNCHPAD_CODE_HASH: `0x${'1'.repeat(64)}`,
    LAUNCHPAD_PROTOCOL_VERSION: `0x${'2'.repeat(64)}`,
    RH_RPC_URL: 'https://rpc.example.com'
  }
  for (const origin of ['http://localhost:5173', 'https://user:pass@app.example', 'https://app.example/path']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./services/indexer/src/config.mjs').then(m=>m.loadConfig())"], { cwd: new URL('..', import.meta.url), env: { ...base, ALLOWED_ORIGINS: origin }, encoding: 'utf8' })
    assert.notEqual(result.status, 0, origin)
  }
})


test('explicit disposable local demo acknowledgement is narrowly scoped', () => {
  const local = {
    ...process.env,
    RH_CHAIN_ID: '31337',
    RH_RPC_URL: 'http://127.0.0.1:8545',
    RH_EXPLORER_URL: 'http://127.0.0.1:8545',
    ALLOWED_ORIGINS: 'http://127.0.0.1:5173',
    PRODUCTION_TRADING_ENABLED: 'true',
    LOCAL_DEMO_ACK: 'I_UNDERSTAND_THIS_IS_DISPOSABLE',
    LAUNCHPAD_ADDRESS: '0x1111111111111111111111111111111111111111',
    LAUNCHPAD_CODE_HASH: `0x${'1'.repeat(64)}`,
    LAUNCHPAD_PROTOCOL_VERSION: `0x${'2'.repeat(64)}`
  }
  const accepted = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./services/indexer/src/config.mjs').then(m=>m.loadConfig())"], { cwd: new URL('..', import.meta.url), env: local, encoding: 'utf8' })
  assert.equal(accepted.status, 0, accepted.stderr)
  const rejected = spawnSync(process.execPath, ['--input-type=module', '-e', "import('./services/indexer/src/config.mjs').then(m=>m.loadConfig())"], { cwd: new URL('..', import.meta.url), env: { ...local, RH_CHAIN_ID: '46630' }, encoding: 'utf8' })
  assert.notEqual(rejected.status, 0)
})
