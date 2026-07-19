import test from 'node:test'
import assert from 'node:assert/strict'
import { StockPairLaunchIntelligenceClient } from '../packages/launch-intelligence-sdk/src/index.js'

test('agent SDK constructs bounded read-only requests', async () => {
  const calls = []
  const fetch = async (url, options) => {
    calls.push({ url, options })
    return new Response(JSON.stringify({ generatedAt: '2026-07-19T00:00:00.000Z', count: 0, total: 0, candidates: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    })
  }
  const client = new StockPairLaunchIntelligenceClient({ baseUrl: 'https://indexer.example.com', fetch })
  const result = await client.getCandidates({ chainId: 4663, minScore: 70 })
  assert.equal(result.count, 0)
  assert.match(calls[0].url, /chainId=4663/)
  assert.match(calls[0].url, /minScore=70/)
  assert.equal(calls[0].options.headers.accept, 'application/json')
})

test('agent SDK rejects credential-bearing, non-http and insecure remote URLs', () => {
  assert.throws(() => new StockPairLaunchIntelligenceClient({ baseUrl: 'javascript:alert(1)' }), /invalid indexer URL/)
  assert.throws(() => new StockPairLaunchIntelligenceClient({ baseUrl: 'https://user:pass@example.com' }), /invalid indexer URL/)
  assert.throws(() => new StockPairLaunchIntelligenceClient({ baseUrl: 'http://indexer.example.com' }), /must use HTTPS/)
  assert.doesNotThrow(() => new StockPairLaunchIntelligenceClient({ baseUrl: 'http://127.0.0.1:8787' }))
})

test('agent SDK rejects oversized and invalid JSON responses', async () => {
  const oversized = new StockPairLaunchIntelligenceClient({
    baseUrl: 'https://indexer.example.com',
    fetch: async () => new Response('{}', { headers: { 'content-length': '3000000' } })
  })
  await assert.rejects(() => oversized.getCandidates(), /exceeds SDK limit/)
  const invalid = new StockPairLaunchIntelligenceClient({
    baseUrl: 'https://indexer.example.com',
    fetch: async () => new Response('not-json', { status: 200 })
  })
  await assert.rejects(() => invalid.getCandidates(), /invalid JSON/)
})
