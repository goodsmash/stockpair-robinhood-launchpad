const MAX_RESPONSE_BYTES = 2_000_000

async function readJson(response) {
  const length = Number(response.headers.get('content-length') ?? 0)
  if (length > MAX_RESPONSE_BYTES) throw new Error('response exceeds SDK limit')
  const text = await response.text()
  if (text.length > MAX_RESPONSE_BYTES) throw new Error('response exceeds SDK limit')
  let value
  try { value = JSON.parse(text) } catch { throw new Error('indexer returned invalid JSON') }
  if (!response.ok) throw new Error(value?.error ?? `request failed: ${response.status}`)
  return value
}

function baseUrl(value) {
  const parsed = new URL(value)
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error('invalid indexer URL')
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1' || parsed.hostname.endsWith('.localhost')
  if (parsed.protocol !== 'https:' && !loopback) throw new Error('non-loopback indexer URLs must use HTTPS')
  return parsed.toString().replace(/\/$/, '')
}

export class StockPairLaunchIntelligenceClient {
  constructor(options) {
    this.baseUrl = baseUrl(options.baseUrl)
    this.fetch = options.fetch ?? globalThis.fetch
    if (typeof this.fetch !== 'function') throw new Error('fetch implementation is required')
  }

  async getSources() {
    return readJson(await this.fetch(`${this.baseUrl}/api/radar/sources`, { headers: { accept: 'application/json' } }))
  }

  async getCandidates(query = {}) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
    return readJson(await this.fetch(`${this.baseUrl}/api/radar/candidates?${params}`, { headers: { accept: 'application/json' } }))
  }

  async getAlerts(query = {}) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== null && value !== '') params.set(key, String(value))
    return readJson(await this.fetch(`${this.baseUrl}/api/radar/alerts?${params}`, { headers: { accept: 'application/json' } }))
  }

  subscribe(onEvent, options = {}) {
    if (typeof EventSource === 'undefined') throw new Error('EventSource is unavailable; provide an environment-specific SSE client')
    const stream = new EventSource(`${this.baseUrl}/api/stream`, { withCredentials: options.withCredentials === true })
    const listener = (event) => {
      try { onEvent(JSON.parse(event.data)) } catch { /* ignore malformed event */ }
    }
    stream.addEventListener('scout', listener)
    return () => stream.close()
  }
}
