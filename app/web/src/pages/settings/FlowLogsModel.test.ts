import { describe, expect, it } from 'vitest'
import { ingestURL, problem, providerBody, randomToken, snippet } from './FlowLogsModel'

describe('cloud flow log settings', () => {
  const v = { enabled: false, token_set: false, endpoint: '/api/ingest/flowlogs/gcp' }
  it('builds the ingest URL', () => {
    expect(ingestURL({ ...v, url: 'https://flow.corp/api/ingest/flowlogs/gcp' }, 'http://localhost:5173')).toBe('https://flow.corp/api/ingest/flowlogs/gcp')
    expect(ingestURL(v, 'http://localhost:8080/')).toBe('http://localhost:8080/api/ingest/flowlogs/gcp')
  })
  it('sends tokens only when entered or removed', () => {
    expect(providerBody({ enabled: true, token: '', remove: false })).toEqual({ enabled: true })
    expect(providerBody({ enabled: true, token: 'x'.repeat(20), remove: false })).toEqual({ enabled: true, token: 'x'.repeat(20) })
    expect(providerBody({ enabled: true, token: '', remove: true })).toEqual({ enabled: false, token: '' })
  })
  it('checks tokens', () => {
    expect(problem(v, { enabled: true, token: '', remove: false })).toBe('fl.err.token')
    expect(problem({ ...v, token_set: true }, { enabled: true, token: '', remove: false })).toBeNull()
    expect(problem(v, { enabled: false, token: 'short', remove: false })).toBe('fl.err.short')
    expect(randomToken().length).toBeGreaterThanOrEqual(32)
  })
  it('fills the snippets', () => {
    expect(snippet('aws', 'https://f/api/ingest/flowlogs/aws')).toContain('"Url": "https://f/api/ingest/flowlogs/aws"')
    expect(snippet('gcp', 'https://f/api/ingest/flowlogs/gcp')).toContain("--push-endpoint='https://f/api/ingest/flowlogs/gcp?token=<token>'")
    expect(snippet('azure', 'https://f/a')).toContain("fetch('https://f/a'")
  })
})
