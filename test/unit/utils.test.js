import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  blocked,
  fail,
  generateBackupCode,
  hit,
  listSetting,
  normalizeBackupCode,
  parseDuration,
  parseJson,
  sessionId,
} from '../../src/utils.js'

describe('parseDuration', () => {
  it('parses Directus duration strings', () => {
    assert.equal(parseDuration('15m', 0), 15 * 60000)
    assert.equal(parseDuration('7d', 0), 7 * 86400000)
    assert.equal(parseDuration('2w', 0), 2 * 604800000)
    assert.equal(parseDuration('500', 0), 500)
    assert.equal(parseDuration(' 30 s ', 0), 30000)
  })

  it('keeps numbers and falls back on invalid input', () => {
    assert.equal(parseDuration(1234, 0), 1234)
    assert.equal(parseDuration(undefined, 42), 42)
    assert.equal(parseDuration('soon', 42), 42)
  })
})

describe('hit (rate limiter)', () => {
  it('allows up to max attempts per window', () => {
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 2, 60000), true)
    assert.equal(hit(key, 2, 60000), true)
    assert.equal(hit(key, 2, 60000), false)
  })

  it('stays bounded under a flood of distinct keys', () => {
    for (let i = 0; i < 25000; i++) hit(`flood:${i}`, 1, 60000)
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 1, 60000), true)
    assert.equal(hit(key, 1, 60000), false)
  })

  it('blocked reports the limit without counting an attempt', () => {
    const key = `test:${Math.random()}`
    assert.equal(blocked(key, 2), false)
    hit(key, 2, 60000)
    assert.equal(blocked(key, 2), false)
    hit(key, 2, 60000)
    assert.equal(blocked(key, 2), true)
  })

  it('resets after the window expires', async () => {
    const key = `test:${Math.random()}`
    assert.equal(hit(key, 1, 10), true)
    assert.equal(hit(key, 1, 10), false)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(hit(key, 1, 10), true)
  })
})

describe('backup codes', () => {
  it('generates XXXXX-XXXXX codes from an unambiguous alphabet', () => {
    for (let i = 0; i < 200; i++) {
      assert.match(generateBackupCode(), /^[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$/)
    }
  })

  it('generates distinct codes', () => {
    const codes = new Set(Array.from({ length: 100 }, generateBackupCode))
    assert.equal(codes.size, 100)
  })

  it('normalizes user input', () => {
    assert.equal(normalizeBackupCode(' abcde-fgh23 '), 'ABCDEFGH23')
    assert.equal(normalizeBackupCode(null), '')
  })
})

describe('listSetting', () => {
  it('accepts comma-separated strings (environment variables)', () => {
    assert.deepEqual(listSetting('https://a.test, https://b.test,,'), ['https://a.test', 'https://b.test'])
  })

  it('accepts arrays and serialized JSON arrays (Directus fields)', () => {
    assert.deepEqual(listSetting(['https://a.test', ' ']), ['https://a.test'])
    assert.deepEqual(listSetting('["https://a.test","https://b.test"]'), ['https://a.test', 'https://b.test'])
  })

  it('returns an empty list for empty values', () => {
    assert.deepEqual(listSetting(undefined), [])
    assert.deepEqual(listSetting(null), [])
    assert.deepEqual(listSetting('[]'), [])
  })
})

describe('misc helpers', () => {
  it('parseJson tolerates objects and invalid JSON', () => {
    assert.deepEqual(parseJson('{"a":1}'), { a: 1 })
    assert.deepEqual(parseJson({ a: 1 }), { a: 1 })
    assert.equal(parseJson('nope'), null)
    assert.equal(parseJson(''), null)
  })

  it('sessionId is a stable, non-reversible 24 chars id', () => {
    assert.equal(sessionId('token'), sessionId('token'))
    assert.notEqual(sessionId('token'), sessionId('other'))
    assert.match(sessionId('token'), /^[0-9a-f]{24}$/)
  })

  it('fail sends a Directus-shaped error', () => {
    const res = { status(code) { this.code = code; return this }, json(body) { this.body = body; return this } }
    fail(res, 401, 'INVALID_CREDENTIALS', 'Nope')
    assert.equal(res.code, 401)
    assert.deepEqual(res.body, { errors: [{ message: 'Nope', extensions: { code: 'INVALID_CREDENTIALS' } }] })
  })

  it('fail adds extra extensions', () => {
    const res = { status() { return this }, json(body) { this.body = body; return this } }
    fail(res, 404, 'ROUTE_NOT_FOUND', 'Not found.', { reason: 'not_found' })
    assert.deepEqual(res.body.errors[0].extensions, { code: 'ROUTE_NOT_FOUND', reason: 'not_found' })
  })
})
