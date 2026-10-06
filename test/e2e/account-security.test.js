// Tests de bout en bout contre une instance Directus démarrée avec l'extension.
// Variables : DIRECTUS_URL, ADMIN_EMAIL, ADMIN_PASSWORD, PASSKEY_ORIGINS / PASSKEY_RP_ID (même valeur que le serveur).
import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'
import { createGuardrails, generateSync } from 'otplib'

const URL = (process.env.DIRECTUS_URL || 'http://localhost:8055').replace(/\/$/, '')
const EMAIL = process.env.ADMIN_EMAIL
const PASSWORD = process.env.ADMIN_PASSWORD
const ENV_ORIGIN = String(process.env.PASSKEY_ORIGINS || '').split(',')[0]
const ENV_RP_ID = process.env.PASSKEY_RP_ID
const guardrails = createGuardrails({ MIN_SECRET_BYTES: 10 })

const api = async (method, path, { body, token, headers = {} } = {}) => {
  const res = await fetch(URL + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token && { authorization: `Bearer ${token}` }),
      ...headers,
    },
    body: body && JSON.stringify(body),
  })
  const text = await res.text()
  let json
  try { json = JSON.parse(text) }
  catch { json = text }
  return { status: res.status, json }
}

const login = async (extra = {}) => {
  const res = await api('POST', '/auth/login', { body: { email: EMAIL, password: PASSWORD, ...extra } })
  assert.equal(res.status, 200, JSON.stringify(res.json))
  return res.json.data
}

const errorCode = res => res.json?.errors?.[0]?.extensions?.code

const until = async (check, timeoutMs = 45000) => {
  const end = Date.now() + timeoutMs
  for (;;) {
    const result = await check()
    if (result || Date.now() > end) return result
    await new Promise(resolve => setTimeout(resolve, 2000))
  }
}

let admin
let tfaSecret
const otp = () => generateSync({ secret: tfaSecret, guardrails })

before(async () => {
  assert.ok(EMAIL && PASSWORD, 'ADMIN_EMAIL and ADMIN_PASSWORD are required')
  admin = await login()
})

describe('setup', () => {
  it('creates the data collections linked to directus_users', async () => {
    const { json } = await api('GET', '/relations', { token: admin.access_token })
    const relations = json.data.filter(r => r.collection.startsWith('account_'))
    assert.deepEqual(
      relations.map(r => r.collection).sort(),
      ['account_backup_codes', 'account_passkey_challenges', 'account_passkeys', 'account_security_events', 'account_trusted_devices'],
    )
    for (const r of relations) assert.equal(r.related_collection, 'directus_users')
  })

  it('adds the settings fields to directus_settings', async () => {
    const { json } = await api('GET', '/fields/directus_settings', { token: admin.access_token })
    const fields = json.data.map(f => f.field)
    for (const name of ['passkey_origins', 'passkey_rp_id', 'passkey_rp_name', 'trusted_device_max_days']) {
      assert.ok(fields.includes(`account_security_${name}`), name)
    }
  })
})

describe('authentication guard', () => {
  for (const path of ['/sessions', '/activity', '/backup-codes', '/passkeys', '/trusted-devices']) {
    it(`GET ${path} requires a user`, async () => {
      const res = await api('GET', `/account-security${path}`)
      assert.equal(res.status, 401)
    })
  }
})

describe('sessions', () => {
  it('lists and revokes the other sessions', async () => {
    const other = await login()
    const list = await api('GET', '/account-security/sessions', { token: admin.access_token })
    assert.equal(list.status, 200)
    assert.ok(list.json.data.length >= 2)

    const revoke = await api('POST', '/account-security/sessions/revoke-others', {
      token: admin.access_token,
      headers: { 'x-refresh-token': admin.refresh_token },
    })
    assert.equal(revoke.status, 200)
    assert.ok(revoke.json.data.revoked >= 1)

    const refresh = await api('POST', '/auth/refresh', { body: { refresh_token: other.refresh_token, mode: 'json' } })
    assert.notEqual(refresh.status, 200, 'revoked session must not be refreshable')
  })
})

describe('passkeys', () => {
  it('returns registration options for an allowed origin', async () => {
    const res = await api('POST', '/account-security/passkeys/register/options', {
      token: admin.access_token,
      headers: { origin: ENV_ORIGIN },
    })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    const rp = res.json.data.options?.rp ?? res.json.data.rp
    assert.equal(rp.id, ENV_RP_ID)
    assert.equal(rp.name, 'Directus')
  })

  it('rejects an unknown origin', async () => {
    const res = await api('POST', '/account-security/passkeys/register/options', {
      token: admin.access_token,
      headers: { origin: 'https://evil.example.com' },
    })
    assert.equal(res.status, 400)
  })

  it('lists no passkey yet', async () => {
    const res = await api('GET', '/account-security/passkeys', { token: admin.access_token })
    assert.deepEqual(res.json.data, [])
  })
})

describe('2FA backup codes', () => {
  it('refuses to generate codes while 2FA is disabled', async () => {
    const res = await api('POST', '/account-security/backup-codes/generate', { token: admin.access_token, body: { otp: '123456' } })
    assert.equal(res.status, 400)
  })

  it('enables 2FA on the admin', async () => {
    const generated = await api('POST', '/users/me/tfa/generate', { token: admin.access_token, body: { password: PASSWORD } })
    assert.equal(generated.status, 200, JSON.stringify(generated.json))
    tfaSecret = generated.json.data.secret

    const enabled = await api('POST', '/users/me/tfa/enable', { token: admin.access_token, body: { secret: tfaSecret, otp: otp() } })
    assert.ok([200, 204].includes(enabled.status), JSON.stringify(enabled.json))
  })

  let codes
  it('generates 10 codes with a valid OTP', async () => {
    const bad = await api('POST', '/account-security/backup-codes/generate', { token: admin.access_token, body: { otp: '000000' } })
    assert.equal(bad.status, 401)

    const res = await api('POST', '/account-security/backup-codes/generate', { token: admin.access_token, body: { otp: otp() } })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    codes = res.json.data.codes
    assert.equal(codes.length, 10)

    const status = await api('GET', '/account-security/backup-codes', { token: admin.access_token })
    assert.equal(status.json.data.tfa_enabled, true)
    assert.equal(status.json.data.remaining, 10)
  })

  it('logs in once with a backup code', async () => {
    const res = await api('POST', '/account-security/backup-login', { body: { email: EMAIL, password: PASSWORD, code: codes[0] } })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.ok(res.json.data.access_token)
    assert.equal(res.json.meta.remaining_backup_codes, 9)

    const reused = await api('POST', '/account-security/backup-login', { body: { email: EMAIL, password: PASSWORD, code: codes[0] } })
    assert.equal(reused.status, 401)
  })

  it('does not consume a code when the password is wrong', async () => {
    const res = await api('POST', '/account-security/backup-login', { body: { email: EMAIL, password: 'wrong-password', code: codes[1] } })
    assert.equal(res.status, 401)

    const status = await api('GET', '/account-security/backup-codes', { token: admin.access_token })
    assert.equal(status.json.data.remaining, 9)
  })
})

describe('trusted devices', () => {
  let deviceToken
  it('registers a device, capped to the default maximum', async () => {
    const res = await api('POST', '/account-security/trusted-devices/register', { token: admin.access_token, body: { days: 365 } })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.equal(res.json.data.days, 30)
    deviceToken = res.json.data.token
  })

  it('logs in without OTP from the trusted device', async () => {
    const withoutDevice = await api('POST', '/auth/login', { body: { email: EMAIL, password: PASSWORD } })
    assert.equal(errorCode(withoutDevice), 'INVALID_OTP')

    const res = await api('POST', '/account-security/trusted-devices/login', { body: { email: EMAIL, password: PASSWORD, device_token: deviceToken } })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.ok(res.json.data.access_token)
  })

  it('renews a session from the device token alone', async () => {
    const res = await api('POST', '/account-security/trusted-devices/session', { body: { device_token: deviceToken } })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.ok(res.json.data.refresh_token)

    const bad = await api('POST', '/account-security/trusted-devices/session', { body: { device_token: 'x'.repeat(64) } })
    assert.equal(bad.status, 401)
  })

  it('revokes all devices', async () => {
    const res = await api('DELETE', '/account-security/trusted-devices', { token: admin.access_token })
    assert.equal(res.status, 200)
    const session = await api('POST', '/account-security/trusted-devices/session', { body: { device_token: deviceToken } })
    assert.equal(session.status, 401)
  })
})

describe('activity', () => {
  it('records the security events', async () => {
    const res = await api('GET', '/account-security/activity?limit=100', { token: admin.access_token })
    assert.equal(res.status, 200)
    const types = new Set(res.json.data.map(e => e.type))
    for (const type of ['backup_codes_generated', 'backup_code_used', 'trusted_device_added']) {
      assert.ok(types.has(type), `${type} missing in ${[...types]}`)
    }
  })
})

describe('settings from Directus', () => {
  it('override the environment variables', async () => {
    const saved = await api('PATCH', '/settings', {
      token: admin.access_token,
      body: {
        account_security_passkey_origins: ['https://ui.example.com'],
        account_security_passkey_rp_id: 'ui.example.com',
        account_security_passkey_rp_name: 'From Directus',
        account_security_trusted_device_max_days: 3,
      },
    })
    assert.equal(saved.status, 200, JSON.stringify(saved.json))

    // Les réglages sont mis en cache 30 s par l'extension. L'origine est vérifiée avant l'OTP (exigé, le 2FA étant
    // actif) : on attend que l'origine soit acceptée sans OTP pour ne pas consommer la limite de tentatives OTP.
    const accepted = await until(async () => {
      const res = await api('POST', '/account-security/passkeys/register/options', {
        token: admin.access_token,
        headers: { origin: 'https://ui.example.com' },
      })
      return res.status !== 400
    })
    assert.ok(accepted, 'origin from Directus settings never accepted')

    const res = await api('POST', '/account-security/passkeys/register/options', {
      token: admin.access_token,
      headers: { origin: 'https://ui.example.com' },
      body: { otp: otp() },
    })
    assert.equal(res.status, 200, JSON.stringify(res.json))
    assert.deepEqual(res.json.data.options?.rp ?? res.json.data.rp, { name: 'From Directus', id: 'ui.example.com' })

    const envOrigin = await api('POST', '/account-security/passkeys/register/options', {
      token: admin.access_token,
      headers: { origin: ENV_ORIGIN },
    })
    assert.equal(envOrigin.status, 400)

    const device = await api('POST', '/account-security/trusted-devices/register', { token: admin.access_token, body: { days: 30 } })
    assert.equal(device.json.data.days, 3)
  })
})
