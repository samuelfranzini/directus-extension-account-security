import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { createTranslator, ERRORS, matchLanguage, MESSAGES, parseAcceptLanguage } from '../../src/i18n.js'

// Faux knex : directus_translations, directus_settings et directus_users
const fakeDatabase = ({ translations = [], defaultLanguage = 'en-US', users = {} } = {}) => table => ({
  where(...args) {
    if (table === 'directus_translations') return { select: async () => translations }
    const id = args[0]?.id
    return { first: async () => users[id] ?? null }
  },
  first: async () => (table === 'directus_settings' ? { default_language: defaultLanguage } : null),
})

const request = ({ acceptLanguage, user } = {}) => ({
  accountability: user ? { user } : null,
  get: name => (name === 'accept-language' ? acceptLanguage : undefined),
})

describe('parseAcceptLanguage', () => {
  it('orders languages by quality', () => {
    assert.deepEqual(parseAcceptLanguage('en;q=0.5, fr-BE, fr;q=0.9'), ['fr-BE', 'fr', 'en'])
  })

  it('ignores wildcards, invalid tags and empty headers', () => {
    assert.deepEqual(parseAcceptLanguage('*, <script>, de;q=0'), [])
    assert.deepEqual(parseAcceptLanguage(undefined), [])
  })
})

describe('matchLanguage', () => {
  it('prefers exact matches, then the base language', () => {
    assert.equal(matchLanguage('fr-FR', ['fr-BE', 'fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('fr-CA', ['en-US', 'fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('fr', ['fr-FR']), 'fr-FR')
    assert.equal(matchLanguage('de', ['en-US', 'fr-FR']), null)
  })
})

describe('messages', () => {
  it('cover every error in every built-in language', () => {
    for (const [language, messages] of Object.entries(MESSAGES)) {
      for (const reason of Object.keys(ERRORS)) assert.ok(messages[reason], `${language}.${reason}`)
    }
  })
})

describe('createTranslator', () => {
  it('falls back to English', async () => {
    const t = createTranslator({ database: fakeDatabase() })
    assert.equal(await t(request(), 'invalid_credentials'), 'Invalid credentials.')
  })

  it('uses the Accept-Language header and built-in translations', async () => {
    const t = createTranslator({ database: fakeDatabase() })
    assert.equal(await t(request({ acceptLanguage: 'fr-BE,fr;q=0.9' }), 'invalid_credentials'), 'Identifiants invalides.')
  })

  it('prefers the Directus user language over Accept-Language', async () => {
    const t = createTranslator({ database: fakeDatabase({ users: { u1: { language: 'fr-FR' } } }) })
    assert.equal(await t(request({ acceptLanguage: 'en-US', user: 'u1' }), 'not_found'), 'Introuvable.')
  })

  it('uses the project default language when nothing else matches', async () => {
    const t = createTranslator({ database: fakeDatabase({ defaultLanguage: 'fr-FR' }) })
    assert.equal(await t(request({ acceptLanguage: 'de-DE' }), 'not_found'), 'Introuvable.')
  })

  it('lets Directus translation strings override built-in messages', async () => {
    const translations = [
      { key: 'account_security.invalid_credentials', language: 'fr-FR', value: 'Mauvais identifiants !' },
      { key: 'account_security.invalid_credentials', language: 'nl-NL', value: 'Ongeldige gegevens.' },
    ]
    const t = createTranslator({ database: fakeDatabase({ translations }) })
    assert.equal(await t(request({ acceptLanguage: 'fr-FR' }), 'invalid_credentials'), 'Mauvais identifiants !')
    assert.equal(await t(request({ acceptLanguage: 'nl-BE' }), 'invalid_credentials'), 'Ongeldige gegevens.')
    assert.equal(await t(request({ acceptLanguage: 'en-US' }), 'invalid_credentials'), 'Invalid credentials.')
  })

  it('interpolates parameters', async () => {
    const t = createTranslator({ database: fakeDatabase() })
    assert.match(await t(request(), 'passkey_limit_reached', { max: 10 }), /\(10\)/)
  })

  it('still answers when the Directus tables cannot be read', async () => {
    const t = createTranslator({ database: () => { throw new Error('down') } })
    assert.equal(await t(request({ acceptLanguage: 'fr' }), 'not_found'), 'Introuvable.')
  })
})
