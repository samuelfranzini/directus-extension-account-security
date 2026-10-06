import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { ensureSchema, SETTINGS_PREFIX } from '../../src/schema.js'

const TABLES = [
  'account_security_events',
  'account_backup_codes',
  'account_passkeys',
  'account_passkey_challenges',
  'account_trusted_devices',
]

// Faux contexte d'extension : enregistre les appels aux services Directus
const fakeContext = ({ tables = [], settingsFields = [] } = {}) => {
  const calls = { collections: [], relations: [], fields: [] }

  const database = () => ({
    where: () => ({ select: async () => settingsFields.map(field => ({ field })) }),
  })
  database.schema = { hasTable: async name => tables.includes(name) }

  return {
    calls,
    context: {
      database,
      getSchema: async () => ({}),
      logger: { info() {} },
      services: {
        CollectionsService: class { async createOne(def) { calls.collections.push(def) } },
        RelationsService: class { async createOne(rel) { calls.relations.push(rel) } },
        FieldsService: class { async createField(collection, field) { calls.fields.push({ collection, ...field }) } },
      },
    },
  }
}

describe('ensureSchema', () => {
  it('creates every collection, user relation and setting on a fresh database', async () => {
    const { calls, context } = fakeContext()
    await ensureSchema(context)

    assert.deepEqual(calls.collections.map(c => c.collection), TABLES)
    assert.deepEqual(calls.relations.map(r => r.collection), TABLES)
    for (const relation of calls.relations) {
      assert.equal(relation.related_collection, 'directus_users')
      assert.equal(relation.schema.on_delete, 'CASCADE')
    }

    assert.ok(calls.fields.length > 0)
    for (const field of calls.fields) {
      assert.equal(field.collection, 'directus_settings')
      assert.ok(field.field.startsWith(SETTINGS_PREFIX))
    }
  })

  it('never touches existing collections or settings', async () => {
    const { calls: first, context: fresh } = fakeContext()
    await ensureSchema(fresh)

    const { calls, context } = fakeContext({ tables: TABLES, settingsFields: first.fields.map(f => f.field) })
    await ensureSchema(context)

    assert.deepEqual(calls, { collections: [], relations: [], fields: [] })
  })

  it('only adds the missing pieces', async () => {
    const { calls, context } = fakeContext({ tables: TABLES.slice(1), settingsFields: [`${SETTINGS_PREFIX}passkey_rp_id`] })
    await ensureSchema(context)

    assert.deepEqual(calls.collections.map(c => c.collection), [TABLES[0]])
    assert.ok(!calls.fields.some(f => f.field === `${SETTINGS_PREFIX}passkey_rp_id`))
  })

  it('defines a uuid primary key on every data collection', async () => {
    const { calls, context } = fakeContext()
    await ensureSchema(context)

    for (const definition of calls.collections) {
      const pk = definition.fields.find(f => f.schema?.is_primary_key)
      assert.equal(pk?.field, 'id', definition.collection)
      assert.equal(pk.type, 'uuid', definition.collection)
    }
  })
})
