// Collections nécessaires à l'extension, créées au démarrage si elles n'existent pas encore. Sur une collection
// existante, seules les colonnes manquantes sont ajoutées (rien n'est modifié ni supprimé).
// Désactivable avec ACCOUNT_SECURITY_AUTO_SETUP=false.

const uuidPk = {
  field: 'id',
  type: 'uuid',
  meta: { hidden: true, readonly: true, special: ['uuid'] },
  schema: { is_primary_key: true, length: 36, has_auto_increment: false },
}

const userField = (nullable = false) => ({
  field: 'user',
  type: 'uuid',
  meta: { special: ['m2o'], interface: 'select-dropdown-m2o', display: 'user', readonly: true },
  schema: { is_nullable: nullable },
})

const string = (field, length = 255, extra = {}) => ({
  field,
  type: 'string',
  meta: { readonly: true },
  schema: { max_length: length, ...extra },
})

const timestamp = (field, nullable = true) => ({
  field,
  type: 'timestamp',
  meta: { readonly: true, display: 'datetime' },
  schema: { is_nullable: nullable },
})

const internal = (icon, note) => ({ icon, note, hidden: true, group: null })

const COLLECTIONS = [
  {
    collection: 'account_security_events',
    meta: internal('history', 'Account security: security events log'),
    schema: {},
    fields: [uuidPk, userField(), string('type', 64), string('ip', 64), string('user_agent', 512), timestamp('date_created', false)],
  },
  {
    collection: 'account_backup_codes',
    meta: internal('password', 'Account security: hashed 2FA backup codes'),
    schema: {},
    fields: [uuidPk, userField(), string('code_hash', 128), string('tfa_hash', 128), timestamp('used_at'), timestamp('date_created', false)],
  },
  {
    collection: 'account_passkeys',
    meta: internal('fingerprint', 'Account security: registered passkeys (WebAuthn)'),
    schema: {},
    fields: [
      uuidPk,
      userField(),
      string('name', 100),
      string('credential_id', 1024, { is_unique: true }),
      { field: 'public_key', type: 'text', meta: { readonly: true } },
      { field: 'counter', type: 'bigInteger', meta: { readonly: true }, schema: { default_value: 0 } },
      { field: 'transports', type: 'text', meta: { readonly: true } },
      string('device_type', 32),
      { field: 'backed_up', type: 'boolean', meta: { readonly: true }, schema: { default_value: false } },
      timestamp('date_created', false),
      timestamp('last_used_at'),
    ],
  },
  {
    collection: 'account_passkey_challenges',
    meta: internal('key', 'Account security: pending WebAuthn challenges'),
    schema: {},
    fields: [uuidPk, string('challenge', 512), string('type', 32), userField(true), timestamp('expires_at', false)],
  },
  {
    collection: 'account_trusted_devices',
    meta: internal('devices', 'Account security: trusted devices'),
    schema: {},
    fields: [
      uuidPk,
      userField(),
      string('token_hash', 128, { is_unique: true }),
      string('credential_hash', 128),
      string('ip', 64),
      string('user_agent', 512),
      timestamp('date_created', false),
      timestamp('expires_at', false),
      timestamp('last_used_at'),
    ],
  },
]

// Réglages ajoutés à directus_settings : section « Account Security » en bas de Settings → Settings.
// La page des paramètres n'affiche pas les enfants d'un groupe personnalisé, d'où un séparateur suivi des champs.
export const SETTINGS_PREFIX = 'account_security_'

const label = (en, fr) => [
  { language: 'en-US', translation: en },
  { language: 'fr-FR', translation: fr },
]

const setting = (name, type, meta, schema = {}) => ({
  field: SETTINGS_PREFIX + name,
  type,
  meta,
  schema,
})

const SETTINGS_FIELDS = [
  {
    field: 'account_security_divider',
    type: 'alias',
    meta: {
      special: ['alias', 'no-data'],
      interface: 'presentation-divider',
      options: { title: 'Account Security', icon: 'shield_lock', inlineTitle: false },
      width: 'full',
      sort: 1,
    },
  },
  setting('passkey_origins', 'json', {
    interface: 'tags',
    special: ['cast-json'],
    width: 'full',
    sort: 2,
    translations: label('Passkey origins', 'Origines des clés d\'accès'),
    note: 'Allowed WebAuthn origins (e.g. https://app.example.com). Falls back to PASSKEY_ORIGINS.',
    options: { placeholder: 'https://app.example.com' },
  }),
  setting('passkey_rp_id', 'string', {
    interface: 'input',
    width: 'half',
    sort: 3,
    translations: label('Passkey relying party ID', 'Identifiant RP des clés d\'accès'),
    note: 'Your parent domain (e.g. example.com). Falls back to PASSKEY_RP_ID.',
    options: { placeholder: 'example.com' },
  }, { max_length: 255 }),
  setting('passkey_rp_name', 'string', {
    interface: 'input',
    width: 'half',
    sort: 4,
    translations: label('Passkey relying party name', 'Nom RP des clés d\'accès'),
    note: 'Name shown by the authenticator. Falls back to PASSKEY_RP_NAME, then "Directus".',
    options: { placeholder: 'Directus' },
  }, { max_length: 255 }),
  setting('trusted_device_max_days', 'integer', {
    interface: 'input',
    width: 'half',
    sort: 5,
    translations: label('Trusted device max days', 'Durée max. des appareils de confiance (jours)'),
    note: 'Between 1 and 90. Falls back to TRUSTED_DEVICE_MAX_DAYS, then 30.',
    options: { min: 1, max: 90 },
  }),
]

export const ensureSchema = async ({ services, getSchema, database, logger }) => {
  const { CollectionsService, FieldsService, RelationsService } = services
  const freshSchema = () => getSchema({ database, bypassCache: true })

  for (const definition of COLLECTIONS) {
    if (await database.schema.hasTable(definition.collection)) {
      const missingColumns = []
      for (const field of definition.fields) {
        if (!(await database.schema.hasColumn(definition.collection, field.field))) missingColumns.push(field)
      }
      if (!missingColumns.length) continue

      const fieldsService = new FieldsService({ knex: database, schema: await freshSchema() })
      for (const field of missingColumns) await fieldsService.createField(definition.collection, field)
      logger.info(`[account-security] fields added to ${definition.collection}: ${missingColumns.map(f => f.field).join(', ')}`)
      continue
    }

    await new CollectionsService({ knex: database, schema: await freshSchema() }).createOne(definition)

    if (definition.fields.some(f => f.field === 'user')) {
      await new RelationsService({ knex: database, schema: await freshSchema() })
        .createOne({
          collection: definition.collection,
          field: 'user',
          related_collection: 'directus_users',
          schema: { on_delete: 'CASCADE' },
        })
    }

    logger.info(`[account-security] collection ${definition.collection} created`)
  }

  const existing = new Set(
    (await database('directus_fields').where({ collection: 'directus_settings' }).select('field')).map(row => row.field),
  )
  const missing = SETTINGS_FIELDS.filter(f => !existing.has(f.field))
  if (!missing.length) return

  const fieldsService = new FieldsService({ knex: database, schema: await freshSchema() })
  for (const field of missing) await fieldsService.createField('directus_settings', field)
  logger.info(`[account-security] settings fields added to directus_settings: ${missing.map(f => f.field).join(', ')}`)
}
