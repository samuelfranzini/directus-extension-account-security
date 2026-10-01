import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { authenticator } from 'otplib'

const BACKUP_CODES_COUNT = 10
const BACKUP_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
const MAX_ACTIVITY_LIMIT = 100

const PROFILE_FIELD_EVENTS = {
  email: 'email_changed',
  password: 'password_changed',
  avatar: 'avatar_changed',
}

const attempts = new Map()

const hit = (key, max, windowMs) => {
  const now = Date.now()
  for (const [k, v] of attempts) if (v.expiresAt <= now) attempts.delete(k)
  const current = attempts.get(key)
  if (!current) {
    attempts.set(key, { count: 1, expiresAt: now + windowMs })
    return true
  }
  if (current.count >= max) return false
  current.count += 1
  return true
}

const fail = (res, status, code, message) =>
  res.status(status).json({ errors: [{ message, extensions: { code } }] })

const sessionId = token => createHash('sha256').update(String(token)).digest('hex').slice(0, 24)

const generateBackupCode = () => {
  const bytes = randomBytes(10)
  const chars = Array.from(bytes, b => BACKUP_ALPHABET[b % BACKUP_ALPHABET.length])
  return `${chars.slice(0, 5).join('')}-${chars.slice(5).join('')}`
}

const normalizeBackupCode = value => String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '')

const parseJson = (value) => {
  if (!value) return null
  if (typeof value === 'object') return value
  try {
    return JSON.parse(value)
  }
  catch {
    return null
  }
}

export default {
  id: 'account-security',
  handler: (router, context) => {
    const { services, getSchema, database, env, logger } = context

    const hashCode = (userId, code) =>
      createHmac('sha256', String(env.SECRET || 'directus')).update(`${userId}:${normalizeBackupCode(code)}`).digest('hex')

    const logEvent = async (userId, type, req) => {
      try {
        await database('account_security_events').insert({
          id: randomUUID(),
          user: userId,
          type,
          ip: req.ip || null,
          user_agent: String(req.get('user-agent') || '').slice(0, 512) || null,
          date_created: new Date(),
        })
      }
      catch (error) {
        logger.warn(`[account-security] événement ${type} non enregistré: ${error.message}`)
      }
    }

    const requireUser = (req, res, next) => {
      if (!req.accountability?.user) return fail(res, 401, 'INVALID_CREDENTIALS', 'Non authentifié')
      next()
    }

    const currentRefreshToken = req => String(req.get('x-refresh-token') || req.accountability?.session || '')

    const getTfaSecret = async userId =>
      (await database('directus_users').where({ id: userId }).first('tfa_secret'))?.tfa_secret || null

    // ── Sessions ──────────────────────────────────────────────────────────────

    const listUserSessions = userId =>
      database('directus_sessions')
        .where('user', userId)
        .whereNull('share')
        .where('expires', '>', new Date())
        .orderBy('expires', 'desc')

    router.get('/sessions', requireUser, async (req, res) => {
      try {
        const current = currentRefreshToken(req)
        const rows = await listUserSessions(req.accountability.user)
        res.json({
          data: rows.map(row => ({
            id: sessionId(row.token),
            ip: row.ip || null,
            user_agent: row.user_agent || null,
            origin: row.origin || null,
            expires: row.expires,
            current: Boolean(current) && (row.token === current || row.next_token === current),
          })),
        })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de lister les sessions')
      }
    })

    router.post('/sessions/revoke-others', requireUser, async (req, res) => {
      try {
        const current = currentRefreshToken(req)
        if (!current) return fail(res, 400, 'INVALID_PAYLOAD', 'Session courante introuvable')

        const rows = await listUserSessions(req.accountability.user)
        const currentRow = rows.find(row => row.token === current || row.next_token === current)
        if (!currentRow) return fail(res, 400, 'INVALID_PAYLOAD', 'Session courante introuvable')

        const revoked = await database('directus_sessions')
          .where('user', req.accountability.user)
          .whereNull('share')
          .whereNot('token', currentRow.token)
          .del()

        if (revoked > 0) await logEvent(req.accountability.user, 'sessions_revoked', req)
        res.json({ data: { revoked } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de révoquer les sessions')
      }
    })

    router.delete('/sessions/:id', requireUser, async (req, res) => {
      try {
        const rows = await listUserSessions(req.accountability.user)
        const target = rows.find(row => sessionId(row.token) === req.params.id)
        if (!target) return fail(res, 404, 'ROUTE_NOT_FOUND', 'Session introuvable')

        await database('directus_sessions').where({ token: target.token, user: req.accountability.user }).del()
        await logEvent(req.accountability.user, 'session_revoked', req)
        res.json({ data: { revoked: 1 } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de révoquer la session')
      }
    })

    // ── Journal d'activité (connexions + changements de compte) ───────────────

    router.get('/activity', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user
        const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), MAX_ACTIVITY_LIMIT)

        const [logins, updates, events] = await Promise.all([
          database('directus_activity')
            .where({ user: userId, action: 'login' })
            .orderBy('timestamp', 'desc')
            .limit(limit)
            .select('id', 'timestamp', 'ip', 'user_agent'),
          database('directus_activity as a')
            .leftJoin('directus_revisions as r', 'r.activity', 'a.id')
            .where({ 'a.user': userId, 'a.collection': 'directus_users', 'a.action': 'update' })
            .where('a.item', String(userId))
            .orderBy('a.timestamp', 'desc')
            .limit(limit)
            .select('a.id', 'a.timestamp', 'a.ip', 'a.user_agent', 'r.delta'),
          database('account_security_events')
            .where({ user: userId })
            .orderBy('date_created', 'desc')
            .limit(limit)
            .select('id', 'type', 'date_created', 'ip', 'user_agent'),
        ])

        const items = [
          ...logins.map(row => ({
            id: `login-${row.id}`,
            type: 'login',
            timestamp: row.timestamp,
            ip: row.ip || null,
            user_agent: row.user_agent || null,
          })),
          ...events.map(row => ({
            id: `event-${row.id}`,
            type: row.type,
            timestamp: row.date_created,
            ip: row.ip || null,
            user_agent: row.user_agent || null,
          })),
        ]

        for (const row of updates) {
          const delta = parseJson(row.delta)
          if (!delta) continue

          // Seules les clés modifiées sont lues : aucune valeur (hash, secret) n'est exposée.
          const types = new Set()
          for (const key of Object.keys(delta)) {
            if (PROFILE_FIELD_EVENTS[key]) types.add(PROFILE_FIELD_EVENTS[key])
            if (key === 'tfa_secret') types.add(delta.tfa_secret ? 'tfa_enabled' : 'tfa_disabled')
          }

          for (const type of types) {
            items.push({
              id: `update-${row.id}-${type}`,
              type,
              timestamp: row.timestamp,
              ip: row.ip || null,
              user_agent: row.user_agent || null,
            })
          }
        }

        items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        res.json({ data: items.slice(0, limit) })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de charger le journal d\'activité')
      }
    })

    // ── Codes de secours 2FA ──────────────────────────────────────────────────

    router.get('/backup-codes', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user
        const [secret, rows] = await Promise.all([
          getTfaSecret(userId),
          database('account_backup_codes').where({ user: userId }).select('used_at', 'date_created'),
        ])

        const generated = rows
          .map(row => new Date(row.date_created).getTime())
          .sort((a, b) => b - a)[0]

        res.json({
          data: {
            tfa_enabled: Boolean(secret),
            total: rows.length,
            remaining: rows.filter(row => !row.used_at).length,
            generated_at: generated ? new Date(generated).toISOString() : null,
          },
        })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de lire les codes de secours')
      }
    })

    router.post('/backup-codes/generate', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user
        const otp = String(req.body?.otp || '').trim()

        if (!/^\d{6}$/.test(otp)) return fail(res, 400, 'INVALID_OTP', 'Code OTP invalide (6 chiffres requis)')
        if (!hit(`generate:${userId}`, 5, 10 * 60 * 1000)) {
          return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez dans quelques minutes.')
        }

        const secret = await getTfaSecret(userId)
        if (!secret) return fail(res, 400, 'INVALID_PAYLOAD', 'Activez d\'abord le 2FA')
        if (!authenticator.check(otp, secret)) return fail(res, 401, 'INVALID_OTP', 'Code OTP invalide')

        const codes = Array.from({ length: BACKUP_CODES_COUNT }, generateBackupCode)
        const now = new Date()

        await database.transaction(async (trx) => {
          await trx('account_backup_codes').where({ user: userId }).del()
          await trx('account_backup_codes').insert(codes.map(code => ({
            id: randomUUID(),
            user: userId,
            code_hash: hashCode(userId, code),
            used_at: null,
            date_created: now,
          })))
        })

        await logEvent(userId, 'backup_codes_generated', req)
        res.json({ data: { codes } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de générer les codes de secours')
      }
    })

    // Connexion avec un code de secours à la place du code OTP (endpoint public).
    // Le code est consommé puis la connexion passe par l'AuthenticationService natif
    // (journal d'activité, hooks, sessions), avec un OTP calculé côté serveur.
    router.post('/backup-login', async (req, res) => {
      const email = String(req.body?.email || '').trim().toLowerCase()
      const password = String(req.body?.password || '')
      const code = String(req.body?.code || '')
      const invalid = () => fail(res, 401, 'INVALID_CREDENTIALS', 'Identifiants ou code de secours invalides')

      if (!email || !password || normalizeBackupCode(code).length !== 10) return invalid()

      const rateKey = `backup-login:${req.ip}:${email}`
      if (!hit(rateKey, 5, 10 * 60 * 1000) || !hit(`backup-login-email:${email}`, 10, 60 * 60 * 1000)) {
        return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez plus tard.')
      }

      let claimedId = null

      try {
        const user = await database('directus_users')
          .whereRaw('lower(email) = ?', [email])
          .where({ status: 'active' })
          .first('id', 'tfa_secret')

        if (!user?.tfa_secret) return invalid()

        const hash = hashCode(user.id, code)
        const claimed = await database('account_backup_codes')
          .where({ user: user.id, code_hash: hash })
          .whereNull('used_at')
          .first('id')

        if (!claimed) return invalid()

        const updated = await database('account_backup_codes')
          .where({ id: claimed.id })
          .whereNull('used_at')
          .update({ used_at: new Date() })

        if (updated !== 1) return invalid()
        claimedId = claimed.id

        const authService = new services.AuthenticationService({
          accountability: {
            role: null,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            origin: req.get('origin'),
          },
          schema: await getSchema(),
        })

        const session = await authService.login(
          'default',
          { email, password },
          { otp: authenticator.generate(user.tfa_secret) },
        )

        await logEvent(user.id, 'backup_code_used', req)

        const remaining = await database('account_backup_codes')
          .where({ user: user.id })
          .whereNull('used_at')
          .count({ count: '*' })
          .first()

        res.json({
          data: {
            access_token: session.accessToken,
            refresh_token: session.refreshToken,
            expires: session.expires,
          },
          meta: { remaining_backup_codes: Number(remaining?.count || 0) },
        })
      }
      catch (error) {
        // Identifiants incorrects : le code de secours n'est pas consommé.
        if (claimedId) {
          await database('account_backup_codes').where({ id: claimedId }).update({ used_at: null }).catch(() => {})
        }
        if (error?.code !== 'INVALID_CREDENTIALS') logger.error(error)
        return invalid()
      }
    })
  },
}
