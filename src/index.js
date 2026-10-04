import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { createGuardrails, generateSync, verifySync } from 'otplib'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'

// Directus génère des secrets TFA de 10 octets (format historique Google Authenticator),
// alors que otplib v13 impose par défaut un minimum de 16 octets (RFC 4226).
const guardrails = createGuardrails({ MIN_SECRET_BYTES: 10 })

const BACKUP_CODES_COUNT = 10
const BACKUP_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
const MAX_ACTIVITY_LIMIT = 100

const PROFILE_FIELD_EVENTS = {
  email: 'email_changed',
  password: 'password_changed',
  avatar: 'avatar_changed',
}

const CHALLENGE_TTL_MS = 5 * 60 * 1000
const MAX_PASSKEYS = 10
const MAX_TRUSTED_DEVICES = 10

const attempts = new Map()

const parseDuration = (value, fallbackMs) => {
  if (typeof value === 'number') return value
  const match = /^(\d+)\s*(ms|s|m|h|d|w)?$/.exec(String(value || '').trim())
  if (!match) return fallbackMs
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[match[2] || 'ms']
  return Number(match[1]) * unit
}

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
        if (!verifySync({ token: otp, secret, epochTolerance: 30, guardrails }).valid) return fail(res, 401, 'INVALID_OTP', 'Code OTP invalide')

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
          { otp: generateSync({ secret: user.tfa_secret, guardrails }) },
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

    // ── Passkeys (WebAuthn) ───────────────────────────────────────────────────
    // Variables d'environnement Directus :
    //   PASSKEY_RP_ID   : domaine parent du site (ex. ambulancepresent.be)
    //   PASSKEY_ORIGINS : origines autorisées, séparées par des virgules (ex. https://ambulancepresent.be,https://www.ambulancepresent.be)
    // Une origine localhost est acceptée avec le RP ID « localhost » (développement).

    const passkeyConfig = (req) => {
      const allowed = String(env.PASSKEY_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean)
      const origin = String(req.get('x-client-origin') || req.get('origin') || '')
      if (!origin || !allowed.includes(origin)) return null

      let hostname
      try {
        hostname = new URL(origin).hostname
      }
      catch {
        return null
      }

      const rpID = hostname === 'localhost' ? 'localhost' : String(env.PASSKEY_RP_ID || '')
      if (!rpID) return null
      return { origin, rpID, rpName: String(env.PASSKEY_RP_NAME || 'Ambulance Présent') }
    }

    const saveChallenge = async (challenge, type, userId = null) => {
      await database('account_passkey_challenges').where('expires_at', '<', new Date()).del()
      const id = randomUUID()
      await database('account_passkey_challenges').insert({
        id,
        challenge,
        type,
        user: userId,
        expires_at: new Date(Date.now() + CHALLENGE_TTL_MS),
      })
      return id
    }

    // Un challenge n'est utilisable qu'une fois
    const consumeChallenge = async (id, type, userId = null) => {
      const row = await database('account_passkey_challenges').where({ id, type }).first()
      if (!row) return null
      const deleted = await database('account_passkey_challenges').where({ id }).del()
      if (deleted !== 1 || new Date(row.expires_at).getTime() < Date.now()) return null
      if (userId && row.user !== userId) return null
      return row.challenge
    }

    const toBase64Url = bytes => Buffer.from(bytes).toString('base64url')
    const fromBase64Url = value => new Uint8Array(Buffer.from(String(value), 'base64url'))

    const passkeyProps = row => ({
      id: row.id,
      name: row.name,
      device_type: row.device_type,
      backed_up: Boolean(row.backed_up),
      date_created: row.date_created,
      last_used_at: row.last_used_at,
    })

    router.get('/passkeys', requireUser, async (req, res) => {
      try {
        const rows = await database('account_passkeys')
          .where({ user: req.accountability.user })
          .orderBy('date_created', 'desc')
        res.json({ data: rows.map(passkeyProps) })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de lister les clés d\'accès')
      }
    })

    router.post('/passkeys/register/options', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user
        const config = passkeyConfig(req)
        if (!config) return fail(res, 400, 'INVALID_PAYLOAD', 'Origine non autorisée pour les clés d\'accès')

        // Ajouter une clé est sensible : un OTP est exigé si le 2FA est actif (sinon le mot de passe est vérifié côté application).
        const secret = await getTfaSecret(userId)
        if (secret) {
          const otp = String(req.body?.otp || '').trim()
          if (!hit(`passkey-otp:${userId}`, 5, 10 * 60 * 1000)) {
            return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez dans quelques minutes.')
          }
          if (!/^\d{6}$/.test(otp) || !verifySync({ token: otp, secret, epochTolerance: 30, guardrails }).valid) {
            return fail(res, 401, 'INVALID_OTP', 'Code OTP invalide')
          }
        }

        const existing = await database('account_passkeys').where({ user: userId }).select('credential_id', 'transports')
        if (existing.length >= MAX_PASSKEYS) {
          return fail(res, 400, 'INVALID_PAYLOAD', `Maximum ${MAX_PASSKEYS} clés d'accès`)
        }

        const user = await database('directus_users').where({ id: userId }).first('email', 'first_name', 'last_name')
        const options = await generateRegistrationOptions({
          rpName: config.rpName,
          rpID: config.rpID,
          userID: new TextEncoder().encode(String(userId)),
          userName: user?.email || String(userId),
          userDisplayName: [user?.first_name, user?.last_name].filter(Boolean).join(' ') || user?.email || String(userId),
          attestationType: 'none',
          excludeCredentials: existing.map(row => ({
            id: row.credential_id,
            transports: parseJson(row.transports) || undefined,
          })),
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        })

        const challengeId = await saveChallenge(options.challenge, 'register', userId)
        res.json({ data: { options, challenge_id: challengeId } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de préparer l\'enregistrement')
      }
    })

    router.post('/passkeys/register/verify', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user
        const config = passkeyConfig(req)
        if (!config) return fail(res, 400, 'INVALID_PAYLOAD', 'Origine non autorisée pour les clés d\'accès')

        const challenge = await consumeChallenge(String(req.body?.challenge_id || ''), 'register', userId)
        if (!challenge) return fail(res, 400, 'INVALID_PAYLOAD', 'Demande expirée, recommencez')

        const verification = await verifyRegistrationResponse({
          response: req.body?.response,
          expectedChallenge: challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpID,
          requireUserVerification: true,
        })

        if (!verification.verified || !verification.registrationInfo) {
          return fail(res, 400, 'INVALID_PAYLOAD', 'Clé d\'accès non vérifiée')
        }

        const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
        const name = String(req.body?.name || '').trim().slice(0, 60) || 'Clé d\'accès'
        const id = randomUUID()

        await database('account_passkeys').insert({
          id,
          user: userId,
          name,
          credential_id: credential.id,
          public_key: toBase64Url(credential.publicKey),
          counter: credential.counter,
          transports: JSON.stringify(credential.transports || []),
          device_type: credentialDeviceType,
          backed_up: credentialBackedUp,
          date_created: new Date(),
          last_used_at: null,
        })

        await logEvent(userId, 'passkey_added', req)
        res.json({ data: { id, name } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 400, 'INVALID_PAYLOAD', 'Impossible d\'enregistrer la clé d\'accès')
      }
    })

    router.delete('/passkeys/:id', requireUser, async (req, res) => {
      try {
        const deleted = await database('account_passkeys')
          .where({ id: req.params.id, user: req.accountability.user })
          .del()
        if (!deleted) return fail(res, 404, 'ROUTE_NOT_FOUND', 'Clé d\'accès introuvable')

        await logEvent(req.accountability.user, 'passkey_removed', req)
        res.json({ data: { deleted } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de supprimer la clé d\'accès')
      }
    })

    // Connexion sans mot de passe (endpoints publics)
    router.post('/passkeys/login/options', async (req, res) => {
      try {
        const config = passkeyConfig(req)
        if (!config) return fail(res, 400, 'INVALID_PAYLOAD', 'Origine non autorisée pour les clés d\'accès')
        if (!hit(`passkey-login-options:${req.ip}`, 30, 10 * 60 * 1000)) {
          return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez plus tard.')
        }

        const options = await generateAuthenticationOptions({ rpID: config.rpID, userVerification: 'required' })
        const challengeId = await saveChallenge(options.challenge, 'login')
        res.json({ data: { options, challenge_id: challengeId } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de préparer la connexion')
      }
    })

    router.post('/passkeys/login/verify', async (req, res) => {
      const invalid = () => fail(res, 401, 'INVALID_CREDENTIALS', 'Clé d\'accès invalide')

      try {
        const config = passkeyConfig(req)
        if (!config) return fail(res, 400, 'INVALID_PAYLOAD', 'Origine non autorisée pour les clés d\'accès')
        if (!hit(`passkey-login-verify:${req.ip}`, 10, 10 * 60 * 1000)) {
          return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez plus tard.')
        }

        const response = req.body?.response
        const challenge = await consumeChallenge(String(req.body?.challenge_id || ''), 'login')
        if (!challenge || !response?.id) return invalid()

        const passkey = await database('account_passkeys').where({ credential_id: response.id }).first()
        if (!passkey) return invalid()

        const verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge,
          expectedOrigin: config.origin,
          expectedRPID: config.rpID,
          requireUserVerification: true,
          credential: {
            id: passkey.credential_id,
            publicKey: fromBase64Url(passkey.public_key),
            counter: Number(passkey.counter) || 0,
            transports: parseJson(passkey.transports) || undefined,
          },
        })

        if (!verification.verified) return invalid()

        const user = await database('directus_users').where({ id: passkey.user, status: 'active' }).first('id')
        if (!user) return invalid()

        await database('account_passkeys')
          .where({ id: passkey.id })
          .update({ counter: verification.authenticationInfo.newCounter, last_used_at: new Date() })

        // Session standard : une ligne directus_sessions est créée puis échangée par le refresh natif,
        // qui produit le jeton d'accès avec les bons droits (rôle, policies).
        const refreshToken = randomBytes(48).toString('base64url')
        await database('directus_sessions').insert({
          token: refreshToken,
          user: user.id,
          expires: new Date(Date.now() + parseDuration(env.REFRESH_TOKEN_TTL, 7 * 86400000)),
          ip: req.ip || null,
          user_agent: String(req.get('user-agent') || '').slice(0, 1024) || null,
          origin: req.get('origin') || null,
        })

        const authService = new services.AuthenticationService({
          accountability: { role: null, ip: req.ip, userAgent: req.get('user-agent'), origin: req.get('origin') },
          schema: await getSchema(),
        })
        const session = await authService.refresh(refreshToken)

        await logEvent(user.id, 'passkey_login', req)
        res.json({
          data: {
            access_token: session.accessToken,
            refresh_token: session.refreshToken,
            expires: session.expires,
          },
        })
      }
      catch (error) {
        logger.error(error)
        invalid()
      }
    })

    // ── Appareils de confiance (OTP non redemandé si 2FA actif + session renouvelée automatiquement) ─────
    // Variable d'environnement Directus : TRUSTED_DEVICE_MAX_DAYS (défaut 30, plafond 90).
    // Le navigateur conserve un jeton aléatoire (seul son hash HMAC est stocké). Il permet :
    //   - /trusted-devices/login   : connexion e-mail + mot de passe sans code OTP (utilisateurs avec 2FA)
    //   - /trusted-devices/session : nouvelle session sans mot de passe tant que l'appareil est de confiance (avec ou sans 2FA)
    // Révoqué à la demande de l'utilisateur, au changement de mot de passe et à la désactivation du 2FA.

    const trustedMaxDays = () => Math.max(1, Math.min(Number(env.TRUSTED_DEVICE_MAX_DAYS) || 30, 90))

    const hashDeviceToken = token =>
      createHmac('sha256', String(env.SECRET || 'directus')).update(`trusted-device:${token}`).digest('hex')

    const findTrustedDevice = async (token) => {
      const value = String(token || '')
      if (value.length < 32 || value.length > 128) return null
      const row = await database('account_trusted_devices').where({ token_hash: hashDeviceToken(value) }).first()
      if (!row || new Date(row.expires_at).getTime() <= Date.now()) return null
      return row
    }

    const sessionPayload = session => ({
      data: {
        access_token: session.accessToken,
        refresh_token: session.refreshToken,
        expires: session.expires,
      },
    })

    router.post('/trusted-devices/register', requireUser, async (req, res) => {
      try {
        const userId = req.accountability.user

        const days = Math.max(1, Math.min(Math.floor(Number(req.body?.days)) || 14, trustedMaxDays()))
        const token = randomBytes(48).toString('base64url')
        const expiresAt = new Date(Date.now() + days * 86400000)

        // Les plus anciens appareils sont écartés au-delà de la limite
        const existing = await database('account_trusted_devices').where({ user: userId }).orderBy('date_created', 'desc').select('id')
        const surplus = existing.slice(MAX_TRUSTED_DEVICES - 1).map(row => row.id)
        if (surplus.length) await database('account_trusted_devices').whereIn('id', surplus).del()

        await database('account_trusted_devices').insert({
          id: randomUUID(),
          user: userId,
          token_hash: hashDeviceToken(token),
          ip: req.ip || null,
          user_agent: String(req.get('user-agent') || '').slice(0, 512) || null,
          date_created: new Date(),
          expires_at: expiresAt,
          last_used_at: new Date(),
        })

        await logEvent(userId, 'trusted_device_added', req)
        res.json({ data: { token, expires_at: expiresAt.toISOString(), days } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible d\'enregistrer l\'appareil de confiance')
      }
    })

    router.get('/trusted-devices', requireUser, async (req, res) => {
      try {
        const currentHash = req.get('x-trusted-device') ? hashDeviceToken(req.get('x-trusted-device')) : null
        const rows = await database('account_trusted_devices')
          .where({ user: req.accountability.user })
          .where('expires_at', '>', new Date())
          .orderBy('date_created', 'desc')
        res.json({
          data: rows.map(row => ({
            id: row.id,
            ip: row.ip || null,
            user_agent: row.user_agent || null,
            date_created: row.date_created,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            current: Boolean(currentHash) && row.token_hash === currentHash,
          })),
        })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de lister les appareils de confiance')
      }
    })

    router.delete('/trusted-devices/:id', requireUser, async (req, res) => {
      try {
        const deleted = await database('account_trusted_devices')
          .where({ id: req.params.id, user: req.accountability.user })
          .del()
        if (!deleted) return fail(res, 404, 'ROUTE_NOT_FOUND', 'Appareil introuvable')

        await logEvent(req.accountability.user, 'trusted_device_removed', req)
        res.json({ data: { deleted } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de retirer l\'appareil')
      }
    })

    router.delete('/trusted-devices', requireUser, async (req, res) => {
      try {
        const deleted = await database('account_trusted_devices').where({ user: req.accountability.user }).del()
        if (deleted) await logEvent(req.accountability.user, 'trusted_device_removed', req)
        res.json({ data: { deleted } })
      }
      catch (error) {
        logger.error(error)
        fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Impossible de retirer les appareils')
      }
    })

    // Connexion sans code OTP depuis un appareil de confiance (endpoint public, mot de passe toujours exigé)
    router.post('/trusted-devices/login', async (req, res) => {
      const email = String(req.body?.email || '').trim().toLowerCase()
      const password = String(req.body?.password || '')
      const invalid = () => fail(res, 401, 'INVALID_CREDENTIALS', 'Identifiants invalides')

      if (!email || !password) return invalid()
      if (!hit(`trusted-login:${req.ip}:${email}`, 10, 10 * 60 * 1000)) {
        return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez plus tard.')
      }

      try {
        const device = await findTrustedDevice(req.body?.device_token)
        const user = await database('directus_users')
          .whereRaw('lower(email) = ?', [email])
          .where({ status: 'active' })
          .first('id', 'tfa_secret')

        // Appareil expiré, révoqué ou 2FA modifié : le client retombe sur la saisie du code OTP
        if (!device || !user?.tfa_secret || device.user !== user.id) {
          return fail(res, 401, 'INVALID_DEVICE', 'Appareil non reconnu')
        }

        const authService = new services.AuthenticationService({
          accountability: { role: null, ip: req.ip, userAgent: req.get('user-agent'), origin: req.get('origin') },
          schema: await getSchema(),
        })
        const session = await authService.login(
          'default',
          { email, password },
          { otp: generateSync({ secret: user.tfa_secret, guardrails }) },
        )

        await database('account_trusted_devices').where({ id: device.id }).update({ last_used_at: new Date() })
        await logEvent(user.id, 'trusted_device_login', req)
        res.json(sessionPayload(session))
      }
      catch (error) {
        if (error?.code !== 'INVALID_CREDENTIALS') logger.error(error)
        invalid()
      }
    })

    // Renouvellement silencieux de la session (endpoint public) : tant que l'appareil est de confiance,
    // une session expirée est remplacée sans mot de passe ni OTP. Au-delà de la durée choisie : connexion classique.
    router.post('/trusted-devices/session', async (req, res) => {
      const invalid = () => fail(res, 401, 'INVALID_DEVICE', 'Appareil non reconnu')

      if (!hit(`trusted-session:${req.ip}`, 30, 10 * 60 * 1000)) {
        return fail(res, 429, 'REQUESTS_EXCEEDED', 'Trop de tentatives. Réessayez plus tard.')
      }

      try {
        const device = await findTrustedDevice(req.body?.device_token)
        if (!device) return invalid()

        const user = await database('directus_users').where({ id: device.user, status: 'active' }).first('id')
        if (!user) return invalid()

        const refreshToken = randomBytes(48).toString('base64url')
        await database('directus_sessions').insert({
          token: refreshToken,
          user: user.id,
          expires: new Date(Date.now() + parseDuration(env.REFRESH_TOKEN_TTL, 7 * 86400000)),
          ip: req.ip || null,
          user_agent: String(req.get('user-agent') || '').slice(0, 1024) || null,
          origin: req.get('origin') || null,
        })

        const authService = new services.AuthenticationService({
          accountability: { role: null, ip: req.ip, userAgent: req.get('user-agent'), origin: req.get('origin') },
          schema: await getSchema(),
        })
        const session = await authService.refresh(refreshToken)

        await database('account_trusted_devices').where({ id: device.id }).update({ last_used_at: new Date() })
        res.json(sessionPayload(session))
      }
      catch (error) {
        logger.error(error)
        invalid()
      }
    })
  },
}
