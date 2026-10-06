// Erreurs de l'API : `extensions.code` reste un code Directus stable (INVALID_CREDENTIALS, INVALID_OTP…), sur lequel
// les clients doivent se baser ; `extensions.reason` précise le cas. Le message est générique et traduisible :
//   1. translation strings Directus (Settings → Translation Strings), clé « account_security.<reason> » ;
//   2. traductions intégrées ci-dessous ;
//   3. anglais.
// Langue retenue : langue de l'utilisateur Directus, sinon en-tête Accept-Language, sinon langue par défaut du projet.

export const TRANSLATION_PREFIX = 'account_security.'
const FALLBACK_LANGUAGE = 'en-US'
const CACHE_TTL_MS = 30 * 1000

export const ERRORS = {
  unauthenticated: { status: 401, code: 'INVALID_CREDENTIALS' },
  invalid_credentials: { status: 401, code: 'INVALID_CREDENTIALS' },
  invalid_otp: { status: 401, code: 'INVALID_OTP' },
  invalid_device: { status: 401, code: 'INVALID_DEVICE' },
  reauthentication_required: { status: 401, code: 'INVALID_CREDENTIALS' },
  tfa_required: { status: 400, code: 'INVALID_PAYLOAD' },
  current_session_unknown: { status: 400, code: 'INVALID_PAYLOAD' },
  origin_not_allowed: { status: 400, code: 'INVALID_PAYLOAD' },
  passkey_limit_reached: { status: 400, code: 'INVALID_PAYLOAD' },
  challenge_expired: { status: 400, code: 'INVALID_PAYLOAD' },
  passkey_verification_failed: { status: 400, code: 'INVALID_PAYLOAD' },
  not_found: { status: 404, code: 'ROUTE_NOT_FOUND' },
  too_many_requests: { status: 429, code: 'REQUESTS_EXCEEDED' },
  internal_error: { status: 500, code: 'INTERNAL_SERVER_ERROR' },
}

export const MESSAGES = {
  'en-US': {
    unauthenticated: 'Authentication required.',
    invalid_credentials: 'Invalid credentials.',
    invalid_otp: 'Invalid one-time password.',
    invalid_device: 'Device not recognized.',
    reauthentication_required: 'Please confirm your identity to continue.',
    tfa_required: 'Two-factor authentication must be enabled first.',
    current_session_unknown: 'The current session could not be identified.',
    origin_not_allowed: 'This origin is not allowed to use passkeys.',
    passkey_limit_reached: 'The maximum number of passkeys ({max}) has been reached.',
    challenge_expired: 'The request has expired. Please try again.',
    passkey_verification_failed: 'The passkey could not be verified.',
    not_found: 'Not found.',
    too_many_requests: 'Too many attempts. Please try again later.',
    internal_error: 'An unexpected error occurred.',
    default_passkey_name: 'Passkey',
  },
  'fr-FR': {
    unauthenticated: 'Authentification requise.',
    invalid_credentials: 'Identifiants invalides.',
    invalid_otp: 'Code à usage unique invalide.',
    invalid_device: 'Appareil non reconnu.',
    reauthentication_required: 'Veuillez confirmer votre identité pour continuer.',
    tfa_required: 'L\'authentification à deux facteurs doit d\'abord être activée.',
    current_session_unknown: 'La session courante n\'a pas pu être identifiée.',
    origin_not_allowed: 'Cette origine n\'est pas autorisée à utiliser les clés d\'accès.',
    passkey_limit_reached: 'Le nombre maximal de clés d\'accès ({max}) est atteint.',
    challenge_expired: 'La demande a expiré. Veuillez réessayer.',
    passkey_verification_failed: 'La clé d\'accès n\'a pas pu être vérifiée.',
    not_found: 'Introuvable.',
    too_many_requests: 'Trop de tentatives. Veuillez réessayer plus tard.',
    internal_error: 'Une erreur inattendue est survenue.',
    default_passkey_name: 'Clé d\'accès',
  },
}

// « fr-BE,fr;q=0.9,en;q=0.8 » → ['fr-BE', 'fr', 'en']
export const parseAcceptLanguage = header =>
  String(header || '')
    .split(',')
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(';')
      const q = Number(params.find(p => p.trim().startsWith('q='))?.split('=')[1] ?? 1)
      return { tag: tag.trim(), q: Number.isFinite(q) ? q : 0, index }
    })
    .filter(l => l.tag && l.tag !== '*' && l.q > 0 && /^[a-z]{2,3}(-[a-z0-9]{2,8})*$/i.test(l.tag))
    .sort((a, b) => b.q - a.q || a.index - b.index)
    .slice(0, 10)
    .map(l => l.tag)

// Langue disponible correspondant à une langue demandée : exacte, sinon même langue de base (fr-BE → fr-FR)
export const matchLanguage = (wanted, available) => {
  const lower = String(wanted).toLowerCase()
  const base = lower.split('-')[0]
  return available.find(l => l.toLowerCase() === lower)
    ?? available.find(l => l.toLowerCase().split('-')[0] === base)
    ?? null
}

const interpolate = (text, params) =>
  String(text).replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match))

export const createTranslator = ({ database }) => {
  let cache = { expiresAt: 0, strings: new Map(), defaultLanguage: FALLBACK_LANGUAGE }

  // Translation strings « account_security.* » et langue par défaut du projet, mises en cache
  const load = async () => {
    if (cache.expiresAt > Date.now()) return cache
    const strings = new Map()
    let defaultLanguage = FALLBACK_LANGUAGE
    try {
      const rows = await database('directus_translations')
        .where('key', 'like', `${TRANSLATION_PREFIX}%`)
        .select('key', 'language', 'value')
      for (const row of rows) {
        const reason = row.key.slice(TRANSLATION_PREFIX.length)
        if (!strings.has(reason)) strings.set(reason, {})
        strings.get(reason)[row.language] = row.value
      }
      defaultLanguage = (await database('directus_settings').first('default_language'))?.default_language || FALLBACK_LANGUAGE
    }
    catch {
      // Tables indisponibles : traductions intégrées uniquement
    }
    cache = { expiresAt: Date.now() + CACHE_TTL_MS, strings, defaultLanguage }
    return cache
  }

  const userLanguage = async (req) => {
    const user = req.accountability?.user
    if (!user) return null
    try {
      return (await database('directus_users').where({ id: user }).first('language'))?.language || null
    }
    catch {
      return null
    }
  }

  return async (req, key, params = {}) => {
    const { strings, defaultLanguage } = await load()
    const wanted = [await userLanguage(req), ...parseAcceptLanguage(req.get?.('accept-language')), defaultLanguage, FALLBACK_LANGUAGE]
      .filter(Boolean)
    const custom = strings.get(key) || {}

    for (const language of wanted) {
      const customMatch = matchLanguage(language, Object.keys(custom))
      if (customMatch) return interpolate(custom[customMatch], params)
      const builtInMatch = matchLanguage(language, Object.keys(MESSAGES))
      if (builtInMatch && MESSAGES[builtInMatch][key]) return interpolate(MESSAGES[builtInMatch][key], params)
    }
    return interpolate(MESSAGES[FALLBACK_LANGUAGE][key] ?? key, params)
  }
}
