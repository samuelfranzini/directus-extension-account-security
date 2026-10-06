import { createHash, randomInt } from 'node:crypto'

const BACKUP_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

// Limiteur de tentatives en mémoire (par processus). Borné pour ne pas pouvoir être saturé par des clés aléatoires.
const attempts = new Map()
const MAX_TRACKED_KEYS = 10000
const SWEEP_INTERVAL_MS = 60 * 1000
let lastSweep = 0

export const parseDuration = (value, fallbackMs) => {
  if (typeof value === 'number') return value
  const match = /^(\d+)\s*(ms|s|m|h|d|w)?$/.exec(String(value || '').trim())
  if (!match) return fallbackMs
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[match[2] || 'ms']
  return Number(match[1]) * unit
}

export const hit = (key, max, windowMs) => {
  const now = Date.now()
  if (now - lastSweep > SWEEP_INTERVAL_MS || attempts.size >= MAX_TRACKED_KEYS) {
    lastSweep = now
    for (const [k, v] of attempts) if (v.expiresAt <= now) attempts.delete(k)
    // Toujours saturé : les entrées les plus anciennes sont abandonnées
    for (const k of attempts.keys()) {
      if (attempts.size < MAX_TRACKED_KEYS) break
      attempts.delete(k)
    }
  }
  const current = attempts.get(key)
  if (!current || current.expiresAt <= now) {
    attempts.set(key, { count: 1, expiresAt: now + windowMs })
    return true
  }
  if (current.count >= max) return false
  current.count += 1
  return true
}

// Limite atteinte, sans compter de tentative (pour ne pénaliser que les échecs avec hit)
export const blocked = (key, max) => {
  const current = attempts.get(key)
  return Boolean(current) && current.expiresAt > Date.now() && current.count >= max
}

export const fail = (res, status, code, message, extensions = {}) =>
  res.status(status).json({ errors: [{ message, extensions: { code, ...extensions } }] })

export const sessionId = token => createHash('sha256').update(String(token)).digest('hex').slice(0, 24)

export const generateBackupCode = () => {
  const chars = Array.from({ length: 10 }, () => BACKUP_ALPHABET[randomInt(BACKUP_ALPHABET.length)])
  return `${chars.slice(0, 5).join('')}-${chars.slice(5).join('')}`
}

export const normalizeBackupCode = value => String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '')

// Liste depuis un tableau (champ JSON Directus, éventuellement sérialisé) ou une chaîne séparée par des virgules
export const listSetting = (value) => {
  const parsed = typeof value === 'string' && value.trim().startsWith('[') ? parseJson(value) : value
  const items = Array.isArray(parsed) ? parsed : String(parsed || '').split(',')
  return items.map(v => String(v).trim()).filter(Boolean)
}

export const parseJson = (value) => {
  if (!value) return null
  if (typeof value === 'object') return value
  try {
    return JSON.parse(value)
  }
  catch {
    return null
  }
}
