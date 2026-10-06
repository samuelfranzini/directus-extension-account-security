# directus-extension-account-security

[![npm](https://img.shields.io/npm/v/directus-extension-account-security)](https://www.npmjs.com/package/directus-extension-account-security)
[![CI](https://github.com/samuelfranzini/directus-extension-account-security/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelfranzini/directus-extension-account-security/actions/workflows/ci.yml)

Directus endpoint extension that adds self-service account security features for the current user:

- **Active sessions**: list, revoke one, revoke all others
- **Activity log**: logins, profile changes (email, password, avatar) and security events
- **2FA backup codes**: generate single-use codes and log in with them
- **Passkeys (WebAuthn)**: register, list, delete and log in with passkeys
- **Trusted devices**: skip the OTP step on remembered devices

Compatible with Directus `^10.10.0 || ^11.0.0 || ^12.0.0`.

## Installation

### From the Directus Marketplace

In your project, go to **Settings → Marketplace**, search for **Account Security** and click **Install**.

> This is a non-sandboxed API extension (it needs direct database access), so the Marketplace only allows installing it when your instance sets `MARKETPLACE_TRUST=all`.

### With npm

```bash
npm install directus-extension-account-security
```

Or add it to your Directus `extensions` folder / Docker image as any other npm extension, then restart Directus.

## Database

On startup, the extension creates the collections it needs if they don't exist yet (existing collections are never modified). Set `ACCOUNT_SECURITY_AUTO_SETUP=false` to manage them yourself.

| Collection | Purpose |
| --- | --- |
| `account_security_settings` | Settings singleton, editable in the Data Studio (see below) |
| `account_security_events` | Security events log (`user`, `type`, `ip`, `user_agent`, `date_created`) |
| `account_backup_codes` | Hashed 2FA backup codes |
| `account_passkeys` | Registered passkeys (WebAuthn) |
| `account_passkey_challenges` | Pending WebAuthn challenges |
| `account_trusted_devices` | Trusted devices (hashed tokens) |

Data collections are hidden in the navigation and their `user` field cascades on user deletion.

## Configuration

Settings can be managed from Directus (**Content → Account Security Settings**) or with environment variables. A value filled in Directus takes precedence; an empty field falls back to the environment variable, then to the default. Changes made in Directus apply within 30 seconds.

| Directus field | Environment variable | Description | Default |
| --- | --- | --- | --- |
| `passkey_origins` | `PASSKEY_ORIGINS` | Allowed WebAuthn origins (comma-separated in env) | — |
| `passkey_rp_id` | `PASSKEY_RP_ID` | WebAuthn relying party ID (your parent domain) | — |
| `passkey_rp_name` | `PASSKEY_RP_NAME` | Name shown by the authenticator | `Directus` |
| `trusted_device_max_days` | `TRUSTED_DEVICE_MAX_DAYS` | Maximum trusted device lifetime in days (1–90) | `30` |
| — | `ACCOUNT_SECURITY_AUTO_SETUP` | Create missing collections on startup | `true` |
| — | `SECRET` / `REFRESH_TOKEN_TTL` | Reused from the Directus configuration | — |

Passkeys stay disabled until at least one origin and a relying party ID are configured (a `localhost` origin always uses the `localhost` RP ID for development).

## Errors & translations

Errors follow the [Directus error format](https://directus.com/docs/guides/connect/errors). Branch on `extensions.code` (a standard Directus code); `extensions.reason` tells the exact case:

```json
{ "errors": [{ "message": "Invalid one-time password.", "extensions": { "code": "INVALID_OTP", "reason": "invalid_otp" } }] }
```

| `reason` | `code` | HTTP |
| --- | --- | --- |
| `unauthenticated` | `INVALID_CREDENTIALS` | 401 |
| `invalid_credentials` | `INVALID_CREDENTIALS` | 401 |
| `invalid_otp` | `INVALID_OTP` | 401 |
| `invalid_device` | `INVALID_DEVICE` | 401 |
| `reauthentication_required` | `INVALID_CREDENTIALS` | 401 |
| `tfa_required` | `INVALID_PAYLOAD` | 400 |
| `current_session_unknown` | `INVALID_PAYLOAD` | 400 |
| `origin_not_allowed` | `INVALID_PAYLOAD` | 400 |
| `passkey_limit_reached` | `INVALID_PAYLOAD` | 400 |
| `challenge_expired` | `INVALID_PAYLOAD` | 400 |
| `passkey_verification_failed` | `INVALID_PAYLOAD` | 400 |
| `not_found` | `ROUTE_NOT_FOUND` | 404 |
| `too_many_requests` | `REQUESTS_EXCEEDED` | 429 |
| `internal_error` | `INTERNAL_SERVER_ERROR` | 500 |

Messages are generic (no hint about which credential was wrong) and translatable. The language is the Directus user's language, then the `Accept-Language` header, then the project default language. English and French are built in; to translate or reword a message, create a translation string in **Settings → Translation Strings** with the key `account_security.<reason>` (for example `account_security.invalid_otp`). `account_security.default_passkey_name` sets the default passkey name. Translation strings apply within 30 seconds.

## Re-authentication

Registering a passkey (`POST /passkeys/register/options`) or a trusted device (`POST /trusted-devices/register`) creates a lasting way to sign in, so a stolen access token is not enough: the request body must contain the current one-time password (`otp`) when 2FA is enabled, the account `password` otherwise. When it is missing or wrong, the error carries `extensions.method` (`otp` or `password`) so the client knows what to ask:

```json
{ "errors": [{ "message": "Please confirm your identity to continue.", "extensions": { "code": "INVALID_CREDENTIALS", "reason": "reauthentication_required", "method": "otp" } }] }
```

Only failed attempts count towards the limit (5 per 10 minutes per user).

## Security notes

- Trusted devices are bound to the user's credentials: changing the password or the 2FA secret revokes them. Backup codes are bound to the 2FA secret: resetting 2FA invalidates them.
- Backup codes and trusted device tokens are stored as HMAC (keyed with `SECRET`); keep `SECRET` stable and private.
- Rate limiting is kept in memory per Directus process. When running several instances, also enable the Directus rate limiter (`RATE_LIMITER_ENABLED`, with Redis) and set `IP_TRUST_PROXY` correctly behind a proxy so client IPs are accurate.

## API reference

All routes are mounted under `/account-security` and exchange JSON. Routes marked **user** need a Directus access token (`Authorization: Bearer …`) or session cookie; **public** routes do not. Errors use the format described in [Errors & translations](#errors--translations).

Routes that sign the user in return a Directus session, like `POST /auth/login` in `json` mode:

```json
{ "data": { "access_token": "…", "refresh_token": "…", "expires": 900000 } }
```

Request headers used by some routes:

| Header | Used by | Purpose |
| --- | --- | --- |
| `x-refresh-token` | sessions | Current refresh token, to flag or keep the current session (not needed in session-cookie mode) |
| `Origin` or `x-client-origin` | passkeys | Origin of the web app, checked against the allowed passkey origins. Send `x-client-origin` when calling from a server (SSR proxy) |
| `x-trusted-device` | `GET /trusted-devices` | Device token stored by the browser, to flag the current device |

### Sessions

| Route | Auth | Request | Response `data` |
| --- | --- | --- | --- |
| `GET /sessions` | user | header `x-refresh-token` (optional) | `[{ id, ip, user_agent, origin, expires, current }]` |
| `POST /sessions/revoke-others` | user | header `x-refresh-token` | `{ revoked }` (number of sessions closed) |
| `DELETE /sessions/:id` | user | `id` from the list | `{ revoked: 1 }` |

Session `id`s are derived from the refresh token (it is never exposed).

### Activity log

| Route | Auth | Request | Response `data` |
| --- | --- | --- | --- |
| `GET /activity` | user | query `limit` (1–100, default 50) | `[{ id, type, timestamp, ip, user_agent }]`, newest first |

`type` is one of: `login`, `email_changed`, `password_changed`, `avatar_changed`, `tfa_enabled`, `tfa_disabled`, `session_revoked`, `sessions_revoked`, `backup_codes_generated`, `backup_code_used`, `passkey_added`, `passkey_removed`, `passkey_login`, `trusted_device_added`, `trusted_device_removed`, `trusted_device_login`, `trusted_device_session`.

### 2FA backup codes

| Route | Auth | Request body | Response |
| --- | --- | --- | --- |
| `GET /backup-codes` | user | — | `data: { tfa_enabled, total, remaining, generated_at }` |
| `POST /backup-codes/generate` | user | `{ otp }` | `data: { codes }`: 10 single-use codes (`XXXXX-XXXXX`), shown once; replaces the previous codes |
| `POST /backup-login` | public | `{ email, password, code }` | Directus session, plus `meta: { remaining_backup_codes }` |

`POST /backup-login` replaces the OTP step for users with 2FA. A code is consumed only when the password is correct. Generating codes requires 2FA (`tfa_required` otherwise).

### Passkeys (WebAuthn)

The `options` and `response` objects are the JSON forms used by [`@simplewebauthn/browser`](https://simplewebauthn.dev/docs/packages/browser): pass `options` to `startRegistration({ optionsJSON })` / `startAuthentication({ optionsJSON })` and send back what they return.

| Route | Auth | Request body | Response `data` |
| --- | --- | --- | --- |
| `GET /passkeys` | user | — | `[{ id, name, device_type, backed_up, date_created, last_used_at }]` |
| `POST /passkeys/register/options` | user | `{ otp }` or `{ password }` (see [Re-authentication](#re-authentication)) | `{ options, challenge_id }` |
| `POST /passkeys/register/verify` | user | `{ challenge_id, response, name? }` | `{ id, name }` |
| `DELETE /passkeys/:id` | user | — | `{ deleted }` |
| `POST /passkeys/login/options` | public | — | `{ options, challenge_id }` |
| `POST /passkeys/login/verify` | public | `{ challenge_id, response }` | Directus session |

Challenges expire after 5 minutes and can be used once. A user can register up to 10 passkeys; `name` is limited to 60 characters (defaults to a translated “Passkey”).

```js
import { startAuthentication } from '@simplewebauthn/browser'

const { data } = await post('/account-security/passkeys/login/options')
const response = await startAuthentication({ optionsJSON: data.options })
const session = await post('/account-security/passkeys/login/verify', { challenge_id: data.challenge_id, response })
```

### Trusted devices

A trusted device lets a user with 2FA skip the OTP step, and renew an expired session without signing in again, until the device expires (at most `trusted_device_max_days`).

| Route | Auth | Request body | Response `data` |
| --- | --- | --- | --- |
| `POST /trusted-devices/register` | user | `{ days?, otp }` or `{ days?, password }` (see [Re-authentication](#re-authentication)) | `{ token, expires_at, days }` |
| `GET /trusted-devices` | user | header `x-trusted-device` (optional) | `[{ id, ip, user_agent, date_created, expires_at, last_used_at, current }]` |
| `DELETE /trusted-devices/:id` | user | — | `{ deleted }` |
| `DELETE /trusted-devices` | user | — | `{ deleted }` (all devices) |
| `POST /trusted-devices/login` | public | `{ email, password, device_token }` | Directus session |
| `POST /trusted-devices/session` | public | `{ device_token }` | Directus session |

`days` defaults to 14 and is capped by the settings. Store `token` safely on the device (it is shown once, only its HMAC is kept) and send it as `device_token`. When a route answers `INVALID_DEVICE` (expired or revoked device, password or 2FA changed), forget the token and fall back to the normal sign-in with OTP.

## Development

```bash
npm install
npm run dev     # watch build
npm run build   # production build in dist/
npm test        # unit tests
```

### End-to-end tests

`npm run test:e2e` runs the API scenarios (setup, sessions, passkeys, 2FA backup codes, trusted devices, settings) against a running Directus instance with the extension installed:

```bash
DIRECTUS_URL=http://localhost:8055 ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=… \
PASSKEY_ORIGINS=https://env.example.com PASSKEY_RP_ID=env.example.com npm run test:e2e
```

Use a throwaway instance: the tests enable 2FA on the admin account and change the settings. In CI they run on every push and pull request against Directus 10, 11 and 12 (SQLite).

## Releasing

Releases are driven by git tags and published to npm by GitHub Actions. Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `perf:`, `refactor:`…) so that the changelog is generated correctly. Commit messages and pull request titles are checked by [commitlint](https://commitlint.js.org) in CI ([commitlint.yml](.github/workflows/commitlint.yml)); `npm install` also enables a local `commit-msg` hook ([.githooks](.githooks)) that rejects non-conventional messages before the commit is created.

```bash
npm version patch   # or minor / major / prerelease --preid beta
git push --follow-tags
```

`npm version` bumps `package.json`, regenerates `CHANGELOG.md` with [git-cliff](https://git-cliff.org), commits and creates the `vX.Y.Z` tag. Pushing the tag triggers the [release workflow](.github/workflows/release.yml), which runs the whole test suite, builds, publishes to npm with provenance (pre-releases go to the matching dist-tag, e.g. `beta`) and creates the GitHub release with the generated notes.

Publishing uses npm [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC): no npm token is stored in GitHub. To set it up, publish the first version manually (`npm publish`, with your 2FA), then on npmjs.com go to the package **Settings → Trusted publishing** and add this repository with the `release.yml` workflow.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[MIT](LICENSE)
