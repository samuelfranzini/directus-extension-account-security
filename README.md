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

## Endpoints

All routes are mounted under `/account-security`.

| Method | Route | Auth |
| --- | --- | --- |
| `GET` | `/sessions` | user |
| `POST` | `/sessions/revoke-others` | user |
| `DELETE` | `/sessions/:id` | user |
| `GET` | `/activity` | user |
| `GET` | `/backup-codes` | user |
| `POST` | `/backup-codes/generate` | user |
| `POST` | `/backup-login` | public |
| `GET` | `/passkeys` | user |
| `POST` | `/passkeys/register/options` | user |
| `POST` | `/passkeys/register/verify` | user |
| `DELETE` | `/passkeys/:id` | user |
| `POST` | `/passkeys/login/options` | public |
| `POST` | `/passkeys/login/verify` | public |
| `GET` | `/trusted-devices` | user |
| `POST` | `/trusted-devices/register` | user |
| `DELETE` | `/trusted-devices/:id` | user |
| `DELETE` | `/trusted-devices` | user |
| `POST` | `/trusted-devices/login` | public |
| `POST` | `/trusted-devices/session` | public |

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

Releases are driven by git tags and published to npm by GitHub Actions. Commits must follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `perf:`, `refactor:`…) so that the changelog is generated correctly.

```bash
npm version patch   # or minor / major / prerelease --preid beta
git push --follow-tags
```

`npm version` bumps `package.json`, regenerates `CHANGELOG.md` with [git-cliff](https://git-cliff.org), commits and creates the `vX.Y.Z` tag. Pushing the tag triggers the [release workflow](.github/workflows/release.yml), which runs the whole test suite, builds, publishes to npm with provenance (pre-releases go to the matching dist-tag, e.g. `beta`) and creates the GitHub release with the generated notes.

Publishing uses npm [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC): no npm token is stored in GitHub. To set it up, publish the first version manually (`npm publish`, with your 2FA), then on npmjs.com go to the package **Settings → Trusted publishing** and add this repository with the `release.yml` workflow.

## License

[MIT](LICENSE)
