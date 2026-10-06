# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.1](https://github.com/samuelfranzini/directus-extension-account-security/releases/tag/v1.0.1) - 2026-10-06

### Documentation

- Document request and response bodies of every route ([a76f44a](https://github.com/samuelfranzini/directus-extension-account-security/commit/a76f44ac1d9a2f8895554d1d321b2b8e1fde44c3))
- Add a security policy ([8c2b0d5](https://github.com/samuelfranzini/directus-extension-account-security/commit/8c2b0d5aaf4ac05d810e997485e23458001bbfa7))

## [1.0.0](https://github.com/samuelfranzini/directus-extension-account-security/releases/tag/v1.0.0) - 2026-10-06

### Features

- Integrate guardrails for TFA secret management in OTP verification ([effb662](https://github.com/samuelfranzini/directus-extension-account-security/commit/effb662d5ed8080306eb60414b9d4ba858617a16))
- Add support for passkeys (WebAuthn) authentication ([648a91c](https://github.com/samuelfranzini/directus-extension-account-security/commit/648a91c6ee2de06f9b4419dc53e567f3c2099584))
- Add trusted devices functionality for 2FA users ([1a37e12](https://github.com/samuelfranzini/directus-extension-account-security/commit/1a37e12338ff1e12a7775c6c33d3e8256b9bce60))
- Configure the extension from Directus settings and create its collections on startup ([d994b5b](https://github.com/samuelfranzini/directus-extension-account-security/commit/d994b5be6d4d108710e4338a0a3164e2e40614f0))
- Translatable error messages, re-authentication and security hardening ([53696dc](https://github.com/samuelfranzini/directus-extension-account-security/commit/53696dc9f16fcc009d2d38113f41df8620ce55d8))

### Refactoring

- Replace authenticator with otplib's generateSync and verifySync for OTP handling ([6421b75](https://github.com/samuelfranzini/directus-extension-account-security/commit/6421b75b6f4ffb0f3ca19588df27d6e77792b065))

