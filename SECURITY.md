# Security Policy

This extension handles authentication material (sessions, 2FA backup codes, passkeys, trusted devices), so security reports are taken seriously and handled first.

## Supported versions

Only the latest release receives security fixes. Upgrade to the [latest version](https://www.npmjs.com/package/directus-extension-account-security) before reporting.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: [**Report a vulnerability**](https://github.com/samuelfranzini/directus-extension-account-security/security/advisories/new) (Security tab → *Report a vulnerability*).

Please include:

- the affected version and Directus version;
- a description of the issue and its impact;
- steps or a proof of concept to reproduce it;
- any suggested fix, if you have one.

## What to expect

- Acknowledgement within 5 business days.
- An assessment and, if confirmed, a fix plan within 14 days.
- A patched release and a GitHub security advisory crediting you (unless you prefer to stay anonymous) once the fix is available.

Please give us a reasonable time to release a fix before any public disclosure.

## Scope

In scope: the code of this extension (`src/`) and its release pipeline (`.github/workflows/`).

Out of scope: vulnerabilities in Directus itself (report them to [Directus](https://github.com/directus/directus/security)), in third-party dependencies (report them upstream; we will update once a fix is published), and issues requiring a compromised server or administrator account.
