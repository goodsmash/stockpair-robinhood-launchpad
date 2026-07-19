# Vercel deployment guide

Vercel serves only the static `apps/web` build. It does not host the long-running REST/SSE indexer in this architecture.

## 1. Prepare a verified deployment

Deploy v0.6 to the intended chain through the reviewed two-phase process. Independently record:

- chain ID;
- launchpad address;
- live runtime code hash;
- launchpad protocol version `0x154b42508933d53fbe3cac1f7e0e8ccf4a36169ed150f9171e2fae441e220309`;
- source commit, compiler and settings hashes; and
- owner/guardian/registry/oracle role addresses.

Do not reuse historical v0.3-v0.5 addresses.

## 2. Deploy the indexer first

Deploy `deploy/indexer/Dockerfile` to a persistent container service with HTTPS, health monitoring and exact `ALLOWED_ORIGINS`. Confirm `/health`, `/api/config` and `/api/stream` before configuring Vercel.

## 3. Import the repository root

The included `vercel.json` defines:

- Vite framework;
- `npm --prefix apps/web ci` install;
- fail-closed `build:vercel` command;
- `apps/web/dist` output;
- SPA routing; and
- security/cache headers.

Do not set the Vercel root directory to `apps/web`; the configuration assumes repository-root import.

## 4. Set Production environment variables

Use the exact variables in `docs/ENVIRONMENT_REFERENCE.md`. `VITE_EXPLORER_URL` and `VITE_INDEXER_URL` must be origins only. The build rejects HTTP, localhost, credentials, zero trust anchors and missing deployment acknowledgement in Production.

Keep `VITE_ENABLE_OPERATIONS=false`.

## 5. Preview validation

Before promoting Production:

```bash
npm --prefix apps/web run build:vercel
```

Then complete `docs/USER_ACCEPTANCE_TESTS.md`, including deliberate wrong hash/version tests on a disposable Preview. Verify that wrong direct on-chain trust anchors produce a red lock, while an unavailable/mismatched indexer produces an amber degraded-data state and cannot authorize writes.

## 6. Production controls

- Protect Vercel account and domain/DNS with phishing-resistant MFA.
- Restrict production deployments and environment changes to reviewed teams.
- Enable deployment protection for previews containing live trust anchors.
- Monitor deployment/bundle hashes, domain/DNS changes, CSP violations and unusual wallet prompts.
- Roll back static assets only to a release matching the same on-chain protocol; never point an older browser at an incompatible deployment.

## 7. Not performed by this handoff

This repository does not create the Vercel project, configure its account permissions, issue domains/certificates or validate the final public deployment. Preserve screenshots, response headers and build logs as production evidence.
