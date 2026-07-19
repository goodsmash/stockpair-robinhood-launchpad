# StockPair v0.6.0 agent instructions

Read this file, `docs/AGENT_HANDOFF.md`, `SECURITY.md`, `docs/UI_SECURITY_MODEL.md` and `docs/THREAT_MODEL.md` before changing executable code.

## Mission

Improve the user application, read-only indexer and contract protocol without weakening the fail-closed trust model or making unsupported production claims.

## Non-negotiable invariants

1. Never commit or log keys, mnemonics, sessions, signatures, unrestricted RPC credentials, compliance secrets or production environment files.
2. Treat REST, SSE, wallet-provider and explorer data as hostile. Runtime-validate and bound it before state or DOM use.
3. Never trust an API-supplied factory, pool, spender, token, code hash, version, fee, issuer or chain ID in a write path; prove it by direct RPC calls.
4. Preserve exact allowance equality, zero-first replacement and residual revocation. Never introduce unlimited approvals.
5. Preserve self-recipient enforcement, 30-minute on-chain deadline ceilings, 3% swap-minimum and 1% liquidity-minimum bounds.
6. Preserve factory-only markets, pool registration/version/initialization/fee/token/issuer/metadata checks and strict stock-asset bytecode policy.
7. Preserve fee-on-transfer and reentrancy rejection, oracle freshness, reserve/input limits, creator vesting and one-year LP custody.
8. Preserve seven-day ownership-acceptance expiry, 48-hour delayed recovery/configuration and guardian cancellation.
9. Keep public `VITE_ENABLE_OPERATIONS=false`. Administrative actions belong on a separate hardened origin/process.
10. Do not weaken CSP, exact CORS, production-origin validation, trusted-proxy parsing, body/SSE limits or slow-client removal.
11. Never describe the project as audited, certified, approved, mainnet-ready, unhackable or incident-recovered without independent evidence.

## Workflow

Bootstrap and fast verification:

```bash
npm run setup
npm run compile
npm run verify
```

Contract, ABI, write-path, scanner, emergency, eligibility or indexer-perimeter changes require affected isolated EVM tests plus the full 13-scenario matrix before release. UI changes require:

```bash
npm --prefix apps/web run check
npm --prefix apps/web run test:ui
npm --prefix apps/web run build
```

Inspect 390, 768, 1024 and 1440 pixel widths. Check keyboard focus, disconnected wallet, loading, empty, invalid API, oversized API, unavailable indexer, mismatched indexer, direct RPC mismatch and emergency states.

## Security ownership by file

- Browser rendering/write path: `apps/web/src/main.ts`.
- Runtime data/URL validation: `apps/web/src/lib/security.ts`.
- Browser ABI: `apps/web/src/abi/contracts.ts`.
- Visual system: `apps/web/src/style.css`.
- Production environment/CSP: `apps/web/scripts/validate-env.mjs`, `apps/web/scripts/harden-dist.mjs`, `vercel.json`.
- Indexer perimeter/config: `services/indexer/src/server.mjs`, `services/indexer/src/config.mjs`.
- Contracts: `src/`.
- Deployed-bytecode tests: `scripts/e2e/`.
- Release gates: `scripts/static-audit.mjs`, `scripts/check-release.mjs`.

## Required change sequence

1. State the threat and user impact.
2. Identify the invariant and existing test.
3. Implement the smallest coherent fix across contract/browser/indexer where required.
4. Add an executable exploit regression before declaring resolution.
5. Compile and regenerate ABI/artifacts.
6. Run quick, isolated EVM, local-stack and production-build checks.
7. Update security/release documentation and evidence.
8. Remove local state, dependencies, secrets and temporary output before packaging.

## Release claims

A passing local suite proves only the tested implementation and scenarios. It does not prove production infrastructure, third-party assets, legal status, independent audit, forensic attribution or fund recovery. Record every unavailable external gate explicitly.
