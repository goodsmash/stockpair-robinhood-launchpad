# StockPair v0.6.0 complete agent handoff

## Current baseline

- Release: `0.6.0`.
- Node: `22.x`; npm: `10.x`.
- Solidity compiler: `0.8.30`, via IR, optimizer settings recorded in `artifacts/solc/_build-info.json`.
- Browser: Vite/TypeScript in `apps/web`.
- Indexer: read-only Node REST/SSE service in `services/indexer`.
- Local stack: Ganache + deployment/seed + indexer + Vite via `npm run local`.
- Public operations: disabled by default and required to remain disabled on Vercel.

Protocol identifiers:

- Launchpad: `STOCKPAIR_LAUNCHPAD_V0.6.0` / `0x154b42508933d53fbe3cac1f7e0e8ccf4a36169ed150f9171e2fae441e220309`.
- Pool: `STOCKPAIR_POOL_V0.6.0` / `0x0269a24b872333bf362a076efb861f9c12f7fee6d061827d296ef0a6d9462e5c`.
- Launch token: `STOCKPAIR_LAUNCH_TOKEN_V0.6.0` / `0xdc9567935f3f37b6cdf78141b374ee0d1f0ea741034125cc37f2e42e0727d40b`.
- Eligibility gate: `STOCKPAIR_ELIGIBILITY_GATE_V0.6.0` / `0x31ce7c3469dd0a4b21e90c5bf36dfcb8560d5de52d2865d311aa39280659dd26`.

## Why v0.6 exists

The final review found two material classes not fully covered in v0.5:

1. indexer-controlled runtime values could reach dynamic HTML/links without complete runtime schemas; and
2. deadline/minimum-output safety was partly selected by the frontend instead of enforced by contracts.

v0.6 adds hostile-input normalization, safe URL reconstruction, exact approval equality, deeper pool provenance, contract-enforced deadline/slippage bounds, expiring ownership acceptance and delayed eligibility recovery controls. See `docs/V0.6.0_SECURITY_REVIEW.md`.

## Start and verify

```bash
npm run setup
npm run local
```

For source changes:

```bash
npm run compile
npm run verify
```

A contract compile regenerates `artifacts/solc`. After ABI changes ensure `apps/web/src/abi/contracts.ts` matches the final artifacts. Never edit generated ABI fragments without rebuilding/rechecking.

Run all 13 EVM scenarios independently. Do not count a timeout, partial TAP output or Ganache process exit as a pass. Only logs ending with zero failures are release evidence. The optional Ganache native µWS binary may not match Node 22 in some Linux containers; the JavaScript fallback is slower but is a test-environment warning, not production code.

## Architecture and trust boundaries

- The browser is the final client-side write gate.
- The indexer is a non-authoritative, read-only aggregation service.
- Direct RPC contract reads establish factory/pool/token/oracle provenance.
- Scanner/Scout discoveries cannot become executable markets.
- Vercel hosts static assets only; the SSE/indexer runs separately.
- No public component has an owner/guardian signer or private key.

The browser must preserve the distinction between:

- red direct on-chain execution lock; and
- amber indexer-data degradation.

## High-risk files

- `src/StockCoinLaunchpad.sol`
- `src/StockCoinPool.sol`
- `src/AttestedEligibilityGate.sol`
- `src/utils/TwoStepAdmin.sol`
- `src/libraries/BytecodePolicy.sol`
- `apps/web/src/main.ts`
- `apps/web/src/lib/security.ts`
- `services/indexer/src/server.mjs`
- `services/indexer/src/config.mjs`
- `scripts/deploy-robinhood-testnet.sh`
- `scripts/verify-deployment.mjs`

Changes to these files require threat-model review and exploit regression coverage.

## Browser invariants

- API and SSE values remain `unknown` until normalized.
- Addresses/hashes/amounts/links must be canonical and bounded.
- External links must never accept `javascript:`, credentials or control characters.
- Approval equality must be exact; zero first when replacing allowance.
- `verifyPool` must prove registration, factory, version, initialization, fee, pair, issuer, launch-token version and metadata commitment.
- Direct on-chain mismatch disables writes regardless of indexer claims.
- Transaction review must show network, target, function, sender, decoded arguments and enforced policy.

## Contract invariants

- Maximum deadline window: 30 minutes.
- Maximum swap-minimum looseness: 3%.
- Maximum liquidity-minimum looseness: 1%.
- Maximum swap input: 5% of input reserve.
- Recipient equals caller.
- Creator allocation <=10%; creator vesting and initial LP custody >=1 year.
- Strict stock runtime policy; no fee-on-transfer, proxy/delegate, privileged mint/tax/blacklist/selfdestruct ambiguity.
- Admin restoration/config changes delayed 48 hours and guardian-cancelable.
- Pending ownership expires after seven days.
- Eligibility validity <=30 days; role/recovery changes delayed.

## Release process

1. Remove old local state and stale QA evidence.
2. Install locked dependencies.
3. Compile; regenerate/check ABI.
4. Run quick suite and every isolated EVM scenario.
5. Run root/web production dependency audits.
6. Run `npm run setup`, `npm run local`, REST/SSE/UI HTTP smoke and responsive browser screenshots/console capture where the execution environment permits local navigation. Record a managed-browser policy block as an external gate; never claim a screenshot or zero-console-error pass without evidence.
7. Validate Vercel production environment and production build.
8. Parse GitHub YAML/JSON and check release tree.
9. Create `RELEASE_VERIFICATION.json`, `SHA256SUMS`, `release-manifest.json`.
10. Remove `node_modules`, `.env.local`, `deployments/local.json`, `.git`, temp processes/files.
11. Package and verify archive integrity/hygiene.

## External gates

Do not report completion of: independent audits, live Robinhood Chain deployment, real Vercel/GitHub account setup, production Docker/image scanning, legal/compliance approval, incident attribution or fund recovery unless concrete evidence is added. The original reported incident remains forensically unresolved without transaction and infrastructure evidence.
