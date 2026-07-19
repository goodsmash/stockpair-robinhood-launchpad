# Changelog

## 0.6.0

### Security

- Added runtime validation and size/content-type limits for every browser REST/SSE payload.
- Restricted explorer links to validated origins and rejected credential-bearing or script URLs.
- Split direct on-chain execution failure from indexer-data degradation.
- Added exact allowance equality, zero-first replacement and best-effort residual revocation.
- Added direct pool protocol/version/initialization/fee/issuer/metadata provenance checks.
- Added on-chain 30-minute deadline ceilings for launch, swap and liquidity calls.
- Added on-chain maximum 3% swap-minimum and 1% liquidity-minimum looseness.
- Added seven-day pending-ownership expiry.
- Added maximum 30-day eligibility attestations.
- Moved eligibility attestor/guardian changes and emergency-denial clearing behind 48-hour guardian-cancelable scheduling.
- Hardened proxy-chain client-IP parsing, SSE accounting/backpressure and production origin validation.

### Tests and handoff

- Added malicious browser-data runtime regressions.
- Added indexer perimeter/SSE regressions.
- Added deployed-bytecode compromised-frontend and eligibility-governance exploit proofs.
- Expanded the isolated deployed-bytecode matrix from 11 to 13 scenarios.
- Updated UI, deployment, Vercel, GitHub, indexer, security and agent handoff documentation.

## 0.5.0

- Completed responsive product UI, local setup, Vercel/static frontend handoff, containerized indexer, GitHub automation and agent/operator guides around the v0.4 protocol.

## 0.4.0

- Emergency security redesign: fail-closed browser verification, strict asset policy, delayed administration, guardian controls, vesting, LP custody, oracle/value controls and hardened deployment workflow.

## 0.3.0

- Initial complete product/Scout handoff. Retained only for historical incident analysis; do not deploy.
