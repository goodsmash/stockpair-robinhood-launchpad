# Deployment readiness

## Repository state

v0.6.0 contains a complete local/Vercel/GitHub/container handoff with source-matched artifacts, built browser assets, hostile-input UI tests, indexer perimeter tests and 13 isolated deployed-bytecode security scenarios.

## Ready for controlled engineering use

- Local setup and seeded stack.
- Static Vercel build with fail-closed environment validation.
- Separate read-only indexer container definition.
- GitHub CI/security/release automation.
- Source/artifact/hash verification and clean packaging.
- Responsive user UI and documented UAT.

## Not authorized for real value

The following are release gates, not optional follow-ups:

- independent smart-contract and economic audit of v0.6 bytecode;
- independent browser/indexer/infrastructure penetration review;
- live target-chain testnet/staging deployment and reorg/RPC-failure testing;
- canonical stock-token, source-verification, oracle and eligibility policy approval;
- hardware-backed owner/guardian multisig configuration and action monitoring;
- durable indexed storage, RPC failover, alerting and incident-response rehearsal;
- final Vercel/GitHub/container/account security configuration; and
- legal, securities/RWA, sanctions, privacy and jurisdictional approval.

The historical user-loss incident remains unresolved without transaction hashes and infrastructure evidence. This release does not recover funds or alter old contracts.
