# StockPair security policy and operating boundary

## Supported release

The actively hardened handoff is **v0.6.0**. Earlier deployments are immutable and must not be represented as upgraded by publishing this source tree. Deploy v0.6 as a new stack with independently verified addresses and hashes.

## Reporting a vulnerability

Do not publish exploitable details, keys, user data or incident evidence in a public issue. Use the repository owner's private vulnerability-reporting channel and include:

- affected release/commit, chain ID and addresses;
- transaction hashes or a minimal local reproduction;
- expected and observed behavior;
- impact, prerequisites and whether exploitation is ongoing; and
- relevant frontend bundle, DNS/CDN/CI, signer, RPC and indexer evidence.

Do not move funds, probe unrelated users or exploit a live deployment to demonstrate impact.

## Security architecture

### Browser

The browser must independently verify the configured chain and factory runtime hash/version. Before any approval/write it proves the factory launch record, pool registration, pool factory/version/initialization/fee/token pair, launch-token issuer/version/metadata commitment, stock code hash, emergency posture, oracle policy and self-recipient. Every REST/SSE payload is normalized and bounded before render. Explorer links are restricted to validated HTTPS origins outside local development.

Approvals must equal the requested amount exactly, replacing a nonzero allowance with zero first. Liquidity/swap/launch workflows attempt to revoke residual allowances after completion or failure.

### Contracts

The protocol enforces, independently of the UI:

- maximum 30-minute transaction deadlines;
- maximum 3% swap minimum-output looseness;
- maximum 1% liquidity minimum-output looseness;
- maximum 5% swap input relative to input reserve;
- self-recipient execution;
- strict stock-token admission and full-runtime bytecode policy;
- fee-on-transfer/reentrancy/oracle rejection;
- creator allocation, one-year vesting and one-year initial LP custody;
- delayed administration with guardian cancellation;
- seven-day ownership-acceptance expiry; and
- maximum 30-day eligibility attestations with delayed recovery changes.

### Indexer

The indexer is read-only and has no signer. It uses exact origin allowlists, request limits, global/per-IP SSE limits, bounded feeds, slow-consumer removal and reviewed trusted-proxy parsing. Its data is informative; it is never sufficient authorization for a wallet write.

## Operational requirements

- Separate owner multisig, guardian and deployer responsibilities.
- Use hardware-backed signers and dedicated authenticated/archive RPC infrastructure.
- Keep public administrative UI disabled.
- Publish exact deployment addresses, code hashes and protocol versions through an authenticated release channel.
- Monitor queued actions, ownership transfers, pauses, registry changes, oracle status, code hashes, DNS/CDN/CI and frontend bundle integrity.
- Rehearse the incident runbook and approval-revocation communication before funding.

## Known boundaries

This repository cannot recover completed thefts, patch historical deployments, prove the original incident root cause or guarantee absence of unknown vulnerabilities. Independent contract, economic, frontend and infrastructure audits plus legal/compliance review remain mandatory before real-value use.
