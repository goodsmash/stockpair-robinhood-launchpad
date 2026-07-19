# User acceptance tests

Run against the exact Vercel Preview and separately hosted indexer before Production promotion.

## Environment/trust

- [ ] Chain, factory address, runtime hash and v0.6 protocol version match independent deployment evidence.
- [ ] Pool version/registration/initialization/fee/pair/issuer/metadata checks pass for a known market.
- [ ] Deliberately wrong factory hash/version locks every write with a red incident state.
- [ ] Unavailable or mismatched indexer produces amber degraded-data state and cannot authorize a write.
- [ ] Public operations are absent.

## Hostile-data behavior

- [ ] Malformed JSON and non-JSON API responses show safe errors.
- [ ] Responses over 2 MB and SSE events over 256 KB are rejected.
- [ ] Invalid addresses/hashes/amounts/risk labels are discarded or normalized.
- [ ] `javascript:`, credential-bearing and control-character explorer URLs never become clickable.
- [ ] HTML-like labels/findings render as text, not markup.

## Navigation/responsive/accessibility

- [ ] All eight views open by hash URL.
- [ ] No horizontal overflow at 390, 768, 1024 and 1440 px.
- [ ] Mobile navigation respects safe-area inset.
- [ ] Keyboard focus is visible; `/` focuses search; dialogs are understandable.
- [ ] Reduced-motion preference suppresses continuous motion.
- [ ] Loading, empty, disconnected, blocked, API-error and stale-indexer states remain readable.

## Wallet and transaction policy

- [ ] Wrong chain invokes switch/add flow and does not sign on the wrong network.
- [ ] Review shows target/function/sender/decoded args/policy.
- [ ] Existing allowance is zeroed and final allowance exactly equals required amount.
- [ ] Residual allowance revocation is attempted after success/failure.
- [ ] A 31-minute deadline reverts on-chain.
- [ ] Swap minimum looser than 3% and liquidity minimum looser than 1% revert on-chain.
- [ ] Input over 5% reserve, high browser price impact and non-self recipient are blocked/revert.
- [ ] Malicious indexer pool/spender substitution fails direct provenance verification.

## Launch/governance/emergency

- [ ] Unapproved, proxy, privileged, fee-on-transfer or wrong-code stock fails.
- [ ] Stale/invalid oracle fails.
- [ ] Creator allocation, vesting, seed value, fee and one-year LP custody checks apply.
- [ ] Eligibility over 30 days fails.
- [ ] Attestor/guardian/recovery changes cannot execute before 48 hours and can be guardian-canceled.
- [ ] Pending ownership cannot be accepted after seven days.
- [ ] Pause/delisting blocks new risk while preserving self-directed LP exit where specified.

## Production response headers

- [ ] CSP, frame denial, MIME, referrer, permissions, COOP/CORP and HSTS are present.
- [ ] Built frontend contains no localhost targets or embedded credentials.
- [ ] Static asset cache headers are immutable; HTML is not incorrectly immutable.
