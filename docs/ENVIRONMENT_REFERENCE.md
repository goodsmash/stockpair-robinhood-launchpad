# Environment reference

## Browser and Vercel variables

Every `VITE_*` value is public and compiled into the browser bundle. Never put private RPC credentials, secrets or access tokens in these variables.

| Variable | Required | Validation |
|---|---:|---|
| `VITE_CHAIN_ID` | yes | Positive integer equal to target deployment chain. |
| `VITE_CHAIN_NAME` | yes | Bounded user-visible name. |
| `VITE_RPC_URL` | yes | HTTPS in production; no embedded credentials. RPC path is permitted. |
| `VITE_EXPLORER_URL` | yes | HTTPS origin only; no path/query/fragment/credentials. |
| `VITE_INDEXER_URL` | production | HTTPS origin only; no path/query/fragment/credentials. |
| `VITE_LAUNCHPAD_ADDRESS` | production | Exact non-zero verified deployment address. |
| `VITE_LAUNCHPAD_CODE_HASH` | production | `keccak256` of live launchpad runtime code. |
| `VITE_LAUNCHPAD_PROTOCOL_VERSION` | production | Must equal `0x154b42508933d53fbe3cac1f7e0e8ccf4a36169ed150f9171e2fae441e220309`. |
| `VITE_DEPLOYMENT_ACK` | production | Exact text `I_HAVE_VERIFIED_THE_FACTORY`. |
| `VITE_ENABLE_OPERATIONS` | always | Must remain `false` on public Vercel. |

Generate and independently review trust anchors with `scripts/verify-deployment.mjs`. Compare the result with the deployment transaction, source commit, compiler settings and authenticated release record.

## Indexer variables

The indexer is server-side and read-only. Inject secrets through the hosting secret manager, not repository files.

| Variable | Default | Purpose/rule |
|---|---|---|
| `HOST` | `127.0.0.1` | Container sets `0.0.0.0`; expose only behind TLS/proxy. |
| `PORT` | `8787` | HTTP listener. |
| `RH_CHAIN_ID` | `46630` | Primary chain ID. |
| `RH_CHAIN_NAME` | testnet label | Display label. |
| `RH_RPC_URL` | configured public endpoint | Use dedicated authenticated/archive RPC for production. |
| `RH_EXPLORER_URL` | configured explorer | Explorer/API origin. |
| `LAUNCHPAD_ADDRESS` | zero | Exact v0.6 deployment. |
| `LAUNCHPAD_CODE_HASH` | zero | Exact runtime hash. |
| `LAUNCHPAD_PROTOCOL_VERSION` | zero | Exact v0.6 launchpad version hash. |
| `PRODUCTION_TRADING_ENABLED` | `false` | Read-side verdict; browser still verifies independently. |
| `REQUIRE_EXPLORER_VERIFICATION` | `true` | Fail closed when required verification evidence is absent. |
| `ALLOWED_ORIGINS` | local Vite origins | Exact comma-separated origins. Wildcard, credentials, paths, queries and fragments are rejected. Production origins require HTTPS. |
| `TRUST_PROXY` | `false` | Enable only behind a reviewed proxy chain. |
| `TRUSTED_PROXY_IPS` | loopback | Exact proxy IPs trusted when walking `X-Forwarded-For` right-to-left. |
| `REQUEST_LIMIT_PER_MINUTE` | `120` | Per-resolved-client request limit. |
| `MAX_SSE_CONNECTIONS` | `100` | Global event-stream cap. |
| `MAX_SSE_PER_IP` | `3` | Per-client event-stream cap. |
| `SCOUT_*` | example config | Bounded lookback/polling, chains, labels and DEX events. |

The indexer response includes version/trust metadata for observability, but those values never replace direct browser RPC verification.

## Local generated files

`npm run local` writes disposable, ignored files:

- `deployments/local.json`
- `apps/web/.env.local`

Remove them before packaging. Never reuse deterministic local accounts or keys.
