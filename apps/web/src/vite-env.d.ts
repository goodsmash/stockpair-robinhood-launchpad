/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_CHAIN_ID?: string
  readonly VITE_CHAIN_NAME?: string
  readonly VITE_RPC_URL?: string
  readonly VITE_EXPLORER_URL?: string
  readonly VITE_INDEXER_URL?: string
  readonly VITE_LAUNCHPAD_ADDRESS?: string
  readonly VITE_LAUNCHPAD_CODE_HASH?: string
  readonly VITE_LAUNCHPAD_PROTOCOL_VERSION?: string
  readonly VITE_ENABLE_OPERATIONS?: string
}
interface ImportMeta { readonly env: ImportMetaEnv }
declare module '*.css'
