// Paraloom bridge program on Solana. The same program id is deployed on both
// mainnet-beta (capped beta) and devnet; the cluster is chosen by the network
// selector, not the program id.
export const PROGRAM_ID = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP"

// Anchor instruction discriminators (first 8 bytes of the instruction data),
// mirrored from the on-chain program / src/bridge/solana/instructions.rs.
export const DEPOSIT_DISCRIMINATOR = new Uint8Array([242, 35, 198, 137, 82, 225, 242, 182])

// Circuit v3 (#350): sha256("global:deposit_note")[..8] — the deposit that
// appends the note commitment to the on-chain incremental tree.
export const DEPOSIT_NOTE_DISCRIMINATOR = new Uint8Array([75, 212, 96, 185, 178, 167, 29, 57])
// #779: sha256("global:deposit_note_spl")[..8] — the SPL analogue that moves a
// token into its per-mint asset vault and appends the note (asset = the mint).
export const DEPOSIT_NOTE_SPL_DISCRIMINATOR = new Uint8Array([
  244, 219, 167, 106, 7, 120, 254, 253
])
// sha256("event:DepositNoteEvent")[..8] / sha256("event:TransactEvent")[..8] —
// the program events the wallet scans to rebuild the v3 tree client-side.
export const DEPOSIT_NOTE_EVENT_DISCRIMINATOR = new Uint8Array([85, 20, 187, 76, 92, 196, 249, 195])
// #779: sha256("event:DepositNoteSplEvent")[..8]. SPL deposits append to the
// SAME tree as native, so their leaves must be included when rebuilding it, or
// the tree diverges from on-chain and every spend (native included) freezes.
export const DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR = new Uint8Array([
  229, 33, 39, 208, 18, 5, 237, 1
])
export const TRANSACT_EVENT_DISCRIMINATOR = new Uint8Array([89, 245, 87, 250, 222, 30, 135, 142])

// PDA seeds.
export const BRIDGE_STATE_SEED = "bridge_state"
export const BRIDGE_VAULT_SEED = "bridge_vault"
export const MERKLE_TREE_SEED = "merkle_tree"
// #779: per-mint shielded-token vault + its config.
export const ASSET_VAULT_SEED = "asset_vault"
export const ASSET_CONFIG_SEED = "asset_config"

// SPL token programs, for building an SPL deposit's account list. The classic
// program covers USDC; a Token-2022 mint passes its own program id.
export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
export const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
export const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

// RPC endpoints. No API key is stored in the extension. Rebuilding the v3 tree
// (fetchV3Leaves) pages the program's full signature history and reads each
// leaf tx, which the public mainnet endpoint rate-limits and prunes; mainnet
// therefore routes through node.paraloom.io/rpc, a server-side proxy to an
// archival provider that keeps the key off the client. Devnet's public
// endpoint is enough for its lighter, non-pruned history.
export const RPC_URLS: Record<"mainnet-beta" | "devnet", string> = {
  "mainnet-beta": "https://node.paraloom.io/rpc",
  devnet: "https://api.devnet.solana.com"
}

export const LAMPORTS_PER_SOL = 1_000_000_000n

// Validator node endpoints, served over HTTPS by the public devnet node
// (Caddy reverse-proxies one host to the node's merkle / withdrawal / transfer
// services by path). One host; the path picks the service.
//   /merkle/path/:commitment   read-only Merkle path (withdrawal/transfer proofs)
//   /withdrawal/submit         withdrawal ingress
//   /transact/submit, /transact/scan   transact ingress + recipient discovery
export const PATH_SERVER_URL = "https://node.paraloom.io"
export const INGRESS_URL = "https://node.paraloom.io"
export const TRANSFER_INGRESS_URL = "https://node.paraloom.io"
export const TRANSACT_INGRESS_URL = "https://node.paraloom.io"

// Non-custodial swap routing service (paraloom-core `swap-router`). Builds an
// UNSIGNED Jupiter swap transaction for a fresh address; the wallet signs it
// locally, so the service never sees a key. Same host, `/swap/*` path.
export const SWAP_ROUTER_URL = "https://node.paraloom.io"
