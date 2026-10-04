import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction
} from "@solana/web3.js"

import { addressSpendPubHex, type WalletKeyPair } from "~lib/crypto/keyManagement"
import { NATIVE_ASSET_HEX } from "~lib/prover"

import {
  ASSET_CONFIG_SEED,
  ASSET_VAULT_SEED,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BRIDGE_STATE_SEED,
  BRIDGE_VAULT_SEED,
  DEPOSIT_DISCRIMINATOR,
  DEPOSIT_NOTE_SPL_DISCRIMINATOR,
  MERKLE_TREE_SEED,
  PROGRAM_ID,
  RPC_URLS,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID
} from "./constants"

export type Network = "mainnet-beta" | "devnet"

// A `fetch` that retries the RPC on a transient upstream failure (5xx or a
// network error) with backoff, so a single Helius/proxy blip mid-swap cannot
// abort the whole flow ("failed to get balance ... 500 Internal server error").
// JSON-RPC reads are idempotent, and sendTransaction is deduped by signature, so
// re-issuing the same request is safe. 4xx is returned as-is (a real client
// error, not worth retrying).
async function retryingFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  let lastErr: unknown
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await fetch(input, init)
      if (res.status < 500) return res
      lastErr = new Error(`RPC ${res.status}`)
    } catch (e) {
      lastErr = e
    }
    if (attempt < 3) await new Promise((r) => setTimeout(r, 300 * 2 ** attempt))
  }
  // Exhausted retries: one last attempt, letting a genuine failure surface.
  try {
    return await fetch(input, init)
  } catch {
    throw lastErr instanceof Error ? lastErr : new Error("RPC request failed")
  }
}

export function getConnection(network: Network): Connection {
  return new Connection(RPC_URLS[network], {
    commitment: "confirmed",
    fetch: retryingFetch
  })
}

const programId = new PublicKey(PROGRAM_ID)

function bridgeStatePda(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(BRIDGE_STATE_SEED)], programId)[0]
}

function bridgeVaultPda(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(BRIDGE_VAULT_SEED)], programId)[0]
}

// The 32-byte shielded-pool recipient carried by a `paraloom1<hex>` address.
export function shieldedAddressToBytes(shieldedAddress: string): Uint8Array {
  const hex = shieldedAddress.replace(/^paraloom1/, "")
  if (hex.length !== 64) {
    throw new Error("invalid shielded address")
  }
  return Uint8Array.from(Buffer.from(hex, "hex"))
}

// Layout: DEPOSIT discriminator (8) | amount u64 LE (8) | recipient (32) | randomness (32).
function depositInstructionData(
  amountLamports: bigint,
  recipient: Uint8Array,
  randomness: Uint8Array
): Buffer {
  const data = new Uint8Array(8 + 8 + 32 + 32)
  data.set(DEPOSIT_DISCRIMINATOR, 0)
  new DataView(data.buffer).setBigUint64(8, amountLamports, true)
  data.set(recipient, 16)
  data.set(randomness, 48)
  return Buffer.from(data)
}

export function buildDepositInstruction(
  depositor: PublicKey,
  amountLamports: bigint,
  recipient: Uint8Array,
  randomness: Uint8Array
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: bridgeStatePda(), isSigner: false, isWritable: true },
      { pubkey: bridgeVaultPda(), isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }
    ],
    data: depositInstructionData(amountLamports, recipient, randomness)
  })
}

export interface DepositResult {
  signature: string
  blinding: Uint8Array
  assetId: string // hex, 32 bytes (all-zero = native SOL)
  amount: bigint
}

// ---- SPL re-shield (#779) --------------------------------------------------

function merkleTreePda(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(MERKLE_TREE_SEED)], programId)[0]
}

function assetVaultPda(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(ASSET_VAULT_SEED), mint.toBytes()],
    programId
  )[0]
}

function assetConfigPda(mint: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(ASSET_CONFIG_SEED), mint.toBytes()],
    programId
  )[0]
}

// The associated token account of `owner` for `mint`, derived without
// @solana/spl-token (the extension bundles only web3.js): ATA =
// findProgramAddress([owner, tokenProgram, mint], associatedTokenProgram).
export function associatedTokenAddress(
  owner: PublicKey,
  mint: PublicKey,
  tokenProgram: PublicKey = new PublicKey(TOKEN_PROGRAM_ID)
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()],
    new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID)
  )[0]
}

/**
 * Dynamically resolves whether a mint is owned by TOKEN_2022_PROGRAM_ID or
 * defaults to classic TOKEN_PROGRAM_ID (#862).
 */
export async function resolveTokenProgram(
  connection: Connection,
  mint: PublicKey
): Promise<PublicKey> {
  try {
    const info = await connection.getAccountInfo(mint)
    if (info && info.owner.toBase58() === TOKEN_2022_PROGRAM_ID) {
      return new PublicKey(TOKEN_2022_PROGRAM_ID)
    }
  } catch {
    // on network or RPC errors, fall back to classic program
  }
  return new PublicKey(TOKEN_PROGRAM_ID)
}

// Layout: DEPOSIT_NOTE_SPL discriminator (8) | amount u64 LE (8) | pubkey (32) |
// blinding (32) — identical arg shape to deposit_note, just the SPL variant.
function depositSplInstructionData(
  amount: bigint,
  pubkey: Uint8Array,
  blinding: Uint8Array
): Buffer {
  const data = new Uint8Array(8 + 8 + 32 + 32)
  data.set(DEPOSIT_NOTE_SPL_DISCRIMINATOR, 0)
  new DataView(data.buffer).setBigUint64(8, amount, true)
  data.set(pubkey, 16)
  data.set(blinding, 48)
  return Buffer.from(data)
}

// Build a `deposit_note_spl` instruction. Account order mirrors the on-chain
// DepositNoteSpl struct exactly: bridge_state, asset_config, mint, asset_vault,
// depositor_token_account, merkle_tree, depositor, token_program.
export function buildDepositSplInstruction(
  depositor: PublicKey,
  mint: PublicKey,
  depositorTokenAccount: PublicKey,
  amount: bigint,
  pubkey: Uint8Array,
  blinding: Uint8Array,
  tokenProgram: PublicKey = new PublicKey(TOKEN_PROGRAM_ID)
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: bridgeStatePda(), isSigner: false, isWritable: false },
      { pubkey: assetConfigPda(mint), isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: assetVaultPda(mint), isSigner: false, isWritable: true },
      { pubkey: depositorTokenAccount, isSigner: false, isWritable: true },
      { pubkey: merkleTreePda(), isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true, isWritable: true },
      { pubkey: tokenProgram, isSigner: false, isWritable: false }
    ],
    data: depositSplInstructionData(amount, pubkey, blinding)
  })
}

// Re-shield `amount` base units of `mint` held at `depositor`'s associated
// token account into the shielded pool, crediting `shieldedAddress`. `depositor`
// is the (fresh) keypair that owns the tokens (e.g. a private-swap output
// address). The blinding is returned so the caller can persist the note for a
// later SPL spend. `assetId` is `mint_to_asset(mint)`.
export async function depositSpl(
  connection: Connection,
  depositor: Keypair,
  shieldedAddress: string,
  mint: PublicKey,
  amount: bigint,
  assetId: string,
  tokenProgram: PublicKey = new PublicKey(TOKEN_PROGRAM_ID),
  // Called the instant the deposit is SUBMITTED (signature + blinding known),
  // BEFORE waiting for confirmation. The blinding is random and lives only here
  // and in the on-chain tx, so persisting the note now means a confirmation
  // timeout or a worker eviction can never lose a shielded balance that already
  // landed on-chain (#reshield-note-loss).
  onSubmitted?: (result: DepositResult) => Promise<void>
): Promise<DepositResult> {
  const recipient = hexToBytes(addressSpendPubHex(shieldedAddress))
  const blinding = new Uint8Array(32)
  crypto.getRandomValues(blinding)

  const ata = associatedTokenAddress(depositor.publicKey, mint, tokenProgram)
  const ix = buildDepositSplInstruction(
    depositor.publicKey,
    mint,
    ata,
    amount,
    recipient,
    blinding,
    tokenProgram
  )
  const tx = new Transaction().add(ix)
  const { blockhash } = await connection.getLatestBlockhash("confirmed")
  tx.recentBlockhash = blockhash
  tx.feePayer = depositor.publicKey
  tx.sign(depositor)

  // Submit first, then persist the note, THEN confirm — so an interrupted
  // confirmation cannot orphan a deposit that already landed.
  const signature = await connection.sendRawTransaction(tx.serialize(), {
    maxRetries: 5
  })
  const result = { signature, blinding, assetId, amount }
  if (onSubmitted) {
    try {
      await onSubmitted(result)
    } catch {
      // Persisting is best-effort here; the recovery scan is the backstop.
    }
  }
  // Tolerant confirm (not the hard blockhash deadline): a busy mainnet must not
  // throw "block height exceeded" on a deposit that actually lands.
  await confirmBySignatureStatus(connection, signature)

  return result
}

// Build the Associated Token Account program's CreateIdempotent instruction:
// creates `owner`'s ATA for `mint`, paid by `payer`, and no-ops if the account
// already exists. Data is the single discriminator byte 1 (CreateIdempotent).
export function buildCreateAtaIdempotentInstruction(
  payer: PublicKey,
  owner: PublicKey,
  mint: PublicKey,
  tokenProgram: PublicKey = new PublicKey(TOKEN_PROGRAM_ID)
): TransactionInstruction {
  const ata = associatedTokenAddress(owner, mint, tokenProgram)
  return new TransactionInstruction({
    programId: new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID),
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false }
    ],
    data: Buffer.from([1])
  })
}

// Confirm a wallet-submitted tx WITHOUT the hard blockhash deadline that
// connection.confirmTransaction enforces. On a busy mainnet that deadline throws
// "block height exceeded" even when the tx confirms a moment later (observed
// aborting a private swap right after the ATA it created had actually landed).
// Polls the signature status instead, tolerating a slow confirmation and only
// rejecting on a real on-chain error. Returns false on a true timeout.
export async function confirmBySignatureStatus(
  connection: Connection,
  signature: string,
  timeoutMs = 90_000
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const st = await connection.getSignatureStatus(signature, {
        searchTransactionHistory: true
      })
      const v = st.value
      if (v) {
        if (v.err) {
          throw new Error(`transaction failed on-chain: ${JSON.stringify(v.err)}`)
        }
        if (v.confirmationStatus === "confirmed" || v.confirmationStatus === "finalized") {
          return true
        }
      }
    } catch (e) {
      // A real on-chain failure must still surface; a transient RPC blip must
      // not — keep polling until the deadline in that case.
      if (e instanceof Error && e.message.startsWith("transaction failed on-chain")) {
        throw e
      }
    }
    await new Promise((r) => setTimeout(r, 2000))
  }
  return false
}

// Create `owner`'s associated token account for `mint` on-chain (idempotent),
// paid and signed by `payer`. Needed before a shielded SPL note can be withdrawn
// to it: the on-chain `transact_spl` withdraw transfers into an EXISTING token
// account, it does not create one. Returns the ATA address.
export async function createTokenAccount(
  connection: Connection,
  payer: Keypair,
  owner: PublicKey,
  mint: PublicKey,
  tokenProgram: PublicKey = new PublicKey(TOKEN_PROGRAM_ID)
): Promise<PublicKey> {
  const ata = associatedTokenAddress(owner, mint, tokenProgram)
  // Re-submit up to 3 times with a fresh blockhash. CreateIdempotent is safe to
  // repeat, so a dropped tx or a confirm that was missed during a transient RPC
  // blip is simply retried, and the account's existence — not the confirm
  // result — is the source of truth (a late-confirmed tx still counts).
  for (let attempt = 0; attempt < 3; attempt++) {
    if (await connection.getAccountInfo(ata, "confirmed")) return ata
    try {
      const ix = buildCreateAtaIdempotentInstruction(
        payer.publicKey,
        owner,
        mint,
        tokenProgram
      )
      const tx = new Transaction().add(ix)
      const { blockhash } = await connection.getLatestBlockhash("confirmed")
      tx.recentBlockhash = blockhash
      tx.feePayer = payer.publicKey
      tx.sign(payer)
      const sig = await connection.sendRawTransaction(tx.serialize(), { maxRetries: 5 })
      if (await confirmBySignatureStatus(connection, sig)) return ata
    } catch {
      // dropped / transient — the loop re-checks existence and re-submits
    }
  }
  if (await connection.getAccountInfo(ata, "confirmed")) return ata
  throw new Error("ATA creation did not confirm after retries")
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"))
}

// 32-byte form of a base58 Solana address — the withdrawal destination.
export function solanaAddressToBytes(address: string): Uint8Array {
  return new PublicKey(address).toBytes()
}

// Deposit `amountLamports` into the shielded pool, crediting the wallet's own
// shielded address. The randomness is returned so the caller can persist the
// note for a later withdrawal.
export async function deposit(
  connection: Connection,
  wallet: WalletKeyPair,
  amountLamports: bigint
): Promise<DepositResult> {
  const signer = Keypair.fromSecretKey(wallet.secretKey)
  // v2 (#293): the on-chain `recipient` field carries the spend public key the
  // commitment binds; `randomness` carries the note's blinding. The spend key
  // itself stays in the wallet (`wallet.spendPrivkey`).
  const recipient = hexToBytes(addressSpendPubHex(wallet.shieldedAddress))
  const blinding = new Uint8Array(32)
  crypto.getRandomValues(blinding)

  const ix = buildDepositInstruction(signer.publicKey, amountLamports, recipient, blinding)
  const tx = new Transaction().add(ix)
  const signature = await sendAndConfirmTransaction(connection, tx, [signer], {
    commitment: "confirmed"
  })

  return { signature, blinding, assetId: NATIVE_ASSET_HEX, amount: amountLamports }
}

export async function getSolBalance(
  connection: Connection,
  publicKey: Uint8Array
): Promise<bigint> {
  const lamports = await connection.getBalance(new PublicKey(publicKey), "confirmed")
  return BigInt(lamports)
}

// Base58 Solana address for a raw ed25519 public key. This is the account that
// funds a deposit (distinct from the paraloom1… shielded address).
export function solanaAddress(publicKey: Uint8Array): string {
  return new PublicKey(publicKey).toBase58()
}

// ── Re-shield note recovery ──────────────────────────────────────────────────
// A re-shield whose deposit landed on-chain but whose note was never persisted
// (a confirmation timeout or worker eviction before the on-submit persist)
// leaves a shielded balance the wallet cannot see or spend. The blinding is
// random and lives only in the deposit instruction data, so recover it by
// reading that instruction back from the fresh address's own deposit tx.

const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function base58Decode(s: string): Uint8Array {
  const bytes: number[] = [0]
  for (const ch of s) {
    const v = B58_ALPHABET.indexOf(ch)
    if (v < 0) throw new Error(`invalid base58 char: ${ch}`)
    let carry = v
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  // preserve leading zero bytes (each leading '1' is a 0x00)
  for (let k = 0; k < s.length && s[k] === "1"; k++) bytes.push(0)
  return Uint8Array.from(bytes.reverse())
}

function bytesStartWith(a: Uint8Array, prefix: Uint8Array): boolean {
  if (a.length < prefix.length) return false
  for (let i = 0; i < prefix.length; i++) if (a[i] !== prefix[i]) return false
  return true
}

/** Recover the re-shield note (amount + blinding) from the fresh address's
 *  on-chain `deposit_note_spl` transaction, or null if none is found. Layout:
 *  disc(8) | amount u64 LE (8) | pubkey(32) | blinding(32). */
export async function recoverReshieldedNote(
  connection: Connection,
  freshAddress: string
): Promise<{ amount: string; blindingHex: string; signature: string } | null> {
  const pk = new PublicKey(freshAddress)
  const sigs = await connection.getSignaturesForAddress(pk, { limit: 12 })
  for (const s of sigs) {
    const tx = await connection.getTransaction(s.signature, {
      maxSupportedTransactionVersion: 0
    })
    if (!tx || tx.meta?.err) continue
    const msg = tx.transaction.message as unknown as {
      staticAccountKeys?: PublicKey[]
      accountKeys?: PublicKey[]
      compiledInstructions?: { programIdIndex: number; data: Uint8Array }[]
      instructions?: { programIdIndex: number; data: string }[]
    }
    const keys = msg.staticAccountKeys ?? msg.accountKeys ?? []
    const ixs = msg.compiledInstructions ?? msg.instructions ?? []
    for (const ix of ixs) {
      const prog = keys[ix.programIdIndex]
      if (!prog || prog.toBase58() !== programId.toBase58()) continue
      const data =
        typeof (ix as { data: unknown }).data === "string"
          ? base58Decode((ix as { data: string }).data)
          : Uint8Array.from((ix as { data: Uint8Array }).data)
      if (data.length < 80 || !bytesStartWith(data, DEPOSIT_NOTE_SPL_DISCRIMINATOR)) {
        continue
      }
      const dv = new DataView(data.buffer, data.byteOffset, data.byteLength)
      const amount = dv.getBigUint64(8, true)
      const blinding = data.slice(48, 80)
      return {
        amount: amount.toString(),
        blindingHex: Buffer.from(blinding).toString("hex"),
        signature: s.signature
      }
    }
  }
  return null
}
