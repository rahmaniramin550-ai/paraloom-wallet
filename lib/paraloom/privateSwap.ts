// Private swap-out (#240): spend a shielded note, exit at a FRESH unlinkable
// address, then swap there on public liquidity (Jupiter). The on-chain trail
// never ties the swap back to the wallet that funded the deposit.
//
// Trust model — non-custodial. The fresh keypair is generated here, inside the
// user's wallet, and never leaves it: the withdraw funds the fresh address, the
// swap is signed locally with the fresh key, and the routing service only ever
// sees a public key. A privacy relayer that could sign could steal; this one
// cannot, and because the withdraw self-funds the fresh address the swap pays
// its own gas without the server holding anything.
//
// Availability: with `reshield` the swapped SPL token is re-shielded into a
// shielded note via deposit_note_spl (#779) — a true round trip (shielded SOL ->
// shielded token). Without it (or for a "SOL" output) the token is left at the
// fresh address as a private *buy*. Re-shielding is best-effort and fund-safe:
// the token is already persisted at the fresh address before it runs, so a
// failed re-shield simply leaves a private buy rather than stranding anything.

import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  VersionedTransaction
} from "@solana/web3.js"

import { assetIdForMint } from "~lib/prover"

import { associatedTokenAddress, createTokenAccount, depositSpl, resolveTokenProgram } from "./bridge"
import { SWAP_ROUTER_URL } from "./constants"
import type { ShieldedNote } from "./notes"
import { saveSwapOutput } from "./swapOutputs"
import { depositV3, spendV3 } from "./transactFlow"

import { WSOL_MINT, isNativeSolOutput } from "./swapReconcileClassify"
export { WSOL_MINT, isNativeSolOutput }

/** Lamports left at the fresh address to cover the swap's own costs: the output
 *  token ATA rent (~0.00204), the fresh account's rent-exempt floor (~0.00089),
 *  and the swap tx + priority fees. The swap trades the funded balance minus
 *  this; 0.006 SOL is a comfortable margin. */
const SWAP_OVERHEAD_LAMPORTS = 6_000_000n

/** How long to wait for the 2-of-2 quorum to settle the withdraw before giving
 *  up (the note is safe either way — its change/spend is on-chain). */
const SETTLE_TIMEOUT_MS = 150_000
const SETTLE_POLL_MS = 3_000

/** Bound the routing call. It used to have NO timeout: an intermittently slow or
 *  hung router would stall the whole swap for minutes with the withdrawn SOL
 *  already sitting at the fresh address, until the page-side poll gave up
 *  ("Private swap timed out") and left the funds stranded. */
const ROUTE_TIMEOUT_MS = 30_000
const ROUTE_RETRIES = 3

export interface PrivateSwapParams {
  /** Output mint (base58) or the literal "SOL" for wrapped SOL. */
  outputMint: string
  /** Lamports of the input note(s) to spend on this private buy. */
  amountLamports: bigint
  /** Max slippage in bps (default 100 = 1%). */
  slippageBps?: number
  /** Re-shield the swapped token back into the shielded pool (a round trip),
   *  instead of leaving it at the fresh address (a private buy). Ignored for a
   *  "SOL" output. Best-effort: on failure the token stays at the fresh address. */
  reshield?: boolean
}

/** The shielded SPL note produced by a re-shield, so the caller can persist it
 *  against the wallet's account (privateSwap does not own note storage). */
export interface ReshieldedNote {
  assetId: string
  /** The SPL mint (base58), needed to later spend the shielded note (#779). */
  mint: string
  amount: string
  blindingHex: string
  depositSignature: string
}

export interface PrivateSwapResult {
  /** The unlinkable address now holding the swapped token. Shares no signer
   *  with the wallet that funded the deposit. */
  freshAddress: string
  /** Secret key of the fresh address (base58-free byte array), so the caller
   *  can persist it — the swapped token lives there. */
  freshSecretKey: Uint8Array
  /** Transact ingress request id for the withdraw leg. */
  withdrawRequestId: string
  /** Swap transaction signature. */
  swapSignature: string
  /** Output amount the route reported, in the out mint's base units. */
  outAmount: number
  /** Present when `reshield` was requested and succeeded: the shielded SPL note
   *  the caller should persist. Absent means the token stayed at the fresh
   *  address (a private buy) — either not requested or the re-shield failed. */
  reshielded?: ReshieldedNote
}

// Wait for the swap transaction to confirm by polling its signature status.
// Unlike connection.confirmTransaction (hard 30s deadline), this tolerates a
// busy mainnet: it only rejects on a real on-chain error or if the tx never
// confirms within the window.
async function waitForSwapConfirmation(
  connection: Connection,
  signature: string,
  timeoutMs = 90_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const st = await connection.getSignatureStatus(signature, {
      searchTransactionHistory: true
    })
    const v = st.value
    if (v) {
      if (v.err) {
        throw new Error(`swap transaction failed on-chain: ${JSON.stringify(v.err)}`)
      }
      if (v.confirmationStatus === "confirmed" || v.confirmationStatus === "finalized") {
        return
      }
    }
    await new Promise((r) => setTimeout(r, 2000))
  }
  throw new Error(
    `swap submitted (${signature}) but not confirmed within ${timeoutMs / 1000}s — check the explorer`
  )
}

// fetch with a hard deadline: aborts instead of hanging forever on a stalled
// connection. Used for the routing call so a slow router fails fast (and retries)
// rather than stranding an already-withdrawn balance.
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: ctrl.signal })
  } finally {
    clearTimeout(timer)
  }
}

// Ask the routing service for an UNSIGNED swap tx, with a bounded timeout and a
// few retries. The service holds no key; it only builds the tx for `freshPubkey`.
async function routeSwap(
  freshPubkey: string,
  outputMint: string,
  amount: bigint,
  inputMint = "SOL"
): Promise<{ out_amount: number; swap_transaction: string }> {
  let lastErr: unknown
  for (let attempt = 1; attempt <= ROUTE_RETRIES; attempt++) {
    try {
      const res = await fetchWithTimeout(
        `${SWAP_ROUTER_URL}/swap/route`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            input_mint: inputMint,
            output_mint: outputMint,
            amount: Number(amount),
            user_public_key: freshPubkey
          })
        },
        ROUTE_TIMEOUT_MS
      )
      if (!res.ok) {
        lastErr = new Error(
          `swap routing failed (${res.status}): ${await res.text()}`
        )
      } else {
        return (await res.json()) as {
          out_amount: number
          swap_transaction: string
        }
      }
    } catch (e) {
      lastErr = e
    }
    if (attempt < ROUTE_RETRIES) {
      await new Promise((r) => setTimeout(r, 1500 * attempt))
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("swap routing failed")
}

// Route -> sign -> submit -> confirm a swap of `swapLamports` SOL at `fresh`.
// Shared by the live swap and the resume/recovery path so both harden identically.
async function executeSwapLeg(
  connection: Connection,
  fresh: Keypair,
  outputMint: string,
  swapLamports: bigint
): Promise<{ swapSignature: string; outAmount: number }> {
  const { out_amount, swap_transaction } = await routeSwap(
    fresh.publicKey.toBase58(),
    outputMint,
    swapLamports
  )
  const tx = VersionedTransaction.deserialize(
    Uint8Array.from(Buffer.from(swap_transaction, "base64"))
  )
  tx.sign([fresh])
  const swapSignature = await connection.sendRawTransaction(tx.serialize(), {
    maxRetries: 5
  })
  await waitForSwapConfirmation(connection, swapSignature)
  return { swapSignature, outAmount: out_amount }
}

// Best-effort re-shield of whatever token actually landed at `fresh` into the
// shielded pool (#779). Returns the shielded note to persist, or undefined if
// nothing landed / the deposit failed (the token then stays as a private buy).
async function reshieldToken(
  connection: Connection,
  fresh: Keypair,
  shieldedAddress: string,
  outputMint: string,
  // Persist the shielded note the instant the deposit is SUBMITTED, before its
  // confirmation. The blinding is random and unrecoverable if lost, so this must
  // not wait for the flow to finish (a worker eviction after the deposit lands
  // would otherwise orphan a real shielded balance).
  persistNote?: (note: ReshieldedNote) => Promise<void>
): Promise<ReshieldedNote | undefined> {
  try {
    const mint = new PublicKey(outputMint)
    const tokenProgram = await resolveTokenProgram(connection, mint)
    const ata = associatedTokenAddress(fresh.publicKey, mint, tokenProgram)
    const bal = await connection.getTokenAccountBalance(ata)
    const tokenAmount = BigInt(bal.value.amount)
    if (tokenAmount <= 0n) return undefined
    const assetId = await assetIdForMint(
      Buffer.from(mint.toBytes()).toString("hex")
    )
    const mintBase58 = mint.toBase58()
    const dep = await depositSpl(
      connection,
      fresh,
      shieldedAddress,
      mint,
      tokenAmount,
      assetId,
      tokenProgram,
      // onSubmitted: note is now known + on-chain; persist immediately.
      async (r) => {
        if (persistNote) {
          await persistNote({
            assetId,
            mint: mintBase58,
            amount: tokenAmount.toString(),
            blindingHex: Buffer.from(r.blinding).toString("hex"),
            depositSignature: r.signature
          })
        }
      }
    )
    return {
      assetId,
      mint: mintBase58,
      amount: tokenAmount.toString(),
      blindingHex: Buffer.from(dep.blinding).toString("hex"),
      depositSignature: dep.signature
    }
  } catch {
    return undefined
  }
}

async function waitForFunding(
  connection: Connection,
  pubkey: Keypair["publicKey"]
): Promise<bigint> {
  const deadline = Date.now() + SETTLE_TIMEOUT_MS
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, SETTLE_POLL_MS))
    const bal = BigInt(await connection.getBalance(pubkey))
    if (bal > 0n) return bal
  }
  throw new Error(
    "withdraw is still settling and has not funded the fresh address yet. Do NOT retry — the spent note is already committed and the funds will arrive at the saved address; reopen the wallet to let the swap resume once it lands."
  )
}

/**
 * Run a private swap-out. Spends `inputs` (1–2 shielded notes) for
 * `params.amountLamports`, withdrawing to a fresh address, then swaps
 * SOL -> `params.outputMint` there.
 */
export async function privateSwap(
  connection: Connection,
  shieldedAddress: string,
  spendPrivkeyHex: string,
  ownBoxPubHex: string,
  inputs: ShieldedNote[],
  params: PrivateSwapParams,
  ingressToken?: string,
  // Persist the re-shielded note the instant its deposit is submitted, so a
  // late failure can never orphan a shielded balance that landed on-chain.
  onReshielded?: (note: ReshieldedNote) => Promise<void>
): Promise<PrivateSwapResult> {
  if (params.amountLamports <= 0n) throw new Error("amount must be > 0")

  // 1. Fresh ephemeral key — generated here, never sent anywhere.
  const fresh = Keypair.generate()
  const freshHex = Buffer.from(fresh.publicKey.toBytes()).toString("hex")

  // Persist the fresh key up front, BEFORE the withdraw funds it. The withdrawn
  // SOL (and later the bought token) live at this address and are spendable only
  // with this key, so it must be saved before anything that can throw — a failed
  // route or a dropped worker must never strand the funds. The realized amount +
  // signature are filled in by an upsert once the swap lands.
  await saveSwapOutput({
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
    outputMint: params.outputMint,
    outAmount: 0,
    swapSignature: "",
    reshield: params.reshield ?? false,
    createdAt: Date.now()
  })

  // 2. Withdraw the note value to the fresh address via the 2-of-2 quorum. The
  //    input notes are marked spent only once this settles (the fresh address is
  //    funded); on a settlement timeout they stay spendable so the swap can be
  //    retried without stranding them (paraloom-core#792).
  let funded = 0n
  const { requestId, settled } = await spendV3(
    connection,
    shieldedAddress,
    spendPrivkeyHex,
    ownBoxPubHex,
    inputs,
    params.amountLamports,
    { kind: "withdraw", recipientSolanaHex: freshHex },
    {
      ingressToken,
      confirmSettled: async () => {
        try {
          funded = await waitForFunding(connection, fresh.publicKey)
          return true
        } catch {
          return false
        }
      }
    }
  )
  if (!settled) {
    throw new Error(
      "withdraw did not settle in time; the spent notes remain spendable, reopen the wallet to retry the swap"
    )
  }

  // 4. Swap the funded balance minus the on-chain-cost reserve. Reading the
  //    real balance (not the requested amount) keeps the swap within what
  //    actually landed after the protocol withdrawal fee.
  const swapLamports = funded - SWAP_OVERHEAD_LAMPORTS
  if (swapLamports <= 0n) {
    throw new Error(
      `withdrawn ${Number(funded) / Number(LAMPORTS_PER_SOL)} SOL is below the swap overhead reserve`
    )
  }

  // 5. Ask the routing service (bounded timeout + retries) to build an UNSIGNED
  //    swap tx for the fresh address (the service holds no key).
  const { out_amount, swap_transaction } = await routeSwap(
    fresh.publicKey.toBase58(),
    params.outputMint,
    swapLamports
  )

  // 6. Sign the swap with the fresh key locally and submit it.
  const tx = VersionedTransaction.deserialize(
    Uint8Array.from(Buffer.from(swap_transaction, "base64"))
  )
  tx.sign([fresh])
  const swapSignature = await connection.sendRawTransaction(tx.serialize(), {
    maxRetries: 5
  })

  // Persist the fresh key + output NOW, the instant the swap is submitted and
  // BEFORE waiting for confirmation. The bought token lives at this fresh
  // address and is only spendable with this key, so it must never be lost to a
  // later throw (a confirm timeout used to strand it). Saving here also makes it
  // show up under "Private buys" immediately.
  await saveSwapOutput({
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
    outputMint: params.outputMint,
    outAmount: out_amount,
    swapSignature,
    createdAt: Date.now()
  })

  // Poll the signature status rather than connection.confirmTransaction, whose
  // 30s deadline throws "not confirmed in 30 seconds" on a busy mainnet even
  // when the swap actually lands. We wait up to ~90s and only fail on a real
  // on-chain error (or if it truly never confirms).
  await waitForSwapConfirmation(connection, swapSignature)

  // 7. Optional round trip: re-shield the swapped token back into the pool. The
  //    token is already safely at the fresh address (persisted above), so this
  //    is best-effort — any failure leaves a private buy rather than stranding
  //    funds. Skipped for a "SOL" output (re-shielding native SOL is pointless).
  let reshielded: ReshieldedNote | undefined
  if (params.reshield && !isNativeSolOutput(params.outputMint)) {
    reshielded = await reshieldToken(
      connection,
      fresh,
      shieldedAddress,
      params.outputMint,
      onReshielded
    )
  }

  return {
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKey: fresh.secretKey,
    withdrawRequestId: requestId,
    swapSignature,
    outAmount: out_amount,
    reshielded
  }
}

/** Shielded SOL withdrawn to self-fund a token swap's gas (Plan A′): the
 *  input-mint ATA rent (~0.00204), the fresh account rent floor, the swap tx +
 *  priority fees, and the re-shield deposit tx. Comes from the user's OWN
 *  shielded SOL, so no third party ever pays and the swap stays fully private.
 *  The unused remainder is swept back into the pool by the re-shield. */
export const GAS_LAMPORTS = 9_000_000n
/** Left at the fresh address to pay the re-shield deposit tx when sweeping the
 *  swapped SOL back into the pool. */
const RESHIELD_FEE_RESERVE = 1_000_000n

// Poll an SPL token account until the withdrawn balance actually lands.
async function waitForTokenFunding(
  connection: Connection,
  ata: PublicKey
): Promise<bigint> {
  const deadline = Date.now() + SETTLE_TIMEOUT_MS
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, SETTLE_POLL_MS))
    try {
      const bal = await connection.getTokenAccountBalance(ata)
      const amt = BigInt(bal.value.amount)
      if (amt > 0n) return amt
    } catch {
      // The ATA may not be indexed for a moment after creation — keep polling.
    }
  }
  throw new Error(
    "token withdraw is still settling and has not funded the fresh address yet. Do NOT retry — the spent note is already committed and the funds will arrive at the saved address; reopen the wallet to let the swap resume once it lands."
  )
}

export interface PrivateSwapFromTokenParams {
  /** Input token mint (base58) whose shielded note is spent. */
  inputMint: string
  /** Amount of the input token to spend, in the input mint's base units. */
  amountTokenUnits: bigint
  /** Output mint (base58) or the literal "SOL". */
  outputMint: string
  slippageBps?: number
  /** Re-shield the swapped output back into the pool (a round trip). For a "SOL"
   *  output this sweeps the swapped SOL back as a native shielded note. */
  reshield?: boolean
}

/**
 * Private swap FROM a shielded SPL token (e.g. USDC -> SOL). The withdrawn token
 * cannot pay its own swap gas, so the swap self-funds gas from the user's own
 * shielded SOL (Plan A′) — no third-party fee-payer, full privacy. Flow:
 *   1. withdraw a little shielded SOL to the fresh address (gas),
 *   2. create the input-mint ATA there (paid from that SOL),
 *   3. withdraw the shielded token note(s) into that ATA,
 *   4. route + sign + submit the token->output swap for the fresh address,
 *   5. (reshield) sweep the swapped output back into the pool.
 * Every leg exits at the SAME fresh, unlinkable address, and both withdrawals
 * leave the shielded pool with no on-chain tie back to the funding wallet.
 */
export async function privateSwapFromToken(
  connection: Connection,
  shieldedAddress: string,
  spendPrivkeyHex: string,
  ownBoxPubHex: string,
  tokenInputs: ShieldedNote[],
  gasInputs: ShieldedNote[],
  params: PrivateSwapFromTokenParams,
  ingressToken?: string,
  onReshielded?: (note: ReshieldedNote) => Promise<void>
): Promise<PrivateSwapResult> {
  if (params.amountTokenUnits <= 0n) throw new Error("amount must be > 0")

  const inputMintPk = new PublicKey(params.inputMint)
  const inputTokenProgram = await resolveTokenProgram(connection, inputMintPk)
  const fresh = Keypair.generate()
  const freshHex = Buffer.from(fresh.publicKey.toBytes()).toString("hex")
  const ata = associatedTokenAddress(fresh.publicKey, inputMintPk, inputTokenProgram)

  // Persist the fresh key up front — the gas SOL, the withdrawn token, and the
  // swapped output all live at this address and are spendable only with this key.
  await saveSwapOutput({
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
    outputMint: params.outputMint,
    outAmount: 0,
    swapSignature: "",
    reshield: params.reshield ?? false,
    createdAt: Date.now()
  })

  // 1. Self-fund gas from the user's own shielded SOL (native withdraw). The gas
  //    notes are marked spent only once the fresh address is funded; a timeout
  //    leaves them spendable to retry (paraloom-core#792).
  const gas = await spendV3(
    connection,
    shieldedAddress,
    spendPrivkeyHex,
    ownBoxPubHex,
    gasInputs,
    GAS_LAMPORTS,
    { kind: "withdraw", recipientSolanaHex: freshHex },
    {
      ingressToken,
      confirmSettled: async () => {
        try {
          await waitForFunding(connection, fresh.publicKey)
          return true
        } catch {
          return false
        }
      }
    }
  )
  if (!gas.settled) {
    throw new Error(
      "gas withdraw did not settle in time; the spent notes remain spendable, reopen the wallet to retry"
    )
  }

  // 2. Create the input-mint ATA at the fresh address (paid from the gas SOL).
  //    The on-chain transact_spl withdraw transfers into an EXISTING account.
  await createTokenAccount(connection, fresh, fresh.publicKey, inputMintPk, inputTokenProgram)

  // 3. Withdraw the shielded token note(s) INTO that ATA — the circuit recipient
  //    is the token account, not the wallet address. The token notes are marked
  //    spent only once the ATA is funded (paraloom-core#792).
  const ataHex = Buffer.from(ata.toBytes()).toString("hex")
  let tokenLanded = 0n
  const { requestId, settled } = await spendV3(
    connection,
    shieldedAddress,
    spendPrivkeyHex,
    ownBoxPubHex,
    tokenInputs,
    params.amountTokenUnits,
    { kind: "withdraw", recipientSolanaHex: ataHex },
    {
      ingressToken,
      confirmSettled: async () => {
        try {
          tokenLanded = await waitForTokenFunding(connection, ata)
          return true
        } catch {
          return false
        }
      }
    }
  )
  if (!settled) {
    throw new Error(
      "token withdraw did not settle in time; the spent notes remain spendable, reopen the wallet to retry"
    )
  }

  // 4. Route the ACTUAL landed token amount (net of the withdraw fee) into the
  //    output for the fresh address, then sign locally and submit.
  const { out_amount, swap_transaction } = await routeSwap(
    fresh.publicKey.toBase58(),
    params.outputMint,
    tokenLanded,
    params.inputMint
  )
  const tx = VersionedTransaction.deserialize(
    Uint8Array.from(Buffer.from(swap_transaction, "base64"))
  )
  tx.sign([fresh])
  const swapSignature = await connection.sendRawTransaction(tx.serialize(), {
    maxRetries: 5
  })

  await saveSwapOutput({
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKeyHex: Buffer.from(fresh.secretKey).toString("hex"),
    outputMint: params.outputMint,
    outAmount: out_amount,
    swapSignature,
    createdAt: Date.now()
  })
  await waitForSwapConfirmation(connection, swapSignature)

  // 5. Round trip: sweep the swapped output back into the shielded pool. For a
  //    "SOL" output this is a native deposit_note (depositV3 persists the note
  //    itself). Best-effort: on failure the output stays at the fresh address as
  //    a private buy, recoverable with its saved key.
  let reshielded: ReshieldedNote | undefined
  if (params.reshield && isNativeSolOutput(params.outputMint)) {
    try {
      const solBal = BigInt(await connection.getBalance(fresh.publicKey))
      const reshieldLamports = solBal - RESHIELD_FEE_RESERVE
      if (reshieldLamports > 0n) {
        await depositV3(
          connection,
          { secretKey: fresh.secretKey },
          shieldedAddress,
          spendPrivkeyHex,
          reshieldLamports
        )
      }
    } catch {
      // leave the swapped SOL as a private buy at the fresh address
    }
  } else if (params.reshield) {
    reshielded = await reshieldToken(
      connection,
      fresh,
      shieldedAddress,
      params.outputMint,
      onReshielded
    )
  }

  return {
    freshAddress: fresh.publicKey.toBase58(),
    freshSecretKey: fresh.secretKey,
    withdrawRequestId: requestId,
    swapSignature,
    outAmount: out_amount,
    reshielded
  }
}

export interface ResumeSwapResult {
  swapSignature: string
  outAmount: number
  reshielded?: ReshieldedNote
}

/**
 * Finish a private swap whose withdraw already settled but whose swap leg never
 * ran — the fresh address holds the withdrawn SOL but no token. This happens
 * when the swap leg (routing / submit) hung or errored after the withdraw
 * landed, so the page timed out with the funds stranded at the fresh address.
 *
 * Recovery is safe and idempotent: it reads the ACTUAL current balance at the
 * fresh address and swaps that (minus the on-chain-cost reserve), so it never
 * double-spends the input note (already consumed by the settled withdraw) and
 * completes exactly the swap the user intended.
 */
export async function resumeSwapAtFreshAddress(
  connection: Connection,
  shieldedAddress: string,
  freshSecretKeyHex: string,
  outputMint: string,
  reshield: boolean,
  onReshielded?: (note: ReshieldedNote) => Promise<void>
): Promise<ResumeSwapResult> {
  const fresh = Keypair.fromSecretKey(
    Uint8Array.from(Buffer.from(freshSecretKeyHex, "hex"))
  )
  const funded = BigInt(await connection.getBalance(fresh.publicKey))
  const swapLamports = funded - SWAP_OVERHEAD_LAMPORTS
  if (swapLamports <= 0n) {
    throw new Error("fresh address balance is below the swap overhead reserve")
  }

  const { swapSignature, outAmount } = await executeSwapLeg(
    connection,
    fresh,
    outputMint,
    swapLamports
  )

  let reshielded: ReshieldedNote | undefined
  if (reshield && outputMint !== "SOL") {
    reshielded = await reshieldToken(
      connection,
      fresh,
      shieldedAddress,
      outputMint,
      onReshielded
    )
  }

  return { swapSignature, outAmount, reshielded }
}
