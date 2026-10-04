// Circuit v3 (#350): wallet orchestration for deposit_note and the unified
// transact spend. One spend flow covers withdraw (ext_amount < 0) and shielded
// transfer (ext_amount == 0, value moves between output notes); partial spends
// return change to the wallet as a new note — the audit #16 fix.

import { Connection, Keypair, PublicKey } from "@solana/web3.js"

import { addressBoxPubHex, addressSpendPubHex } from "~lib/crypto/keyManagement"
import {
  proveTransact,
  v3MerklePath,
  v3NoteCommitment,
  v3NoteCommitmentAsset,
  v3NotePubkey
} from "~lib/prover"

import { NATIVE_ASSET_HEX } from "~lib/prover"
import { encryptNote } from "./noteCrypto"
import {
  addNote,
  markNoteSpentByIdentity,
  setNoteLeafIndex,
  type ShieldedNote
} from "./notes"
import { confirmCommitmentInTree } from "./settlementConfirm"
import { fetchV3Leaves, sendDepositNote, submitTransact } from "./transact"
import { resolveTokenProgram } from "./bridge"

function randomHex32(): string {
  const b = new Uint8Array(32)
  crypto.getRandomValues(b)
  b[31] &= 0x1f // stay well under the BN254 modulus
  return Buffer.from(b).toString("hex")
}

// How long spendV3 waits for a spend to actually settle on-chain before it gives
// up and leaves the inputs unspent. Settlement is a 2-of-2 quorum co-sign plus an
// on-chain transact, so seconds normally; the ceiling tolerates a slow quorum.
const SETTLE_CONFIRM_TIMEOUT_MS = 150_000
// fetchV3Leaves pages the whole program history, so poll it sparingly.
const SETTLE_CONFIRM_POLL_MS = 6_000

// Confirm a spend settled by watching for one of its output commitments to land
// in the on-chain tree. Settlement is atomic — the transact instruction records
// the input nullifiers and appends both output commitments together — so the
// output commitment appearing is proof the nullifiers were consumed and the
// inputs are truly spent. Used as the settlement signal for a shielded transfer,
// which has no external recipient balance to watch (a withdraw's caller passes a
// cheaper `confirmSettled` that polls the funded address instead). The polling
// logic lives in settlementConfirm.ts so it can be unit-tested without the prover.
function confirmSettledByTree(
  connection: Connection,
  commitmentHex: string,
  timeoutMs = SETTLE_CONFIRM_TIMEOUT_MS,
  pollMs = SETTLE_CONFIRM_POLL_MS
): Promise<boolean> {
  return confirmCommitmentInTree(
    () => fetchV3Leaves(connection),
    commitmentHex,
    timeoutMs,
    pollMs
  )
}

/// Deposit lamports as a v3 note: the program computes the commitment and
/// appends it on-chain; the leaf index comes back in the DepositNoteEvent.
export async function depositV3(
  connection: Connection,
  wallet: { secretKey: Uint8Array },
  shieldedAddress: string,
  spendPrivkeyHex: string,
  lamports: bigint
): Promise<{ signature: string; leafIndex: number }> {
  const blindingHex = randomHex32()
  const pubkeyHex = await v3NotePubkey(spendPrivkeyHex)
  const payer = Keypair.fromSecretKey(wallet.secretKey)
  // The commitment is the note's stable identity, computed up front so the note
  // can be persisted the instant the deposit is submitted and finalized by
  // commitment once the leaf index is known.
  const commitment = await v3NoteCommitment(lamports, pubkeyHex, blindingHex)

  const signature = await sendDepositNote(
    connection,
    payer,
    lamports,
    Uint8Array.from(Buffer.from(pubkeyHex, "hex")),
    Uint8Array.from(Buffer.from(blindingHex, "hex")),
    // Persist the note (with its blinding) the moment the deposit is submitted,
    // BEFORE confirmation and the leaf-index lookup below. Previously the note
    // was written only after that lookup — a getTransaction plus a possible
    // full-history rebuild — so a worker eviction (a known MV3 failure mode) or
    // a dropped RPC anywhere in that window left the deposit committed on-chain
    // with its spend secret gone and unrecoverable (paraloom-core#791). Stored
    // with the commitment but no leaf index yet; ensureLeafIndex can still locate
    // the leaf by commitment, so the note is spendable even if the flow is
    // interrupted right here.
    async (sig) => {
      await addNote(shieldedAddress, {
        amount: lamports.toString(),
        blinding: blindingHex,
        assetId: NATIVE_ASSET_HEX,
        signature: sig,
        createdAt: Date.now(),
        spent: false,
        source: "deposit",
        commitment
      })
    }
  )

  // Read our leaf index from the event this deposit emitted.
  const tx = await connection.getTransaction(signature, {
    maxSupportedTransactionVersion: 0
  })
  let leafIndex = -1
  for (const line of tx?.meta?.logMessages ?? []) {
    const m = line.match(/^Program log: Deposit note appended at leaf (\d+)$/)
    if (m) leafIndex = Number(m[1])
  }
  if (leafIndex < 0) {
    // Fallback: locate our commitment in the rebuilt leaf list.
    const leaves = await fetchV3Leaves(connection)
    leafIndex = leaves.findIndex((l) => l.commitmentHex === commitment)
  }
  if (leafIndex < 0) {
    // The note is already persisted (above) and spendable — ensureLeafIndex will
    // resolve the index by commitment at spend time — so surface the lookup miss
    // without losing the deposit.
    throw new Error("deposit confirmed but leaf index not found")
  }

  // Finalize the persisted note with its now-known leaf index, saving
  // ensureLeafIndex a full-history rebuild at spend time.
  await setNoteLeafIndex(shieldedAddress, commitment, leafIndex)
  return { signature, leafIndex }
}

/// Locate a note's leaf index by its commitment (for received notes that were
/// scanned from ciphertexts and carry no index).
async function ensureLeafIndex(
  connection: Connection,
  note: ShieldedNote,
  spendPrivkeyHex: string,
  // Leaves already rebuilt by the caller THIS instant (same tree snapshot), so
  // spendV3 doesn't page the whole chain history again per input note. Only ever
  // pass leaves fetched in the same spend — never a stale snapshot from a prior
  // settlement, whose root may no longer be known on-chain.
  cachedLeaves?: { commitmentHex: string }[]
): Promise<number> {
  if (note.leafIndex !== undefined && note.leafIndex >= 0) return note.leafIndex
  const pubkeyHex = await v3NotePubkey(spendPrivkeyHex)
  // Compute the commitment under the note's own asset (#779): a shielded SPL
  // note's leaf binds its mint-derived assetId, not the native all-zero one, so
  // a native-only commitment would never match its on-chain leaf.
  const commitment =
    note.assetId && note.assetId !== NATIVE_ASSET_HEX
      ? await v3NoteCommitmentAsset(BigInt(note.amount), pubkeyHex, note.blinding, note.assetId)
      : await v3NoteCommitment(BigInt(note.amount), pubkeyHex, note.blinding)
  const leaves = cachedLeaves ?? (await fetchV3Leaves(connection))
  const idx = leaves.findIndex((l) => l.commitmentHex === commitment)
  if (idx < 0) throw new Error("note commitment not found in the on-chain tree")
  return idx
}

export interface SpendResult {
  requestId: string
  /// Change returned to the wallet, if any (recorded as a new local note).
  changeLamports: bigint
  /// Whether the spend was confirmed settled on-chain. When false, the inputs
  /// were deliberately left unspent and no change note was booked, so the spend
  /// can be retried safely (paraloom-core#792).
  settled: boolean
}

export interface SpendOptions {
  /// Bearer token for the transact ingress, when the endpoint gates submission.
  ingressToken?: string
  /// Settlement signal supplied by the caller: resolves true once the spend is
  /// confirmed on-chain (e.g. the withdrawn funds landed at the recipient), or
  /// false on timeout. A withdraw caller passes this to reuse the cheap
  /// recipient-balance poll it already runs; when omitted (a shielded transfer),
  /// spendV3 falls back to watching the output commitment land in the tree.
  confirmSettled?: () => Promise<boolean>
}

/// Spend 1–2 notes through the unified transact:
///  - `recipientSolanaHex` set → withdraw `payLamports` to that Solana address
///    (`ext_amount = -payLamports`), change stays shielded.
///  - `recipientShielded` set → shielded transfer: `payLamports` moves to the
///    recipient's note, change back to us, no external flow (`ext_amount = 0`).
export async function spendV3(
  connection: Connection,
  shieldedAddress: string,
  spendPrivkeyHex: string,
  ownBoxPubHex: string,
  inputs: ShieldedNote[],
  payLamports: bigint,
  dest:
    | { kind: "withdraw"; recipientSolanaHex: string }
    | { kind: "transfer"; recipientShielded: string },
  opts: SpendOptions = {}
): Promise<SpendResult> {
  if (inputs.length < 1 || inputs.length > 2) {
    throw new Error("transact spends 1 or 2 notes")
  }
  const sumIn = inputs.reduce((acc, n) => acc + BigInt(n.amount), 0n)
  if (payLamports <= 0n || payLamports > sumIn) {
    throw new Error("amount exceeds the selected notes")
  }
  const change = sumIn - payLamports

  // Asset (#779): every input in one transact shares a single asset. Native SOL
  // is the all-zero id; a shielded SPL note carries its mint-derived assetId and
  // the mint itself (needed to tell the node to settle via transact_spl).
  const assetIdHex = inputs[0].assetId || NATIVE_ASSET_HEX
  if (inputs.some((n) => (n.assetId || NATIVE_ASSET_HEX) !== assetIdHex)) {
    throw new Error("all spent notes must share one asset")
  }
  const isSpl = assetIdHex !== NATIVE_ASSET_HEX
  const mintPk = isSpl && inputs[0].mint ? new PublicKey(inputs[0].mint) : undefined
  const mintHex = mintPk ? mintPk.toBuffer().toString("hex") : undefined
  if (isSpl && !mintHex) {
    throw new Error("a shielded SPL note must carry its mint to be spent")
  }
  let tokenProgramHex: string | undefined
  if (isSpl && mintPk) {
    const tokenProg = await resolveTokenProgram(connection, mintPk)
    tokenProgramHex = tokenProg.toBuffer().toString("hex")
  }
  const noteCommitment = (amount: bigint, pubkeyHex: string, blindingHex: string) =>
    isSpl
      ? v3NoteCommitmentAsset(amount, pubkeyHex, blindingHex, assetIdHex)
      : v3NoteCommitment(amount, pubkeyHex, blindingHex)

  // Membership paths from the client-side tree rebuild — the root every path
  // folds to is the root the proof cites.
  const leaves = await fetchV3Leaves(connection)
  const leavesHex = leaves.map((l) => l.commitmentHex)
  const inputSpecs = [] as {
    amount: bigint
    privkeyHex: string
    blindingHex: string
    leafIndex: number
    pathHex: string[]
  }[]
  let rootHex = ""
  for (const note of inputs) {
    // Reuse the leaves rebuilt just above (same snapshot) instead of paging the
    // whole chain history again per input note.
    const leafIndex = await ensureLeafIndex(connection, note, spendPrivkeyHex, leaves)
    const { path, root } = await v3MerklePath(leavesHex, leafIndex)
    rootHex = root
    inputSpecs.push({
      amount: BigInt(note.amount),
      privkeyHex: spendPrivkeyHex,
      blindingHex: note.blinding,
      leafIndex,
      pathHex: path
    })
  }
  // Pad a single-note spend with a zero-value dummy (membership is skipped
  // in-circuit for zero notes; the path just needs the right shape).
  if (inputSpecs.length === 1) {
    const { path } = await v3MerklePath(leavesHex, inputSpecs[0].leafIndex)
    inputSpecs.push({
      amount: 0n,
      privkeyHex: randomHex32(),
      blindingHex: randomHex32(),
      leafIndex: 0,
      pathHex: path
    })
  }

  // Outputs: for a withdraw both outputs stay ours (change + zero filler);
  // for a transfer the payment note goes to the recipient's v3 spend pubkey.
  const ownPubHex = await v3NotePubkey(spendPrivkeyHex)
  const changeBlind = randomHex32()
  const fillerBlind = randomHex32()

  let extAmount: bigint
  let recipientHex: string
  let outputs: { amount: bigint; pubkeyHex: string; blindingHex: string }[]
  let ciphertexts: [string, string]

  if (dest.kind === "withdraw") {
    extAmount = -payLamports
    recipientHex = dest.recipientSolanaHex
    outputs = [
      { amount: change, pubkeyHex: ownPubHex, blindingHex: changeBlind },
      { amount: 0n, pubkeyHex: ownPubHex, blindingHex: fillerBlind }
    ]
    ciphertexts = [
      encryptNote(ownBoxPubHex, {
        amount: change,
        blindingHex: changeBlind,
        assetIdHex
      }),
      encryptNote(ownBoxPubHex, {
        amount: 0n,
        blindingHex: fillerBlind,
        assetIdHex
      })
    ]
  } else {
    extAmount = 0n
    recipientHex = "00".repeat(32)
    const toSpendPub = addressSpendPubHex(dest.recipientShielded)
    const toBoxPub = addressBoxPubHex(dest.recipientShielded)
    const payBlind = randomHex32()
    outputs = [
      { amount: payLamports, pubkeyHex: toSpendPub, blindingHex: payBlind },
      { amount: change, pubkeyHex: ownPubHex, blindingHex: changeBlind }
    ]
    ciphertexts = [
      encryptNote(toBoxPub, {
        amount: payLamports,
        blindingHex: payBlind,
        assetIdHex
      }),
      encryptNote(ownBoxPubHex, {
        amount: change,
        blindingHex: changeBlind,
        assetIdHex
      })
    ]
  }

  const bundle = await proveTransact(
    rootHex,
    extAmount,
    recipientHex,
    assetIdHex,
    [inputSpecs[0], inputSpecs[1]] as never,
    [outputs[0], outputs[1]] as never
  )

  const { requestId } = await submitTransact(
    rootHex,
    extAmount,
    recipientHex,
    bundle,
    ciphertexts,
    opts.ingressToken,
    mintHex,
    tokenProgramHex
  )

  // Wait until the spend actually settles before touching local bookkeeping.
  // submitTransact only returns a queue ticket — the ingress accepts the request
  // before the proof is verified and the quorum settles it, so a HTTP 200 is not
  // a settlement. Marking the inputs spent (or booking the change) on acceptance
  // meant that when settlement then failed, the wallet hid real, still-spendable
  // funds as spent and showed a change note whose commitment never landed
  // on-chain — corrupting the balance in both directions with no self-healing
  // path (paraloom-core#792). The signal is the first output commitment landing
  // in the tree; a withdraw caller supplies a cheaper recipient-funded check.
  const settleCommitmentHex = await noteCommitment(
    outputs[0].amount,
    outputs[0].pubkeyHex,
    outputs[0].blindingHex
  )
  const settled = opts.confirmSettled
    ? await opts.confirmSettled()
    : await confirmSettledByTree(connection, settleCommitmentHex)

  if (settled) {
    // Mark inputs spent and record the change note locally. Deliberately WITHOUT
    // a leaf index: the index can only be predicted from a pre-settlement tree
    // snapshot, and any deposit or transact that lands in the prove+ingress
    // window shifts the real slot. A wrong index was persisted and then trusted
    // forever by ensureLeafIndex, so the change output built a membership path to
    // the wrong slot and became permanently unspendable. Storing only the
    // commitment forces ensureLeafIndex to locate the note by commitment against
    // a fresh rebuild at spend time, which is authoritative. (Deposit notes keep
    // their index because it comes from the on-chain event and never moves.)
    for (const note of inputs) {
      await markNoteSpentByIdentity(shieldedAddress, note)
    }
    if (change > 0n) {
      await addNote(shieldedAddress, {
        amount: change.toString(),
        blinding: changeBlind,
        assetId: assetIdHex,
        mint: isSpl ? inputs[0].mint : undefined,
        signature: "",
        createdAt: Date.now(),
        spent: false,
        source: "transfer",
        commitment: await noteCommitment(change, ownPubHex, changeBlind)
      })
    }
  }

  return { requestId, changeLamports: change, settled }
}
