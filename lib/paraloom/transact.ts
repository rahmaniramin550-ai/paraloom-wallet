// Circuit v3 (#350): deposit_note + the unified transact spend.
//
// The v3 model replaces the leader-published root with the program's own
// on-chain incremental tree: `deposit_note` appends the commitment on-chain,
// and a spend proves membership against a root from the program's root
// history. The wallet rebuilds the tree CLIENT-SIDE from the program's public
// event logs — asking a validator for a path would leak which leaf is ours —
// and computes the membership path locally (`v3MerklePath`, the same circom
// Poseidon as the circuit and the on-chain syscall).

import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type Keypair
} from "@solana/web3.js"

import { confirmBySignatureStatus } from "./bridge"
import {
  BRIDGE_STATE_SEED,
  BRIDGE_VAULT_SEED,
  DEPOSIT_NOTE_DISCRIMINATOR,
  DEPOSIT_NOTE_EVENT_DISCRIMINATOR,
  DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR,
  MERKLE_TREE_SEED,
  PROGRAM_ID,
  TRANSACT_EVENT_DISCRIMINATOR,
  TRANSACT_INGRESS_URL
} from "./constants"

const programId = new PublicKey(PROGRAM_ID)

function pda(seed: string): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(seed)], programId)[0]
}

// Layout: DEPOSIT_NOTE discriminator (8) | amount u64 LE (8) | pubkey (32) |
// blinding (32) — matching the on-chain `deposit_note(amount, pubkey, blinding)`.
function depositNoteInstructionData(
  amountLamports: bigint,
  pubkey: Uint8Array,
  blinding: Uint8Array
): Buffer {
  const data = new Uint8Array(8 + 8 + 32 + 32)
  data.set(DEPOSIT_NOTE_DISCRIMINATOR, 0)
  new DataView(data.buffer).setBigUint64(8, amountLamports, true)
  data.set(pubkey, 16)
  data.set(blinding, 48)
  return Buffer.from(data)
}

export function depositNoteInstruction(
  depositor: PublicKey,
  amountLamports: bigint,
  pubkey: Uint8Array,
  blinding: Uint8Array
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: pda(BRIDGE_STATE_SEED), isSigner: false, isWritable: true },
      { pubkey: pda(BRIDGE_VAULT_SEED), isSigner: false, isWritable: true },
      { pubkey: pda(MERKLE_TREE_SEED), isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }
    ],
    data: depositNoteInstructionData(amountLamports, pubkey, blinding)
  })
}

/// Send a v3 deposit: moves lamports into the vault and appends the note
/// commitment to the on-chain tree. Returns the transaction signature; the
/// wallet learns its leaf index by scanning the DepositNoteEvent it emitted.
export async function sendDepositNote(
  connection: Connection,
  payer: Keypair,
  amountLamports: bigint,
  pubkey: Uint8Array,
  blinding: Uint8Array,
  // Called the instant the deposit is SUBMITTED (signature known), BEFORE the
  // confirm wait. The blinding is fresh randomness that lives only here and in
  // the on-chain instruction, so persisting the note now means a worker eviction
  // or crash during confirmation can never orphan a landed deposit with its
  // secret gone (paraloom-core#791). Mirrors depositSpl's on-submit persist.
  onSubmitted?: (signature: string) => Promise<void>
): Promise<string> {
  const tx = new Transaction().add(
    depositNoteInstruction(payer.publicKey, amountLamports, pubkey, blinding)
  )
  const { blockhash } = await connection.getLatestBlockhash("confirmed")
  tx.recentBlockhash = blockhash
  tx.feePayer = payer.publicKey
  tx.sign(payer)
  // Tolerant confirm (not the hard blockhash deadline): a busy mainnet must not
  // throw "block height exceeded" on a deposit that actually lands, which would
  // orphan the note's blinding before it is persisted.
  const signature = await connection.sendRawTransaction(tx.serialize(), {
    maxRetries: 5
  })
  if (onSubmitted) {
    // Persisting is best-effort and must not abort a submitted deposit; the note
    // is still recoverable from the on-chain instruction data if this throws.
    try {
      await onSubmitted(signature)
    } catch {
      // swallow — confirmation proceeds regardless
    }
  }
  await confirmBySignatureStatus(connection, signature)
  return signature
}

export interface V3Leaf {
  index: number
  commitmentHex: string
}

// Collect only the `Program data:` lines our program emitted. A Solana log
// stream interleaves `Program <id> invoke` / `Program data:` / `Program <id>
// success|failed` from every program in the transaction, including CPIs, and the
// event discriminators are public (`sha256("event:<Name>")[..8]`), so an
// unrelated program in the same tx could emit a byte-identical DepositNote/
// Transact line. `getSignaturesForAddress(programId)` only selects the tx, not
// the emitter. Track the invoke/success stack and keep a `Program data:` line
// only while our program is the one currently executing (top of stack).
function eventPayloads(logs: string[], expectedProgramId: string): Uint8Array[] {
  const out: Uint8Array[] = []
  const stack: string[] = []
  for (const line of logs) {
    const invoke = line.match(/^Program (\S+) invoke \[\d+\]$/)
    if (invoke) {
      stack.push(invoke[1])
      continue
    }
    if (/^Program \S+ (success|failed)/.test(line)) {
      stack.pop()
      continue
    }
    const data = line.match(/^Program data: (.+)$/)
    if (data && stack[stack.length - 1] === expectedProgramId) {
      out.push(Uint8Array.from(Buffer.from(data[1], "base64")))
    }
  }
  return out
}

function startsWith(buf: Uint8Array, prefix: Uint8Array): boolean {
  if (buf.length < prefix.length) return false
  for (let i = 0; i < prefix.length; i++) if (buf[i] !== prefix[i]) return false
  return true
}

/// Rebuild the ordered v3 leaf list from the program's public event logs.
///
/// DepositNoteEvent: depositor(32) amount(8) commitment(32)@40 leaf_index(8)@72.
/// TransactEvent: nf0(32) nf1(32) oc0(32)@64 oc1(32)@96 new_root(32)
///   ext_amount(8) fee(8) recipient(32) ts(8) settlement_id(8) — the two
///   output commitments land at consecutive indices; the first one's index is
///   inferred from append order, so leaves are collected then sorted.
export async function fetchV3Leaves(connection: Connection): Promise<V3Leaf[]> {
  // Page through the FULL signature history, newest to oldest, following
  // `before`. `getSignaturesForAddress` caps each call at 1000, so a single
  // unpaginated fetch only ever saw the newest 1000 — once the program passed
  // 1000 transactions the wallet rebuilt a tree missing its oldest leaves,
  // producing a root the on-chain `is_known_root` rejects and freezing every
  // spend. Walk until a short page signals the end of history.
  const sigs: Awaited<ReturnType<typeof connection.getSignaturesForAddress>> = []
  let before: string | undefined
  for (;;) {
    const page = await connection.getSignaturesForAddress(programId, {
      limit: 1000,
      ...(before ? { before } : {})
    })
    if (page.length === 0) break
    sigs.push(...page)
    if (page.length < 1000) break
    before = page[page.length - 1].signature
  }

  const leaves: V3Leaf[] = []
  let transactLeafCursor: number | null = null

  // Oldest first so transact outputs are numbered in append order. Each page is
  // newest-first and pages go newest→oldest, so the full list is newest-first;
  // reversing yields true append order across the whole history.
  for (const sig of [...sigs].reverse()) {
    if (sig.err) continue
    // A null getTransaction on a program signature is usually a transient RPC
    // hiccup, and most program txs carry no leaf at all (cosign, register,
    // vote, config), so a plain skip of a genuine gap would corrupt the
    // positional rebuild. Retry a few times first; only if it stays null do we
    // stop, because we cannot tell a body-pruned leaf tx from a transient miss,
    // and silently dropping a leaf tx desyncs the tree and freezes spends. The
    // contiguity check below is the backstop for a dropped leaf; this throw is
    // the backstop for a dropped trailing leaf the contiguity check can't see.
    let tx = null
    for (let attempt = 0; attempt < 3 && !tx; attempt++) {
      tx = await connection.getTransaction(sig.signature, {
        maxSupportedTransactionVersion: 0
      })
    }
    if (!tx) {
      throw new Error(
        `getTransaction returned null for ${sig.signature} after retries; the ` +
          `leaf history may be incomplete and the tree cannot be rebuilt safely ` +
          `(retry, or use an archival RPC if the node prunes history)`
      )
    }
    const logs = tx.meta?.logMessages ?? []
    for (const payload of eventPayloads(logs, PROGRAM_ID)) {
      if (startsWith(payload, DEPOSIT_NOTE_EVENT_DISCRIMINATOR)) {
        const body = payload.slice(8)
        const commitment = body.slice(40, 72)
        const leafIndex = Number(new DataView(body.buffer, body.byteOffset + 72, 8).getBigUint64(0, true))
        leaves.push({ index: leafIndex, commitmentHex: Buffer.from(commitment).toString("hex") })
        transactLeafCursor = Math.max(transactLeafCursor ?? 0, leafIndex + 1)
      } else if (startsWith(payload, DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR)) {
        // SPL deposit (#779): same tree, one extra `mint` (32) field before the
        // commitment. Body: depositor(32) | mint(32) | amount(8) | commitment(32)
        // | leaf_index(8) | timestamp(8). Its leaf MUST be included or the tree
        // diverges from on-chain and every spend freezes.
        const body = payload.slice(8)
        const commitment = body.slice(72, 104)
        const leafIndex = Number(
          new DataView(body.buffer, body.byteOffset + 104, 8).getBigUint64(0, true)
        )
        leaves.push({ index: leafIndex, commitmentHex: Buffer.from(commitment).toString("hex") })
        transactLeafCursor = Math.max(transactLeafCursor ?? 0, leafIndex + 1)
      } else if (startsWith(payload, TRANSACT_EVENT_DISCRIMINATOR)) {
        const body = payload.slice(8)
        const oc0 = body.slice(64, 96)
        const oc1 = body.slice(96, 128)
        const base = transactLeafCursor ?? leaves.length
        leaves.push({ index: base, commitmentHex: Buffer.from(oc0).toString("hex") })
        leaves.push({ index: base + 1, commitmentHex: Buffer.from(oc1).toString("hex") })
        transactLeafCursor = base + 2
      }
    }
  }
  leaves.sort((a, b) => a.index - b.index)
  // The tree is append-only and gap-free: indices must be exactly 0..N-1. The
  // callers consume this list positionally (v3_merkle_path folds by array
  // position), so a missing or duplicated index would fold to a wrong root and
  // freeze spends. Assert it here rather than let it surface as an opaque
  // "prover root not recognized" later.
  for (let i = 0; i < leaves.length; i++) {
    if (leaves[i].index !== i) {
      throw new Error(
        `leaf history is not contiguous at position ${i} (saw index ${leaves[i].index}); ` +
          `refusing to build a tree from an incomplete leaf set`
      )
    }
  }
  return leaves
}

export interface TransactSpendInput {
  amount: bigint
  privkeyHex: string
  blindingHex: string
  leafIndex: number
  pathHex: string[]
}

export interface TransactOutputNote {
  amount: bigint
  pubkeyHex: string
  blindingHex: string
}

export interface TransactSubmission {
  requestId: string
}

/// POST a proven transact to the ingress. `proofBundleJson` is the exact JSON
/// `proveTransact` returns ({ nullifiers, output_commitments, proof }); the
/// wallet adds root / ext_amount / recipient / ciphertexts around it.
export async function submitTransact(
  rootHex: string,
  extAmount: bigint,
  recipientHex: string,
  proofBundleJson: string,
  ciphertexts: [string, string],
  ingressToken?: string,
  // SPL settlement (#779): the mint being spent, 32-byte hex. Omitted for a
  // native-SOL spend; when present the node settles via transact_spl and
  // `recipientHex` is the recipient token account.
  mintHex?: string,
  // Token-2022 program resolution (#862): 32-byte hex of the token program.
  tokenProgramHex?: string
): Promise<TransactSubmission> {
  const bundle = JSON.parse(proofBundleJson)
  const body: Record<string, unknown> = {
    recipient: recipientHex,
    nullifiers: bundle.nullifiers,
    output_commitments: bundle.output_commitments,
    root: rootHex,
    ext_amount: Number(extAmount),
    proof: bundle.proof,
    ciphertexts
  }
  if (mintHex) body.mint = mintHex
  if (tokenProgramHex) body.token_program = tokenProgramHex
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (ingressToken) headers["Authorization"] = `Bearer ${ingressToken}`
  const res = await fetch(`${TRANSACT_INGRESS_URL}/transact/submit`, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(`transact ingress rejected: ${res.status} ${await res.text()}`)
  }
  const json = await res.json()
  return { requestId: json.request_id ?? json.requestId }
}
