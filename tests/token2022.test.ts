import { Connection, Keypair, PublicKey } from "@solana/web3.js"
import { describe, expect, it, vi } from "vitest"

import {
  associatedTokenAddress,
  resolveTokenProgram
} from "~lib/paraloom/bridge"
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID
} from "~lib/paraloom/constants"
import { submitTransact } from "~lib/paraloom/transact"

vi.mock("~lib/prover", () => ({
  NATIVE_ASSET_HEX: "00".repeat(32),
  assetIdForMint: vi.fn().mockResolvedValue("11".repeat(32))
}))

describe("Token-2022 Program Resolution (#862)", () => {
  it("resolves to TOKEN_2022_PROGRAM_ID when mint is owned by Token-2022", async () => {
    const mint = Keypair.generate().publicKey
    const connection = {
      getAccountInfo: vi.fn().mockResolvedValue({
        owner: new PublicKey(TOKEN_2022_PROGRAM_ID)
      })
    } as unknown as Connection

    const resolved = await resolveTokenProgram(connection, mint)
    expect(resolved.toBase58()).toBe(TOKEN_2022_PROGRAM_ID)
  })

  it("resolves to TOKEN_PROGRAM_ID when mint is owned by classic SPL Token Program", async () => {
    const mint = Keypair.generate().publicKey
    const connection = {
      getAccountInfo: vi.fn().mockResolvedValue({
        owner: new PublicKey(TOKEN_PROGRAM_ID)
      })
    } as unknown as Connection

    const resolved = await resolveTokenProgram(connection, mint)
    expect(resolved.toBase58()).toBe(TOKEN_PROGRAM_ID)
  })

  it("falls back to TOKEN_PROGRAM_ID when mint account info is null or errors", async () => {
    const mint = Keypair.generate().publicKey
    const connectionNull = {
      getAccountInfo: vi.fn().mockResolvedValue(null)
    } as unknown as Connection

    const resolvedNull = await resolveTokenProgram(connectionNull, mint)
    expect(resolvedNull.toBase58()).toBe(TOKEN_PROGRAM_ID)

    const connectionErr = {
      getAccountInfo: vi.fn().mockRejectedValue(new Error("RPC network failure"))
    } as unknown as Connection

    const resolvedErr = await resolveTokenProgram(connectionErr, mint)
    expect(resolvedErr.toBase58()).toBe(TOKEN_PROGRAM_ID)
  })

  it("derives different ATAs for classic SPL vs Token-2022 programs", () => {
    const wallet = Keypair.generate().publicKey
    const mint = Keypair.generate().publicKey

    const classicAta = associatedTokenAddress(
      wallet,
      mint,
      new PublicKey(TOKEN_PROGRAM_ID)
    )
    const token2022Ata = associatedTokenAddress(
      wallet,
      mint,
      new PublicKey(TOKEN_2022_PROGRAM_ID)
    )

    expect(classicAta.toBase58()).not.toBe(token2022Ata.toBase58())
  })

  it("binds token_program in submitTransact payload when tokenProgramHex is provided", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ request_id: "req-12345" })
    })
    globalThis.fetch = fetchSpy

    const proofBundle = JSON.stringify({
      nullifiers: ["aa".repeat(32)],
      output_commitments: ["bb".repeat(32), "cc".repeat(32)],
      proof: "ff".repeat(64)
    })

    const mintHex = "11".repeat(32)
    const tokenProgramHex = new PublicKey(TOKEN_2022_PROGRAM_ID)
      .toBuffer()
      .toString("hex")

    const res = await submitTransact(
      "00".repeat(32),
      1000n,
      "22".repeat(32),
      proofBundle,
      ["ct1", "ct2"],
      undefined,
      mintHex,
      tokenProgramHex
    )

    expect(res.requestId).toBe("req-12345")
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const callBody = JSON.parse(fetchSpy.mock.calls[0][1].body)
    expect(callBody.mint).toBe(mintHex)
    expect(callBody.token_program).toBe(tokenProgramHex)
  })
})
