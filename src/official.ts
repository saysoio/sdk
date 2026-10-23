// sayso's own signing addresses, built into the SDK. A verdict counts only if it is signed by the address listed
// here for the server's chain, and a Safe co-signature only if it comes from the co-signer listed here, unless the
// caller names other addresses (their own or a local server). The server is never asked who its signer is: a server
// that could name its own signer, or anyone who took over its web address, could forge "allow".
//
// The keys live in AWS KMS and cannot be copied out. Addresses as answered by the two hosted servers' GET /health
// and by `pnpm kms:check` (docs/decisions.md, 2026-10-04), checked again against the live servers on 2026-10-06.
import { getAddress, type Address } from 'viem'

/** signs verdict receipts and the decision log */
export const OATHLINE_SIGNERS: Readonly<Record<number, Address>> = Object.freeze({
  8453: '0x96489eBC8C0ff7FBa482536699B1f78d87f1306d',     // Base
  84532: '0x70aA81eB7ED4b1636b50c88E9B0D0CA3107DeE3f',    // Base Sepolia (the public test server; test money only)
})
/** sayso's key on customers' Safes */
export const OATHLINE_COSIGNERS: Readonly<Record<number, Address>> = Object.freeze({
  8453: '0x7ad359D3E76eCbf460156457cbB61f1643149841',   // v2 since 2026-10-12: a multi-Region key (Frankfurt + Ireland); the old address 0xAA5541299230c6D8036273Afa3F26a4A084B2C7D is retired
  84532: '0x97d1089DaB43EE469Afd84B0713CdF00FfB08B7d',
})

/** sayso's verdict signer on a chain. Throws for a chain sayso does not serve: then the caller must name the signer. */
export function officialSigner(chainId: number): Address {
  const a = OATHLINE_SIGNERS[chainId]
  if (!a) throw new Error(`no sayso signing address is known for chain ${chainId}; if this is your own or a local server, pass its address as \`signer\``)
  return getAddress(a)
}
