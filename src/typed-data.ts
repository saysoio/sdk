// What gets signed, by whom. Shared by the check API, the SDK and the demos (EIP-712 typed data,
// so a wallet shows the owner readable fields instead of an opaque hash).
//
//   Link         signed by the AGENT WALLET   → "this owner may set my rules"
//   Mandate      signed by the OWNER          → the rules (plain text + hash of the compiled form)
//   Instruction  signed by the OWNER          → a one-off instruction, with an expiry
//   Channel      signed by the OWNER          → "send approval requests for this wallet to the chat that presents my link"
//   Verdict      signed by OATHLINE           → allow/ask/block for one exact transaction, with an expiry
//   CheckMode    signed by the OWNER          → "check this wallet in shadow / enforce mode from now on" (step 5d)
//   ModeStatement signed by OATHLINE          → the mode in force for one exact transaction, and when the owner set it
//   Relink       signed by the OWNER          → "register this wallet again as what it now is" (an EIP-7702 upgrade, or
//                                              a cleared delegation), once, with an expiry; the wallet signs a fresh Link too (R5 part 3)
import { encodeAbiParameters, keccak256, toHex, type Address, type Hex } from 'viem'

/** Base mainnet, the default. One sayso server works on one chain and says which in GET /health. */
export const CHAIN_ID = 8453
/** Everything signed for sayso names the chain, so a signature made for the test network counts for nothing on mainnet. */
export const oathlineDomain = (chainId: number = CHAIN_ID) => ({ name: 'oathline', version: '1', chainId }) as const
export const OATHLINE_DOMAIN = oathlineDomain()

export const OATHLINE_TYPES = {
  Link: [{ name: 'wallet', type: 'address' }, { name: 'owner', type: 'address' }],
  Mandate: [{ name: 'wallet', type: 'address' }, { name: 'text', type: 'string' }, { name: 'mandateHash', type: 'bytes32' }, { name: 'issuedAt', type: 'uint64' }],
  Instruction: [{ name: 'wallet', type: 'address' }, { name: 'text', type: 'string' }, { name: 'nonce', type: 'bytes32' }, { name: 'expiresAt', type: 'uint64' }],
  Channel: [{ name: 'wallet', type: 'address' }, { name: 'channel', type: 'string' }, { name: 'nonce', type: 'bytes32' }, { name: 'expiresAt', type: 'uint64' }],
  Verdict: [{ name: 'wallet', type: 'address' }, { name: 'txDigest', type: 'bytes32' }, { name: 'mandateId', type: 'bytes32' }, { name: 'verdict', type: 'string' }, { name: 'issuedAt', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' }],
  CheckMode: [{ name: 'wallet', type: 'address' }, { name: 'mode', type: 'string' }, { name: 'issuedAt', type: 'uint64' }],
  ModeStatement: [{ name: 'wallet', type: 'address' }, { name: 'txDigest', type: 'bytes32' }, { name: 'mode', type: 'string' }, { name: 'setAt', type: 'uint64' }, { name: 'expiresAt', type: 'uint64' }],
  Relink: [{ name: 'wallet', type: 'address' }, { name: 'owner', type: 'address' }, { name: 'nonce', type: 'bytes32' }, { name: 'expiresAt', type: 'uint64' }],
} as const

/** JSON with keys sorted at every level, so the same object always hashes the same. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : typeof v === 'bigint' ? v.toString() : v)
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  const o = v as Record<string, unknown>
  return `{${Object.keys(o).filter(k => o[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
}

/** Hash of the compiled mandate the owner was shown. */
export const mandateHash = (compiled: unknown): Hex => keccak256(toHex(canonicalJson(compiled)))

/** Identifies one exact transaction of one wallet on one chain: a verdict is valid for this and nothing else. When the
 *  SDK pinned the position (nonce) the transaction takes, the position is part of it: the verdict is then valid at that
 *  position only. A transaction without one hashes as before. */
export function txDigest(tx: { wallet: Address; to: Address; data: Hex; value?: bigint; nonce?: number }, chainId: number = CHAIN_ID): Hex {
  if (tx.nonce === undefined) return keccak256(encodeAbiParameters(
    [{ type: 'uint256' }, { type: 'address' }, { type: 'address' }, { type: 'uint256' }, { type: 'bytes32' }],
    [BigInt(chainId), tx.wallet, tx.to, tx.value ?? 0n, keccak256(tx.data)],
  ))
  return keccak256(encodeAbiParameters(
    [{ type: 'uint256' }, { type: 'address' }, { type: 'address' }, { type: 'uint256' }, { type: 'bytes32' }, { type: 'uint64' }],
    [BigInt(chainId), tx.wallet, tx.to, tx.value ?? 0n, keccak256(tx.data), BigInt(tx.nonce)],
  ))
}

export interface VerdictReceipt { wallet: Address; txDigest: Hex; mandateId: Hex; verdict: string; issuedAt: number; expiresAt: number; signer: Address; signature: Hex }

/** The two ways a wallet can be checked. shadow: verdicts are recorded and the agent signs anyway; enforce: a block is
 *  refused and an ask waits for the owner. */
export type CheckModeName = 'shadow' | 'enforce'
/** enforce counts as higher than shadow: a builder's floor in code and the owner's switch combine to the higher one */
export const strongerMode = (a: CheckModeName, b: CheckModeName): CheckModeName => (a === 'enforce' || b === 'enforce' ? 'enforce' : 'shadow')
/** sayso's signed word on which mode is in force for one exact transaction. setAt: when the owner signed the mode now in
 *  force (seconds; 0 = nobody has set one, the default shadow). The SDK never lets an older setAt replace a newer one. */
export interface ModeStatement { wallet: Address; txDigest: Hex; mode: CheckModeName; setAt: number; expiresAt: number; signer: Address; signature: Hex }
