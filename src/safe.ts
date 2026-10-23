// Safe (multisig) helpers shared by the co-signer and by agents that act through a Safe.
// A Safe transaction is identified by its EIP-712 hash; every owner signs exactly that hash.
import { getAddress, hashTypedData, concat, type Address, type Hex } from 'viem'
import { CHAIN_ID } from './typed-data'

export interface SafeTx {
  to: Address; value: bigint; data: Hex
  /** 0 = call, 1 = delegatecall (the co-signer refuses delegatecall) */
  operation: number
  safeTxGas: bigint; baseGas: bigint; gasPrice: bigint; gasToken: Address; refundReceiver: Address
  nonce: bigint
}
const ZERO: Address = '0x0000000000000000000000000000000000000000'

export const SAFE_TX_TYPES = {
  SafeTx: [
    { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' }, { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }, { name: 'nonce', type: 'uint256' },
  ],
} as const
/** Safe v1.3+ domain: chain id + the Safe's own address (no name/version). */
export const safeDomain = (safe: Address, chainId = CHAIN_ID) => ({ chainId, verifyingContract: getAddress(safe) }) as const

/** A plain call with no gas refund: the only shape the co-signer signs. */
export const buildSafeTx = (t: { to: Address; data?: Hex; value?: bigint; nonce: bigint }): SafeTx =>
  ({ to: getAddress(t.to), value: t.value ?? 0n, data: t.data ?? '0x', operation: 0, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZERO, refundReceiver: ZERO, nonce: t.nonce })

export const safeTxHash = (safe: Address, tx: SafeTx, chainId = CHAIN_ID): Hex =>
  hashTypedData({ domain: safeDomain(safe, chainId), types: SAFE_TX_TYPES, primaryType: 'SafeTx', message: tx })

/** Safe wants the 65-byte signatures concatenated in ascending order of signer address. */
export function packSignatures(sigs: Array<{ signer: Address; signature: Hex }>): Hex {
  const sorted = [...sigs].sort((a, b) => (BigInt(a.signer) < BigInt(b.signer) ? -1 : 1))
  return concat(sorted.map(s => s.signature))
}

export const safeTxToJson = (t: SafeTx) => ({ ...t, value: t.value.toString(), safeTxGas: t.safeTxGas.toString(), baseGas: t.baseGas.toString(), gasPrice: t.gasPrice.toString(), nonce: t.nonce.toString() })
export function safeTxFromJson(j: any): SafeTx {
  return { to: getAddress(j.to), value: BigInt(j.value ?? 0), data: (j.data ?? '0x') as Hex, operation: Number(j.operation ?? 0), safeTxGas: BigInt(j.safeTxGas ?? 0), baseGas: BigInt(j.baseGas ?? 0),
    gasPrice: BigInt(j.gasPrice ?? 0), gasToken: getAddress(j.gasToken ?? ZERO), refundReceiver: getAddress(j.refundReceiver ?? ZERO), nonce: BigInt(j.nonce) }
}

export const safeAbi = [
  { type: 'function', name: 'VERSION', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { type: 'function', name: 'getOwners', stateMutability: 'view', inputs: [], outputs: [{ type: 'address[]' }] },
  { type: 'function', name: 'getThreshold', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'nonce', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getModulesPaginated', stateMutability: 'view', inputs: [{ name: 'start', type: 'address' }, { name: 'pageSize', type: 'uint256' }], outputs: [{ name: 'array', type: 'address[]' }, { name: 'next', type: 'address' }] },
  { type: 'function', name: 'getTransactionHash', stateMutability: 'view', outputs: [{ type: 'bytes32' }],
    inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
      { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }, { name: '_nonce', type: 'uint256' }] },
  { type: 'function', name: 'execTransaction', stateMutability: 'payable', outputs: [{ type: 'bool' }],
    inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' },
      { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }, { name: 'signatures', type: 'bytes' }] },
  { type: 'function', name: 'setup', stateMutability: 'nonpayable', outputs: [],
    inputs: [{ name: '_owners', type: 'address[]' }, { name: '_threshold', type: 'uint256' }, { name: 'to', type: 'address' }, { name: 'data', type: 'bytes' }, { name: 'fallbackHandler', type: 'address' },
      { name: 'paymentToken', type: 'address' }, { name: 'payment', type: 'uint256' }, { name: 'paymentReceiver', type: 'address' }] },
  { type: 'function', name: 'removeOwner', stateMutability: 'nonpayable', outputs: [], inputs: [{ name: 'prevOwner', type: 'address' }, { name: 'owner', type: 'address' }, { name: '_threshold', type: 'uint256' }] },
  { type: 'function', name: 'changeThreshold', stateMutability: 'nonpayable', outputs: [], inputs: [{ name: '_threshold', type: 'uint256' }] },
] as const

export const safeProxyFactoryAbi = [
  { type: 'function', name: 'createProxyWithNonce', stateMutability: 'nonpayable', inputs: [{ name: '_singleton', type: 'address' }, { name: 'initializer', type: 'bytes' }, { name: 'saltNonce', type: 'uint256' }], outputs: [{ name: 'proxy', type: 'address' }] },
  { type: 'event', name: 'ProxyCreation', inputs: [{ name: 'proxy', type: 'address', indexed: true }, { name: 'singleton', type: 'address', indexed: false }] },
] as const

export function execCalldataArgs(tx: SafeTx, signatures: Hex) {
  return [tx.to, tx.value, tx.data, tx.operation, tx.safeTxGas, tx.baseGas, tx.gasPrice, tx.gasToken, tx.refundReceiver, signatures] as const
}
