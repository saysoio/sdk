// For an agent that acts through a 2-of-3 Safe with sayso as co-signer: build the Safe transaction, sign it
// with the agent's key, get sayso's signature (only on allow, or after the owner approved), execute.
// The agent's key alone can do nothing; the SDK holds no keys.
import { getAddress, type Address, type Hex } from 'viem'
import type { Oathline } from './index'
import { callOptions, chainFor, type CallOptions } from './chain'
import { SAFE_TX_TYPES, buildSafeTx, execCalldataArgs, safeAbi, safeDomain, safeTxToJson, type SafeTx } from './safe'

/** the two viem clients, described loosely so any viem version fits */
export interface SafeAgentClients {
  publicClient: { readContract(args: any): Promise<any> }
  /** the agent's own wallet client: signs the Safe transaction and pays the gas to submit it */
  walletClient: { account?: { address: Address; signTypedData?: (args: any) => Promise<Hex> } | undefined; signTypedData(args: any): Promise<Hex>; writeContract(args: any): Promise<Hex> }
}

/** Sends one call from the Safe. Throws OathlineBlocked / OathlineNeedsApproval / OathlineUnavailable like a guarded wallet. */
export async function sendViaSafe(oathline: Oathline, c: SafeAgentClients, safe: Address, call: { to: Address; data?: Hex; value?: bigint }, extra: Record<string, unknown> = {}): Promise<Hex> {
  const account = c.walletClient.account
  if (!account) throw new Error('walletClient has no account')
  const nonce = await c.publicClient.readContract({ address: safe, abi: safeAbi, functionName: 'nonce' }) as bigint
  const tx = buildSafeTx({ ...call, nonce })
  const typed = { domain: safeDomain(safe, await oathline.chainId()), types: SAFE_TX_TYPES, primaryType: 'SafeTx', message: tx } as const
  const agentSignature = account.signTypedData ? await account.signTypedData(typed) : await c.walletClient.signTypedData({ account, ...typed })
  const { signatures } = await oathline.cosign(getAddress(safe), tx, agentSignature)
  return c.walletClient.writeContract({ address: safe, abi: safeAbi, functionName: 'execTransaction', args: execCalldataArgs(tx, signatures), account, ...extra })
}

/** Propose a Safe transaction through sayso's queue (for a watched Safe): signed by an owner, judged by the watcher.
 *  Nothing is executed; the proposal just becomes visible to sayso the way a Safe-app proposal is. */
export async function proposeSafeTx(apiUrl: string, apiKey: string, safe: Address, owner: { address: Address; signTypedData(args: any): Promise<Hex> }, call: { to: Address; data?: Hex; value?: bigint; nonce: bigint; operation?: number }, o?: CallOptions): Promise<{ safeTxHash: Hex; queued: boolean }> {
  const tx: SafeTx = { ...buildSafeTx(call), operation: call.operation ?? 0 }
  const signature = await owner.signTypedData({ domain: safeDomain(safe, await chainFor(apiUrl, o)), types: SAFE_TX_TYPES, primaryType: 'SafeTx', message: tx })
  const res = await (callOptions(o).fetch ?? fetch)(`${apiUrl.replace(/\/$/, '')}/safe/propose`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` }, body: JSON.stringify({ safeTx: safeTxToJson(tx), signature }) })
  const json = await res.json().catch(() => ({})) as any
  if (!res.ok) throw new Error(`sayso /safe/propose ${res.status}: ${json.error ?? 'request failed'}`)
  return json
}

/** What the watcher has said so far about a watched Safe's proposals. */
export async function watchVerdicts(apiUrl: string, apiKey: string, f: typeof fetch = fetch): Promise<Array<{ safeTxHash: Hex; verdict: string; reason: string; at: string }>> {
  const res = await f(`${apiUrl.replace(/\/$/, '')}/watch/verdicts`, { headers: { authorization: `Bearer ${apiKey}` } })
  if (!res.ok) throw new Error(`sayso /watch/verdicts ${res.status}`)
  return ((await res.json()) as any).verdicts
}
