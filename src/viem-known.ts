// What the SDK knows about viem (0.6.3, security desk 2026-10-25, F2 and F3). On a guarded viem client every function is
// one of: a checked or refused action of the SDK's own; one added later through the guarded `extend` (it was handed the
// guarded client); or one named below, which neither signs nor sends. Anything else (a new viem action, an add-on's
// method installed before guard()) is refused in enforce mode and reported in shadow mode until sayso knows it.
import { BaseError, createClient, custom, publicActions, walletActions } from 'viem'
import { erc7821Actions } from 'viem/experimental'
import { publicActionsL2 } from 'viem/op-stack'

/** The newest viem the SDK's tests ran on. Kept equal to the viem in package.json's devDependencies by a test; a newer
 *  installed viem gets one warning (its new functions are refused in enforce mode until sayso knows them). */
export const TESTED_VIEM = '2.57.10'

/** Functions that neither sign nor send, read in viem 2.57.10: the wallet client's own reads and wallet-UI calls, every
 *  public action except the two sends (`sendRawTransaction`, `sendRawTransactionSync`: the SDK's refused ones sit on top
 *  of them), the OP Stack L2 public actions (fee estimates on Base), and ERC-7821's mode query. They read through the
 *  node; on the guarded client nothing signs without passing the check. */
export const CLIENT_READS: ReadonlySet<string> = new Set([
  // wallet actions that do not sign or send (switchChain and addChain are not here: they change which chain a wallet
  // signs for, and are refused in enforce mode since 0.6.3, review 2026-10-27 M3)
  'fillTransaction', 'getAddresses', 'getCallsStatus', 'getCapabilities', 'getChainId', 'getPermissions',
  'prepareAuthorization', 'prepareTransactionRequest', 'requestAddresses', 'requestPermissions', 'showCallsStatus',
  'waitForCallsStatus', 'watchAsset',
  // public actions
  'call', 'createAccessList', 'createBlockFilter', 'createContractEventFilter', 'createEventFilter',
  'createPendingTransactionFilter', 'estimateContractGas', 'estimateFeesPerGas', 'estimateGas',
  'estimateMaxPriorityFeePerGas', 'getBalance', 'getBlobBaseFee', 'getBlock', 'getBlockNumber', 'getBlockReceipts',
  'getBlockTransactionCount', 'getBytecode', 'getCode', 'getContractEvents', 'getDelegation', 'getEip712Domain',
  'getEnsAddress', 'getEnsAvatar', 'getEnsName', 'getEnsResolver', 'getEnsText', 'getFeeHistory', 'getFilterChanges',
  'getFilterLogs', 'getGasPrice', 'getLogs', 'getProof', 'getRawTransaction', 'getStorageAt', 'getStorageValues',
  'getTransaction', 'getTransactionConfirmations', 'getTransactionCount', 'getTransactionReceipt', 'multicall',
  'readContract', 'simulate', 'simulateBlocks', 'simulateCalls', 'simulateContract', 'uninstallFilter', 'verifyHash',
  'verifyMessage', 'verifySiweMessage', 'verifyTypedData', 'waitForTransactionReceipt', 'watchBlockHeaders',
  'watchBlockNumber', 'watchBlocks', 'watchContractEvent', 'watchEvent', 'watchPendingTransactions',
  // OP Stack L2 public actions (viem/op-stack publicActionsL2): estimates and transaction builders, nothing signed
  'buildDepositTransaction', 'buildProveWithdrawal', 'estimateContractL1Fee', 'estimateContractL1Gas',
  'estimateContractTotalFee', 'estimateContractTotalGas', 'estimateInitiateWithdrawalGas', 'estimateL1Fee',
  'estimateL1Gas', 'estimateOperatorFee', 'estimateTotalFee', 'estimateTotalGas', 'getL1BaseFee',
  // ERC-7821 (viem/experimental erc7821Actions): asks the account which execution modes it supports
  'supportsExecutionMode',
])

/** The source text of viem's own functions under each name (its decorators are `(args) => action(client, args)`, the
 *  same text on every client), read once from a throwaway client of the installed viem. A function on a guarded client
 *  counts as one of CLIENT_READS only when it is viem's own under that name, so an add-on's method that happens to be
 *  called `simulate`, or an add-on's own `scope`, is not trusted by its name (review 2026-10-27, L1). */
let ownTexts: Map<string, Set<string>> | null = null
const textOf = (f: unknown): string => { try { return Function.prototype.toString.call(f) } catch { return '' } }
export function isViemOwn(name: string, fn: unknown): boolean {
  if (!ownTexts) {
    ownTexts = new Map()
    try {
      const c: any = createClient({ transport: custom({ request: async () => { throw new Error('reference client: no node') } }) })
      const sets = [c, publicActions(c), walletActions(c), publicActionsL2()(c), erc7821Actions()(c)]
      for (const o of sets) for (const [k, v] of Object.entries(o)) if (typeof v === 'function') { const t = ownTexts.get(k) ?? new Set<string>(); t.add(textOf(v)); ownTexts.set(k, t) }
    } catch { /* nothing is trusted by name: every CLIENT_READS function is then refused in enforce mode (fail closed) */ }
  }
  return typeof fn === 'function' && !!ownTexts.get(name)?.has(textOf(fn))
}

/** The viem version installed next to the SDK, as viem's own errors name it; null when it cannot be read. */
export function installedViem(): string | null {
  try { const v = String((new BaseError('version') as { version?: unknown }).version ?? ''); const m = v.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/); return m ? m[0] : null } catch { return null }
}

/** Is `installed` newer than `tested`? A pre-release of a newer version counts as newer; one of the same version does not. */
export function newerViem(installed: string, tested: string = TESTED_VIEM): boolean {
  const parse = (v: string) => { const m = v.match(/^(\d+)\.(\d+)\.(\d+)/); return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null }
  const a = parse(installed), b = parse(tested)
  if (!a || !b) return false
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i]
  return false
}

/** The warning for an installed viem newer than the newest the SDK was tested with; null when there is nothing to say. */
export function untestedViemWarning(installed: string | null): string | null {
  if (!installed || !newerViem(installed)) return null
  return `[sayso] viem ${installed} is newer than the newest viem this SDK was tested with (${TESTED_VIEM}). Wallet functions sayso does not know are refused (in shadow mode too) and reported; look for a newer saysoio (npm install saysoio@latest).`
}

let warned = false
/** One warning per process when the installed viem is newer than the newest the SDK was tested with. */
export function warnIfUntestedViem(warn: (message: string) => void = console.warn): void {
  if (warned) return
  const message = untestedViemWarning(installedViem())
  if (!message) return
  warned = true
  warn(message)
}
