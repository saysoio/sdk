// sayso SDK — wraps an agent's wallet so every transaction is checked against the owner's
// mandate BEFORE it is signed. Two modes: shadow (log only) and enforce (refuse on block, wait for
// the owner on ask). The owner switches the mode from the dashboard (step 5d); the SDK learns it from
// sayso's signed answer, and a builder may fix a floor in code that the switch can only raise.
// Fails closed by default: if the check API cannot be reached in enforce mode, nothing is signed. The SDK never sees or holds keys; it only decides whether a signing call proceeds.
import { encodeFunctionData, getAddress, isAddressEqual, parseEther, recoverAddress, verifyTypedData, type Address, type Hex } from 'viem'
import { OATHLINE_TYPES, oathlineDomain, strongerMode, txDigest, type CheckModeName, type ModeStatement, type VerdictReceipt } from './typed-data'
import { chainOf } from './chain'
import { OATHLINE_COSIGNERS, officialSigner } from './official'
import { safeTxHash, safeTxToJson, type SafeTx } from './safe'
import { GUARDED } from './owner'
import { SDK_VERSION } from './version'
import { CLIENT_READS, isViemOwn, warnIfUntestedViem } from './viem-known'

export * from './version'
export { TESTED_VIEM } from './viem-known'
export * from './typed-data'
export * from './chain'
export * from './official'
export * from './owner'
export * from './safe'
export * from './safe-agent'

export type Verdict = 'allow' | 'ask' | 'block'
export interface CheckResult { verdict: Verdict; reason: string; [k: string]: unknown }
export interface AgentContext { reason?: string; inputs?: string[] }
/** `nonce`: the position the SDK will sign with, when it could read it from the wallet's node. It is sent with the
 *  check and is part of the signed verdict, so sayso knows which allowed transactions are still ahead of the chain. */
export interface TxRequest { to: Address; data: Hex; value?: bigint; nonce?: number }
export type Decision = 'signed' | 'refused' | 'shadow'
/** an 'ask' that sayso has put to the owner on their own channel */
export interface PendingApproval { id: string; channel: string; expiresAt: number }

export interface OathlineOptions {
  /** sayso check API, e.g. http://127.0.0.1:3000 */
  apiUrl: string
  /** the agent's API key for its wallet (from registering the wallet). The rules themselves are NOT sent by the
   *  agent: the owner signs the mandate and sayso keeps it. */
  apiKey: string
  /** the address verdicts must be signed by. Leave it out for sayso's own servers: the SDK then trusts only
   *  sayso's signing address for the chain, which is built in (the server is never asked who its signer is).
   *  Name it only for your own or a local server. */
  signer?: Address
  /** Safe wallets: the address the co-signature must come from. Leave it out for sayso's own servers (built in);
   *  name it only for your own or a local server. */
  cosigner?: Address
  /** the chain the sayso server works on (8453 Base, 84532 Base Sepolia). If omitted it is learned from GET /health. */
  chainId?: number
  /** The LOWEST mode this agent runs in. Leave it out to let the owner decide: every wallet starts in shadow (verdicts
   *  are recorded, nothing is refused) until the owner turns enforce on from the dashboard, which the SDK learns from
   *  sayso's signed answer to its next check. 'enforce' here fixes enforce whatever the owner's switch says; the switch
   *  can raise 'shadow' to enforce, never lower 'enforce'. (Before 0.3.0, leaving it out meant enforce.) */
  mode?: CheckModeName
  /** enforce mode only: refuse to sign when the API is unreachable (default true) */
  failClosed?: boolean
  /** LOCAL owner-approval hook for 'ask', used only when the owner has no approval channel linked at sayso
   *  (it runs next to the agent, so it is weaker than the owner's own Telegram chat). Return true to proceed.
   *  Default: not approved. */
  onAsk?: (result: CheckResult, tx: TxRequest) => Promise<boolean>
  /** called when an 'ask' has been sent to the owner's chat and the SDK starts waiting for their answer */
  onWaiting?: (result: CheckResult, tx: TxRequest, approval: PendingApproval) => void
  /** how often to look for the owner's answer, ms (default 2000) */
  approvalPollMs?: number
  /** what the agent is thinking / has read right now — passed to the check as UNTRUSTED context */
  context?: () => AgentContext | undefined
  /**
   * Signature requests (typed data such as token permits and x402 payments, personal messages, raw hashes)
   * can move tokens without any transaction and cannot be simulated. Policy in enforce mode:
   * 'ask' (default) → the owner hook decides, refused if there is none; 'refuse' → never; 'allow' → sign.
   */
  signatures?: 'ask' | 'refuse' | 'allow'
  /** observer for every decision (audit log, metrics) */
  onDecision?: (result: CheckResult, tx: TxRequest, decision: Decision) => void
  /** how long one check may take, ms (default 20000; co-signing 60000). In shadow mode a slower check is skipped and the
   *  transaction goes ahead; in enforce mode it is refused (OathlineUnavailable), unless failClosed is false. Waiting
   *  for the owner's answer to an "ask" is not counted: that lasts until the request expires (about 10 minutes). */
  timeoutMs?: number
  fetch?: typeof fetch
}

export class OathlineBlocked extends Error {
  constructor(public result: CheckResult, public tx: TxRequest) { super(`sayso blocked this transaction: ${result.reason}`); this.name = 'OathlineBlocked' }
}
export class OathlineNeedsApproval extends Error {
  constructor(public result: CheckResult, public tx: TxRequest) { super(`sayso needs the owner's approval: ${result.reason}${result.ownerAnswer ? ` — ${result.ownerAnswer}` : ''}`); this.name = 'OathlineNeedsApproval' }
}
export class OathlineUnavailable extends Error {
  constructor(public cause: unknown, public tx: TxRequest) { super(`sayso check API unavailable; refusing to sign (fail closed): ${(cause as Error)?.message ?? cause}`); this.name = 'OathlineUnavailable' }
}
/** The server answered and said no (a 4xx with its reason: a wallet that gained code, a call into the wallet's own
 *  EIP-7702 code, no mandate, a wrong wallet or key). Not an outage: it becomes OathlineBlocked whatever `failClosed`
 *  says (security desk 2026-10-19 and 10-21, F2; since 0.6.0). */
class ServerRefusal extends Error {
  constructor(public status: number, public reason: string, public code?: string) { super(`check API ${status}: ${reason}`); this.name = 'ServerRefusal' }
}
/** An answer that does not verify (a receipt or mode statement not signed by sayso for this transaction, or no verdict
 *  at all): a forged "allow" must never sign, so the `failClosed: false` opt-out does not cover it (since 0.6.0). */
class VerificationFailure extends Error {
  constructor(message: string) { super(message); this.name = 'VerificationFailure' }
}

const ZERO: Address = '0x0000000000000000000000000000000000000000'

// EIP-7702 wallets (R5 part 2, review 2026-10-21 M1). On a wallet whose code is Uniswap's Calibur, one off-chain
// signature by the agent's key can run any batch of calls: a `SignedBatchedCall` under the wallet's own domain (anyone
// may submit it), a user operation through the ERC-4337 EntryPoint (a bundler runs it), a blind hash (which could be
// either), or an ERC-7739 wrapper around a permit. None of those ever reaches sayso's check, so on such a wallet the SDK
// refuses them outright, never asks. The names and addresses below were read from the verified sources on Base on
// 2026-10-21 (Calibur's EIP-712 domain is "Calibur" / "1.0.0" in both Base deployments; the EntryPoint v0.8 it trusts
// signs user operations under the domain "ERC4337"; ERC20ETH is the ERC-20 face of a Calibur wallet's ETH).
const CALIBUR_DOMAIN_NAME = 'Calibur'
const ENTRY_POINT_V08: Address = '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108'
const ERC20ETH: Address = '0x00000000e20E49e6dCeE6e8283A0C090578F0fb9'
// R5 part 3: ZeroDev's Kernel v3.3 (EIP-712 domain "Kernel" / "0.3.3" under the wallet's own address, also in a
// chain-agnostic form with chain id 0; its ERC-1271 wrapper type is `Kernel(bytes32 hash)` and its enable-mode type
// `Enable(...)`), built on the v0.7 EntryPoint, whose user-operation hash is not typed data: a Kernel wallet signs it as
// a PERSONAL MESSAGE over the 32-byte hash (`toEthSignedMessageHash(userOpHash)` in the verified source), so on an
// EIP-7702 wallet a personal message of exactly 32 bytes is refused too (read 2026-10-23, apps/api/src/wallet-code.ts).
const KERNEL_DOMAIN_NAME = 'Kernel'
const ENTRY_POINT_V07: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'
const HASH_MESSAGE_RISK = 'a personal signature over exactly 32 bytes: on an EIP-7702 wallet running Kernel that is how a user operation is authorised (the user-operation hash signed as a personal message), so a bundler could run any batch of calls as the wallet'
/** how long the SDK trusts what it learned about a wallet's kind (plain or EIP-7702) before asking again */
const WALLET_KIND_MS = 120_000
const isHexAddress = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v)
/** Why typed data would hand a relayer or bundler the whole of an EIP-7702 wallet; null when it is an ordinary message. */
function batchSignatureRisk(td: any, wallet: Address): string | null {
  const d = td?.domain ?? {}, primary = String(td?.primaryType ?? ''), types = td?.types && typeof td.types === 'object' ? Object.keys(td.types) : []
  const has = (...names: string[]) => names.includes(primary) || types.some(t => names.includes(t))
  const vc = isHexAddress(d.verifyingContract) ? getAddress(d.verifyingContract) : null
  if (vc && isAddressEqual(vc, wallet)) return 'typed data under the wallet\'s own domain (a batch of calls, a key, module or setting change that anyone could then submit)'
  if (String(d.name ?? '') === CALIBUR_DOMAIN_NAME || has('SignedBatchedCall', 'BatchedCall')) return 'a signed batch of calls for the wallet\'s Calibur code, which anyone could then submit'
  if (String(d.name ?? '') === KERNEL_DOMAIN_NAME || has('Enable', 'Kernel')) return 'typed data for the wallet\'s Kernel code (a module enabled by signature, or a wrapped signature), which anyone could then submit'
  if (has('TypedDataSign', 'PersonalSign')) return 'an ERC-7739 wrapped signature (a permission hidden one level down)'
  if (String(d.name ?? '') === 'ERC4337' || (vc && (isAddressEqual(vc, ENTRY_POINT_V08) || isAddressEqual(vc, ENTRY_POINT_V07))) || has('PackedUserOperation', 'UserOperation')) return 'a user operation, with which a bundler would run any batch of calls as the wallet'
  return null
}
/** the byte length of a personal message as it would be signed: text as UTF-8, `{ raw }` or bytes as they are; null when unknown */
function messageBytes(m: unknown): number | null {
  if (typeof m === 'string') return new TextEncoder().encode(m).length
  if (m instanceof Uint8Array) return m.length
  if (m && typeof m === 'object' && 'raw' in (m as Record<string, unknown>)) {
    const r = (m as { raw: unknown }).raw
    if (typeof r === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(r)) return (r.length - 2) / 2
    if (r instanceof Uint8Array) return r.length
  }
  return null
}
/** the token a signed message is about, when it names one (Permit2's details.token, a token permit's own contract) */
const typedDataToken = (td: any): Address | null => { const m = td?.message ?? {}; const t = m.details?.token ?? m.token ?? td?.domain?.verifyingContract; return isHexAddress(t) ? getAddress(t) : null }

// Coinbase CDP (step 5f part 2, R2). AgentKit's CdpEvmWalletProvider hands out its raw CDP client (`getClient()`), and
// AgentKit's own swap and spend-permission actions sign through it (`account.swap`, `account.useSpendPermission`), never
// through the provider's sendTransaction. On a wrapped provider the client is wrapped too: lookups pass; anything else
// is a call sayso cannot check yet (refused in enforce mode, reported in shadow mode). Deny by default: a method not
// named here is treated as one that can move money.
/** CDP client `evm` methods that only read (or bring test money in) */
const CDP_EVM_READ = new Set(['getSwapPrice', 'listSpendPermissions', 'listTokenBalances', 'getUserOperation', 'waitForUserOperation', 'getEvmEip7702DelegationOperationById', 'waitForEvmEip7702DelegationOperationStatus', 'requestFaucet'])
/** CDP client `evm` methods that return accounts: the accounts come back wrapped */
const CDP_EVM_ACCOUNTS = new Set(['getAccount', 'getOrCreateAccount', 'listAccounts', 'createAccount', 'getSmartAccount', 'getOrCreateSmartAccount', 'listSmartAccounts', 'createSmartAccount'])
/** CDP account methods that only read (or bring test money in) */
const CDP_ACCOUNT_READ = new Set(['listTokenBalances', 'requestFaucet', 'getUserOperation', 'waitForUserOperation', 'listSpendPermissions', 'waitForTransactionReceipt'])
/** a field of an exported wallet that would let someone sign for the wallet without the guard */
const SECRET_FIELD = /private|secret|mnemonic|seed|authori[sz]ation.*key/i
const holdsSecret = (o: unknown): boolean => !!o && typeof o === 'object' && Object.entries(o as Record<string, unknown>).some(([k, v]) => SECRET_FIELD.test(k) && typeof v === 'string' && v.length > 0)
/** Provider methods that are private only in TypeScript and reach the provider's API directly (AgentKit 0.10's Privy
 *  embedded-wallet provider: a raw eth_sendTransaction, and the app secret with a valid authorization signature).
 *  Refused in enforce mode, reported in shadow mode (review 2026-10-19, H1). */
const PROVIDER_RAW_DOORS = new Set(['executePrivyRequest', 'getPrivyHeaders', 'generatePrivySignature'])
/** AgentKit 0.10's `nativeTransfer(to, value)` takes wei as a whole-number string (every provider does BigInt(value));
 *  a decimal string is read as ETH, as before (review 2026-10-19, M1: a wei amount was checked as ETH). */
const nativeAmount = (value: string): bigint => (/^\d+$/.test(String(value).trim()) ? BigInt(String(value).trim()) : parseEther(String(value)))
const addressIn = (a: any): Address => (typeof a?.to === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a.to) ? getAddress(a.to) : ZERO)

function describeTypedData(td: any): string {
  const type = td?.primaryType ?? 'unknown type', domain = td?.domain?.name ?? 'unknown domain'
  const m = td?.message ?? {}
  const who = m.spender ?? m.to ?? m.operator ?? m.delegate ?? null
  const token = typedDataToken(td)
  return `${type} for ${domain}${who ? `, in favour of ${who}` : ''}${token && isAddressEqual(token, ERC20ETH) ? ' (the token is ERC20ETH: on an EIP-7702 wallet this is the wallet\'s own ETH)' : ''}`
}
/** whom a signed message favours (the spender, recipient or operator it names), as an address, else the zero address */
const typedDataCounterparty = (td: any): Address => { const m = td?.message ?? {}; return addressIn({ to: m.spender ?? m.to ?? m.operator ?? m.delegate }) }

/** Proxy traps that refuse every write: a write through a guarded object would reach the raw one, and a property made
 *  non-configurable would then read raw through its descriptor (review 2026-10-23, H2 and M1). */
const NO_WRITES = { defineProperty: () => false, deleteProperty: () => false, preventExtensions: () => false, setPrototypeOf: () => false } as const

export class Oathline {
  private readonly floor: CheckModeName
  private readonly failClosed: boolean
  /** the owner's switch as sayso last signed it for this wallet: kept for when sayso cannot be reached, and never
   *  replaced by a statement older than it (setAt is when the owner signed the change) */
  private ownerMode: { mode: CheckModeName; setAt: number } | null = null
  constructor(private readonly opts: OathlineOptions) {
    if (opts.mode !== undefined && opts.mode !== 'shadow' && opts.mode !== 'enforce') throw new Error(`mode must be 'shadow' or 'enforce' (got ${String(opts.mode)})`)
    this.floor = opts.mode ?? 'shadow'
    this.failClosed = opts.failClosed ?? true
    warnIfUntestedViem()   // once per process, when the installed viem is newer than the newest the SDK was tested with (0.6.3)
  }

  /** The mode in force now: the higher of the floor fixed in code and the owner's switch as last seen (shadow until
   *  sayso has answered once, unless the floor is enforce). */
  get mode(): CheckModeName { return strongerMode(this.floor, this.ownerMode?.mode ?? 'shadow') }
  /** The mode for decisions taken WITHOUT a fresh answer from sayso (sayso unreachable, signature requests): the last
   *  mode seen; before any, the mode the builder wrote in code, and when they wrote none (the owner decides) enforce,
   *  because the owner's switch may be on (review 2026-10-15, H1/H2). */
  private get modeWithoutAnswer(): CheckModeName { return this.ownerMode ? this.mode : this.opts.mode ?? 'enforce' }

  private signerAddress: Address | undefined

  /** What the SDK knows about a wallet's kind (R5 part 2): an EIP-7702 wallet refuses more. Learned from every check
   *  answer (`walletKind`), from GET /wallets/:wallet, and from the wallet's own node (an `0xef0100…` code). */
  private readonly walletKinds = new Map<string, { delegated: boolean; at: number }>()
  private learnKind(wallet: Address, kind: unknown): void {
    if (kind === 'delegated' || kind === 'plain' || kind === 'safe') this.walletKinds.set(wallet.toLowerCase(), { delegated: kind === 'delegated', at: Date.now() })
  }
  /** Is this an EIP-7702 wallet? The server's word or the node's code, whichever says so first; what was learned is
   *  kept for two minutes. When neither can be read, the last answer counts, and before any, a plain wallet (the
   *  signature policy then applies, as it did before 0.6.0). */
  private async isDelegated(wallet: Address, code?: () => Promise<unknown>): Promise<boolean> {
    const k = wallet.toLowerCase(), hit = this.walletKinds.get(k)
    if (hit && Date.now() - hit.at < WALLET_KIND_MS) return hit.delegated
    const f = this.opts.fetch ?? fetch
    const [server, node] = await Promise.all([
      f(`${this.opts.apiUrl.replace(/\/$/, '')}/wallets/${getAddress(wallet)}`, { signal: AbortSignal.timeout(Math.min(this.opts.timeoutMs ?? 20000, 5000)) })
        .then(async r => { const j = r.ok ? await r.json() as { kind?: unknown } : null; return j?.kind === 'delegated' ? true : j?.kind === 'plain' || j?.kind === 'safe' ? false : null }).catch(() => null),
      code ? code().then(c => (typeof c === 'string' && c !== '0x' ? /^0xef0100[0-9a-fA-F]{40}$/i.test(c) : c === '0x' ? false : null)).catch(() => null) : Promise.resolve(null),
    ])
    if (server === null && node === null) return hit?.delegated ?? false
    const delegated = server === true || node === true
    this.walletKinds.set(k, { delegated, at: Date.now() })
    return delegated
  }

  /** The chain this sayso server works on. Verdicts and Safe signatures are only ever valid for that chain. */
  chainId(): Promise<number> { return this.opts.chainId !== undefined ? Promise.resolve(this.opts.chainId) : chainOf(this.opts.apiUrl, this.opts.fetch ?? fetch) }

  /** Raw check: ask the API what it thinks of this transaction. Throws on transport/API errors and on any
   *  verdict that is not properly signed by sayso for exactly this transaction. */
  async check(wallet: Address, tx: TxRequest): Promise<CheckResult> { return (await this.checkWithMode(wallet, tx)).result }

  /** The check, and the mode sayso stated for exactly this transaction: the policy for it follows that statement, not
   *  whatever another check running at the same time learned meanwhile (review 2026-10-15, M3). */
  private async checkWithMode(wallet: Address, tx: TxRequest): Promise<{ result: CheckResult; txMode: CheckModeName }> {
    const f = this.opts.fetch ?? fetch
    const base = this.opts.apiUrl.replace(/\/$/, '')
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 20000)
    try {
      const res = await f(`${base}/check`, {
        method: 'POST', signal: ctrl.signal, headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.apiKey}` },
        body: JSON.stringify({ wallet, tx: { to: tx.to, data: tx.data, value: tx.value !== undefined ? tx.value.toString() : undefined, nonce: tx.nonce }, agent: this.opts.context?.(), modeFloor: this.floor, sdk: SDK_VERSION, ...(this.mode === 'shadow' ? { shadow: true } : {}) }),
      })
      if (!res.ok) {
        // The server's own no (a 4xx with a reason in JSON) is a refusal, not an outage. An answer that says "try
        // again" (429, or any answer with retry-after) and every 5xx is an outage, like a server that does not answer.
        const text = (await res.text()).slice(0, 400)
        let body: any = null; try { body = JSON.parse(text) } catch { /* not JSON: an outage */ }
        const tryLater = res.status === 429 || res.status === 408 || res.headers.get('retry-after') !== null
        if (res.status >= 400 && res.status < 500 && !tryLater && body && typeof body.error === 'string') throw new ServerRefusal(res.status, body.error.slice(0, 300), typeof body.code === 'string' ? body.code.slice(0, 40) : undefined)
        throw new Error(`check API ${res.status}: ${text.slice(0, 200)}`)
      }
      const json = await res.json() as CheckResult & { receipt?: VerdictReceipt }
      if (!['allow', 'ask', 'block'].includes(json?.verdict)) throw new VerificationFailure('check API returned no verdict')
      this.learnKind(wallet, (json as { walletKind?: unknown }).walletKind)

      try {
        // The verdict must be signed by sayso, for this wallet, this exact transaction, and still be fresh.
        await this.verifyReceipt(json.receipt, json.verdict, wallet, tx, ctrl.signal)
        // The owner's mode (step 5d), when the server sends it: signed by sayso for this exact transaction. A statement
        // that does not verify fails the whole check; a server that sends none (older than 0.3.0) leaves the mode as it was.
        // sayso's own servers always send one (review 2026-10-15, M2: an answer stripped of it must not keep the agent in shadow)
        const ms = (json as { mode?: unknown }).mode
        if (ms !== undefined && ms !== null) return { result: json, txMode: await this.acceptMode(ms as ModeStatement, wallet, tx) }
        if (!this.opts.signer) throw new Error('the answer carries no signed mode (a sayso server older than SDK 0.3.0?)')
        return { result: json, txMode: this.mode }
      } catch (e) { throw e instanceof VerificationFailure ? e : new VerificationFailure((e as Error).message) }
    } finally { clearTimeout(t) }
  }

  private async verifyReceipt(r: VerdictReceipt | undefined | null, verdict: string, wallet: Address, tx: TxRequest, signal?: AbortSignal): Promise<void> {
    if (!r) throw new Error('verdict has no signed receipt')
    const chainId = await this.chainId()
    // whose signature counts: the address the caller named, otherwise sayso's own for this chain (built in, never asked from the server)
    this.signerAddress ??= this.opts.signer ? getAddress(this.opts.signer) : officialSigner(chainId)
    if (r.verdict !== verdict) throw new Error('receipt verdict does not match the response')
    if (getAddress(r.wallet) !== getAddress(wallet) || r.txDigest !== txDigest({ wallet, ...tx }, chainId)) throw new Error('receipt is for a different transaction')
    if (r.expiresAt <= Math.floor(Date.now() / 1000)) throw new Error('receipt has expired')
    const ok = await verifyTypedData({ address: this.signerAddress, domain: oathlineDomain(chainId), types: OATHLINE_TYPES, primaryType: 'Verdict',
      message: { wallet: getAddress(r.wallet), txDigest: r.txDigest, mandateId: r.mandateId, verdict: r.verdict, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) }, signature: r.signature }).catch(() => false)
    if (!ok) throw new Error('receipt signature is not from sayso')
  }

  /** Verifies the statement, remembers it if it is the newest seen, and returns the mode for this transaction: the
   *  statement's own, or, when an older statement arrives after a newer one, the stronger of the two (it can only raise). */
  private async acceptMode(m: ModeStatement, wallet: Address, tx: TxRequest): Promise<CheckModeName> {
    const chainId = await this.chainId()
    this.signerAddress ??= this.opts.signer ? getAddress(this.opts.signer) : officialSigner(chainId)
    if (!m || typeof m !== 'object' || (m.mode !== 'shadow' && m.mode !== 'enforce') || !Number.isSafeInteger(m.setAt) || m.setAt < 0 || !Number.isSafeInteger(m.expiresAt)) throw new Error('mode statement is malformed')
    if (typeof m.wallet !== 'string' || getAddress(m.wallet) !== getAddress(wallet) || m.txDigest !== txDigest({ wallet, ...tx }, chainId)) throw new Error('mode statement is for a different transaction')
    if (m.expiresAt <= Math.floor(Date.now() / 1000)) throw new Error('mode statement has expired')
    const ok = await verifyTypedData({ address: this.signerAddress, domain: oathlineDomain(chainId), types: OATHLINE_TYPES, primaryType: 'ModeStatement',
      message: { wallet: getAddress(m.wallet), txDigest: m.txDigest, mode: m.mode, setAt: BigInt(m.setAt), expiresAt: BigInt(m.expiresAt) }, signature: m.signature }).catch(() => false)
    if (!ok) throw new Error('mode statement signature is not from sayso')
    // never step back to an older switch (a replayed statement); an equal one is the same switch seen again
    const older = !!this.ownerMode && m.setAt < this.ownerMode.setAt
    const stated = older ? strongerMode(m.mode, this.ownerMode!.mode) : m.mode
    if (!older) this.ownerMode = { mode: m.mode, setAt: m.setAt }
    return strongerMode(this.floor, stated)
  }

  /** Wait for the owner's answer on their own channel. True only with a signed allow for exactly this transaction. */
  private async waitForOwner(wallet: Address, tx: TxRequest, approval: PendingApproval): Promise<{ approved: boolean; note: string }> {
    const f = this.opts.fetch ?? fetch
    const url = `${this.opts.apiUrl.replace(/\/$/, '')}/approvals/${approval.id}`
    while (Date.now() / 1000 < approval.expiresAt + 30) {
      try {
        const res = await f(url, { headers: { authorization: `Bearer ${this.opts.apiKey}` }, signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20000) })
        if (res.status === 404 || res.status === 401) return { approved: false, note: 'the approval request is no longer known to sayso' }
        if (res.ok) {
          const a = await res.json() as { status: string; note?: string | null; receipt?: VerdictReceipt | null }
          if (a.status === 'approved') { await this.verifyReceipt(a.receipt, 'allow', wallet, tx); return { approved: true, note: `approved by the owner on ${approval.channel}` } }
          if (a.status !== 'pending') return { approved: false, note: a.status === 'rejected' ? `rejected by the owner on ${approval.channel}` : a.status === 'expired' ? 'the owner did not answer in time' : `not approved (${a.note ?? a.status})` }
        }
      } catch (e) {
        if (/receipt/.test((e as Error).message)) return { approved: false, note: `approval could not be verified: ${(e as Error).message}` }
        // network hiccup: keep waiting until the request expires
      }
      await new Promise(r => setTimeout(r, this.opts.approvalPollMs ?? 2000))
    }
    return { approved: false, note: 'the owner did not answer in time' }
  }

  /** The chain the wallet itself is on must be the chain the server answers for. A server (or whoever holds its web
   *  address) that claims another chain would otherwise choose which of sayso's keys the SDK expects. */
  private async sameChain(walletChain: number | undefined): Promise<void> {
    if (walletChain === undefined || !Number.isInteger(walletChain)) return
    const serverChain = await this.chainId()
    if (serverChain !== walletChain) throw new Error(`this wallet is on chain ${walletChain} but the sayso server answers for chain ${serverChain}`)
  }

  /** Check + policy. Resolves when signing may proceed; throws otherwise (enforce mode).
   *  walletChain: the chain the wallet is on, when the caller knows it (the guards pass it). */
  async gate(wallet: Address, tx: TxRequest, walletChain?: number): Promise<CheckResult> {
    let result: CheckResult, mode: CheckModeName
    try { await this.sameChain(walletChain); ({ result, txMode: mode } = await this.checkWithMode(wallet, tx)) } catch (e) {
      // The server said no: a block in the agent's hands, whatever failClosed says. Shadow mode stops nothing, so there
      // the call goes ahead and sayso is told, like any other call it could not check (the owner sees "would have blocked").
      if (e instanceof ServerRefusal) {
        // the server's own word that the wallet runs code counts as learning its kind (review 2026-10-22, M1): the signature paths refuse from here on
        if (e.code === 'wallet-has-code' || e.code === 'wallet-code-refused') this.walletKinds.set(wallet.toLowerCase(), { delegated: true, at: Date.now() })
        result = { verdict: 'block', reason: `refused by sayso (check API ${e.status}): ${e.reason}`, ...(e.code ? { code: e.code } : {}) }
        if (this.modeWithoutAnswer === 'shadow') { this.opts.onDecision?.(result, tx, 'shadow'); this.report(`refused by sayso${e.code ? ` (${e.code})` : ''}`, e.reason, tx); return result }
        this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineBlocked(result, tx)
      }
      // no answer: the last mode seen, or enforce while the owner's switch has not been seen yet (it may be on). An
      // answer that does not verify is refused even under the opt-out: it could be a forged allow.
      if (this.modeWithoutAnswer === 'enforce' && (this.failClosed || e instanceof VerificationFailure)) {
        this.opts.onDecision?.({ verdict: 'block', reason: `check unavailable: ${(e as Error).message}` }, tx, 'refused')
        throw new OathlineUnavailable(e, tx)
      }
      result = { verdict: 'allow', reason: `sayso unavailable (${(e as Error).message}); proceeding because mode=${this.modeWithoutAnswer}, failClosed=${this.failClosed}` }
      this.opts.onDecision?.(result, tx, 'shadow'); return result
    }
    if (mode === 'shadow') { this.opts.onDecision?.(result, tx, 'shadow'); return result }
    if (result.verdict === 'allow') { this.opts.onDecision?.(result, tx, 'signed'); return result }
    if (result.verdict === 'ask') {
      // Held on the position side (an earlier allowed call to the owner's contracts not yet on the chain, or no pinned
      // position): nobody's to approve here, neither the owner's chat nor the local hook; the agent asks again later.
      const rules = Array.isArray((result as any).rules) ? (result as any).rules as Array<{ id?: string; reason?: string }> : []
      const held = rules.find(r => r?.id === 'position-pending' || r?.id === 'position-unknown')
      if (held) { result = { ...result, ownerAnswer: `held on the position side (${held.reason ?? held.id}); not approvable here, ask again once the chain has caught up` }; this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineNeedsApproval(result, tx) }
      // The owner's own channel (linked by the owner's signature at sayso) decides when there is one;
      // the local hook is only the fallback for wallets without a channel.
      const approval = (result as { approval?: PendingApproval | { id: null; note: string } | null }).approval
      if (approval?.id) {
        this.opts.onWaiting?.(result, tx, approval)
        const answer = await this.waitForOwner(wallet, tx, approval)
        result = { ...result, ownerAnswer: answer.note }
        if (answer.approved) { this.opts.onDecision?.(result, tx, 'signed'); return result }
        this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineNeedsApproval(result, tx)
      }
      if (approval && approval.id === null) { result = { ...result, ownerAnswer: approval.note }; this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineNeedsApproval(result, tx) }
      const ok = this.opts.onAsk ? await this.opts.onAsk(result, tx) : false
      if (ok) { this.opts.onDecision?.(result, tx, 'signed'); return result }
      this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineNeedsApproval(result, tx)
    }
    this.opts.onDecision?.(result, tx, 'refused'); throw new OathlineBlocked(result, tx)
  }

  /**
   * For a wallet that is a 2-of-3 Safe with sayso as co-signer: ask sayso for the second signature on this
   * exact Safe transaction. Resolves with both signatures packed for execTransaction; throws like gate() otherwise.
   * An "ask" waits for the owner on their own channel. There is no shadow mode here: without sayso's
   * signature the Safe does not move.
   */
  async cosign(safe: Address, tx: SafeTx, agentSignature: Hex): Promise<{ signatures: Hex; signature: Hex; cosigner: Address; result: CheckResult }> {
    const f = this.opts.fetch ?? fetch
    const inner: TxRequest = { to: tx.to, data: tx.data, value: tx.value }
    const call = async (approvalId?: string): Promise<any> => {
      const res = await f(`${this.opts.apiUrl.replace(/\/$/, '')}/cosign`, { method: 'POST', signal: AbortSignal.timeout(this.opts.timeoutMs ?? 60000), headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.apiKey}` },
        body: JSON.stringify({ safeTx: safeTxToJson(tx), signature: agentSignature, agent: this.opts.context?.(), ...(approvalId ? { approvalId } : {}) }) })
      if (!res.ok) throw new Error(`co-sign API ${res.status}: ${(await res.text()).slice(0, 200)}`)
      return res.json()
    }
    const accept = async (j: any): Promise<{ signatures: Hex; signature: Hex; cosigner: Address; result: CheckResult }> => {
      // sayso's signed allow must name this transaction, and its Safe signature must really be over this Safe transaction
      await this.verifyReceipt(j.receipt, 'allow', safe, inner)
      const who = await recoverAddress({ hash: safeTxHash(safe, tx, await this.chainId()), signature: j.signature }).catch(() => null)
      if (!who || !isAddressEqual(who, j.cosigner)) throw new Error('the co-signature is not over this Safe transaction')
      const chainId = await this.chainId()
      const expected = this.opts.cosigner ?? OATHLINE_COSIGNERS[chainId]
      if (!expected) throw new Error(`no sayso co-signer is known for chain ${chainId}; name it with \`cosigner\``)
      if (!isAddressEqual(who, expected)) throw new Error('the co-signature is not from sayso\'s co-signer key')
      return { signatures: j.signatures, signature: j.signature, cosigner: getAddress(j.cosigner), result: j }
    }
    let j: any
    try {
      j = await call()
      if (!['allow', 'ask', 'block'].includes(j?.verdict)) throw new Error('co-sign API returned no verdict')
      if (j.verdict === 'allow' && j.cosigned) { const out = await accept(j); this.opts.onDecision?.(j, inner, 'signed'); return out }
    } catch (e) {
      this.opts.onDecision?.({ verdict: 'block', reason: `co-signer unavailable: ${(e as Error).message}` }, inner, 'refused')
      throw new OathlineUnavailable(e, inner)
    }
    let result: CheckResult = j
    if (j.verdict === 'ask' && j.approval?.id) {
      this.opts.onWaiting?.(result, inner, j.approval)
      const answer = await this.waitForOwner(safe, inner, j.approval)
      result = { ...result, ownerAnswer: answer.note }
      if (answer.approved) {
        try { const out = await accept(await call(j.approval.id)); this.opts.onDecision?.(result, inner, 'signed'); return { ...out, result } }
        catch (e) { result = { ...result, ownerAnswer: `${answer.note}, but the co-signature could not be obtained: ${(e as Error).message}` } }
      }
    } else if (j.verdict === 'ask' && j.approval?.note) result = { ...result, ownerAnswer: j.approval.note }
    this.opts.onDecision?.(result, inner, 'refused')
    if (j.verdict === 'ask') throw new OathlineNeedsApproval(result, inner)
    throw new OathlineBlocked(result, inner)
  }

  /** EIP-7702: an authorization lets the wallet run other code, which is how a wallet is taken over. It is never signed
   *  (there is no owner hook: an agent has no legitimate use for it), unless the builder chose shadow in code AND the
   *  mode is known to be shadow: then it is logged as a block, reported to sayso and goes ahead, as before 0.3.0.
   *  Leaving `mode` out never lets one through (review 2026-10-15, H1). */
  private async gateAuthorization(detail: string, tx: TxRequest): Promise<void> {
    const result: CheckResult = { verdict: 'block', reason: `EIP-7702 authorization (${detail}): the wallet would run other code, which is how a wallet is taken over; sayso never signs that` }
    if (this.opts.mode === 'shadow' && this.modeWithoutAnswer === 'shadow') { this.opts.onDecision?.(result, tx, 'shadow'); this.report('EIP-7702 authorization', detail, tx); return }
    this.opts.onDecision?.(result, tx, 'refused')
    throw new OathlineBlocked(result, tx)
  }

  /** Calls sayso cannot check yet (since 0.4.0): a batch of calls (EIP-5792 `sendCalls`), an already signed
   *  transaction (`sendRawTransaction`), a raw JSON-RPC send, a contract deployment. In enforce mode they are refused
   *  (fail closed; until R5 and R9 teach the check to read them); in shadow mode they go ahead and sayso is told, so the
   *  owner sees "would have blocked" instead of nothing. Decided like a signature request: on the last mode seen, and
   *  on enforce while the owner's switch is not known yet. */
  private async gateUnchecked(kind: string, detail: string, tx: TxRequest): Promise<void> {
    const result: CheckResult = { verdict: 'block', reason: `${kind}${detail ? ` (${detail})` : ''}: sayso cannot check this kind of call yet, so it is refused in enforce mode` }
    if (this.modeWithoutAnswer === 'shadow') { this.opts.onDecision?.(result, tx, 'shadow'); this.report(kind, detail, tx); return }
    this.opts.onDecision?.(result, tx, 'refused')
    throw new OathlineBlocked(result, tx)
  }
  /** The same rule, for a call that must answer at once (a key export): refused in enforce mode, reported in shadow. */
  private gateUncheckedNow(kind: string, detail: string, tx: TxRequest): void {
    const result: CheckResult = { verdict: 'block', reason: `${kind}${detail ? ` (${detail})` : ''}: it would let the wallet sign without sayso, so it is refused in enforce mode` }
    if (this.modeWithoutAnswer === 'shadow') { this.opts.onDecision?.(result, tx, 'shadow'); this.report(kind, detail, tx); return }
    this.opts.onDecision?.(result, tx, 'refused')
    throw new OathlineBlocked(result, tx)
  }

  /** A function on a guarded viem client that the SDK does not know (0.6.3, security desk 2026-10-25, F2): a new viem
   *  action, or an add-on's method installed before guard(), which holds the raw client. Refused in enforce mode, reported
   *  as "would have blocked" in shadow mode; decided like the other calls sayso cannot check (the last mode seen, and
   *  enforce while the owner's switch is not known yet). Returns the refusal, or null when the call may go ahead. */
  private unknownFunction(name: string): OathlineBlocked | null {
    const tx: TxRequest = { to: ZERO, data: '0x' }
    const result: CheckResult = { verdict: 'block', reason: `${name}: this wallet function is not one sayso knows; it is refused in enforce mode until sayso supports it` }
    if (this.modeWithoutAnswer === 'shadow') {
      this.opts.onDecision?.(result, tx, 'shadow')
      // told to sayso once per function every 10 minutes, so a helper polled in a loop does not flood the owner's log and chat (review 2026-10-27, L3)
      const last = this.unknownReported.get(name) ?? 0
      if (Date.now() - last > 600_000) { this.unknownReported.set(name, Date.now()); this.report(`unknown wallet function (${name})`, '', tx) }
      return null
    }
    this.opts.onDecision?.(result, tx, 'refused')
    return new OathlineBlocked(result, tx)
  }
  private readonly unknownReported = new Map<string, number>()

  /** A CDP client (`getClient()` on AgentKit's CDP provider), wrapped: see CDP_EVM_READ above. */
  private guardCdpClient(raw: any): any {
    const self = this
    const gated = (kind: string, fn: (...a: any[]) => any, thisArg: any) => async (...a: any[]) => { await self.gateUnchecked(kind, '', { to: addressIn(a[0]), data: '0x' }); return fn.apply(thisArg, a) }
    const account = (acc: any): any => (!acc || typeof acc !== 'object' ? acc : new Proxy(acc, {
      ...NO_WRITES,
      getOwnPropertyDescriptor(t, p) { const d = Reflect.getOwnPropertyDescriptor(t, p); return d && 'value' in d && d.configurable ? { ...d, value: this.get!(t, p, t) } : d },
      get(t, p) {
        const v = Reflect.get(t, p, t)
        if (typeof p !== 'string' || typeof v !== 'function') return v
        if (CDP_ACCOUNT_READ.has(p)) return v.bind(t)
        if (p === 'useNetwork') return async (...a: any[]) => account(await v.apply(t, a))   // a network-scoped account
        return gated(`CDP account.${p}`, v, t)
      },
    }))
    const accounts = (r: any): any => (r && typeof r === 'object' && Array.isArray(r.accounts) ? { ...r, accounts: r.accounts.map(account) } : account(r))
    const space = (obj: any, path: string): any => new Proxy(obj, {
      // a property read through its descriptor is wrapped the same way (review M3); non-configurable ones cannot be
      ...NO_WRITES,
      getOwnPropertyDescriptor(t, p) { const d = Reflect.getOwnPropertyDescriptor(t, p); return d && 'value' in d && d.configurable ? { ...d, value: this.get!(t, p, t) } : d },
      get(t, p) {
        const v = Reflect.get(t, p, t)
        if (typeof p !== 'string') return v
        if (typeof v === 'function') {
          if (path === 'evm' && CDP_EVM_READ.has(p)) return v.bind(t)
          if (path === 'evm' && CDP_EVM_ACCOUNTS.has(p)) return async (...a: any[]) => accounts(await v.apply(t, a))
          return gated(`CDP client ${path ? `${path}.` : ''}${p}`, v, t)
        }
        return v && typeof v === 'object' ? space(v, path ? `${path}.${p}` : p) : v
      },
    })
    return raw && typeof raw === 'object' ? space(raw, '') : raw
  }

  /** Tells sayso what went ahead unchecked in shadow mode (POST /unchecked, with the API key), with the verdict the
   *  SDK would have given in enforce mode (block, or ask for a signature request under the 'ask' policy). Best effort:
   *  it never delays or fails the agent's call, and it carries no more than the kind of call, a short detail and the address. */
  private report(kind: string, detail: string, tx: TxRequest, verdict: 'ask' | 'block' = 'block'): void {
    const f = this.opts.fetch ?? fetch
    try {
      void f(`${this.opts.apiUrl.replace(/\/$/, '')}/unchecked`, { method: 'POST', signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20000), headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.apiKey}` }, body: JSON.stringify({ kind: kind.slice(0, 80), ...(detail ? { detail: detail.slice(0, 200) } : {}), ...(tx.to !== ZERO ? { to: tx.to } : {}), verdict }) }).catch(() => undefined)
    } catch { /* the record is best effort */ }
  }

  /** Gate for anything that produces a signature without a transaction. Resolves when signing may proceed. In shadow
   *  mode it signs and tells sayso what the policy would have done ("would have asked" / "would have blocked"), so the
   *  one class of request the check cannot simulate is on the owner's record too (security desk 2026-10-21, F3);
   *  under `signatures: 'allow'` there is nothing to report. `ctx.to`: whom the message favours, for the record. */
  async gateSignature(kind: string, detail: string, ctx: { to?: Address; wallet?: Address; typedData?: unknown; raw?: boolean; message?: unknown; code?: () => Promise<unknown> } = {}): Promise<void> {
    const result: CheckResult = { verdict: 'ask', reason: `signature request (${kind}: ${detail}) — a signature can move tokens without a transaction and cannot be simulated` }
    const tx: TxRequest = { to: ctx.to ?? ZERO, data: '0x' }
    const policy = this.opts.signatures ?? 'ask'
    // EIP-7702 wallets (review 2026-10-21, M1): a blind hash, or typed data that is a batch, a user operation or an
    // ERC-7739 wrapper, hands whoever holds the signature the whole wallet. Refused outright on such a wallet, in
    // every mode but shadow (where it is signed and reported as "would have blocked"); no policy and no hook applies.
    // Part 3: so is a personal message of exactly 32 bytes (a Kernel user-operation hash; any other length cannot be one).
    const risk = ctx.wallet && isHexAddress(ctx.wallet) ? (ctx.raw ? 'a blind signature over a hash, which could be a user operation or a signed batch that moves everything' : ctx.typedData !== undefined ? batchSignatureRisk(ctx.typedData, getAddress(ctx.wallet)) : ctx.message !== undefined && messageBytes(ctx.message) === 32 ? HASH_MESSAGE_RISK : null) : null
    if (risk && (await this.isDelegated(getAddress(ctx.wallet!), ctx.code))) {
      const refused: CheckResult = { verdict: 'block', reason: `signature request (${kind}: ${detail}) on an EIP-7702 wallet: ${risk}; sayso cannot check it, so it is never signed` }
      if (this.modeWithoutAnswer === 'shadow') { this.opts.onDecision?.(refused, tx, 'shadow'); this.report('signature request on an EIP-7702 wallet', `${kind}: ${detail}; ${risk}`, tx, 'block'); return }
      this.opts.onDecision?.(refused, tx, 'refused')
      throw new OathlineBlocked(refused, tx)
    }
    // no transaction check here: the last mode seen decides, and enforce while the owner's switch is not known yet
    if (this.modeWithoutAnswer === 'shadow') {
      this.opts.onDecision?.(result, tx, 'shadow')
      if (policy !== 'allow') this.report('signature request', `${kind}: ${detail}`, tx, policy === 'refuse' ? 'block' : 'ask')
      return
    }
    if (policy === 'allow') { this.opts.onDecision?.(result, tx, 'signed'); return }
    if (policy === 'ask' && this.opts.onAsk && (await this.opts.onAsk(result, tx))) { this.opts.onDecision?.(result, tx, 'signed'); return }
    this.opts.onDecision?.(result, tx, 'refused')
    throw new OathlineNeedsApproval(result, tx)
  }

  /**
   * Guard a viem WalletClient: sendTransaction, writeContract and signTransaction (and their Sync variants) are
   * checked first; signTypedData and signMessage go through the signature policy; batches (sendCalls), already signed
   * transactions (sendRawTransaction), deployments and the raw JSON-RPC door (request) are refused in enforce mode
   * until sayso can check them (0.4.0). Any other function is refused in enforce mode and reported in shadow mode
   * unless it neither signs nor sends (CLIENT_READS) or was added through the guarded client's `extend` (0.6.3): guard
   * the client right after creating it and add extensions to the guarded client. Returns a new client; the original
   * stays unguarded (keep it private).
   */
  guard<C extends { extend: (fn: (c: any) => any) => any; account?: { address: Address } | undefined; sendTransaction: (args: any) => Promise<Hex>; writeContract: (args: any) => Promise<Hex>; signTransaction: (args: any) => Promise<any> }>(client: C): C {
    const self = this
    const walletOf = (args: any): Address => getAddress(args?.account?.address ?? client.account?.address ?? ZERO)
    const chainOfWallet = (args: any): number | undefined => args?.chain?.id ?? (client as any).chain?.id
    const unchecked: TxRequest = { to: ZERO, data: '0x' }
    const count = (calls: unknown) => (Array.isArray(calls) ? `${calls.length} call${calls.length === 1 ? '' : 's'}` : '')
    // JSON-RPC methods that send or sign a transaction without passing through a checked action, and the signing ones
    const RAW_SENDS = new Set(['wallet_sendCalls', 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTransaction', 'wallet_sendTransaction', 'wallet_sendPreparedCalls', 'wallet_grantPermissions', 'eth_sendUserOperation'])
    const RAW_SIGNS = new Set(['personal_sign', 'eth_sign', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4'])
    /** viem's `extend` never lets an extension replace `request` (or `extend`), so those two are set on the way out:
     *  the raw JSON-RPC door is gated here, and a guarded client extended further stays guarded. An extension CAN
     *  replace an earlier extension's actions (walletActions applied again would put an unguarded sendTransaction on
     *  top), so the guarded actions are put back after every extension (review 2026-10-19). */
    /** the wallet's code, from its own node (an EIP-7702 wallet answers with a 23-byte pointer) */
    const codeOf = (wallet: Address) => () => (client as any).request({ method: 'eth_getCode', params: [wallet, 'latest'] })
    const door = (send: (req: any, o?: any) => any) => async (req: any, o?: any) => {
      const m = req?.method, params = Array.isArray(req?.params) ? req.params : []
      if (RAW_SENDS.has(m)) await self.gateUnchecked(`raw RPC call (${m})`, '', unchecked)
      else if (RAW_SIGNS.has(m)) {
        // eth_sign is a blind hash; eth_signTypedData* carries the typed data (as JSON text or an object) after the address
        const wallet = isHexAddress(params[0]) ? getAddress(params[0]) : isHexAddress(params[1]) && m === 'personal_sign' ? getAddress(params[1]) : walletOf({})
        let typedData: unknown
        if (m.startsWith('eth_signTypedData')) { const raw = params[1]; try { typedData = typeof raw === 'string' ? JSON.parse(raw) : raw } catch { typedData = {} } }
        await self.gateSignature('raw RPC call', m, { wallet, raw: m === 'eth_sign', typedData, ...(m === 'personal_sign' && typeof params[0] === 'string' ? { message: /^0x([0-9a-fA-F]{2})*$/.test(params[0]) ? { raw: params[0] } : params[0] } : {}), code: codeOf(wallet), to: typedData !== undefined ? typedDataCounterparty(typedData) : ZERO })
      }
      return send(req, o)
    }
    /** The client's own account and transport are doors around the guard too (review M1 of step 2d): a local account
     *  signs by itself, and the transport's `request` sends what it is given. The guarded client hands out the
     *  account's address and type only, and the transport with its `request` shut like the client's. The checked
     *  actions still sign with the real account, through the original client (since 0.5.0). */
    const views = new WeakSet<object>(), viewOf = new WeakMap<object, any>()
    const accountView = (a: any): any => {
      if (!a || typeof a !== 'object') return a
      let v = viewOf.get(a)
      if (!v) { v = Object.freeze({ address: a.address, type: a.type, ...(a.publicKey !== undefined ? { publicKey: a.publicKey } : {}), ...(a.source !== undefined ? { source: a.source } : {}) }); views.add(v); viewOf.set(a, v) }
      return v
    }
    /** an action given that view back as its `account` (`{ account: guarded.account, ... }`) signs with the real one */
    const real = (args: any): any => (args && typeof args === 'object' && args.account && typeof args.account === 'object' && views.has(args.account) ? { ...args, account: client.account } : args)
    /** The transport, from a list of plain fields only: a fallback's inner transports, a socket, the RPC client, the
     *  URL (which can hold a provider key) and the fetch options stay inside (review 2026-10-20, H1). */
    const TRANSPORT_FIELDS = ['key', 'name', 'type', 'retryCount', 'retryDelay', 'timeout', 'methods']
    const transportOf = new WeakMap<object, any>()
    const transportView = (tr: any): any => {
      if (!tr || typeof tr !== 'object') return tr
      let v = transportOf.get(tr)
      if (!v) { v = Object.freeze({ ...Object.fromEntries(TRANSPORT_FIELDS.filter(k => k in tr).map(k => [k, tr[k]])), request: door((req, o) => tr.request(req, o)) }); transportOf.set(tr, v) }
      return v
    }
    /** Groups of actions viem puts on the client itself, bound to the original client (viem 2.5x: `token.transfer`,
     *  `token.approve` and their Sync variants call viem's writeContract directly, so they skipped the check; review
     *  2026-10-20, C1). Token transfers and approvals go through the checked writeContract; any other function in such a
     *  group is refused in enforce mode and reported in shadow mode until sayso knows it. A group of that name brought back by
     *  `extend` is treated the same; other groups added through `extend` are built on the guarded client, so they pass. */
    const DATA_GROUPS = new Set(['account', 'transport', 'chain', 'ccipRead', 'batch'])
    const TOKEN_WRITES: Record<string, 'writeContract' | 'writeContractSync'> = { transfer: 'writeContract', approve: 'writeContract', transferSync: 'writeContractSync', approveSync: 'writeContractSync' }
    /** every function name an object answers to: its own (also non-enumerable) and inherited ones, but not plain
     *  object methods (a Map's get, a class's methods count; review 2026-10-27, L1) */
    // data whose methods only read (a list, a date, bytes): never a group of actions (re-check 2026-10-27, R3: viem's `tokens` option is a list)
    // (only an object whose own prototype IS one of these is data: a subclass with methods of its own is not; a Promise
    // is never data, its value is guarded when it arrives; re-check 2026-10-26, R4)
    const DATA_PROTOS = new Set<unknown>([Array.prototype, Date.prototype, RegExp.prototype, ...[Uint8Array, Uint8ClampedArray, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array].map(T => T.prototype), Object.getPrototypeOf(Uint8Array.prototype), ArrayBuffer.prototype, Error.prototype, String.prototype, Number.prototype, Boolean.prototype])
    const isThenable = (o: any): boolean => { try { return typeof o?.then === 'function' } catch { return true } }
    /** how deep a group is copied; deeper objects (or a cycle) are guarded lazily, as they are read */
    const MAX_DEPTH = 6
    const fnNames = (o: any): string[] => {
      const names = new Set<string>()
      for (let p = o; p && p !== Object.prototype && !DATA_PROTOS.has(p); p = Object.getPrototypeOf(p)) for (const k of Object.getOwnPropertyNames(p)) { if (k === 'constructor' || (Array.isArray(o) && /^\d+$|^length$/.test(k))) continue; try { if (typeof o[k] === 'function') names.add(k) } catch { /* a getter that throws */ } }
      return [...names]
    }
    /** does this object hold functions anywhere? Past the depth budget a non-empty object counts as holding some (fail closed, R4) */
    const hasFunctions = (o: any, depth = 0): boolean => {
      if (!o || typeof o !== 'object') return false
      if (isThenable(o)) return true
      if (depth >= MAX_DEPTH) return Reflect.ownKeys(o).length > 0
      return fnNames(o).length > 0 || Object.values(o).some(v => typeof v === 'function' || hasFunctions(v, depth + 1))
    }
    const ownGroups = new Set(Object.getOwnPropertyNames(client).filter(k => !DATA_GROUPS.has(k) && hasFunctions((client as any)[k])))
    const groupCache = new Map<string, { raw: any; view: any }>()
    /** one value inside a group, guarded: a function the SDK does not know is refused, an object holding functions is a group */
    const inGroup = (o: any, v: unknown, path: string, depth: number): any =>
      typeof v === 'function' ? (extFns.has(v) ? v : gatedIn(o, path, v as (...a: any[]) => any)) : v && typeof v === 'object' && hasFunctions(v) ? group(v, path, depth + 1) : v
    /** past the depth budget (or in a cycle): a read-through view that guards each value as it is read */
    const deepViews = new WeakMap<object, any>()
    const deepView = (o: any, path: string): any => {
      let v = deepViews.get(o)
      if (!v) {
        v = new Proxy(o, {
          ...NO_WRITES,
          get(t, p) { const x = Reflect.get(t, p, t); if (typeof p !== 'string' && typeof x !== 'function') return x; return typeof x === 'function' ? (extFns.has(x) ? x : gatedIn(t, `${path}.${String(p)}`, x)) : x && typeof x === 'object' ? deepView(x, `${path}.${String(p)}`) : x },
          getOwnPropertyDescriptor(t, p) { const d = Reflect.getOwnPropertyDescriptor(t, p); return d && 'value' in d && d.configurable ? { ...d, value: this.get!(t, p, t) } : d },
        })
        deepViews.set(o, v)
      }
      return v
    }
    const group = (o: any, path: string, depth = 0): any => {
      if (depth >= MAX_DEPTH) return deepView(o, path)
      // a promise: what it resolves to is guarded the same way when it arrives (R4)
      if (isThenable(o)) { const p = Promise.resolve(o).then(v => inGroup(o, v, `${path}.then`, depth)); p.catch(() => undefined); return p }
      // a plain list stays a list (R3); its elements are copied into a plain array, so a subclass cannot bring its methods (R4)
      if (Array.isArray(o) && Object.getPrototypeOf(o) === Array.prototype) return Object.freeze(Array.from({ length: o.length }, (_, i) => inGroup(o, o[i], `${path}.${i}`, depth)))
      const out: Record<string, any> = {}
      const entries: Array<[string, unknown]> = [...Object.entries(o), ...fnNames(o).filter(k => !Object.prototype.propertyIsEnumerable.call(o, k)).map(k => [k, o[k]] as [string, unknown])]
      for (const [k, v] of entries) {
        if (typeof v === 'function') {
          const fn = v as (...a: any[]) => any
          const write = path === 'token' ? TOKEN_WRITES[k] : undefined
          // the call viem would write, from the action's own `.call` helper (a Sync variant has none: its plain twin's)
          const helper = [fn, (o as any)[k.replace(/Sync$/, '')]].find(f => typeof f === 'function' && Object.hasOwn(f, 'call') && typeof f.call === 'function')
          out[k] = write && helper
            ? async (args: any) => (actions as any)[write]({ ...args, ...helper.call(args) })
            : extFns.has(fn) ? fn   // added by an extension after guard(), which was handed the guarded client (by identity, at any depth; re-check R2)
            : gatedIn(o, `${path}.${k}`, fn)
        } else out[k] = inGroup(o, v, `${path}.${k}`, depth)
      }
      return Object.freeze(out)
    }
    /** a function inside a group that the SDK does not know: refused in enforce mode, reported in shadow mode; the
     *  refusal is marked handled, so one nobody awaits does not take the agent down (re-check 2026-10-27, L2) */
    function gatedIn(o: any, name: string, fn: (...a: any[]) => any) {
      return (...a: any[]) => { const p = (async () => { await self.gateUnchecked(`client action ${name}`, '', unchecked); return fn.apply(o, a) })(); p.catch(() => undefined); return p }
    }
    const groupView = (p: string, raw: any): any => { const c = groupCache.get(p); if (c && c.raw === raw) return c.view; const view = group(raw, p); groupCache.set(p, { raw, view }); return view }
    /** Functions added through the guarded `extend` (0.6.3): their extension was handed the guarded client, so what they
     *  sign or send goes through the check. Kept by identity, not by name: a later extension cannot vouch for an earlier
     *  raw function of the same name on another copy. viem's scope() runs the extension again, which records its new ones. */
    const extFns = new WeakSet<object>()
    const recordExt = (out: any, depth = 0): any => {
      if (out && typeof out === 'object' && depth < 6) for (const k of Reflect.ownKeys(out)) { let v: any; try { v = out[k] } catch { continue } if (typeof v === 'function') extFns.add(v); else if (v && typeof v === 'object') recordExt(v, depth + 1) }
      return out
    }
    /** a function the guarded client may hand out as it is: a checked action of the SDK's own, one added through the
     *  guarded extend, one that neither signs nor sends (CLIENT_READS), or a plain object method (toString and the like) */
    const knownFn = (t: object, p: string | symbol, v: Function): boolean =>
      (typeof p === 'string' && Object.hasOwn(actions, p) && v === (actions as Record<string | symbol, unknown>)[p]) || extFns.has(v)
      || (Object.hasOwn(t, p) ? typeof p === 'string' && CLIENT_READS.has(p) && isViemOwn(p, v) : (Object.prototype as unknown as Record<string | symbol, unknown>)[p] === v)
    /** the stand-in for an unknown function: one per function, so it reads the same twice */
    const unknownOf = new WeakMap<Function, Function>()
    const unknownFn = (name: string, fn: Function): Function => {
      let w = unknownOf.get(fn)
      if (!w) {
        // refused as a rejected promise that is marked handled: an agent that awaits it gets the refusal, and one that
        // does not (a plain function's caller) is not taken down by an unhandled rejection (review 2026-10-27, L2)
        w = function (this: unknown, ...a: unknown[]) { const no = self.unknownFunction(name); if (!no) return fn.apply(this, a); const p = Promise.reject(no); p.catch(() => undefined); return p }
        unknownOf.set(fn, w)
      }
      return w
    }
    /** one guarded view per client object, so viem's own memo (a scope per signal) gives the same guarded copy back */
    const shutOf = new WeakMap<object, any>()
    const isClient = (o: any): boolean => !!o && typeof o === 'object' && typeof o.request === 'function'
    const shut = (c: any): C => {
      const known = shutOf.get(c)
      if (known) return known
      const px: any = new Proxy(c, {
        get(t, p, r) {
          if (p === 'request') return door((req, o) => t.request(req, o))
          if (p === 'account') return accountView(t.account)
          if (p === 'transport') return transportView(t.transport)
          // an extension is handed the shut client, so it cannot give the account or transport out either
          if (p === 'extend') return (fn: any) => shut(t.extend((inner: any) => recordExt(fn(shut(inner)))).extend(() => actions))
          const v = Reflect.get(t, p, r)
          // viem 2.57.10 (22 Oct 2026) added scope(): a copy rebuilt from the original client with the same extensions,
          // so it has the checked actions but the raw request, account and transport; it is shut the same way. An
          // extension may define its own scope: it runs with the guarded client, never the raw one, as `this` (2026-10-23)
          // (0.6.3: only viem's own scope or one added after guard(); an add-on's scope from before guard() holds the raw client)
          if (p === 'scope' && typeof v === 'function') return extFns.has(v) || isViemOwn('scope', v) ? (...a: any[]) => { const s = v.apply(px, a); return isClient(s) ? shut(s) : s } : unknownFn('scope', v)
          if (typeof p === 'string' && ownGroups.has(p) && hasFunctions(v)) return groupView(p, v)
          // 0.6.3: deny by default. A function the SDK does not know (a new viem action, an add-on installed before
          // guard() with the raw client inside, one under a symbol) is refused in enforce mode and reported in shadow mode
          if (typeof v === 'function' && !knownFn(t, p, v)) return unknownFn(String(p), v)
          return v
        },
        // the same answers when read through a property descriptor (non-configurable ones cannot be; viem's are configurable)
        getOwnPropertyDescriptor(t, p) {
          const d = Reflect.getOwnPropertyDescriptor(t, p)
          return d && 'value' in d && d.configurable ? { ...d, value: this.get!(t, p, px) } : d
        },
        // a write would reach the raw client, and a property made non-configurable would then read raw (review 2026-10-23, H2)
        ...NO_WRITES,
      })
      shutOf.set(c, px)
      return px as C
    }
    /** The position the signed transaction will take: pinned here and used for the signing call, so the verdict (and
     *  sayso's record of what is still ahead of the chain) is for exactly that position. Read from the wallet's own
     *  node; if that fails no position is sent, and calls to the owner's own contracts are asked instead of allowed. */
    const nonceFor = async (args: any, wallet: Address): Promise<number | undefined> => {
      if (Number.isInteger(args?.nonce) && args.nonce >= 0) return args.nonce
      try { const n = await (client as any).request({ method: 'eth_getTransactionCount', params: [wallet, 'pending'] }); const v = typeof n === 'string' ? parseInt(n, 16) : Number(n); return Number.isInteger(v) && v >= 0 ? v : undefined } catch { return undefined }
    }
    const placed = (args: any, nonce: number | undefined) => (nonce === undefined ? args : { ...args, nonce })
    // an EIP-7702 authorization attached to a transaction is refused before anything is checked (third review H2)
    const authorized = (args: any) => Array.isArray(args?.authorizationList) && args.authorizationList.length > 0
    /** The suffix viem would add to the data (per call, else the client's own), so it is part of what is checked. */
    const suffixOf = (args: any): Hex => {
      const cs = (client as any).dataSuffix
      const sfx = args?.dataSuffix ?? (typeof cs === 'string' ? cs : cs?.value)
      if (sfx === undefined || sfx === null || sfx === '' || sfx === '0x') return '0x'
      if (typeof sfx !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(sfx)) throw new Error('dataSuffix is not hex data')
      return sfx as Hex
    }
    const withSuffix = (data: Hex, sfx: Hex): Hex => (sfx === '0x' ? data : (`${data}${sfx.slice(2)}` as Hex))
    /** The checked path, shared by sendTransaction, signTransaction, writeContract and their Sync variants. What is
     *  signed is exactly what was checked (review 2026-10-20, N1 and N2): the checked `to` and `data` (with any
     *  suffix already in it) are set on the signing call and the suffix is cleared, so neither a `to`/`data` passed to
     *  writeContract nor a suffix added by viem afterwards can change the transaction. writeContract signs through the
     *  original client's sendTransaction for that reason. A transaction with no `to` deploys a contract: refused in
     *  enforce mode like deployContract. */
    /** Why this call would be signed for another chain than the one sayso checks for (review 2026-10-27, M3: with a
     *  local account viem signs for a `chainId` passed in the call; with `chain: null` or `assertChainId: false` a JSON-RPC
     *  wallet signs on whatever chain it is on); null when it cannot. */
    /** the chain sayso checks for; when it cannot be read (sayso unreachable), the client's own chain, so the outage is
     *  decided by gate() like any other (re-check 2026-10-27, R1: shadow mode must not stop on it) */
    const checkedChain = async (): Promise<number | undefined> => (await self.chainId().catch(() => undefined)) ?? (client as any).chain?.id
    const otherChain = async (args: any): Promise<string | null> => {
      const serverChain = await checkedChain()
      if (serverChain === undefined) return null
      if (args?.chain === null) return 'chain: null'
      if (args?.assertChainId === false) return 'assertChainId: false'
      if (args?.chain && args.chain.id !== serverChain) return `chain ${String(args.chain.id)}`
      if (args?.chainId !== undefined && args.chainId !== null && Number(args.chainId) !== serverChain) return `chainId ${String(args.chainId)}`
      return null
    }
    const checked = (method: string, kind: 'plain' | 'contract') => async (args: any) => {
      if (kind === 'plain' && (args?.to === undefined || args?.to === null)) { await self.gateUnchecked(`contract deployment (${method} with no \`to\`)`, '', unchecked); return (client as any)[method](real(args)) }
      const wallet = walletOf(args), tx = kind === 'plain' ? plainTx(args) : contractTx(args)
      const elsewhere = await otherChain(args)
      if (elsewhere) { await self.gateUnchecked(`transaction for another chain than sayso checks (${method}, ${elsewhere})`, '', tx); return (client as any)[method](real(args)) }
      if (authorized(args)) await self.gateAuthorization('attached to the transaction', tx)
      const nonce = await nonceFor(args, wallet)
      await self.gate(wallet, { ...tx, nonce }, chainOfWallet(args))
      // signed for the checked chain: a local account signs for this chainId, a JSON-RPC wallet must be on the client's chain
      const pinned = await checkedChain()
      const pin = { ...(pinned !== undefined ? { chainId: pinned } : {}), assertChainId: true }
      if (kind === 'plain') return (client as any)[method](placed(real({ ...args, to: tx.to, data: tx.data, dataSuffix: '0x', ...pin }), nonce))
      const { abi: _abi, address: _address, functionName: _fn, args: _args, to: _to, data: _data, ...rest } = args
      return (client as any)[method === 'writeContractSync' ? 'sendTransactionSync' : 'sendTransaction'](placed(real({ ...rest, to: tx.to, data: tx.data, dataSuffix: '0x', ...pin }), nonce))
    }
    const plainTx = (args: any): TxRequest => ({ to: getAddress(args.to), data: withSuffix(args.data ?? '0x', suffixOf(args)), value: args.value })
    const contractTx = (args: any): TxRequest => ({ to: getAddress(args.address), data: withSuffix(encodeFunctionData({ abi: args.abi, functionName: args.functionName, args: args.args }), suffixOf(args)), value: args.value })
    const refused = (method: string, kind: string, detail: (args: any) => string = () => '') => async (args: any) => { await self.gateUnchecked(kind, detail(args), unchecked); return (client as any)[method](real(args)) }
    const actions = {
      sendTransaction: checked('sendTransaction', 'plain'),
      sendTransactionSync: checked('sendTransactionSync', 'plain'),
      signTransaction: checked('signTransaction', 'plain'),
      writeContract: checked('writeContract', 'contract'),
      writeContractSync: checked('writeContractSync', 'contract'),
      // what sayso cannot check yet (0.4.0): refused in enforce, reported in shadow
      sendCalls: refused('sendCalls', 'batch of calls (sendCalls)', a => count(a?.calls)),
      sendCallsSync: refused('sendCallsSync', 'batch of calls (sendCallsSync)', a => count(a?.calls)),
      sendRawTransaction: refused('sendRawTransaction', 'already signed transaction (sendRawTransaction)'),
      sendRawTransactionSync: refused('sendRawTransactionSync', 'already signed transaction (sendRawTransactionSync)'),
      deployContract: refused('deployContract', 'contract deployment (deployContract)'),
      // they change which chain a JSON-RPC wallet signs for: refused in enforce mode (review 2026-10-27, M3)
      switchChain: refused('switchChain', 'switching the wallet\'s chain (switchChain)'),
      addChain: refused('addChain', 'adding a chain to the wallet (addChain)'),
      signAuthorization: async (args: any) => { const code = args?.contractAddress ?? args?.address; await self.gateAuthorization(`signAuthorization for ${code ?? 'unknown code'}`, { to: typeof code === 'string' && /^0x[0-9a-fA-F]{40}$/.test(code) ? getAddress(code) : ZERO, data: '0x' }); return (client as any).signAuthorization(real(args)) },
      signTypedData: async (args: any) => { const wallet = walletOf(args); await self.gateSignature('typed data', describeTypedData(args), { to: typedDataCounterparty(args), wallet, typedData: args, code: codeOf(wallet) }); return (client as any).signTypedData(real(args)) },
      signMessage: async (args: any) => { const wallet = walletOf(args); await self.gateSignature('message', 'personal message', { wallet, message: args?.message, code: codeOf(wallet) }); return (client as any).signMessage(real(args)) },
    }
    return shut(client.extend(() => actions))
  }

  /**
   * Guard an AgentKit-style wallet provider (sendTransaction / signTransaction / nativeTransfer).
   * Works with Coinbase AgentKit's ViemWalletProvider, CdpEvmWalletProvider (CDP Server Wallet v2) and
   * PrivyEvmWalletProvider, and anything with the same shape. On CDP, `getClient()` comes back wrapped; on Privy, an
   * export that would hand out the authorization key is refused in enforce mode.
   */
  guardWalletProvider<P extends { getAddress(): string; sendTransaction(tx: any): Promise<Hex> }>(provider: P): P {
    const self = this
    const wallet = () => getAddress(provider.getAddress())
    const chainOfWallet = (): number | undefined => { try { const id = Number((provider as any).getNetwork?.()?.chainId); return Number.isInteger(id) && id > 0 ? id : undefined } catch { return undefined } }
    /** The position the transaction will take, when the provider can say (AgentKit's viem provider exposes a public
     *  client). Pinned before the check and passed to the signing call. Without it, calls to the owner's own contracts
     *  are asked instead of allowed. */
    const nonceFor = async (tx: any): Promise<number | undefined> => {
      if (Number.isInteger(tx?.nonce) && tx.nonce >= 0) return tx.nonce
      const p: any = provider
      try {
        if (typeof p.getNonce === 'function') { const v = Number(await p.getNonce()); if (Number.isInteger(v) && v >= 0) return v }
        const pc = typeof p.getPublicClient === 'function' ? p.getPublicClient() : p.publicClient
        if (pc && typeof pc.getTransactionCount === 'function') { const v = Number(await pc.getTransactionCount({ address: wallet(), blockTag: 'pending' })); if (Number.isInteger(v) && v >= 0) return v }
      } catch { /* no position: sayso then treats the transaction as unplaced */ }
      return undefined
    }
    const placed = (tx: any, nonce: number | undefined) => (nonce === undefined || Number.isInteger(tx?.nonce) ? tx : { ...tx, nonce })
    const authorized = (tx: any) => Array.isArray(tx?.authorizationList) && tx.authorizationList.length > 0
    const txOf = (tx: any): TxRequest => ({ to: getAddress(tx.to ?? ZERO), data: tx.data ?? '0x', value: tx.value !== undefined ? BigInt(tx.value) : undefined })
    /** What the provider would send that the check would not see (review 2026-10-20, N2): a data suffix added after
     *  the check, or no `to` (a contract deployment). Refused in enforce mode, reported in shadow mode. */
    const unseen = async (tx: any, method: string): Promise<boolean> => {
      if (tx?.to === undefined || tx?.to === null) { await self.gateUnchecked(`contract deployment (${method} with no \`to\`)`, '', { to: ZERO, data: '0x' }); return true }
      if (tx?.dataSuffix !== undefined && tx.dataSuffix !== null && tx.dataSuffix !== '' && tx.dataSuffix !== '0x') { await self.gateUnchecked(`data suffix on ${method}`, '', txOf(tx)); return true }
      // `input` is `data` under another name for many signers: one the check did not see is refused (review P2)
      if (tx?.input !== undefined && tx.input !== null && String(tx.input).toLowerCase() !== String(tx.data ?? '0x').toLowerCase()) { await self.gateUnchecked(`data under another name (input) on ${method}`, '', txOf(tx)); return true }
      // another chain than the one sayso answers for: the verdict would be for Base and the signature for elsewhere (review P1)
      // the same under the snake_case names some provider APIs read (Privy's; review P3)
      if (Array.isArray(tx?.authorization_list) && tx.authorization_list.length > 0) { await self.gateAuthorization('attached to the transaction (authorization_list)', txOf(tx)); return false }
      for (const key of ['chainId', 'chain_id']) {
        if (tx?.[key] === undefined || tx[key] === null) continue
        const asked = Number(tx[key]), serverChain = await self.chainId().catch(() => undefined)
        if (!Number.isInteger(asked) || asked !== serverChain) { await self.gateUnchecked(`transaction for chain ${String(tx[key])} (${method})`, '', txOf(tx)); return true }
      }
      return false
    }
    /** A signed transaction can be sent on any chain it is valid for: it is always signed for the checked chain (P1). */
    const onChecked = async (tx: any): Promise<any> => ({ ...tx, chainId: await self.chainId() })
    /** the wallet's code from the provider's own node, when it has one (AgentKit's providers expose a public client) */
    const codeOf = () => async (): Promise<unknown> => {
      const p: any = provider
      const pc = typeof p.getPublicClient === 'function' ? p.getPublicClient() : p.publicClient
      if (!pc) throw new Error('no public client')
      if (typeof pc.getCode === 'function') return pc.getCode({ address: wallet() })
      if (typeof pc.getBytecode === 'function') return pc.getBytecode({ address: wallet() })
      throw new Error('no code read')
    }
    const wrapped: Record<string, (...a: any[]) => any> = {
      sendTransaction: async (tx: any) => { if (await unseen(tx, 'sendTransaction')) return provider.sendTransaction(tx); if (authorized(tx)) await self.gateAuthorization('attached to the transaction', txOf(tx)); const nonce = await nonceFor(tx); await self.gate(wallet(), { ...txOf(tx), nonce }, chainOfWallet()); return provider.sendTransaction(placed(tx, nonce)) },
      signTransaction: async (tx: any) => { if (await unseen(tx, 'signTransaction')) return (provider as any).signTransaction(tx); if (authorized(tx)) await self.gateAuthorization('attached to the transaction', txOf(tx)); const nonce = await nonceFor(tx); await self.gate(wallet(), { ...txOf(tx), nonce }, chainOfWallet()); return (provider as any).signTransaction(placed(await onChecked(tx), nonce)) },
      signAuthorization: async (auth: any) => { await self.gateAuthorization(`signAuthorization for ${auth?.contractAddress ?? auth?.address ?? 'unknown code'}`, { to: ZERO, data: '0x' }); return (provider as any).signAuthorization(auth) },
      // nativeTransfer builds its own transaction: the position is read the same way the provider will, and sent along
      nativeTransfer: async (to: string, value: string) => { const nonce = await nonceFor({}); await self.gate(wallet(), { to: getAddress(to), data: '0x', value: nativeAmount(value), nonce }, chainOfWallet()); return (provider as any).nativeTransfer(to, value) },
      // signing paths that never become a transaction sayso can simulate
      signTypedData: async (typedData: any) => { await self.gateSignature('typed data', describeTypedData(typedData), { to: typedDataCounterparty(typedData), wallet: wallet(), typedData, code: codeOf() }); return (provider as any).signTypedData(typedData) },
      signMessage: async (message: any) => { await self.gateSignature('message', 'personal message', { wallet: wallet(), message, code: codeOf() }); return (provider as any).signMessage(message) },
      sign: async (hash: any) => { await self.gateSignature('raw hash', 'blind signature over a hash', { wallet: wallet(), raw: true, code: codeOf() }); return (provider as any).sign(hash) },
      // CDP: AgentKit's own swap and spend-permission actions sign through the raw CDP client (R2)
      getClient: (...a: any[]) => self.guardCdpClient((provider as any).getClient(...a)),
      // Privy's export hands out the authorization key, which signs for the wallet at Privy without the guard (R2);
      // an export with no secret in it (CDP: name and address) passes
      exportWallet: (...a: any[]) => {
        const seen = (o: any) => { if (holdsSecret(o)) self.gateUncheckedNow('key export (exportWallet)', '', { to: ZERO, data: '0x' }); return o }
        const out = (provider as any).exportWallet(...a)
        return out && typeof out.then === 'function' ? out.then(seen) : seen(out)
      },
      ...Object.fromEntries([...PROVIDER_RAW_DOORS].map(m => [m, (...a: any[]) => { self.gateUncheckedNow(`provider's own API door (${m})`, '', { to: ZERO, data: '0x' }); return (provider as any)[m](...a) }])),
      toSigner: () => {
        // on a wallet the SDK knows to be an EIP-7702 wallet the raw signer would sign user operations and batches: refused in every mode but shadow, no policy (review 2026-10-22, L3)
        if (self.walletKinds.get(wallet().toLowerCase())?.delegated && self.modeWithoutAnswer !== 'shadow') { const r: CheckResult = { verdict: 'block', reason: 'exporting the raw signer on an EIP-7702 wallet would let a user operation or a signed batch move everything; sayso never allows it' }; self.opts.onDecision?.(r, { to: ZERO, data: '0x' }, 'refused'); throw new OathlineBlocked(r, { to: ZERO, data: '0x' }) }
        if (self.modeWithoutAnswer === 'enforce' && (self.opts.signatures ?? 'ask') !== 'allow') throw new OathlineNeedsApproval({ verdict: 'ask', reason: 'exporting the raw signer would let signatures bypass sayso' }, { to: ZERO, data: '0x' })
        return (provider as any).toSigner()
      },
    }
    return new Proxy(provider, {
      get(target, prop, _receiver) {
        if (prop === GUARDED) return true
        if (typeof prop === 'string' && prop in wrapped && typeof (target as any)[prop] === 'function') return wrapped[prop]
        const v = Reflect.get(target, prop, target)
        return typeof v === 'function' ? v.bind(target) : v   // bind: private fields (#x) need the real object as `this`
      },
      // a provider whose methods are its own properties: read through a descriptor, they are the guarded ones too (review 2026-10-23, M1)
      getOwnPropertyDescriptor(t, p) { const d = Reflect.getOwnPropertyDescriptor(t, p); return d && 'value' in d && d.configurable ? { ...d, value: (this as ProxyHandler<any>).get!(t, p, t) } : d },
      ...NO_WRITES,
    })
  }
}
