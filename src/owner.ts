// Owner-side helpers: the signatures that set a wallet up, the one-off instruction, and linking an approval channel.
// The owner's key and the agent wallet's key stay with their holders; only signatures travel.
import { getAddress, isAddressEqual, type Address, type Hex } from 'viem'
import { KEY_RESET_ACTION, OATHLINE_TYPES, apiKeyHash, mandateHash, newApiKey, oathlineDomain } from './typed-data'
import { callOptions, chainFor, inviteField, type CallOptions } from './chain'

/** anything that can sign EIP-712 typed data and has an address (a viem account, a wallet client's account, …) */
export interface TypedSigner { address: Address; signTypedData(args: any): Promise<Hex> }

const randomNonce = () => `0x${[...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, '0')).join('')}` as Hex

const post = async (apiUrl: string, path: string, body: unknown, f: typeof fetch = fetch) => {
  const res = await f(`${apiUrl.replace(/\/$/, '')}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const json = await res.json().catch(() => ({})) as any
  if (!res.ok) throw new Error(`sayso ${path} ${res.status}: ${json.error ?? 'request failed'}`)
  return json
}

/** Setup helper: the owner's plain words → the compiled rules they read and then sign. Decides nothing.
 *  The text model behind it occasionally fails or times out, so it is tried a few times; a failure is reported in
 *  plain words instead of surfacing later as a confusing error. */
export async function compileMandate(apiUrl: string, text: string, f: typeof fetch = fetch, tries = 3): Promise<{ compiled: any; shownToOwner: string }> {
  let last = 'no answer'
  for (let i = 0; i < tries; i++) {
    try {
      const res = await f(`${apiUrl.replace(/\/$/, '')}/mandate/compile`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(90_000) })
      const json = await res.json().catch(() => ({})) as any
      if (res.ok && json?.compiled && Array.isArray(json.compiled.allowedTokens)) return json
      last = String(json?.error ?? `HTTP ${res.status}`).slice(0, 160)
    } catch (e) { last = (e as Error).name === 'TimeoutError' ? 'timed out' : (e as Error).message.slice(0, 160) }
    if (i < tries - 1) await new Promise(r => setTimeout(r, 2000))
  }
  throw new Error(`could not turn the mandate into rules after ${tries} tries (${last}). The text model is not answering; try again in a minute.`)
}

/** Signed by the AGENT WALLET: "this owner may set my rules". Returns the API key for the agent (shown once).
 *  The owner must be another wallet: an agent that is its own owner could sign its own rules (refused here before
 *  anything is signed, and again by the server). */
export async function registerWallet(apiUrl: string, wallet: TypedSigner, owner: Address, f?: CallOptions): Promise<{ apiKey: string }> {
  if (isAddressEqual(wallet.address, owner)) throw new Error('the owner must be a different wallet from the agent\'s: an agent that is its own owner could sign its own rules')
  const walletSignature = await wallet.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'Link', message: { wallet: wallet.address, owner: getAddress(owner) } })
  return post(apiUrl, '/wallets/register', { wallet: wallet.address, owner, walletSignature, ...inviteField(f) }, callOptions(f).fetch)
}

/** R5 part 3: a registered wallet whose code changed is registered again as what it now is: a plain wallet that was
 *  upgraded with EIP-7702 to code sayso accepts, an EIP-7702 wallet whose delegation was cleared, or one that moved to
 *  other accepted code. The OWNER signs a Relink (once, expiring in `ttlSeconds`, an hour at most) and the WALLET signs a
 *  fresh Link with its own key (the same key still signs after an upgrade). The API key, the rules, the Telegram chat and
 *  the mode stay. Use the agent's account BEFORE it is wrapped (a wrapped provider refuses typed data in enforce mode). */
export async function reregisterWallet(apiUrl: string, owner: TypedSigner, wallet: TypedSigner, ttlSeconds = 600, f?: CallOptions): Promise<{ wallet: Address; kind: 'plain' | 'delegated'; delegate: Address | null; caveat?: string; checks?: string[]; note: string }> {
  if (isAddressEqual(wallet.address, owner.address)) throw new Error('the owner must be a different wallet from the agent\'s')
  const domain = oathlineDomain(await chainFor(apiUrl, f))
  const nonce = randomNonce(), expiresAt = Math.floor(Date.now() / 1000) + Math.min(Math.max(60, ttlSeconds), 3600)
  const ownerSignature = await owner.signTypedData({ domain, types: OATHLINE_TYPES, primaryType: 'Relink', message: { wallet: wallet.address, owner: owner.address, nonce, expiresAt: BigInt(expiresAt) } })
  const walletSignature = await wallet.signTypedData({ domain, types: OATHLINE_TYPES, primaryType: 'Link', message: { wallet: wallet.address, owner: owner.address } })
  return post(apiUrl, `/wallets/${wallet.address}/reregister`, { nonce, expiresAt, ownerSignature, walletSignature }, callOptions(f).fetch)
}

/** A marker every wrapped provider answers to (`guardWalletProvider`), so a wrapped one is never used to register. */
export const GUARDED: unique symbol = Symbol.for('saysoio.guarded') as any

/** The signer `registerWallet` needs, from a viem account (a plain key, `@turnkey/viem`, Privy's or CDP's viem account)
 *  or from an AgentKit wallet provider (CDP Server Wallet v2, Privy, viem): the provider's own `signTypedData` signs, so
 *  no key leaves it. Use the provider BEFORE it is wrapped: a wrapped one refuses typed data in enforce mode. */
export function providerSigner(w: { address: string; signTypedData(args: any): Promise<Hex> } | { getAddress(): string; signTypedData(args: any): Promise<Hex> }): TypedSigner {
  const x = w as any
  if (x && x[GUARDED] === true) throw new Error('register with the provider before you wrap it: a wrapped provider refuses to sign typed data in enforce mode')
  const address = typeof x?.address === 'string' ? x.address : typeof x?.getAddress === 'function' ? x.getAddress() : undefined
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error('providerSigner needs a viem account (with an address) or a wallet provider (with getAddress())')
  if (typeof x.signTypedData !== 'function') throw new Error('providerSigner needs something that signs typed data (signTypedData)')
  return { address: getAddress(address), signTypedData: (args: any) => x.signTypedData(args) }
}

/** How a Safe was created: sayso re-derives the Safe's address from this, so only a plainly created Safe registers. */
export interface SafeSetup { owners: Address[]; threshold: number; saltNonce: bigint | string; fallbackHandler?: Address }

/** For a wallet that is a Safe: the Link is signed by as many of the Safe's owners as the Safe itself requires
 *  (typically the agent's key and the owner's own key; sayso's co-signer key never counts). The Safe must be
 *  freshly created by the standard factory with exactly `setup` (owners in the same order). */
export async function registerSafe(apiUrl: string, safe: Address, signers: TypedSigner[], owner: Address, setup?: SafeSetup, f?: CallOptions): Promise<{ apiKey: string }> {
  return registerSafePartial(apiUrl, safe, signers, owner, setup, f, false) as Promise<{ apiKey: string }>
}
/** The same, but one owner at a time: `partial` keeps this signature at sayso until the other owners (the agent) add
 *  theirs. Resolves with `pending: true` until the Safe's threshold is met. */
export async function registerSafePartial(apiUrl: string, safe: Address, signers: TypedSigner[], owner: Address, setup?: SafeSetup, f?: CallOptions, partial = true): Promise<{ apiKey?: string; pending?: boolean; have?: number; need?: number }> {
  const message = { wallet: getAddress(safe), owner: getAddress(owner) }
  const domain = oathlineDomain(await chainFor(apiUrl, f))
  const walletSignatures = await Promise.all(signers.map(s => s.signTypedData({ domain, types: OATHLINE_TYPES, primaryType: 'Link', message })))
  return post(apiUrl, '/wallets/register', { wallet: safe, owner, walletSignatures, ...(setup ? { safeSetup: { ...setup, saltNonce: setup.saltNonce.toString() } } : {}), ...(partial ? { partial: true } : {}), ...inviteField(f) }, callOptions(f).fetch)
}

/** Watch only: sayso reports on what waits for signatures in an existing Safe and can stop nothing, so one owner's
 *  signature is enough. Nothing about the Safe changes. */
export async function watchSafe(apiUrl: string, safe: Address, ownerOfSafe: TypedSigner, owner: Address, f?: CallOptions): Promise<{ apiKey: string }> {
  const message = { wallet: getAddress(safe), owner: getAddress(owner) }
  const sig = await ownerOfSafe.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'Link', message })
  return post(apiUrl, '/wallets/register', { wallet: safe, owner, walletSignatures: [sig], watchOnly: true, ...inviteField(f) }, callOptions(f).fetch)
}

/** Signed by the OWNER: the mandate in plain words plus the hash of the compiled rules they were shown. */
export async function setMandate(apiUrl: string, owner: TypedSigner, wallet: Address, text: string, compiled: unknown, f?: CallOptions): Promise<{ mandateId: Hex }> {
  const issuedAt = Math.floor(Date.now() / 1000)
  const signature = await owner.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'Mandate', message: { wallet: getAddress(wallet), text, mandateHash: mandateHash(compiled), issuedAt: BigInt(issuedAt) } })
  return post(apiUrl, '/mandates', { wallet, text, mandate: compiled, issuedAt, signature, ...inviteField(f) }, callOptions(f).fetch)
}

/** Signed by the OWNER: a one-off instruction ("send 100 USDC to my saved address"), valid for ttlSeconds, usable once. */
export async function giveInstruction(apiUrl: string, owner: TypedSigner, wallet: Address, text: string, ttlSeconds = 3600, f?: CallOptions): Promise<void> {
  const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds
  const nonce = randomNonce()
  const signature = await owner.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'Instruction', message: { wallet: getAddress(wallet), text, nonce, expiresAt: BigInt(expiresAt) } })
  await post(apiUrl, '/instructions', { wallet, text, nonce, expiresAt, signature }, callOptions(f).fetch)
}

/** Signed by the OWNER: "send this wallet's approval requests to the Telegram chat that opens my link".
 *  Returns a one-time link; the owner opens it in Telegram and presses Start. Only a private chat can be linked. */
export async function linkTelegram(apiUrl: string, owner: TypedSigner, wallet: Address, f?: CallOptions): Promise<{ url: string; expiresAt: number }> {
  const expiresAt = Math.floor(Date.now() / 1000) + 900
  const nonce = randomNonce()
  const signature = await owner.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'Channel', message: { wallet: getAddress(wallet), channel: 'telegram', nonce, expiresAt: BigInt(expiresAt) } })
  return post(apiUrl, '/channels/telegram/link', { wallet, nonce, expiresAt, signature }, callOptions(f).fetch)
}

/** The same chat for several wallets of one owner at once (the dashboard's "Link Telegram for all my wallets"): one
 *  Channel signature per wallet (the same message `linkTelegram` signs; nothing new is signed), one link to open in
 *  Telegram. sayso refuses the whole request if any wallet is not registered to this owner. At most 20 wallets. */
export async function linkTelegramAll(apiUrl: string, owner: TypedSigner, wallets: Address[], f?: CallOptions): Promise<{ url: string; expiresAt: number; wallets: Address[] }> {
  if (!wallets.length || wallets.length > 20) throw new Error('linkTelegramAll takes 1 to 20 wallets')
  const domain = oathlineDomain(await chainFor(apiUrl, f))
  const expiresAt = Math.floor(Date.now() / 1000) + 900
  const links = []
  for (const w of wallets) {
    const nonce = randomNonce()
    const signature = await owner.signTypedData({ domain, types: OATHLINE_TYPES, primaryType: 'Channel', message: { wallet: getAddress(w), channel: 'telegram', nonce, expiresAt: BigInt(expiresAt) } })
    links.push({ wallet: getAddress(w), nonce, expiresAt, signature })
  }
  return post(apiUrl, '/channels/telegram/link-all', { links }, callOptions(f).fetch)
}

/** Signed by the OWNER (step 5d): check this wallet in 'shadow' or 'enforce' mode from the agent's next check on. sayso
 *  refuses 'enforce' until a Telegram chat is linked for the wallet (its questions travel there). The agent's SDK learns
 *  the mode from sayso's signed answer; a floor its builder fixed in code still applies. */
export async function setCheckMode(apiUrl: string, owner: TypedSigner, wallet: Address, mode: 'shadow' | 'enforce', f?: CallOptions): Promise<{ wallet: Address; mode: 'shadow' | 'enforce'; setAt: number; note: string }> {
  if (mode !== 'shadow' && mode !== 'enforce') throw new Error(`mode must be 'shadow' or 'enforce' (got ${String(mode)})`)
  const issuedAt = Math.floor(Date.now() / 1000)
  const signature = await owner.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'CheckMode', message: { wallet: getAddress(wallet), mode, issuedAt: BigInt(issuedAt) } })
  return post(apiUrl, `/wallets/${getAddress(wallet)}/mode`, { mode, issuedAt, signature }, callOptions(f).fetch)
}

/** Signed by the OWNER (step 3b): a new API key for this agent wallet, for a lost or leaked key. The key is made here
 *  and only its hash is signed and sent, so sayso never sees it and a copied signature installs a key only you hold.
 *  sayso checks that the signer is the wallet's registered owner and cancels the old key at once (every route refuses it
 *  from then on). Returns the new key: hand it to the agent. The signature is good for 10 minutes and once only. */
export async function rotateApiKey(apiUrl: string, owner: TypedSigner, wallet: Address, f?: CallOptions): Promise<{ wallet: Address; apiKey: string; note: string; logged?: boolean }> {
  if (isAddressEqual(wallet, owner.address)) throw new Error('the owner must be a different wallet from the agent\'s')
  const w = getAddress(wallet), nonce = randomNonce(), issuedAt = Math.floor(Date.now() / 1000)
  const apiKey = newApiKey(), keyHash = apiKeyHash(apiKey)
  const signature = await owner.signTypedData({ domain: oathlineDomain(await chainFor(apiUrl, f)), types: OATHLINE_TYPES, primaryType: 'KeyReset', message: { wallet: w, owner: getAddress(owner.address), action: KEY_RESET_ACTION, nonce, issuedAt: BigInt(issuedAt), keyHash } })
  const r = await post(apiUrl, `/wallets/${w}/key`, { nonce, issuedAt, keyHash, signature }, callOptions(f).fetch)
  return { ...r, wallet: w, apiKey }
}
