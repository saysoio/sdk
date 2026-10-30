// Review round 8 (27 Oct): what is signed must be exactly what was checked. No caller option reaches a raw signer, and
// every signing path decodes the signed bytes and compares them with the checked transaction before releasing them.
// assert the guard holds. No unsigned field changes what the gate does; the request door and the provider are allow lists.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createWalletClient, custom, type Address, type Hex } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { base } from 'viem/chains'
const sdk: any = await import('../src/index.js')
const { Oathline, OathlineBlocked, OATHLINE_TYPES, oathlineDomain, txDigest, modeQueryDigest } = sdk
const key = privateKeyToAccount(generatePrivateKey())
const W: Address = '0x1111111111111111111111111111111111111111'
const TO: Address = '0x2222222222222222222222222222222222222222'
const now = () => Math.floor(Date.now() / 1000)
async function stmt(m: 'shadow' | 'enforce', digest: Hex, wallet: Address = W) {
  const msg = { wallet, txDigest: digest, mode: m, setAt: 100, expiresAt: now() + 120 }
  const signature = await key.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'ModeStatement', message: { ...msg, setAt: 100n, expiresAt: BigInt(msg.expiresAt) } })
  return { ...msg, signer: key.address, signature }
}
async function receipt(verdict: string, digest: Hex, wallet: Address = W) {
  const r = { wallet, txDigest: digest, mandateId: `0x${'ab'.repeat(32)}` as Hex, verdict, issuedAt: now(), expiresAt: now() + 120 }
  const signature = await key.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'Verdict', message: { ...r, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) } })
  return { ...r, signer: key.address, signature }
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
/** an honest sayso whose owner is on ENFORCE; `tamper` lets a MITM edit a /check answer */
function enforceServer(wallet: Address, tamper: (b: any) => any = b => b) {
  return async (url: string, init: any) => {
    if (url.endsWith('/unchecked')) return json(200, { ok: true })
    if (url.includes('/wallets/')) return json(200, { kind: 'delegated' })
    const b = JSON.parse(init.body)
    if (url.endsWith('/mode')) return json(200, { wallet, mode: await stmt('enforce', modeQueryDigest(wallet, b.nonce, 8453), wallet) })
    const t = { to: b.tx.to, data: b.tx.data, value: b.tx.value !== undefined ? BigInt(b.tx.value) : undefined, nonce: b.tx.nonce }
    const d = txDigest({ wallet, ...t }, 8453)
    return json(200, tamper({ verdict: 'allow', reason: 'ok', receipt: await receipt('allow', d, wallet), mode: await stmt('enforce', d, wallet), walletKind: 'delegated' }))
  }
}
const go = async (p: Promise<unknown>) => p.then(() => 'SIGNED', e => `refused:${e.name}`)
import { serializeTransaction, parseTransaction } from 'viem'
import { toAccount } from 'viem/accounts'
const evil = { chainId: 8453, to: '0x9999999999999999999999999999999999999999' as Address, value: 10n ** 20n, nonce: 7, gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, type: 'eip1559' as const }
const fees = { gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, type: 'eip1559' as const }
/** a local account that signs something else than it was asked to: the swap the check must catch after signing */
const swapping = (pk: ReturnType<typeof privateKeyToAccount>) => toAccount({ address: pk.address, signMessage: pk.signMessage, signTypedData: pk.signTypedData, signTransaction: async () => pk.signTransaction(evil) })

test('r8 toSigner(): a caller-supplied serializer never reaches the signer; what is signed is what was checked', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const provider = { getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async () => '0x' as Hex, toSigner: () => pk }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) })
  const s: any = (g.guardWalletProvider(provider) as any).toSigner()
  const out = await s.signTransaction({ to: TO, value: 1n, nonce: 7, ...fees }, { serializer: (_tx: any, sig?: any) => serializeTransaction(evil, sig) })
  const p = parseTransaction(out)
  assert.equal(p.to?.toLowerCase(), TO.toLowerCase()); assert.equal(p.value, 1n); assert.equal(p.chainId, 8453)
})

test('r8 toSigner(): a signer that signs another transaction after the check is refused, and its signature dropped', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const provider = { getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async () => '0x' as Hex, toSigner: () => swapping(pk) }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) })
  const s: any = (g.guardWalletProvider(provider) as any).toSigner()
  assert.equal(await go(s.signTransaction({ to: TO, value: 1n, nonce: 7, ...fees })), 'refused:OathlineBlocked')
})

test('r8 provider: a provider whose signTransaction returns another transaction is refused', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const provider = { getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async () => '0x' as Hex, signTransaction: async (_tx: any) => pk.signTransaction(evil) }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) })
  const p: any = g.guardWalletProvider(provider)
  assert.equal(await go(p.signTransaction({ to: TO, value: 1n, nonce: 7, ...fees })), 'refused:OathlineBlocked')
  // an honest provider passes
  const honest: any = g.guardWalletProvider({ ...provider, signTransaction: async (tx: any) => pk.signTransaction({ ...tx, chainId: 8453 }) })
  assert.equal(parseTransaction(await honest.signTransaction({ to: TO, value: 1n, nonce: 7, ...fees })).value, 1n)
})

const node = (sent: string[]) => custom({ request: async ({ method, params }: any) => { if (method === 'eth_sendRawTransaction') { sent.push(params[0]); return `0x${'aa'.repeat(32)}` } return ({ eth_chainId: '0x2105', eth_getTransactionCount: '0x7', eth_estimateGas: '0x5208', eth_gasPrice: '0x1', eth_maxPriorityFeePerGas: '0x1', eth_getBlockByNumber: { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` } } as any)[method] ?? null } })

test('r8 viem client, local account: a chain with its own serializer passed in the call changes nothing; the sent bytes are the checked transaction', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g: any = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) }).guard(createWalletClient({ account: pk, chain: base, transport: node(sent) }) as any)
  const chain = { ...base, serializers: { transaction: (_tx: any, sig?: any) => serializeTransaction(evil, sig) } }
  await g.sendTransaction({ to: TO, value: 1n, chain })
  assert.equal(sent.length, 1)
  const p = parseTransaction(sent[0] as Hex); assert.equal(p.to?.toLowerCase(), TO.toLowerCase()); assert.equal(p.value, 1n)
  const signed = await g.signTransaction({ to: TO, value: 1n, chain })
  assert.equal(parseTransaction(signed).to?.toLowerCase(), TO.toLowerCase())
})

test('r8 viem client, a local account that swaps the transaction: refused, nothing is sent', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g: any = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) }).guard(createWalletClient({ account: swapping(pk), chain: base, transport: node(sent) }) as any)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n })), 'refused:OathlineBlocked')
  assert.equal(await go(g.writeContract({ address: TO, abi: [{ type: 'function', name: 'f', inputs: [], outputs: [], stateMutability: 'payable' }], functionName: 'f', value: 1n })), 'refused:OathlineBlocked')
  assert.equal(await go(g.signTransaction({ to: TO, value: 1n })), 'refused:OathlineBlocked')
  assert.deepEqual(sent, [])
})

test('r8 viem client, a JSON-RPC wallet whose eth_signTransaction returns another transaction: refused', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const wallet = custom({ request: async ({ method }: any) => method === 'eth_signTransaction' ? pk.signTransaction(evil) : ({ eth_chainId: '0x2105', eth_getTransactionCount: '0x7', eth_estimateGas: '0x5208', eth_gasPrice: '0x1', eth_maxPriorityFeePerGas: '0x1', eth_getBlockByNumber: { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` } } as any)[method] ?? null })
  const g: any = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) }).guard(createWalletClient({ account: pk.address, chain: base, transport: wallet }) as any)
  assert.equal(await go(g.signTransaction({ to: TO, value: 1n, nonce: 7, ...fees })), 'refused:OathlineBlocked')
})
