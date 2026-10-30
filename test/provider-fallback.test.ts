// #69 review (27 Oct). (1) A provider whose signTransaction loses fields (AgentKit's ViemWalletProvider and every provider
// built on it, such as PrivyEvmWalletProvider, keep only to, value and data), returns no signed transaction (the legacy
// CDP provider returns a bare signature) or says in its own words that it cannot sign (CDP smart wallets) must still
// send: through its own sendTransaction with the checked, bounded fields, never by broadcasting what it signed. A
// signature for another recipient stays a block. (The fee budget: fee-budget-per-wallet.test.ts.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createWalletClient, custom, keccak256, serializeTransaction, type Address, type Hex } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { base } from 'viem/chains'
const sdk: any = await import('../src/index.js')
const { Oathline, OATHLINE_TYPES, oathlineDomain, txDigest, modeQueryDigest } = sdk
const key = privateKeyToAccount(generatePrivateKey())
const TO: Address = '0x2222222222222222222222222222222222222222'
const EVIL: Address = '0x9999999999999999999999999999999999999999'
const GWEI = 10n ** 9n
const now = () => Math.floor(Date.now() / 1000)
async function stmt(m: 'shadow' | 'enforce', digest: Hex, wallet: Address) {
  const msg = { wallet, txDigest: digest, mode: m, setAt: 100, expiresAt: now() + 120 }
  const signature = await key.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'ModeStatement', message: { ...msg, setAt: 100n, expiresAt: BigInt(msg.expiresAt) } })
  return { ...msg, signer: key.address, signature }
}
async function receipt(verdict: string, digest: Hex, wallet: Address) {
  const r = { wallet, txDigest: digest, mandateId: `0x${'ab'.repeat(32)}` as Hex, verdict, issuedAt: now(), expiresAt: now() + 120 }
  const signature = await key.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'Verdict', message: { ...r, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) } })
  return { ...r, signer: key.address, signature }
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
/** an honest sayso on ENFORCE that allows everything, for whichever wallet asks */
const allowAll = async (url: string, init: any) => {
  if (url.endsWith('/unchecked')) return json(200, { ok: true })
  if (url.includes('/wallets/')) return json(200, { kind: 'plain' })
  const b = JSON.parse(init.body), wallet = b.wallet as Address
  if (url.endsWith('/mode')) return json(200, { wallet, mode: await stmt('enforce', modeQueryDigest(wallet, b.nonce, 8453), wallet) })
  const d = txDigest({ wallet, to: b.tx.to, data: b.tx.data, value: b.tx.value !== undefined ? BigInt(b.tx.value) : undefined, nonce: b.tx.nonce }, 8453)
  return json(200, { verdict: 'allow', reason: 'ok', receipt: await receipt('allow', d, wallet), mode: await stmt('enforce', d, wallet) })
}
const go = async (p: Promise<unknown>) => p.then(() => 'SENT', e => `refused:${e.name}:${e.message}`)
const sdkNew = (extra: Record<string, unknown> = {}) => new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: allowAll, ...extra })
/** a Base node for a viem client: base fee as given; `broadcast` decides what eth_sendRawTransaction does */
const node = (sent: string[], baseFee: bigint, broadcast: (raw: string) => unknown = () => undefined) => custom({ request: async ({ method, params }: any) => {
  if (method === 'eth_sendRawTransaction') { const x = broadcast(params[0]); if (x instanceof Error) throw x; sent.push(params[0]); return keccak256(params[0]) }
  if (method === 'eth_getBlockByNumber') return { baseFeePerGas: `0x${baseFee.toString(16)}`, number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }
  return ({ eth_chainId: '0x2105', eth_getTransactionCount: '0x7', eth_estimateGas: '0x5208', eth_gasPrice: '0x1', eth_maxPriorityFeePerGas: '0x1', eth_getCode: '0x' } as any)[method] ?? null
} })

type Sign = (tx: any, pk: ReturnType<typeof privateKeyToAccount>) => Promise<unknown>
/** an AgentKit-shaped provider with the given signTransaction, a public client that broadcasts, and its own sendTransaction */
function provider(pk: ReturnType<typeof privateKeyToAccount>, sign: Sign, o: { sendFails?: () => Error | undefined } = {}) {
  const raw: Hex[] = [], sentTx: any[] = [], signCalls: any[] = []
  const pc = {
    getTransactionCount: async () => 7,
    getBlock: async () => ({ baseFeePerGas: 1n }),
    estimateGas: async () => 21000n,
    estimateFeesPerGas: async () => ({ maxFeePerGas: 3n, maxPriorityFeePerGas: 1n }),
    sendRawTransaction: async ({ serializedTransaction }: any) => { raw.push(serializedTransaction); return `0x${'cc'.repeat(32)}` as Hex },
  }
  return {
    raw, sentTx, signCalls,
    getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), getPublicClient: () => pc,
    signTransaction: async (tx: any) => { signCalls.push(tx); return sign(tx, pk) },
    sendTransaction: async (tx: any) => { const e = o.sendFails?.(); if (e) throw e; sentTx.push(tx); return `0x${'dd'.repeat(32)}` as Hex },
    nativeTransfer: async () => { throw new Error('the provider\'s own nativeTransfer is never called') },
  }
}
/** AgentKit 0.10.4 ViemWalletProvider.signTransaction (PrivyEvmWalletProvider inherits it): only to, value and data */
const agentKitViem: Sign = (tx, pk) => createWalletClient({ account: pk, chain: base, transport: node([], 1n) }).signTransaction({ account: pk, chain: base, to: tx.to, value: tx.value, data: tx.data } as any)
/** LegacyCdpWalletProvider.signTransaction: a bare signature over the transaction's hash, not a signed transaction */
const legacyCdp: Sign = (tx, pk) => pk.sign({ hash: keccak256(serializeTransaction({ ...tx, type: 'eip1559' })) })
/** a signer that signs to, value and data but picks its own position and fees */
const ownNonce: Sign = (tx, pk) => pk.signTransaction({ chainId: 8453, to: tx.to, value: tx.value, data: tx.data, nonce: 0, gas: 21000n, maxFeePerGas: 3n, maxPriorityFeePerGas: 1n })
const smartWallet: Sign = async () => { throw new Error('Direct transaction signing not supported for smart wallets. Use sendTransaction instead.') }
const legacySmartWallet: Sign = async () => { throw new Error('Not implemented') }

for (const [name, sign] of [['AgentKit viem provider (and Privy server wallets)', agentKitViem], ['legacy CDP (bare signature)', legacyCdp], ['a signer that picks its own nonce', ownNonce], ['CDP smart wallet', smartWallet], ['legacy CDP smart wallet', legacySmartWallet]] as const) {
  test(`fallback, ${name}: the send goes through the provider's own sendTransaction with the checked, bounded fields; nothing it signed is broadcast`, async () => {
    const pk = privateKeyToAccount(generatePrivateKey())
    const p = provider(pk, sign), g: any = sdkNew().guardWalletProvider(p)
    assert.equal(await g.sendTransaction({ to: TO, value: 5n, data: '0x' }), `0x${'dd'.repeat(32)}`)
    assert.equal(p.raw.length, 0)
    const t = p.sentTx[0]
    assert.equal(t.to.toLowerCase(), TO.toLowerCase()); assert.equal(t.value, 5n); assert.equal(t.nonce, 7); assert.equal(t.chainId, 8453)
    assert.equal(t.gas, 21000n); assert.equal(t.maxFeePerGas, 3n); assert.equal(t.maxPriorityFeePerGas, 1n)
    assert.deepEqual(Object.keys(t).sort(), ['chainId', 'data', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'to', 'value'])
    // nativeTransfer takes the same way; and once seen, the provider is not asked to sign again
    assert.equal(await g.nativeTransfer(TO, '9'), `0x${'dd'.repeat(32)}`)
    assert.equal(p.sentTx.at(-1).value, 9n); assert.equal(p.raw.length, 0)
    assert.equal(p.signCalls.length, 1)
    // the fallback is still fee-bounded
    assert.match(await go(g.sendTransaction({ to: TO, value: 5n, data: '0x', gas: 21000n, maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 1n })), /^refused:OathlineBlocked/)
    assert.equal(p.sentTx.length, 2)
  })
}

test('no fallback: a signature for another recipient is still a block, and a refusal by the user is not a reason to send another way', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const swap = provider(pk, (tx, k) => k.signTransaction({ ...tx, to: EVIL, chainId: 8453 }))
  assert.match(await go(sdkNew().guardWalletProvider(swap).sendTransaction({ to: TO, value: 5n, data: '0x' })), /^refused:OathlineBlocked/)
  assert.equal(swap.raw.length + swap.sentTx.length, 0)
  const no = provider(pk, async () => { throw Object.assign(new Error('User rejected the request.'), { code: 4001 }) })
  assert.match(await go(sdkNew().guardWalletProvider(no).sendTransaction({ to: TO, value: 5n, data: '0x' })), /rejected/)
  assert.equal(no.raw.length + no.sentTx.length, 0)
})

test('a provider that signs every field is still signed, compared and broadcast by the SDK (no fallback)', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const p = provider(pk, (tx, k) => k.signTransaction(tx))
  assert.equal(await sdkNew().guardWalletProvider(p).sendTransaction({ to: TO, value: 5n, data: '0x' }), `0x${'cc'.repeat(32)}`)
  assert.equal(p.raw.length, 1); assert.equal(p.sentTx.length, 0)
})
