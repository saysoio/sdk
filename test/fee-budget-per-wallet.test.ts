// #69 review (27 Oct): the hourly fee budget belongs to the wallet, not to one SDK object, is charged only when the bytes
// are released or broadcast, and is given back when the node definitely refused them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createWalletClient, custom, keccak256, type Address, type Hex } from 'viem'
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
/** a provider that cannot sign without sending (EIP-1193 4200) */
const cannotSign: Sign = async () => { throw Object.assign(new Error('unsupported method'), { code: 4200 }) }

const BIG = { gas: 200_000n, maxFeePerGas: 40n * GWEI, maxPriorityFeePerGas: GWEI }   // 0.008 ETH each at most; 2 fit in 0.02
const client = (o: any, pk: ReturnType<typeof privateKeyToAccount>, sent: string[], broadcast?: (raw: string) => unknown) =>
  o.guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 10n * GWEI, broadcast) }) as any)

test('fee budget: two SDK objects guarding the same wallet share one hourly budget', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const a = client(sdkNew(), pk, sent), b = client(sdkNew(), pk, sent)
  assert.equal(await go(a.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.equal(await go(b.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.match(await go(b.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
  assert.match(await go(a.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
  assert.equal(sent.length, 2)
})

test('fee budget: one SDK object guarding two wallets keeps a budget for each', async () => {
  const o = sdkNew(), sent: string[] = []
  const a = client(o, privateKeyToAccount(generatePrivateKey()), sent), b = client(o, privateKeyToAccount(generatePrivateKey()), sent)
  for (const g of [a, a, b, b]) assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.match(await go(b.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
  assert.equal(sent.length, 4)
})

test('fee budget: a broadcast the node definitely refused is given back', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  let fails = 3
  const g = client(sdkNew(), pk, sent, () => (fails-- > 0 ? Object.assign(new Error('insufficient funds for gas * price + value'), { code: -32000 }) : undefined))
  for (let i = 0; i < 3; i++) assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /insufficient funds/)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
})

test('fee budget: a failure that may have reached the network keeps its charge (a lost answer, "already known")', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const errs = [new Error('fetch failed'), Object.assign(new Error('already known'), { code: -32000 })]
  const g = client(sdkNew(), pk, sent, () => errs.shift())
  assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /^refused/)
  assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /^refused/)
  assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
  assert.equal(sent.length, 0)
})

test('fee budget: a released signature is charged; a signature that is dropped (not the checked transaction) is not', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g = client(sdkNew(), pk, sent)
  assert.equal(await go(g.signTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  // a provider on the same wallet whose signature names another recipient: dropped, nothing charged
  const swap = provider(pk, (tx, k) => k.signTransaction({ ...tx, ...BIG, to: EVIL, chainId: 8453 }))
  const gs: any = sdkNew().guardWalletProvider(swap)
  for (let i = 0; i < 3; i++) assert.match(await go(gs.sendTransaction({ to: TO, value: 1n, data: '0x', ...BIG })), /not the one sayso checked/)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), 'SENT')
  assert.match(await go(g.sendTransaction({ to: TO, value: 1n, ...BIG })), /hour/)
})

test('fee budget: a provider fallback send the node definitely refused is given back', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  let fails = 3
  const p = provider(pk, cannotSign, { sendFails: () => (fails-- > 0 ? Object.assign(new Error('nonce too high'), { code: -32003 }) : undefined) })
  const big = { gas: 200_000n, maxFeePerGas: 2n * GWEI, maxPriorityFeePerGas: GWEI }   // 0.0004 ETH at most; 2 fit
  const o = sdkNew({ fees: { hourlyFeeWei: 2n * 200_000n * 2n * GWEI } })
  const gs: any = o.guardWalletProvider(p)
  for (let i = 0; i < 3; i++) assert.match(await go(gs.sendTransaction({ to: TO, value: 1n, data: '0x', ...big })), /nonce too high/)
  assert.equal(await go(gs.sendTransaction({ to: TO, value: 1n, data: '0x', ...big })), 'SENT')
  assert.equal(await go(gs.sendTransaction({ to: TO, value: 1n, data: '0x', ...big })), 'SENT')
  assert.match(await go(gs.sendTransaction({ to: TO, value: 1n, data: '0x', ...big })), /hour/)
  assert.equal(p.sentTx.length, 2)
})
