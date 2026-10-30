// Review round 9 follow-up (27 Oct). (1) Gas fees: an allowed transaction must not carry a fee that burns the balance to
// the sequencer. Every signed transaction is decoded and its fee bounded (maxFeePerGas or gasPrice at most a multiple of
// the latest base fee, with a floor, and gas × that fee under an absolute ceiling). (2) Sends that were not decoded: a
// JSON-RPC wallet's sendTransaction, a provider's sendTransaction and nativeTransfer now sign first, decode and compare,
// and broadcast the bytes themselves; a wallet that cannot sign without sending gets exactly the checked fields.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createWalletClient, custom, parseTransaction, type Address, type Hex } from 'viem'
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
/** an honest sayso whose owner is on ENFORCE and who allows everything; records what it checked */
function allowAll(wallet: Address, checked: any[] = []) {
  return async (url: string, init: any) => {
    if (url.endsWith('/unchecked')) return json(200, { ok: true })
    if (url.includes('/wallets/')) return json(200, { kind: 'plain' })
    const b = JSON.parse(init.body)
    if (url.endsWith('/mode')) return json(200, { wallet, mode: await stmt('enforce', modeQueryDigest(wallet, b.nonce, 8453), wallet) })
    checked.push(b.tx)
    const d = txDigest({ wallet, to: b.tx.to, data: b.tx.data, value: b.tx.value !== undefined ? BigInt(b.tx.value) : undefined, nonce: b.tx.nonce }, 8453)
    return json(200, { verdict: 'allow', reason: 'ok', receipt: await receipt('allow', d, wallet), mode: await stmt('enforce', d, wallet) })
  }
}
const go = async (p: Promise<unknown>) => p.then(() => 'SIGNED', e => `refused:${e.name}`)
const sdkFor = (wallet: Address, extra: Record<string, unknown> = {}, checked: any[] = []) => new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: allowAll(wallet, checked), ...extra })
const block = (baseFee: bigint) => ({ baseFeePerGas: `0x${baseFee.toString(16)}`, number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` })
/** a node: base fee as given (null: it cannot be read), records what was broadcast */
const node = (sent: string[], baseFee: bigint | null = 1n, extra: (m: string, p: any[]) => unknown = () => undefined) => custom({ request: async ({ method, params }: any) => {
  const x = await extra(method, params); if (x !== undefined) return x
  if (method === 'eth_sendRawTransaction' || method === 'eth_sendRawTransactionSync') { sent.push(params[0]); return `0x${'aa'.repeat(32)}` }
  if (method === 'eth_getBlockByNumber') { if (baseFee === null) throw new Error('no block'); return block(baseFee) }
  return ({ eth_chainId: '0x2105', eth_getTransactionCount: '0x7', eth_estimateGas: '0x5208', eth_gasPrice: '0x1', eth_maxPriorityFeePerGas: '0x1' } as any)[method] ?? null
} })
const big = (v: unknown) => (v === undefined || v === null ? undefined : BigInt(v as string))
/** a JSON-RPC wallet that signs on eth_signTransaction with pk, filling any fee it was not given with `fill` */
const rpcSigner = (pk: ReturnType<typeof privateKeyToAccount>, fill: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } = { maxFeePerGas: 3n, maxPriorityFeePerGas: 1n }) => async (method: string, params: any[]) => {
  if (method !== 'eth_signTransaction') return undefined
  const t = params[0]
  return pk.signTransaction({ chainId: Number(t.chainId), to: t.to, value: big(t.value) ?? 0n, data: t.data ?? t.input, nonce: Number(t.nonce ?? 7), gas: big(t.gas) ?? 21000n, maxFeePerGas: big(t.maxFeePerGas) ?? fill.maxFeePerGas, maxPriorityFeePerGas: big(t.maxPriorityFeePerGas) ?? fill.maxPriorityFeePerGas, type: 'eip1559' })
}

// ---------------------------------------------------------------- (1) fees

test('fees, local account: a 1 ETH/gas fee on an allowed transaction is refused on every path and nothing is sent; prepared fees pass', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk, chain: base, transport: node(sent) }) as any)
  const burn = { maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 10n ** 18n, gas: 21000n }
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...burn })), 'refused:OathlineBlocked')
  assert.equal(await go(g.signTransaction({ to: TO, value: 1n, ...burn })), 'refused:OathlineBlocked')
  assert.equal(await go(g.writeContract({ address: TO, abi: [{ type: 'function', name: 'f', inputs: [], outputs: [], stateMutability: 'payable' }], functionName: 'f', value: 1n, ...burn })), 'refused:OathlineBlocked')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gasPrice: 10n ** 18n, gas: 21000n })), 'refused:OathlineBlocked')   // legacy too
  assert.deepEqual(sent, [])
  await g.sendTransaction({ to: TO, value: 1n })                                       // the client's own estimate passes
  assert.equal(sent.length, 1)
})

test('fees: the per-gas bound is 4x the base fee plus 2 gwei of priority fee, and gas x fee has an absolute ceiling (0.01 ETH by default)', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const busy: any = sdkFor(pk.address).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 10n * GWEI) }) as any)
  assert.equal(await go(busy.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 42n * GWEI, maxPriorityFeePerGas: GWEI })), 'SIGNED')
  assert.equal(await go(busy.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 42n * GWEI + 1n, maxPriorityFeePerGas: GWEI })), 'refused:OathlineBlocked')
  // within the per-gas bound, but 1M gas x 40 gwei = 0.04 ETH of fee
  assert.equal(await go(busy.sendTransaction({ to: TO, value: 1n, gas: 1_000_000n, maxFeePerGas: 40n * GWEI, maxPriorityFeePerGas: GWEI })), 'refused:OathlineBlocked')
  // the builder can set the bounds in code
  const loose: any = sdkFor(pk.address, { fees: { maxFeeWei: 10n ** 17n, hourlyFeeWei: 10n ** 18n } }).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 10n * GWEI) }) as any)
  assert.equal(await go(loose.sendTransaction({ to: TO, value: 1n, gas: 1_000_000n, maxFeePerGas: 40n * GWEI, maxPriorityFeePerGas: GWEI })), 'SIGNED')
  // a quiet chain: the priority allowance applies, and the priority fee itself is bounded (another wallet: the hourly
  // budget is per wallet since #69's review, and the loose object above spent 0.04 ETH of this one's)
  const pk2 = privateKeyToAccount(generatePrivateKey())
  const quiet: any = sdkFor(pk2.address).guard(createWalletClient({ account: pk2, chain: base, transport: node(sent, 1n) }) as any)
  assert.equal(await go(quiet.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 2n * GWEI, maxPriorityFeePerGas: 2n * GWEI })), 'SIGNED')
  assert.equal(await go(quiet.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 2n * GWEI + 5n, maxPriorityFeePerGas: 2n * GWEI + 1n })), 'refused:OathlineBlocked')
  assert.equal(sent.length, 3)
})

test('fees: when the base fee cannot be read, only the priority allowance counts (a node that hides the block cannot raise the bound)', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, null) }) as any)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, nonce: 7 })), 'SIGNED')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 3n * GWEI, maxPriorityFeePerGas: 1n, nonce: 7 })), 'refused:OathlineBlocked')
  assert.equal(sent.length, 1)
})

test('fees: the options are validated', () => {
  for (const fees of [{ maxFeeMultiple: 0.5 }, { maxFeeMultiple: Number.NaN }, { maxFeeWei: 0n }, { maxFeeWei: 5 }, { maxPriorityFeePerGas: -1n }, { hourlyFeeWei: 0n }])
    assert.throws(() => new Oathline({ apiUrl: 'http://x', apiKey: 'k', fees }), /fees/, JSON.stringify(fees, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)))
})

test('fees: a JSON-RPC wallet that fills in a burning fee itself is refused; so are a provider and toSigner() that sign one', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const greedy = { maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 10n ** 18n }
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk.address, chain: base, transport: node(sent, 1n, rpcSigner(pk, greedy)) }) as any)
  assert.equal(await go(g.signTransaction({ to: TO, value: 1n })), 'refused:OathlineBlocked')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n })), 'refused:OathlineBlocked')
  assert.deepEqual(sent, [])
  const burn = { gas: 21000n, ...greedy, type: 'eip1559' as const }
  const provider = { getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async () => '0x' as Hex, signTransaction: async (tx: any) => pk.signTransaction({ ...burn, ...tx, chainId: 8453 }), toSigner: () => pk }
  const p: any = sdkFor(pk.address).guardWalletProvider(provider)
  assert.equal(await go(p.signTransaction({ to: TO, value: 1n, nonce: 7 })), 'refused:OathlineBlocked')
  assert.equal(await go(p.toSigner().signTransaction({ to: TO, value: 1n, nonce: 7, ...burn })), 'refused:OathlineBlocked')
})

// ---------------------------------------------------------------- (2) sends

test('JSON-RPC wallet with eth_signTransaction: a send is signed, decoded, compared and broadcast raw; eth_sendTransaction is never used', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = [], methods: string[] = []
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk.address, chain: base, transport: node(sent, 1n, (m, p) => { methods.push(m); return rpcSigner(pk)(m, p) }) }) as any)
  assert.equal(await g.sendTransaction({ to: TO, value: 5n }), `0x${'aa'.repeat(32)}`)
  assert.equal(await g.writeContract({ address: TO, abi: [{ type: 'function', name: 'f', inputs: [], outputs: [], stateMutability: 'payable' }], functionName: 'f', value: 1n }), `0x${'aa'.repeat(32)}`)
  assert.equal(sent.length, 2)
  const p = parseTransaction(sent[0] as Hex); assert.equal(p.to?.toLowerCase(), TO.toLowerCase()); assert.equal(p.value, 5n); assert.equal(p.nonce, 7); assert.equal(p.chainId, 8453)
  assert.ok(!methods.includes('eth_sendTransaction'))
  // a wallet that signs something else: dropped, nothing broadcast
  const evil = async (m: string, prm: any[]) => (m === 'eth_signTransaction' ? rpcSigner(pk)(m, [{ ...prm[0], to: EVIL }]) : undefined)
  const sent2: string[] = []
  const bad: any = sdkFor(pk.address).guard(createWalletClient({ account: pk.address, chain: base, transport: node(sent2, 1n, evil) }) as any)
  assert.equal(await go(bad.sendTransaction({ to: TO, value: 5n })), 'refused:OathlineBlocked')
  assert.deepEqual(sent2, [])
})

test('JSON-RPC wallet without eth_signTransaction: the send goes out with exactly the checked fields, fees filled and bounded by the SDK', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  for (const unsupported of [{ code: 4200, message: 'The Provider does not support the requested method.' }, { code: -32601, message: 'the method eth_signTransaction does not exist/is not available' }]) {
    const sent: string[] = [], asked: any[] = [], checked: any[] = []
    const wallet = async (m: string, p: any[]) => {
      if (m === 'eth_signTransaction') throw Object.assign(new Error(unsupported.message), unsupported)
      if (m === 'eth_sendTransaction') { asked.push(p[0]); return `0x${'bb'.repeat(32)}` }
      return undefined
    }
    const g: any = sdkFor(pk.address, {}, checked).guard(createWalletClient({ account: pk.address, chain: base, transport: node(sent, 1n, wallet) }) as any)
    assert.equal(await g.sendTransaction({ to: TO, value: 5n }), `0x${'bb'.repeat(32)}`)
    assert.equal(asked.length, 1)
    const t = asked[0], c = checked.at(-1)
    assert.equal(t.to.toLowerCase(), c.to.toLowerCase()); assert.equal(BigInt(t.value), BigInt(c.value)); assert.equal(Number(t.nonce), c.nonce)   // the chain: viem asserts the wallet's own (eth_chainId) before sending
    for (const k of ['gas', 'maxFeePerGas', 'maxPriorityFeePerGas']) assert.ok(t[k] !== undefined, `${k} is sent, not left to the wallet`)
    assert.ok(BigInt(t.maxFeePerGas) <= GWEI / 10n)
    // a burning fee is refused before anything reaches the wallet
    assert.equal(await go(g.sendTransaction({ to: TO, value: 5n, gas: 21000n, maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 1n })), 'refused:OathlineBlocked')
    assert.equal(asked.length, 1)
  }
})

test('JSON-RPC wallet: any other signing error (the user said no) is not a reason to send unchecked', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = [], asked: any[] = []
  const wallet = async (m: string, p: any[]) => {
    if (m === 'eth_signTransaction') throw Object.assign(new Error('User rejected the request.'), { code: 4001 })
    if (m === 'eth_sendTransaction') { asked.push(p[0]); return `0x${'bb'.repeat(32)}` }
    return undefined
  }
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk.address, chain: base, transport: node(sent, 1n, wallet) }) as any)
  await assert.rejects(() => g.sendTransaction({ to: TO, value: 5n }), /rejected/i)
  assert.deepEqual(asked, []); assert.deepEqual(sent, [])
})

/** an AgentKit-like provider (viem provider shape): signs with pk, has a public client that broadcasts */
function provider(pk: ReturnType<typeof privateKeyToAccount>, o: { swap?: boolean; noSign?: boolean; noClient?: boolean; baseFee?: bigint } = {}) {
  const raw: Hex[] = [], sentTx: any[] = [], transfers: any[] = [], signed: any[] = []
  const pc = {
    getTransactionCount: async () => 7,
    getBlock: async () => ({ baseFeePerGas: o.baseFee ?? 1n }),
    estimateGas: async () => 21000n,
    estimateFeesPerGas: async () => ({ maxFeePerGas: 3n, maxPriorityFeePerGas: 1n }),
    sendRawTransaction: async ({ serializedTransaction }: any) => { raw.push(serializedTransaction); return `0x${'cc'.repeat(32)}` as Hex },
  }
  const p: any = {
    raw, sentTx, transfers, signed,
    getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }),
    sendTransaction: async (tx: any) => { sentTx.push(tx); return `0x${'dd'.repeat(32)}` as Hex },
    nativeTransfer: async (to: string, value: string) => { transfers.push({ to, value }); return `0x${'ee'.repeat(32)}` as Hex },
    waitForTransactionReceipt: async (hash: Hex) => ({ transactionHash: hash, status: 'success' }),
  }
  if (!o.noSign) p.signTransaction = async (tx: any) => { signed.push(tx); return pk.signTransaction({ gas: 21000n, maxFeePerGas: 3n, maxPriorityFeePerGas: 1n, ...tx, ...(o.swap ? { to: EVIL } : {}), chainId: 8453 }) }
  if (!o.noClient) p.getPublicClient = () => pc
  return p
}

test('provider sendTransaction: signed by the provider, decoded, compared and broadcast through its public client', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const p = provider(pk), g: any = sdkFor(pk.address).guardWalletProvider(p)
  assert.equal(await g.sendTransaction({ to: TO, value: 5n, data: '0x' }), `0x${'cc'.repeat(32)}`)
  assert.equal(p.sentTx.length, 0); assert.equal(p.raw.length, 1)
  const t = parseTransaction(p.raw[0]); assert.equal(t.to?.toLowerCase(), TO.toLowerCase()); assert.equal(t.value, 5n); assert.equal(t.nonce, 7)
  const s = provider(pk, { swap: true }), gs: any = sdkFor(pk.address).guardWalletProvider(s)
  assert.equal(await go(gs.sendTransaction({ to: TO, value: 5n, data: '0x' })), 'refused:OathlineBlocked')
  assert.equal(s.raw.length + s.sentTx.length, 0)
})

test('nativeTransfer: the checked amount is what is signed and broadcast; the provider\'s own nativeTransfer is never called', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), checked: any[] = []
  const p = provider(pk), g: any = sdkFor(pk.address, {}, checked).guardWalletProvider(p)
  assert.equal(await g.nativeTransfer(TO, '1000'), `0x${'cc'.repeat(32)}`)
  assert.equal(p.transfers.length, 0); assert.equal(p.raw.length, 1)
  const t = parseTransaction(p.raw[0]); assert.equal(t.value, 1000n); assert.equal(t.to?.toLowerCase(), TO.toLowerCase())
  assert.equal(checked.at(-1).value, '1000'); assert.equal(checked.at(-1).nonce, 7)
  const s = provider(pk, { swap: true })
  assert.equal(await go(sdkFor(pk.address).guardWalletProvider(s).nativeTransfer(TO, '1000')), 'refused:OathlineBlocked')
  assert.equal(s.raw.length + s.sentTx.length + s.transfers.length, 0)
})

test('provider that cannot sign without sending: its sendTransaction gets exactly the checked fields, fees filled from its node and bounded', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), checked: any[] = []
  const p = provider(pk, { noSign: true }), g: any = sdkFor(pk.address, {}, checked).guardWalletProvider(p)
  assert.equal(await g.sendTransaction({ to: TO, value: 5n, data: '0x' }), `0x${'dd'.repeat(32)}`)
  const t = p.sentTx[0]
  assert.equal(t.to.toLowerCase(), TO.toLowerCase()); assert.equal(t.value, 5n); assert.equal(t.nonce, 7); assert.equal(t.chainId, 8453)
  assert.equal(t.gas, 21000n); assert.equal(t.maxFeePerGas, 3n); assert.equal(t.maxPriorityFeePerGas, 1n)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 5n, data: '0x', gas: 21000n, maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 1n })), 'refused:OathlineBlocked')
  assert.equal(p.sentTx.length, 1)
  // nativeTransfer takes the same way
  assert.equal(await g.nativeTransfer(TO, '9'), `0x${'dd'.repeat(32)}`)
  assert.equal(p.transfers.length, 0); assert.equal(p.sentTx.at(-1).value, 9n)
  // a provider that has a signer but no node to broadcast through sends the same way (nothing decoded)
  const q = provider(pk, { noClient: true }), gq: any = sdkFor(pk.address).guardWalletProvider(q)
  assert.equal(await gq.sendTransaction({ to: TO, value: 5n, data: '0x' }), `0x${'dd'.repeat(32)}`)
  assert.equal(q.signed.length, 0); assert.equal(q.sentTx.length, 1)
})

// ---------------------------------------------------------------- (3) review round 10

test('r10 fees: a priority-fee spike of a normal agent passes (Base: 0.005 gwei base fee, 1.5 gwei priority)', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = []
  const g: any = sdkFor(pk.address).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 5_000_000n) }) as any)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 200_000n, maxFeePerGas: 1_510_000_000n, maxPriorityFeePerGas: 1_500_000_000n })), 'SIGNED')
})

test('r10 fees: the refusal says what to change', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = [], reasons: string[] = []
  const g: any = sdkFor(pk.address, { onDecision: (r: any, _t: any, d: string) => { if (d === 'refused') reasons.push(r.reason) } }).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 5_000_000n) }) as any)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 10n ** 12n, maxPriorityFeePerGas: 10n ** 12n })), 'refused:OathlineBlocked')
  assert.match(reasons.at(-1)!, /gwei/); assert.match(reasons.at(-1)!, /fees\.maxPriorityFeePerGas|fees\.maxFeeMultiple/)
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 20_000_000n, maxFeePerGas: GWEI, maxPriorityFeePerGas: GWEI })), 'refused:OathlineBlocked')
  assert.match(reasons.at(-1)!, /fees\.maxFeeWei/)
})

test('r10 fees: many max-fee transactions cannot add up past the hourly budget (0.02 ETH by default)', async () => {
  const pk = privateKeyToAccount(generatePrivateKey()), sent: string[] = [], reasons: string[] = []
  const g: any = sdkFor(pk.address, { onDecision: (r: any, _t: any, d: string) => { if (d === 'refused') reasons.push(r.reason) } }).guard(createWalletClient({ account: pk, chain: base, transport: node(sent, 10n * GWEI) }) as any)
  const big = { gas: 200_000n, maxFeePerGas: 40n * GWEI, maxPriorityFeePerGas: GWEI }   // 0.008 ETH each, at most
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...big })), 'SIGNED')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...big })), 'SIGNED')
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, ...big })), 'refused:OathlineBlocked')
  assert.match(reasons.at(-1)!, /hour/); assert.match(reasons.at(-1)!, /fees\.hourlyFeeWei/)
  assert.equal(sent.length, 2)
  // small ones still fit
  assert.equal(await go(g.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 11n * GWEI, maxPriorityFeePerGas: GWEI })), 'SIGNED')
})
