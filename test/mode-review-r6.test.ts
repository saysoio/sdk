// Independent review round 6 (27 Oct). The FINDING tests showed each bypass; flipped, they assert it is closed. CONTROL tests
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
const calibur = (w: Address) => ({ domain: { name: 'Calibur', version: '1.0.0', chainId: 8453, verifyingContract: '0x000000009b1d0af20d8c6d0a44e162d11f9b8f00' }, types: { SignedBatchedCall: [{ name: 'x', type: 'uint256' }] }, primaryType: 'SignedBatchedCall', message: { x: 1n } })
const delegatedCode = async () => `0xef0100${'ab'.repeat(20)}`

test('M1: an unsigned walletKind:"plain" injected into a check answer changes nothing; the EIP-7702 refusal holds', async () => {
  const fetch = enforceServer(W, b => ({ ...b, walletKind: 'plain' }))
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch, signatures: 'allow' })
  await g.gate(W, { to: TO, data: '0x', value: 1n, nonce: 1 })   // an honest allow, plus the MITM's unsigned field
  assert.equal(await go(g.gateSignature('typed data', 'Calibur batch', { wallet: W, typedData: calibur(W), code: delegatedCode })), 'refused:OathlineBlocked')
})
test('CONTROL M1: without the injected field the node says delegated and the Calibur batch is refused', async () => {
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W, b => { const { walletKind: _k, ...r } = b; return r }), signatures: 'allow' })
  await g.gate(W, { to: TO, data: '0x', value: 1n, nonce: 1 })
  assert.equal(await go(g.gateSignature('typed data', 'Calibur batch', { wallet: W, typedData: calibur(W), code: delegatedCode })), 'refused:OathlineBlocked')
})

test('M2: the guarded client\'s request door is an allow list: methods that sign or send but are not routed through the gate are refused (enforce)', async () => {
  const seen: string[] = []
  const transport = custom({ request: async ({ method }: any) => { seen.push(method); if (method === 'eth_chainId') return '0x2105'; return '0x' + '11'.repeat(32) } })
  const raw = createWalletClient({ account: W, chain: base, transport })
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W) })
  const guarded: any = g.guard(raw as any)
  for (const method of ['personal_sendTransaction', 'personal_signTransaction', 'eth_signTypedData_v2', 'wallet_signTypedData', 'eth_sendUnsignedTransaction'])
    assert.equal(await go(guarded.request({ method, params: [{ from: W, to: TO, value: '0xde0b6b3a7640000' }, ''] })), 'refused:OathlineBlocked', method)
  assert.deepEqual(seen.filter(m => m !== 'eth_chainId'), [])
  // control: a listed method is refused
  assert.equal(await go(guarded.request({ method: 'eth_sendTransaction', params: [{ from: W, to: TO }] })), 'refused:OathlineBlocked')
})

test('M3: a wrapped provider refuses every method it does not know, e.g. a smart-wallet sendUserOperation (enforce)', async () => {
  let sent = 0
  const provider = { getAddress: () => W, sendTransaction: async () => '0x' as Hex, sendUserOperation: async (_: any) => { sent++; return '0xop' }, sendBatch: async () => { sent++; return '0x' } }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W) })
  const p: any = g.guardWalletProvider(provider)
  assert.equal(await go(Promise.resolve().then(() => p.sendUserOperation({ calls: [{ to: TO, value: 10n ** 18n, data: '0x' }] }))), 'refused:OathlineBlocked')
  assert.equal(await go(Promise.resolve().then(() => p.sendBatch())), 'refused:OathlineBlocked')
  assert.equal(sent, 0)
  assert.equal(p.getAddress(), W)                                                       // reads pass
})

test('L1: toSigner() hands out a gated signer: its transactions go through the check, even with signatures:"allow" (enforce)', async () => {
  let rawTx = 0
  const pk = privateKeyToAccount(generatePrivateKey())                                 // round 8: the signed bytes are decoded, so the fake signs for real
  const provider = { getAddress: () => pk.address, sendTransaction: async () => '0x' as Hex, toSigner: () => ({ address: pk.address, signTransaction: async (tx: any) => { rawTx++; return pk.signTransaction({ gas: 21000n, gasPrice: 1n, ...tx }) } }) }
  const checks: string[] = []
  const honest = enforceServer(pk.address), counting = (async (u: string, i: any) => { if (u.endsWith('/check')) checks.push(JSON.parse(i.body).tx.to); return honest(u, i) }) as any
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: counting, signatures: 'allow' })
  const s = (g.guardWalletProvider(provider) as any).toSigner()
  assert.equal(s.address, pk.address)
  await s.signTransaction({ to: TO, value: 10n ** 18n })                               // the honest server allows it
  assert.equal(rawTx, 1); assert.deepEqual(checks, [TO])                              // ...after the check
})

test('SHADOW usability: toSigner() works in shadow (AgentKit actions such as x402 call it); its messages ask sayso for the mode', async () => {
  const shadowFetch = async (url: string, init: any) => { const b = JSON.parse(init?.body ?? '{}'); return url.endsWith('/mode') ? json(200, { wallet: W, mode: await stmt('shadow', modeQueryDigest(W, b.nonce, 8453)) }) : json(200, { ok: true }) }
  let signed = 0
  const provider = { getAddress: () => W, sendTransaction: async () => '0x' as Hex, toSigner: () => ({ address: W, signMessage: async () => { signed++; return '0xsig' }, exportKey: () => 'secret' }) }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: shadowFetch })
  const s = (g.guardWalletProvider(provider) as any).toSigner()
  assert.equal(await s.signMessage({ message: 'hi' }), '0xsig')                         // shadow, signed for this call: goes ahead
  assert.equal(signed, 1)
  assert.throws(() => s.exportKey, OathlineBlocked)                                    // no other function is handed out
  assert.equal(s.somethingElse, undefined)                                              // what is not there stays not there (round 7)
})

test('M2 enumerated: reads pass the request door; signing goes through the gate; everything else is refused', async () => {
  const seen: string[] = []
  const transport = custom({ request: async ({ method }: any) => { seen.push(method); return method === 'eth_chainId' ? '0x2105' : '0x1' } })
  const g: any = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W) }).guard(createWalletClient({ account: W, chain: base, transport }) as any)
  const reads = ['eth_call', 'eth_getBalance', 'eth_chainId', 'eth_blockNumber', 'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory', 'eth_getTransactionReceipt', 'eth_getTransactionByHash', 'eth_getTransactionCount', 'eth_getCode', 'eth_getBlockByNumber', 'eth_getLogs']
  for (const method of reads) assert.equal(await go(g.request({ method, params: [] })), 'SIGNED', method)
  assert.deepEqual(seen.filter(m => reads.includes(m)).sort(), [...reads].sort())
  const refused = ['personal_sendTransaction', 'personal_signTransaction', 'eth_signTypedData_v2', 'wallet_signTypedData', 'eth_sendUnsignedTransaction', 'eth_sendUserOperation', 'wallet_sendUserOperation', 'wallet_somethingNew', 'eth_sendTransaction', 'eth_sendRawTransaction', 'wallet_sendCalls', 'eth_signTransaction', 'personal_sign', 'eth_sign', 'eth_signTypedData_v4']
  const before = seen.length
  for (const method of refused) assert.match(await go(g.request({ method, params: [W, '0x00'] })), /^refused:/, method)
  assert.deepEqual(seen.slice(before).filter(m => m !== 'eth_getCode'), [], 'none reached the node')
})
