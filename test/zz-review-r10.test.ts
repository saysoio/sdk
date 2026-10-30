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
test('r10: provider without a node, caller names a huge maxFeePerGas and no gas', async () => {
  const got: any[] = []
  const provider = { getAddress: () => W, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async (t: any) => { got.push(t); return '0xhash' as Hex } }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W) })
  const p: any = g.guardWalletProvider(provider)
  const noNode = await go(p.sendTransaction({ to: TO, value: 1n, maxFeePerGas: 10n ** 15n, maxPriorityFeePerGas: 10n ** 15n }))
  console.log('r10 no node:', noNode, got.map(t => String(t.maxFeePerGas)))
  assert.equal(noNode, 'refused:OathlineBlocked'); assert.equal(got.length, 0)
  const pc = { getBlock: async () => ({ baseFeePerGas: 10_000_000n }), estimateGas: async () => { throw new Error('reverts') }, estimateFeesPerGas: async () => ({ maxFeePerGas: 1n, maxPriorityFeePerGas: 1n }) }
  const p2: any = g.guardWalletProvider({ ...provider, getPublicClient: () => pc })
  const noGas = await go(p2.sendTransaction({ to: TO, value: 1n, maxFeePerGas: 10n ** 15n, maxPriorityFeePerGas: 10n ** 15n }))
  console.log('r10 estimateGas fails:', noGas, got.map(t => String(t.maxFeePerGas)))
  assert.equal(noGas, 'refused:OathlineBlocked'); assert.equal(got.length, 0)
  // a modest fee the SDK can bound per gas, but no gas limit to bound the total: refused too (fail closed)
  assert.equal(await go(p2.sendTransaction({ to: TO, value: 1n, maxFeePerGas: 10n ** 7n, maxPriorityFeePerGas: 1n })), 'refused:OathlineBlocked')
  // control: the same with a gas limit named passes, with exactly those fields
  assert.equal(await go(p2.sendTransaction({ to: TO, value: 1n, gas: 21000n, maxFeePerGas: 10n ** 7n, maxPriorityFeePerGas: 1n })), 'SIGNED')
  const sent: any[] = got; assert.equal(sent.length, 1); assert.equal(sent[0].maxFeePerGas, 10n ** 7n); assert.equal(sent[0].gas, 21000n)
})
