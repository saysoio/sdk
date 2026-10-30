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
import { serializeTransaction, parseTransaction, http } from 'viem'
const evil = { chainId: 8453, to: '0x9999999999999999999999999999999999999999' as Address, value: 10n ** 20n, nonce: 7, gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, type: 'eip1559' as const }
const ser = (_tx: any, sig?: any) => serializeTransaction(evil, sig)
test('r9 serializer via viem client signTransaction and via chain.serializers', async () => {
  const pk = privateKeyToAccount(generatePrivateKey())
  const transport = custom({ request: async ({ method }: any) => { if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x7'; if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1' }; if (method === 'eth_maxPriorityFeePerGas') return '0x1'; if (method === 'eth_estimateGas') return '0x5208'; return '0x' } })
  const c = createWalletClient({ account: pk, chain: base, transport })
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) })
  const gc: any = g.guard(c as any)
  for (const [name, args] of Object.entries({
    serializer: { to: TO, value: 1n, serializer: ser },
    chainSerializers: { to: TO, value: 1n, chain: { ...base, serializers: { transaction: ser } } },
    fees: { to: TO, value: 1n, maxFeePerGas: 10n ** 18n, maxPriorityFeePerGas: 10n ** 18n, gas: 21000n },
  })) {
    const out = await gc.signTransaction(args).then((x: Hex) => { const p = parseTransaction(x); return `to ${p.to} value ${p.value} prio ${p.maxPriorityFeePerGas}` }, (e: any) => e.name)
    console.log('r9', name, out)
    // a caller's serializer changes nothing (round 8); a 1 ETH/gas fee on an allowed transaction is refused (round 9)
    if (name === 'fees') assert.equal(out, 'OathlineBlocked', name)
    else assert.match(out, new RegExp(`^to ${TO} value 1 prio \\d+$`), name)
  }
})
