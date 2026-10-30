// Independent review round 7 (27 Oct): the gated signer takes the same checks as the provider path (another chain, a
// deployment, both spellings of an authorization list), viem can build a client on it, and the request door lets the
// read-only filter and subscription methods through. The probes printed what happened; now they assert it.
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
import { publicActions } from 'viem'
import { toAccount } from 'viem/accounts'
const shadowFetch = async (url: string, init: any) => { const b = JSON.parse(init?.body ?? '{}'); return url.endsWith('/mode') ? json(200, { wallet: W, mode: await stmt('shadow', modeQueryDigest(W, b.nonce, 8453)) }) : url.includes('/wallets/') ? json(404, {}) : json(200, { ok: true }) }
function rpc(seen: string[]) { return custom({ request: async ({ method }: any) => { seen.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_blockNumber') return '0x10'; return method.startsWith('eth_new') ? '0x1' : [] } }) }

test('door tricks: case, whitespace, batch array, non-string method are refused', async () => {
  const seen: string[] = []
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(W) })
  const c: any = g.guard(createWalletClient({ account: W, chain: base, transport: rpc(seen) }) as any)
  for (const req of [{ method: 'ETH_SENDTRANSACTION' }, { method: ' eth_call' }, [{ method: 'eth_sendTransaction' }], { method: ['eth_call'] }, { method: { toString: () => 'eth_call' } }, { method: 'eth_call\u0000' }]) {
    assert.match(await go(c.request(req)), /^refused:/, JSON.stringify(req)); assert.match(await go(c.transport.request(req)), /^refused:/, JSON.stringify(req))
  }
  assert.deepEqual(seen, [], 'nothing reached the transport')
})

test('SHADOW usability: public reads added after guard() through the door', async () => {
  const seen: string[] = []
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: shadowFetch })
  const c: any = g.guard(createWalletClient({ account: W, chain: base, transport: rpc(seen) }) as any).extend(publicActions)
  const calls: Record<string, () => Promise<unknown>> = {
    createEventFilter: () => c.createEventFilter(), createBlockFilter: () => c.createBlockFilter(), getBlockReceipts: () => c.getBlockReceipts({ blockNumber: 1n }),
    simulateCalls: () => c.simulateCalls({ calls: [{ to: TO }] }), requestAddresses: () => c.requestAddresses(), getPermissions: () => c.getPermissions(),
    fillTransaction: () => c.fillTransaction({ to: TO }), byIndex: () => c.request({ method: 'eth_getTransactionByBlockNumberAndIndex', params: ['0x1', '0x0'] }),
    ethSubscribe: () => c.request({ method: 'eth_subscribe', params: ['newHeads'] }), switchEth: () => c.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x2105' }] }),
    getLogs: () => c.getLogs(), getBalance: () => c.getBalance({ address: W }),
  }
  const out: Record<string, string> = {}
  for (const [k, f] of Object.entries(calls)) out[k] = await f().then(() => 'ok', e => e.name)
  for (const k of ['createEventFilter', 'createBlockFilter', 'getBlockReceipts', 'byIndex', 'ethSubscribe', 'getLogs', 'getBalance']) assert.equal(out[k], 'ok', k)
  assert.ok(seen.includes('eth_simulateV1'), 'eth_simulateV1 reached the node (the stub answers nothing viem can parse)')
  assert.match(out.switchEth, /OathlineBlocked/)                                      // switching the wallet's chain stays refused
})

test('toSigner(): another chainId, no to, snake authorization_list; nonceManager read', async () => {
  const signed: any[] = []
  const pk = privateKeyToAccount(generatePrivateKey())                                 // round 8: the signed bytes are decoded, so the fake signs for real
  const raw = toAccount({ address: pk.address, signMessage: async () => '0x', signTypedData: async () => '0x', signTransaction: async (tx: any, o?: any) => { signed.push(tx); return pk.signTransaction({ gas: 21000n, gasPrice: 1n, ...tx }, o) } })
  const provider = { getAddress: () => pk.address, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async () => '0x' as Hex, toSigner: () => raw }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch: enforceServer(pk.address) })
  const s: any = (g.guardWalletProvider(provider) as any).toSigner()
  assert.equal(await go(s.signTransaction({ to: TO, value: 10n ** 18n, chainId: 1, nonce: 3 })), 'refused:OathlineBlocked')   // another chain
  assert.equal(await go(s.signTransaction({ data: '0x6000', nonce: 4 })), 'refused:OathlineBlocked')                           // a deployment
  assert.equal(await go(s.signTransaction({ to: TO, nonce: 5, authorization_list: [{}] })), 'refused:OathlineBlocked')         // snake_case
  assert.equal(await go(s.signTransaction({ to: TO, nonce: 6, authorizationList: [{}] })), 'refused:OathlineBlocked')          // camelCase
  assert.deepEqual(signed, [])
  // an allowed one is signed for the checked chain whatever it asked for
  assert.equal(await go(s.signTransaction({ to: TO, value: 1n, nonce: 7 })), 'SIGNED'); assert.equal((signed as any[])[0].chainId, 8453)
  assert.equal(s.nonceManager, undefined)                                               // viem reads it on every account
  const node = custom({ request: async ({ method }: any) => ({ eth_chainId: '0x2105', eth_getTransactionCount: '0x8', eth_estimateGas: '0x5208', eth_gasPrice: '0x1', eth_maxPriorityFeePerGas: '0x1', eth_getBlockByNumber: { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }, eth_sendRawTransaction: `0x${'aa'.repeat(32)}` } as any)[method] ?? null })
  const wc: any = createWalletClient({ account: s, chain: base, transport: node })
  assert.equal(await wc.sendTransaction({ to: TO, value: 1n }), `0x${'aa'.repeat(32)}`)  // checked (honest allow), signed, sent
})
