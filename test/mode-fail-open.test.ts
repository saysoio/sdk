// Adversarial review (27 Oct, round 3): which answers that are not a signed allow let a transaction through. The rule
// (setup fixes; Artem's decision of 27 Oct, as implemented after review round 5): the SDK goes ahead only on a signed
// allow for the exact transaction, or a signed shadow inside the same answer, bound to that request's nonce. Nothing is
// cached across requests; `mode: 'shadow'` in code opens nothing. Against main's SDK every "last seen shadow" row signed, stale or not
// (docs/reviews/2026-10-27-mode-fail-open.md).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import type { Address, Hex } from 'viem'
const sdk: any = await import('../src/index.js')
const { Oathline, OATHLINE_TYPES, oathlineDomain, txDigest, modeQueryDigest } = sdk
const key = privateKeyToAccount(generatePrivateKey()), other = privateKeyToAccount(generatePrivateKey())
const W: Address = '0x1111111111111111111111111111111111111111', W2: Address = '0x5555555555555555555555555555555555555555'
const TO: Address = '0x2222222222222222222222222222222222222222'
const now = () => Math.floor(Date.now() / 1000)
const dig = (tx: any, wallet = W, chain = 8453) => txDigest({ wallet, ...tx }, chain)
async function mode(m: 'shadow' | 'enforce', digest: Hex, o: { setAt?: number; exp?: number; signer?: any; wallet?: Address; chain?: number } = {}) {
  const msg = { wallet: o.wallet ?? W, txDigest: digest, mode: m, setAt: o.setAt ?? 100, expiresAt: o.exp ?? now() + 120 }
  const signature = await (o.signer ?? key).signTypedData({ domain: oathlineDomain(o.chain ?? 8453), types: OATHLINE_TYPES, primaryType: 'ModeStatement', message: { ...msg, setAt: BigInt(msg.setAt), expiresAt: BigInt(msg.expiresAt) } })
  return { ...msg, signer: key.address, signature }
}
async function receipt(verdict: string, digest: Hex, signer: any = key) {
  const r = { wallet: W, txDigest: digest, mandateId: `0x${'ab'.repeat(32)}` as Hex, verdict, issuedAt: now(), expiresAt: now() + 120 }
  const signature = await signer.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'Verdict', message: { ...r, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) } })
  return { ...r, signer: key.address, signature }
}
const json = (status: number, body: unknown, h: Record<string, string> = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...h } })
type Answer = (tx: any, nonce: Hex) => Promise<Response> | Response
// prime: one honest check that says shadow (setAt 100); then the owner switches to enforce (setAt 200) and `next` answers
async function run(next: Answer, o: { floor?: 'shadow' | 'enforce'; prime?: 'shadow' | 'enforce' | null; timeoutMs?: number; stale?: boolean } = {}) {
  let n = 0
  const fetch = async (url: string, init: any) => {
    if (url.endsWith('/unchecked')) return json(200, { ok: true })
    if (url.includes('/wallets/')) return json(200, { kind: 'plain' })
    const tx = JSON.parse(init.body).tx; const t = { to: tx.to, data: tx.data, value: tx.value !== undefined ? BigInt(tx.value) : undefined, nonce: tx.nonce }
    if (n++ === 0 && o.prime !== null) return json(200, { verdict: 'allow', reason: 'ok', receipt: await receipt('allow', dig(t)), mode: await mode(o.prime ?? 'shadow', dig(t), { setAt: 100 }) })
    return Promise.race([Promise.resolve().then(() => next(t, init.headers['x-sayso-nonce'])), new Promise<Response>((_, rej) => init.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))))])
  }
  const g = new Oathline({ apiUrl: 'http://127.0.0.1:1', apiKey: 'ol_x', signer: key.address, chainId: 8453, fetch, timeoutMs: o.timeoutMs ?? 300, ...(o.floor ? { mode: o.floor } : {}) })
  if (o.prime !== null) await g.gate(W, { to: TO, data: '0x01', value: 1n, nonce: 1 })
  try { await g.gate(W, { to: TO, data: '0xdead', value: 5n, nonce: 2 }); return 'SIGNED' } catch (e) { return `refused:${(e as Error).name}` }
}
const cases: Record<string, Answer> = {
  'unsigned 409': () => json(409, { error: 'no owner-signed mandate is registered for this wallet' }),
  'unsigned 413 (honest body limit)': () => json(413, { error: 'request body too large' }),
  '409 + signed enforce': async t => json(409, { error: 'x', mode: await mode('enforce', dig(t), { setAt: 200 }) }),
  '409 + signed shadow, other tx': async t => json(409, { error: 'x', mode: await mode('shadow', dig({ ...t, nonce: 9 }), { setAt: 300 }) }),
  '409 + signed shadow, other wallet': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t, W2), { setAt: 300, wallet: W2 }) }),
  '409 + signed shadow, other chain': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t, W, 84532), { setAt: 300, chain: 84532 }) }),
  '409 + signed shadow, wrong key': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t), { setAt: 300, signer: other }) }),
  '409 + signed shadow, expired': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t), { setAt: 300, exp: now() - 1 }) }),
  '409 + replayed shadow (same tx, old setAt, in TTL)': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t), { setAt: 100 }) }),
  '409 + shadow with older setAt (50)': async t => json(409, { error: 'x', mode: await mode('shadow', dig(t), { setAt: 50 }) }),
  '500': () => json(500, 'boom'),
  '429 (rate limit)': () => json(429, { error: 'too many' }, { 'retry-after': '30' }),
  'network error': () => { throw new TypeError('fetch failed') },
  'timeout': () => new Promise(() => {}),
  '200 malformed JSON': () => json(200, '{not json'),
  '200 allow, bad receipt signature': async t => json(200, { verdict: 'allow', reason: 'x', receipt: await receipt('allow', dig(t), other), mode: await mode('shadow', dig(t), { setAt: 300 }) }),
  '200 allow, receipt ok, mode signed by wrong key': async t => json(200, { verdict: 'allow', reason: 'x', receipt: await receipt('allow', dig(t), other), mode: await mode('enforce', dig(t), { setAt: 300, signer: other }) }),
  '200 block, receipt ok + signed enforce (honest)': async t => json(200, { verdict: 'block', reason: 'x', receipt: await receipt('block', dig(t)), mode: await mode('enforce', dig(t), { setAt: 200 }) }),
  '200 block + shadow for the transaction only (no modeNonce)': async t => json(200, { verdict: 'block', reason: 'x', receipt: await receipt('block', dig(t)), mode: await mode('shadow', dig(t), { setAt: 300 }) }),
  // round 5: the only shadow that counts is signed for this request's nonce
  '409 + shadow for this request': async (_t, n) => json(409, { error: 'x', mode: await mode('shadow', modeQueryDigest(W, n, 8453), { setAt: 300 }) }),
  '409 + enforce for this request': async (_t, n) => json(409, { error: 'x', mode: await mode('enforce', modeQueryDigest(W, n, 8453), { setAt: 300 }) }),
  '503 + shadow for this request': async (_t, n) => json(503, { error: 'x', mode: await mode('shadow', modeQueryDigest(W, n, 8453), { setAt: 300 }) }),
  '200 block + shadow for this request': async (t, n) => json(200, { verdict: 'block', reason: 'x', receipt: await receipt('block', dig(t)), mode: await mode('shadow', dig(t), { setAt: 300 }), modeNonce: await mode('shadow', modeQueryDigest(W, n, 8453), { setAt: 300 }) }),
  '200 block + shadow for another request': async t => json(200, { verdict: 'block', reason: 'x', receipt: await receipt('block', dig(t)), modeNonce: await mode('shadow', modeQueryDigest(W, `0x${'77'.repeat(32)}`, 8453), { setAt: 300 }) }),
}
// what may sign, per situation; every other answer must be refused
const THIS_REQUEST_SHADOW = ['409 + shadow for this request', '503 + shadow for this request', '200 block + shadow for this request']
const expectSigned: Record<string, string[]> = {
  'last seen shadow': THIS_REQUEST_SHADOW,                 // what the SDK saw before counts for nothing
  'last seen enforce': THIS_REQUEST_SHADOW,                // the owner now says shadow, signed, for this request (newer setAt)
  'never seen, no floor': THIS_REQUEST_SHADOW,
  'floor shadow, seen enforce': THIS_REQUEST_SHADOW,
  'floor shadow, never seen': THIS_REQUEST_SHADOW,
  'floor enforce': [],                                     // enforce written in code is never lowered
}
const rows: string[] = []
for (const [scenario, o] of [['last seen shadow', {}], ['last seen enforce', { prime: 'enforce' }], ['never seen, no floor', { prime: null }], ['floor shadow, seen enforce', { floor: 'shadow', prime: 'enforce' }], ['floor shadow, never seen', { floor: 'shadow', prime: null }], ['floor enforce', { floor: 'enforce' }]] as const) {
  test(`${scenario}: only the expected answers sign`, async () => {
    const signed: string[] = []
    for (const [name, a] of Object.entries(cases)) { const r = await run(a, o as any); rows.push(`${scenario.padEnd(28)} | ${name.padEnd(48)} | ${r}`); if (r === 'SIGNED') signed.push(name) }
    assert.deepEqual(signed.sort(), [...expectSigned[scenario]].sort())
  })
}
