// Security desk 28 Oct (F2): a local onAsk hook in enforce mode signs what sayso asked about without the owner's
// approval at sayso, including asks raised by the daily cap. The SDK says so once per guard, in the console; it never
// approves anything by itself.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Address, Hex } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { Oathline, OathlineNeedsApproval, OATHLINE_TYPES, oathlineDomain, txDigest } from '../src/index.js'

const CHAIN = 84532
const server = privateKeyToAccount(generatePrivateKey())
const WALLET: Address = '0x1111111111111111111111111111111111111111'
const TO: Address = '0x4444444444444444444444444444444444444444'

/** A /check that answers `verdict`, signed, with the owner's switch at `ownerMode` (a signed mode statement). */
function fakeApi(verdict: 'allow' | 'ask', ownerMode: 'shadow' | 'enforce'): typeof fetch {
  return (async (_url: string, init?: RequestInit) => {
    const j = JSON.parse(String(init!.body))
    const now = Math.floor(Date.now() / 1000)
    const digest = txDigest({ wallet: j.wallet, to: j.tx.to, data: j.tx.data, value: j.tx.value !== undefined ? BigInt(j.tx.value) : undefined, nonce: j.tx.nonce }, CHAIN)
    const r = { wallet: j.wallet as Address, txDigest: digest, mandateId: `0x${'ab'.repeat(32)}` as Hex, verdict, issuedAt: now, expiresAt: now + 120 }
    const signature = await server.signTypedData({ domain: oathlineDomain(CHAIN), types: OATHLINE_TYPES, primaryType: 'Verdict', message: { ...r, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) } })
    const m = { wallet: j.wallet as Address, txDigest: digest, mode: ownerMode, setAt: now - 10, expiresAt: now + 120 }
    const ms = await server.signTypedData({ domain: oathlineDomain(CHAIN), types: OATHLINE_TYPES, primaryType: 'ModeStatement', message: { ...m, setAt: BigInt(m.setAt), expiresAt: BigInt(m.expiresAt) } })
    return new Response(JSON.stringify({ verdict, reason: `stub ${verdict}`, rules: [], receipt: { ...r, signature }, approval: null, mode: { ...m, signature: ms } }), { status: 200, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof fetch
}

async function warningsDuring(f: () => Promise<void> | void): Promise<string[]> {
  const seen: string[] = [], warn = console.warn
  console.warn = (...a: unknown[]) => { seen.push(a.map(String).join(' ')) }
  try { await f() } finally { console.warn = warn }
  return seen.filter(s => /onAsk/.test(s))
}

const opts = (o: Partial<ConstructorParameters<typeof Oathline>[0]>) => ({ apiUrl: 'http://sayso.test', apiKey: 'k', signer: server.address, chainId: CHAIN, ...o })

// One process: the warning is printed at most once per process, so these run in order.
test('no hook, or shadow mode: no warning', async () => {
  assert.deepEqual(await warningsDuring(async () => {
    const g = new Oathline(opts({ mode: 'enforce', fetch: fakeApi('allow', 'enforce') }))
    await g.gate(WALLET, { to: TO, data: '0x', nonce: 1 })
    const h = new Oathline(opts({ onAsk: async () => true, fetch: fakeApi('allow', 'shadow') }))
    await h.gate(WALLET, { to: TO, data: '0x', nonce: 1 })
  }), [])
})

test('the owner switched to enforce: one warning with the first answer that says so, that it applies with no Telegram linked', async () => {
  const w = await warningsDuring(async () => {
    const g = new Oathline(opts({ onAsk: async () => true, fetch: fakeApi('allow', 'enforce') }))
    await g.gate(WALLET, { to: TO, data: '0x', nonce: 1 })
    await g.gate(WALLET, { to: TO, data: '0x', nonce: 2 })
  })
  assert.equal(w.length, 1)
  assert.match(w[0], /no Telegram linked|not linked Telegram/); assert.match(w[0], /daily cap/); assert.match(w[0], /owner/); assert.match(w[0], /never approve automatically/i); assert.match(w[0], /Signature requests .* still go to this hook/); assert.doesNotMatch(w[0], /hook is then unused/)
})

test('once per process: another guard in enforce with a hook prints nothing more; the warning never approves', async () => {
  let asked = 0
  const w = await warningsDuring(async () => {
    const g = new Oathline(opts({ mode: 'enforce', onAsk: async () => { asked++; return false }, fetch: fakeApi('ask', 'enforce') }))
    await assert.rejects(g.gate(WALLET, { to: TO, data: '0x', nonce: 1 }), OathlineNeedsApproval)
  })
  assert.deepEqual(w, [])
  assert.equal(asked, 1)
})
