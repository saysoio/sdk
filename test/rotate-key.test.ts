// rotateApiKey: the owner makes the new key locally and signs a KeyReset over its hash for the server's own chain (asked
// from GET /health, or pinned), with a fresh nonce and the current time. The key never travels; only its hash does. A refusal comes back as an error naming the route and status.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { getAddress, recoverTypedDataAddress, type Address, type Hex } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { KEY_RESET_ACTION, OATHLINE_TYPES, apiKeyHash, newApiKey, oathlineDomain, rotateApiKey } from '../src/index.js'

const WALLET: Address = '0x3333333333333333333333333333333333333333'

function fakeApi(chainId: number, answer: { status: number; body: unknown } = { status: 200, body: { wallet: WALLET, note: 'stored' } }) {
  const posts: Array<{ path: string; body: any }> = []
  const f = (async (url: string, init?: RequestInit) => {
    const path = new URL(url).pathname
    if (path === '/health') return new Response(JSON.stringify({ ok: true, chainId }), { status: 200 })
    posts.push({ path, body: JSON.parse(String(init?.body)) })
    return new Response(JSON.stringify(answer.body), { status: answer.status })
  }) as unknown as typeof fetch
  return { f, posts }
}

test('rotateApiKey makes the key locally, signs its hash for the server\'s chain and never sends the key', async () => {
  const owner = privateKeyToAccount(generatePrivateKey())
  const api = fakeApi(84532)
  const before = Math.floor(Date.now() / 1000)
  const r = await rotateApiKey('http://rotate-a.test', owner, WALLET.toLowerCase() as Address, api.f)
  assert.match(r.apiKey, /^ol_[0-9a-f]{64}$/)
  assert.equal(api.posts[0].body.keyHash, apiKeyHash(r.apiKey))
  assert.ok(!JSON.stringify(api.posts[0].body).includes(r.apiKey))
  assert.equal(api.posts.length, 1)
  const { path, body } = api.posts[0]
  assert.equal(path, `/wallets/${WALLET}/key`)
  assert.match(body.nonce, /^0x[0-9a-f]{64}$/)
  assert.ok(body.issuedAt >= before && body.issuedAt <= before + 5)
  const signer = await recoverTypedDataAddress({ domain: oathlineDomain(84532), types: OATHLINE_TYPES, primaryType: 'KeyReset', message: { wallet: getAddress(WALLET), owner: owner.address, action: KEY_RESET_ACTION, nonce: body.nonce as Hex, issuedAt: BigInt(body.issuedAt), keyHash: body.keyHash }, signature: body.signature })
  assert.equal(signer, owner.address)
  assert.equal(Object.keys(body).sort().join(), 'issuedAt,keyHash,nonce,signature')   // nothing else travels: the server rebuilds the message
})

test('newApiKey has the server\'s key format and apiKeyHash is the sha256 the server stores', async () => {
  const a = newApiKey(), b = newApiKey()
  assert.match(a, /^ol_[0-9a-f]{64}$/); assert.notEqual(a, b)
  const { createHash } = await import('node:crypto')
  assert.equal(apiKeyHash(a), `0x${createHash('sha256').update(a).digest('hex')}`)
})

test('rotateApiKey uses a fresh nonce each time and a pinned chain without asking the server', async () => {
  const owner = privateKeyToAccount(generatePrivateKey())
  const api = fakeApi(1)                                                // would be wrong if asked
  await rotateApiKey('http://rotate-b.test', owner, WALLET, { fetch: api.f, chainId: 8453 })
  await rotateApiKey('http://rotate-b.test', owner, WALLET, { fetch: api.f, chainId: 8453 })
  assert.notEqual(api.posts[0].body.nonce, api.posts[1].body.nonce)
  assert.notEqual(api.posts[0].body.keyHash, api.posts[1].body.keyHash)
  const signer = await recoverTypedDataAddress({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'KeyReset', message: { wallet: WALLET, owner: owner.address, action: KEY_RESET_ACTION, nonce: api.posts[0].body.nonce, issuedAt: BigInt(api.posts[0].body.issuedAt), keyHash: api.posts[0].body.keyHash }, signature: api.posts[0].body.signature })
  assert.equal(signer, owner.address)
})

test('rotateApiKey reports a refusal, and refuses an owner that is the wallet itself before signing', async () => {
  const owner = privateKeyToAccount(generatePrivateKey())
  const api = fakeApi(8453, { status: 401, body: { error: 'signature is not a valid KeyReset signature by the registered owner' } })
  await assert.rejects(() => rotateApiKey('http://rotate-c.test', owner, WALLET, api.f), /sayso \/wallets\/0x[0-9a-fA-F]{40}\/key 401: signature is not a valid KeyReset/)
  await assert.rejects(() => rotateApiKey('http://rotate-c.test', owner, owner.address, api.f), /different wallet/)
})
