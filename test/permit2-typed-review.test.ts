// Review test (untracked): Permit2 SignatureTransfer typed data through the guarded viem client, enforce and shadow.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { createWalletClient, custom, type Address } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { base } from 'viem/chains'
import { Oathline, OathlineNeedsApproval, OATHLINE_TYPES, modeQueryDigest, oathlineDomain } from '../src/index.js'

const ATTACKER: Address = '0x2222222222222222222222222222222222222222'
const USDC: Address = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
const PERMIT2: Address = '0x000000000022D473030F116dDEE9F6B43aC78BA3'
const signerKey = privateKeyToAccount(generatePrivateKey())
const reports: any[] = []
let server: Server, apiUrl: string
before(async () => {
  server = createServer((req, res) => { let b = ''; req.on('data', c => b += c); req.on('end', () => {
    res.setHeader('content-type', 'application/json')
    if (req.url === '/health') return res.end(JSON.stringify({ ok: true, chainId: 8453, signer: signerKey.address }))
    if (req.url?.startsWith('/wallets/')) return res.end(JSON.stringify({ registered: true, kind: 'plain' }))
    if (req.url === '/unchecked') { reports.push(JSON.parse(b)); return res.end('{}') }
    // since #67 the SDK goes ahead in shadow only on sayso's signed shadow for its own nonce: the owner's switch is shadow here
    // (in the enforce tests the builder's floor is the stronger)
    if (req.url === '/mode') {
      const { nonce, wallet } = JSON.parse(b), msg = { wallet, txDigest: modeQueryDigest(wallet, nonce, 8453), mode: 'shadow' as const, setAt: 0, expiresAt: Math.floor(Date.now() / 1000) + 120 }
      void signerKey.signTypedData({ domain: oathlineDomain(8453), types: OATHLINE_TYPES, primaryType: 'ModeStatement', message: { ...msg, setAt: 0n, expiresAt: BigInt(msg.expiresAt) } })
        .then(signature => res.end(JSON.stringify({ wallet, mode: { ...msg, signer: signerKey.address, signature } })))
      return
    }
    res.statusCode = 404; res.end('{}')
  }) })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
  apiUrl = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => server.close())

const witness = {
  domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 },
  primaryType: 'PermitWitnessTransferFrom',
  types: {
    PermitWitnessTransferFrom: [{ name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'witness', type: 'Order' }],
    TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }],
    Order: [{ name: 'recipient', type: 'address' }],
  },
  message: { permitted: { token: USDC, amount: 10n ** 12n }, spender: ATTACKER, nonce: 1n, deadline: 2n ** 48n, witness: { recipient: ATTACKER } },
} as const

function client(signed: string[]) {
  const account = privateKeyToAccount(generatePrivateKey())
  return createWalletClient({ account, chain: base, transport: custom({ request: async ({ method }: any) => { signed.push(method); if (method === 'eth_getCode') return '0x'; if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_signTypedData_v4') return '0xsig'; throw new Error(`unexpected ${method}`) } }) })
}

test('enforce: Permit2 PermitWitnessTransferFrom via signTypedData and eth_signTypedData_v4 is refused without an owner yes', async () => {
  const signed: string[] = []
  const c = client(signed)
  const asked: string[] = []
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: 'k', signer: signerKey.address }).guard(c)
  await assert.rejects(() => g.signTypedData(witness as any), OathlineNeedsApproval)
  const json = JSON.stringify(witness, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))
  await assert.rejects(() => g.request({ method: 'eth_signTypedData_v4', params: [c.account.address, json] } as any), OathlineNeedsApproval)
  assert.ok(!signed.includes('eth_signTypedData_v4'))
  // with an owner hook, the owner is shown the spender (not the token or amount)
  const g2 = new Oathline({ mode: 'enforce', apiUrl, apiKey: 'k', signer: signerKey.address, onAsk: async r => { asked.push(r.reason); return false } }).guard(c)
  await assert.rejects(() => g2.signTypedData(witness as any), OathlineNeedsApproval)
  console.log('owner sees:', asked[0])
})

test('shadow: the same typed data is signed and reported', async () => {
  const signed: string[] = []
  const c = client(signed)
  reports.length = 0
  const g = new Oathline({ mode: 'shadow', apiUrl, apiKey: 'k', signer: signerKey.address }).guard(c)
  const sig = await g.signTypedData(witness as any)
  assert.ok(sig)
  for (let i = 0; i < 50 && !reports.length; i++) await new Promise(r => setTimeout(r, 20))
  assert.equal(reports.length, 1); assert.equal(reports[0].to, ATTACKER)
})

test('signatures: allow signs Permit2 typed data unchecked even in enforce (by the builder\'s choice)', async () => {
  const signed: string[] = []
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: 'k', signer: signerKey.address, signatures: 'allow' }).guard(client(signed))
  assert.ok(await g.signTypedData(witness as any))
})
