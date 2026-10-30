// Permit2 SignatureTransfer (PermitTransferFrom, PermitWitnessTransferFrom, the batch form): the owner's prompt names the
// token (by address) and the raw amount, and a permit over ERC20ETH (an EIP-7702 wallet's own ETH) says so.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { createWalletClient, custom, type Address } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { base } from 'viem/chains'
import { Oathline, OathlineNeedsApproval } from '../src/index.js'

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

function client() {
  const account = privateKeyToAccount(generatePrivateKey())
  return createWalletClient({ account, chain: base, transport: custom({ request: async ({ method }: any) => { if (method === 'eth_getCode') return '0x'; if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_signTypedData_v4') return '0xsig'; throw new Error(`unexpected ${method}`) } }) })
}
const ERC20ETH: Address = '0x00000000e20E49e6dCeE6e8283A0C090578F0fb9'
const TP = [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }]
const transferFrom = (token: Address, amount: bigint) => ({
  domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 }, primaryType: 'PermitTransferFrom',
  types: { PermitTransferFrom: [{ name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }], TokenPermissions: TP },
  message: { permitted: { token, amount }, spender: ATTACKER, nonce: 1n, deadline: 2n ** 48n },
})
const batch = (tokens: Address[]) => ({
  domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 }, primaryType: 'PermitBatchTransferFrom',
  types: { PermitBatchTransferFrom: [{ name: 'permitted', type: 'TokenPermissions[]' }, { name: 'spender', type: 'address' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }], TokenPermissions: TP },
  message: { permitted: tokens.map(token => ({ token, amount: 5n })), spender: ATTACKER, nonce: 1n, deadline: 2n ** 48n },
})
async function shown(td: unknown): Promise<string> {
  let asked = ''
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: 'k', signer: signerKey.address, onAsk: async r => { asked = r.reason; return false } }).guard(client())
  await assert.rejects(() => g.signTypedData(td as any), OathlineNeedsApproval)
  return asked
}

test('PermitTransferFrom and PermitWitnessTransferFrom: the owner sees the token and the amount', async () => {
  for (const td of [transferFrom(USDC, 10n ** 12n), { ...witness, message: { ...witness.message } }]) {
    const s = await shown(td)
    assert.ok(s.includes(USDC), s); assert.match(s, /1000000000000/); assert.match(s, /in favour of 0x2222/)
  }
})

test('a SignatureTransfer permit over ERC20ETH carries the EIP-7702 warning, single or in a batch', async () => {
  assert.match(await shown(transferFrom(ERC20ETH, 10n ** 18n)), /ERC20ETH/)
  assert.match(await shown(batch([USDC, ERC20ETH])), /ERC20ETH/)
})
