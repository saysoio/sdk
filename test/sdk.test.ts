import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { createWalletClient, custom, encodeFunctionData, fallback, parseAbi, publicActions, parseEther, parseTransaction, walletActions, type Address, type Hex } from 'viem'
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts'
import { sendTransaction as sendTransactionAction, signMessage as signMessageAction } from 'viem/actions'
import { base, baseSepolia } from 'viem/chains'
import { Oathline, OathlineBlocked, OathlineNeedsApproval, OathlineUnavailable, OATHLINE_DOMAIN, OATHLINE_TYPES, OATHLINE_SIGNERS, OATHLINE_COSIGNERS, SDK_VERSION, officialSigner, txDigest } from '../src/index.js'
import { readFileSync } from 'node:fs'
import { isAddress } from 'viem'
import { erc7821Actions, erc7715Actions } from 'viem/experimental'
import { publicActionsL2, walletActionsL2 } from 'viem/op-stack'
import { sendTransaction as rawSend } from 'viem/actions'
import { CLIENT_READS, TESTED_VIEM, installedViem, newerViem, untestedViemWarning, warnIfUntestedViem } from '../src/viem-known.js'

const ATTACKER: Address = '0x2222222222222222222222222222222222222222'
const ASKER: Address = '0x4444444444444444444444444444444444444444'
const HELD: Address = '0x7777777777777777777777777777777777777777'    // an ask held on the position side
const SAVED: Address = '0x3333333333333333333333333333333333333333'

// Fake check API: verdict by destination, with a properly signed receipt. Records what it was asked.
const KEY = 'ol_test_key'
const serverAccount = privateKeyToAccount(generatePrivateKey())   // stands in for sayso's verdict-signing key
const SIGNER = serverAccount.address
let healthChain = 8453
let server: Server, apiUrl: string, failNext = false, tamper: 'none' | 'other-tx' | 'other-nonce' | 'bad-sig' | 'no-receipt' = 'none'
let refuseNext: { status: number; body: string; headers?: Record<string, string> } | null = null   // R5 part 2: the server's own refusal of the next /check
const walletKinds: Record<string, 'plain' | 'delegated'> = {}                                    // R5 part 2: what GET /wallets/:w and the /check answer say about a wallet
let kindLookups = 0
const requests: any[] = []
const authSeen: Array<string | undefined> = []
const reports: any[] = []                                           // what the SDK let through unchecked in shadow mode (step 2d, fix 7)
before(async () => {
  server = createServer((req, res) => {
    let body = ''; req.on('data', c => body += c); req.on('end', async () => {
      if (req.method === 'GET' && req.url === '/health') { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ ok: true, chainId: healthChain, signer: SIGNER })) }   // names its chain, and its OWN key as the signer
      if (req.method === 'GET' && /^\/wallets\/0x[0-9a-fA-F]{40}$/.test(req.url ?? '')) { kindLookups++; const w = req.url!.slice(9).toLowerCase(); res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ wallet: w, registered: true, kind: walletKinds[w] ?? 'plain' })) }
      if (failNext) { failNext = false; res.statusCode = 500; return res.end('boom') }
      if (refuseNext && req.url === '/check') { const r = refuseNext; refuseNext = null; res.statusCode = r.status; for (const [k, v] of Object.entries(r.headers ?? {})) res.setHeader(k, v); res.setHeader('content-type', 'application/json'); return res.end(r.body) }
      authSeen.push(req.headers.authorization)
      if (req.headers.authorization !== `Bearer ${KEY}`) { res.statusCode = 401; return res.end('{"error":"missing or unknown API key"}') }
      if (req.method === 'POST' && req.url === '/unchecked') { reports.push(JSON.parse(body)); res.setHeader('content-type', 'application/json'); return res.end('{"ok":true}') }
      const j = JSON.parse(body); requests.push(j)
      const to = (j.tx.to as string).toLowerCase()
      const verdict = to === ATTACKER.toLowerCase() ? 'block' : to === ASKER.toLowerCase() || to === HELD.toLowerCase() ? 'ask' : 'allow'
      const now = Math.floor(Date.now() / 1000)
      const digest = txDigest({ wallet: j.wallet, to: tamper === 'other-tx' ? ATTACKER : j.tx.to, data: j.tx.data, value: j.tx.value !== undefined ? BigInt(j.tx.value) : undefined, nonce: tamper === 'other-nonce' ? (j.tx.nonce ?? 0) + 1 : j.tx.nonce })
      const r = { wallet: j.wallet as Address, txDigest: digest, mandateId: `0x${'ab'.repeat(32)}` as Hex, verdict, issuedAt: now, expiresAt: now + 120 }
      const signer = tamper === 'bad-sig' ? privateKeyToAccount(generatePrivateKey()) : serverAccount
      const signature = await signer.signTypedData({ domain: OATHLINE_DOMAIN, types: OATHLINE_TYPES, primaryType: 'Verdict', message: { ...r, issuedAt: BigInt(r.issuedAt), expiresAt: BigInt(r.expiresAt) } })
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ verdict, reason: `fake: ${verdict}`, rules: to === HELD.toLowerCase() ? [{ id: 'position-pending', verdict: 'ask', reason: 'held: an earlier allowed call is not yet on the chain' }] : [], walletKind: walletKinds[String(j.wallet).toLowerCase()] ?? 'plain', ...(tamper === 'no-receipt' ? {} : { receipt: { ...r, signer: SIGNER, signature } }) }))
    })
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  apiUrl = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => server.close())

const fakeProvider = () => {
  const sent: any[] = []
  return { sent, getAddress: () => SAVED, sendTransaction: async (tx: any) => { sent.push(tx); return '0xabc' as Hex }, nativeTransfer: async (to: string, v: string) => { sent.push({ to, v }); return '0xdef' as Hex }, other: () => 'passthrough' }
}

test('enforce: allow proceeds, block throws and nothing is sent', async () => {
  const p = fakeProvider(); const decisions: string[] = []
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (_r, _t, d) => decisions.push(d) }).guardWalletProvider(p)
  assert.equal(await g.sendTransaction({ to: SAVED, data: '0x', value: 1n }), '0xabc')
  await assert.rejects(() => g.sendTransaction({ to: ATTACKER, data: '0x' }), OathlineBlocked)
  assert.equal(p.sent.length, 1)
  assert.deepEqual(decisions, ['signed', 'refused'])
  assert.equal(g.other(), 'passthrough')
})

test('enforce: ask waits for the owner; refused by default, proceeds when approved', async () => {
  const p = fakeProvider()
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p).sendTransaction({ to: ASKER, data: '0x' }), OathlineNeedsApproval)
  assert.equal(p.sent.length, 0)
  const approved = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => true }).guardWalletProvider(p)
  await approved.sendTransaction({ to: ASKER, data: '0x' })
  assert.equal(p.sent.length, 1)
})

test('enforce fails closed when the API is down; shadow proceeds', async () => {
  const p = fakeProvider()
  failNext = true
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p).sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
  assert.equal(p.sent.length, 0)
  const decisions: string[] = []
  const shadow = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (_r, _t, d) => decisions.push(d) }).guardWalletProvider(p)
  await shadow.sendTransaction({ to: ATTACKER, data: '0x' })   // blocked verdict, but shadow only logs
  assert.equal(p.sent.length, 1)
  assert.deepEqual(decisions, ['shadow'])
})

test('stop when sayso is down (step 8): enforce mode refuses to sign when the server cannot be reached at all; failClosed: false is the opt-out', async () => {
  // a port nobody listens on: the connection is refused, there is no answer to misread
  const probe = createServer(); await new Promise<void>(r => probe.listen(0, '127.0.0.1', r))
  const dead = `http://127.0.0.1:${(probe.address() as any).port}`; await new Promise<void>(r => probe.close(() => r()))
  const p = fakeProvider(), decisions: Array<[string, string]> = []
  const strict = new Oathline({ mode: 'enforce', apiUrl: dead, apiKey: KEY, signer: SIGNER, timeoutMs: 2000, onDecision: (r, _t, d) => decisions.push([d, r.reason]) }).guardWalletProvider(p)
  await assert.rejects(() => strict.sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)   // the default: enforce, failClosed
  await assert.rejects(() => strict.nativeTransfer(SAVED, '1'), OathlineUnavailable)
  assert.equal(p.sent.length, 0)
  assert.deepEqual(decisions.map(d => d[0]), ['refused', 'refused']); assert.match(decisions[0][1], /check unavailable/)
  // the team's opt-out, spelled out: the transaction goes ahead and the decision says why
  const optOut = new Oathline({ mode: 'enforce', apiUrl: dead, apiKey: KEY, signer: SIGNER, timeoutMs: 2000, failClosed: false, onDecision: (r, _t, d) => decisions.push([d, r.reason]) }).guardWalletProvider(p)
  await optOut.sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(p.sent.length, 1)
  assert.equal(decisions.at(-1)![0], 'shadow'); assert.match(decisions.at(-1)![1], /sayso unavailable .*failClosed=false/)
  // shadow mode never needed the opt-out
  await new Oathline({ apiUrl: dead, apiKey: KEY, signer: SIGNER, mode: 'shadow', timeoutMs: 2000 }).guardWalletProvider(p).sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(p.sent.length, 2)
})

test('R5 part 2 (security desk F2): a refusal by the server is a block, not an outage, whatever failClosed says; outages stay outages', async () => {
  const refusals = [
    [409, '{"error":"this wallet now runs code (an EIP-7702 delegation or a contract) but is registered as a plain wallet: nothing is checked until its owner registers it again as what it now is","code":"wallet-has-code"}', 'wallet-has-code'],
    [409, '{"error":"this is a call into the wallet\'s own EIP-7702 code (a batch of calls, or a change to its keys or settings): sayso cannot check that kind of call yet, so it is refused; send each call on its own","code":"self-call"}', 'self-call'],
    [409, '{"error":"this wallet runs EIP-7702 code sayso does not support yet","code":"wallet-code-refused"}', 'wallet-code-refused'],
    [409, '{"error":"no owner-signed mandate is registered for this wallet"}', undefined],
    [403, '{"error":"this API key belongs to a different wallet"}', undefined],
    [400, '{"error":"tx.to and tx.data are required"}', undefined],
  ] as const
  for (const failClosed of [true, false]) {
    const p = fakeProvider(), decisions: Array<[string, string, string]> = []
    const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, failClosed, onDecision: (r, _t, d) => decisions.push([d, r.verdict, r.reason]) }).guardWalletProvider(p)
    for (const [status, body, code] of refusals) {
      refuseNext = { status, body }
      await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x' }), (e: any) => {
        assert.ok(e instanceof OathlineBlocked, `failClosed=${failClosed} ${status}: ${e?.name} ${e?.message}`)
        assert.match(e.message, new RegExp(JSON.parse(body).error.slice(0, 40).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), 'carries the server\'s words')
        assert.match(e.message, new RegExp(`check API ${status}`))
        if (code) assert.equal(e.result.code, code); else assert.equal(e.result.code, undefined)
        return true
      })
    }
    assert.equal(p.sent.length, 0, `failClosed=${failClosed}: nothing was sent`)
    assert.ok(decisions.every(d => d[0] === 'refused' && d[1] === 'block'), JSON.stringify(decisions))
    assert.match(decisions[0][2], /refused by sayso \(check API 409\)/)
  }
  // outages are still outages: a 5xx, a "try again" answer (429 with retry-after) and a dead server; the opt-out covers those
  const p = fakeProvider()
  const strict = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p)
  failNext = true
  await assert.rejects(() => strict.sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
  refuseNext = { status: 429, body: '{"error":"too many requests for this API key; try again in 12 s"}', headers: { 'retry-after': '12' } }
  await assert.rejects(() => strict.sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
  refuseNext = { status: 503, body: '{"error":"the check server is busy; try again in a few seconds"}', headers: { 'retry-after': '5' } }
  await assert.rejects(() => strict.sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
  assert.equal(p.sent.length, 0)
  const optOut = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, failClosed: false }).guardWalletProvider(p)
  failNext = true
  await optOut.sendTransaction({ to: SAVED, data: '0x' })
  refuseNext = { status: 429, body: '{"error":"too many requests"}', headers: { 'retry-after': '12' } }
  await optOut.sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(p.sent.length, 2)
  // a receipt or a mode statement that does not verify is never covered by the opt-out either (a forged "allow" must not sign)
  for (const t of ['other-tx', 'bad-sig', 'no-receipt'] as const) {
    tamper = t
    await assert.rejects(() => optOut.sendTransaction({ to: SAVED, data: '0x', value: 1n }), OathlineUnavailable, `tamper: ${t}`)
  }
  tamper = 'none'
  assert.equal(p.sent.length, 2)
  // shadow mode never stops anything: a refusal goes ahead, the decision says shadow, and sayso is told so the owner sees "would have blocked"
  reports.length = 0
  const shadowLog: Array<[string, string]> = []
  const shadow = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (r, _t, d) => shadowLog.push([r.verdict, d]) }).guardWalletProvider(p)
  refuseNext = { status: 409, body: '{"error":"this is a call into the wallet\'s own EIP-7702 code","code":"self-call"}' }
  await shadow.sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(p.sent.length, 3); assert.deepEqual(shadowLog, [['block', 'shadow']])
  for (let i = 0; i < 50 && reports.length < 1; i++) await new Promise(r => setTimeout(r, 20))
  assert.equal(reports[0]?.kind, 'refused by sayso (self-call)'); assert.match(reports[0]?.detail ?? '', /EIP-7702 code/)
})

test('R5 part 2 (review 2026-10-22, M1 and L3): a refusal that says the wallet runs code teaches the SDK its kind, so a blind hash and toSigner() are refused from then on, whatever the signatures policy', async () => {
  const signed: string[] = []
  const p = { getAddress: () => SAVED, sendTransaction: async (_tx?: any) => '0x1' as Hex, sign: async (_h?: any) => { signed.push('raw'); return '0xsig' as Hex }, toSigner: () => 'the raw signer' }
  const decisions: string[] = []
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, signatures: 'allow', onDecision: (r, _t, d) => decisions.push(`${d}:${r.verdict}`) }).guardWalletProvider(p)
  assert.equal(g.toSigner(), 'the raw signer', 'kind unknown and signatures: allow: the policy applies, as before')
  refuseNext = { status: 409, body: '{"error":"this wallet now runs code (an EIP-7702 delegation or a contract) but is registered as a plain wallet","code":"wallet-has-code"}' }
  await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x' }), OathlineBlocked)
  await assert.rejects(() => g.sign('0xabc'), (e: any) => e instanceof OathlineBlocked && /EIP-7702/.test(e.message) && /blind/.test(e.message))
  assert.throws(() => g.toSigner(), (e: any) => e instanceof OathlineBlocked && /EIP-7702/.test(e.message))
  assert.deepEqual(signed, [], 'nothing reached the provider')
  assert.deepEqual(decisions, ['refused:block', 'refused:block', 'refused:block'])
  // in shadow mode the export goes ahead (shadow stops nothing)
  const sh = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow' }).guardWalletProvider(p)
  refuseNext = { status: 409, body: '{"error":"this wallet now runs code","code":"wallet-has-code"}' }
  await sh.sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(sh.toSigner(), 'the raw signer')
})

test('the agent sends its API key and context — never a mandate or an owner instruction; nativeTransfer is gated too', async () => {
  const p = fakeProvider(); requests.length = 0; authSeen.length = 0
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, context: () => ({ reason: 'because', inputs: ['page'] }) }).guardWalletProvider(p)
  await g.nativeTransfer(SAVED, '0.5')
  assert.equal(authSeen[0], `Bearer ${KEY}`)
  assert.equal(requests[0].agent.reason, 'because')
  assert.ok(!('mandate' in requests[0])); assert.ok(!('ownerInstruction' in requests[0]))
  assert.equal(requests[0].tx.value, parseEther('0.5').toString()); assert.equal(requests[0].wallet, SAVED)
  await assert.rejects(() => g.nativeTransfer(ATTACKER, '0.5'), OathlineBlocked)
  // a wrong API key cannot get a verdict → nothing is signed (since 0.6.0 a refusal, not an outage: the opt-out never covers it)
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl, apiKey: 'wrong', signer: SIGNER }).guardWalletProvider(p).sendTransaction({ to: SAVED, data: '0x' }), OathlineBlocked)
})

test('a verdict only counts if sayso signed it for exactly this transaction', async () => {
  const p = fakeProvider()
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p)
  for (const t of ['other-tx', 'bad-sig', 'no-receipt'] as const) {
    tamper = t
    await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x', value: 1n }), OathlineUnavailable, `tamper: ${t}`)
  }
  tamper = 'none'
  assert.equal(p.sent.length, 0)                                   // an "allow" that is not properly signed signs nothing
  await g.sendTransaction({ to: SAVED, data: '0x', value: 1n })
  assert.equal(p.sent.length, 1)
  // No signer given: the SDK trusts only sayso's own signing address for the chain, which is built into it. This
  // server's verdicts are properly signed with ITS key, and its /health even names that key, but it is not sayso:
  // nothing is signed. (A server that could name its own signer could forge "allow": security review 2026-10-06, threat 4.)
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY }).guardWalletProvider(p).sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
  assert.equal(p.sent.length, 1)
})

test('viem wallet client: sendTransaction and writeContract are gated', async () => {
  const raw: string[] = []
  const transport = custom({ request: async ({ method }: any) => { if (method === 'eth_sendRawTransaction') { raw.push(method); return '0x' + '11'.repeat(32) } throw new Error(`unexpected rpc ${method}`) } })
  const account = privateKeyToAccount(generatePrivateKey())   // throwaway key, never funded
  const client = createWalletClient({ account, chain: base, transport })
  const guarded = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(client)
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  await guarded.sendTransaction({ to: SAVED, value: 1n, ...fees })
  await assert.rejects(() => guarded.sendTransaction({ to: ATTACKER, value: 1n, ...fees }), OathlineBlocked)
  const abi = parseAbi(['function transfer(address to, uint256 amount) returns (bool)'])
  await guarded.writeContract({ address: SAVED, abi, functionName: 'transfer', args: [SAVED, 1n], ...fees })
  await assert.rejects(() => guarded.writeContract({ address: ATTACKER, abi, functionName: 'transfer', args: [SAVED, 1n], ...fees }), OathlineBlocked)
  assert.equal(raw.length, 2)
  const last = requests.at(-1); assert.equal(last.tx.to, ATTACKER); assert.match(last.tx.data, /^0xa9059cbb/)
})

test('signature requests are gated: refused by default, allowed by the owner hook, logged in shadow', async () => {
  const signed: string[] = []
  const provider = { getAddress: () => SAVED, sendTransaction: async () => '0x1' as Hex, signTypedData: async (_td?: any) => { signed.push('typed'); return '0xsig' as Hex }, signMessage: async (_m?: any) => { signed.push('msg'); return '0xsig' as Hex }, sign: async (_h?: any) => { signed.push('raw'); return '0xsig' as Hex }, toSigner: () => 'signer' }
  const permit = { primaryType: 'Permit', domain: { name: 'USD Coin' }, message: { spender: ATTACKER, value: '1000000000' } }
  const enforce = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider)
  await assert.rejects(() => enforce.signTypedData(permit), OathlineNeedsApproval)
  await assert.rejects(() => enforce.signMessage('hi'), OathlineNeedsApproval)
  await assert.rejects(() => enforce.sign('0xabc'), OathlineNeedsApproval)
  assert.throws(() => enforce.toSigner(), OathlineNeedsApproval)
  assert.equal(signed.length, 0)
  let asked = ''
  const approved = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async r => { asked = r.reason; return true } }).guardWalletProvider(provider)
  await approved.signTypedData(permit)
  assert.match(asked, /Permit for USD Coin, in favour of 0x2222/)
  const decisions: string[] = []
  const shadow = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (_r, _t, d) => decisions.push(d) }).guardWalletProvider(provider)
  await shadow.signMessage('hi')
  assert.deepEqual(signed, ['typed', 'msg']); assert.deepEqual(decisions, ['shadow'])
  // viem client path
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: async () => { throw new Error('no rpc expected') } }) })
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(client).signMessage({ message: 'hi' }), OathlineNeedsApproval)
})

test('R5 part 2 (security desk F3): in shadow mode a signature request is reported to sayso as "would have asked" (or blocked, per the policy); with signatures: \'allow\' nothing is reported', async () => {
  const provider = { getAddress: () => SAVED, sendTransaction: async () => '0x1' as Hex, signTypedData: async (_td?: any) => '0xsig' as Hex, signMessage: async (_m?: any) => '0xsig' as Hex, sign: async (_h?: any) => '0xsig' as Hex }
  const permit = { primaryType: 'Permit', domain: { name: 'USD Coin' }, message: { spender: ATTACKER, value: '1000000000' } }
  const wait = async (n: number) => { for (let i = 0; i < 50 && reports.length < n; i++) await new Promise(r => setTimeout(r, 20)) }
  await new Promise(r => setTimeout(r, 100)); reports.length = 0                      // let reports from earlier tests land first
  const asking = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow' }).guardWalletProvider(provider)
  await asking.signTypedData(permit); await asking.signMessage('hi'); await asking.sign('0xabc')
  await wait(3)
  assert.deepEqual(reports.map(r => [r.kind, r.verdict]), [['signature request', 'ask'], ['signature request', 'ask'], ['signature request', 'ask']])
  assert.equal(reports[0].detail, 'typed data: Permit for USD Coin, in favour of 0x2222222222222222222222222222222222222222'); assert.equal(reports[0].to, ATTACKER)
  assert.equal(reports[2].detail, 'raw hash: blind signature over a hash')
  reports.length = 0
  const refusing = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', signatures: 'refuse' }).guardWalletProvider(provider)
  await refusing.signTypedData(permit); await wait(1)
  assert.deepEqual(reports.map(r => [r.kind, r.verdict]), [['signature request', 'block']])
  reports.length = 0
  const allowing = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', signatures: 'allow' }).guardWalletProvider(provider)
  await allowing.signTypedData(permit); await new Promise(r => setTimeout(r, 100))
  assert.equal(reports.length, 0)
  // the raw RPC door reports the same way
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: async () => '0xsig' }) })
  await new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow' }).guard(client).request({ method: 'personal_sign', params: ['0x68', SAVED] } as any)
  await wait(1)
  assert.deepEqual(reports.map(r => [r.kind, r.detail, r.verdict]), [['signature request', 'raw RPC call: personal_sign', 'ask']])
})

test('R5 part 2 (review M1): on an EIP-7702 wallet the SDK refuses outright, never asks, what could let a relayer or bundler run a batch; plain wallets keep the policy', async () => {
  const CALIBUR_WALLET: Address = '0x5555555555555555555555555555555555555555'
  const ENTRY_POINT: Address = '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108'
  const ERC20ETH: Address = '0x00000000e20E49e6dCeE6e8283A0C090578F0fb9'
  const USDC: Address = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
  const signed: string[] = []
  const provider = (addr: Address) => ({ getAddress: () => addr, sendTransaction: async (_tx?: any) => '0x1' as Hex, signTypedData: async (td?: any) => { signed.push(`typed:${td?.primaryType}`); return '0xsig' as Hex }, signMessage: async (_m?: any) => { signed.push('msg'); return '0xsig' as Hex }, sign: async (_h?: any) => { signed.push('raw'); return '0xsig' as Hex } })
  const call = { to: ATTACKER, value: 0n, data: '0x' }
  const batchUnderWallet = { domain: { name: 'Calibur', version: '1.0.0', chainId: 8453, verifyingContract: CALIBUR_WALLET }, primaryType: 'SignedBatchedCall', types: { SignedBatchedCall: [{ name: 'batchedCall', type: 'BatchedCall' }, { name: 'nonce', type: 'uint256' }, { name: 'keyHash', type: 'bytes32' }, { name: 'executor', type: 'address' }, { name: 'deadline', type: 'uint256' }], BatchedCall: [{ name: 'calls', type: 'Call[]' }, { name: 'revertOnFailure', type: 'bool' }], Call: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }] }, message: { batchedCall: { calls: [call], revertOnFailure: true }, nonce: 0n, keyHash: `0x${'00'.repeat(32)}`, executor: `0x${'00'.repeat(20)}`, deadline: 0n } }
  const caliburName = { domain: { name: 'Calibur', version: '1.0.0', chainId: 8453, verifyingContract: SAVED }, primaryType: 'Anything', types: { Anything: [{ name: 'x', type: 'uint256' }] }, message: { x: 1n } }
  const wrapped = { domain: { name: 'Some App', chainId: 8453, verifyingContract: SAVED }, primaryType: 'TypedDataSign', types: { TypedDataSign: [{ name: 'contents', type: 'Permit' }, { name: 'name', type: 'string' }], Permit: [{ name: 'spender', type: 'address' }] }, message: { contents: { spender: ATTACKER }, name: 'Calibur' } }
  const personal = { domain: { name: 'Some App', chainId: 8453, verifyingContract: SAVED }, primaryType: 'PersonalSign', types: { PersonalSign: [{ name: 'prefixed', type: 'bytes' }] }, message: { prefixed: '0x1234' } }
  const userOp = { domain: { name: 'ERC4337', version: '1', chainId: 8453, verifyingContract: ENTRY_POINT }, primaryType: 'PackedUserOperation', types: { PackedUserOperation: [{ name: 'sender', type: 'address' }, { name: 'nonce', type: 'uint256' }] }, message: { sender: CALIBUR_WALLET, nonce: 0n } }
  const usdcPermit = { domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: USDC }, primaryType: 'Permit', types: { Permit: [{ name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }] }, message: { spender: ATTACKER, value: 10n ** 9n } }
  const ethPermit2 = { domain: { name: 'Permit2', chainId: 8453, verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3' }, primaryType: 'PermitSingle', types: { PermitSingle: [{ name: 'details', type: 'PermitDetails' }, { name: 'spender', type: 'address' }], PermitDetails: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint160' }] }, message: { details: { token: ERC20ETH, amount: 2n ** 160n - 1n }, spender: ATTACKER } }
  const dangerous = [batchUnderWallet, caliburName, wrapped, personal, userOp]
  // 1. the server says the wallet is an EIP-7702 wallet
  walletKinds[CALIBUR_WALLET.toLowerCase()] = 'delegated'
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => true }).guardWalletProvider(provider(CALIBUR_WALLET))
  await assert.rejects(() => g.sign('0xabc'), (e: any) => e instanceof OathlineBlocked && /EIP-7702/.test(e.message) && /blind/.test(e.message))
  for (const td of dangerous) await assert.rejects(() => g.signTypedData(td), (e: any) => e instanceof OathlineBlocked && /EIP-7702/.test(e.message), td.primaryType)
  assert.deepEqual(signed, [], 'nothing reached the provider')
  // an ordinary token permit and a personal message still follow the signatures policy (here: the local hook says yes)
  await g.signTypedData(usdcPermit); await g.signMessage('hi')
  assert.deepEqual(signed, ['typed:Permit', 'msg'])
  // a Permit2 permit on ERC20ETH is a permission over the wallet's ETH, and the request says so
  let asked = ''
  const g2 = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async r => { asked = r.reason; return false } }).guardWalletProvider(provider(CALIBUR_WALLET))
  await assert.rejects(() => g2.signTypedData(ethPermit2), OathlineNeedsApproval)
  assert.match(asked, /PermitSingle for Permit2, in favour of 0x2222.*ERC20ETH.*ETH/)
  // 2. shadow: the dangerous ones go ahead, and each is reported as "would have blocked" on an EIP-7702 wallet
  await new Promise(r => setTimeout(r, 100)); reports.length = 0; signed.length = 0
  const sh = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow' }).guardWalletProvider(provider(CALIBUR_WALLET))
  await sh.sign('0xabc'); for (const td of dangerous) await sh.signTypedData(td); await sh.signTypedData(usdcPermit)
  for (let i = 0; i < 50 && reports.length < 7; i++) await new Promise(r => setTimeout(r, 20))
  assert.equal(signed.length, 7)
  assert.deepEqual(reports.map(r => [r.kind, r.verdict]), [...Array(6).fill(['signature request on an EIP-7702 wallet', 'block']), ['signature request', 'ask']])
  assert.match(reports[0].detail, /raw hash/); assert.match(reports[1].detail, /own domain/)
  // 3. the SDK learns it from the wallet's own node too: the server says plain, the node returns the EIP-7702 pointer
  const account = privateKeyToAccount(generatePrivateKey())
  walletKinds[account.address.toLowerCase()] = 'plain'
  const rpc: string[] = []
  const transport = custom({ request: async ({ method, params }: any) => { rpc.push(method); if (method === 'eth_getCode') return `0xef0100${SAVED.slice(2)}`; if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_signTypedData_v4' || method === 'personal_sign' || method === 'eth_sign') return '0xsig'; throw new Error(`unexpected rpc ${method} ${JSON.stringify(params)}`) } })
  const client = createWalletClient({ account, chain: base, transport })
  const gc = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => true }).guard(client)
  await assert.rejects(() => gc.request({ method: 'eth_sign', params: [account.address, '0xabc'] } as any), OathlineBlocked)
  await assert.rejects(() => gc.request({ method: 'eth_signTypedData_v4', params: [account.address, JSON.stringify(batchUnderWallet, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))] } as any), OathlineBlocked)
  await assert.rejects(() => gc.signTypedData({ ...userOp, account } as any), OathlineBlocked)
  assert.ok(!rpc.includes('eth_sign') && !rpc.includes('eth_signTypedData_v4'), 'nothing reached the node')
  await gc.request({ method: 'personal_sign', params: ['0x68', account.address] } as any)             // a personal message: the policy (the hook said yes)
  // 4. a plain wallet (server plain, node has no code): the same requests follow the policy, as before
  const plain = privateKeyToAccount(generatePrivateKey())
  const plainClient = createWalletClient({ account: plain, chain: base, transport: custom({ request: async ({ method }: any) => { if (method === 'eth_getCode') return '0x'; if (method === 'eth_sign') return '0xsig'; throw new Error(`unexpected rpc ${method}`) } }) })
  const gp = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(plainClient)
  await assert.rejects(() => gp.request({ method: 'eth_sign', params: [plain.address, '0xabc'] } as any), OathlineNeedsApproval)
  await assert.rejects(() => gp.signTypedData({ ...batchUnderWallet, domain: { ...batchUnderWallet.domain, verifyingContract: plain.address } } as any), OathlineNeedsApproval)
  // 5. learned from a /check answer: no lookup needed afterwards
  const w3: Address = '0x6666666666666666666666666666666666666666'
  walletKinds[w3.toLowerCase()] = 'delegated'
  const p3 = provider(w3)
  const g3 = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p3)
  await g3.sendTransaction({ to: SAVED, data: '0x' })
  const before = kindLookups
  await assert.rejects(() => g3.sign('0xabc'), OathlineBlocked)
  assert.equal(kindLookups, before, 'the /check answer already said it')
})

test('sayso\'s own signing addresses are built in, one pair per chain; a chain without one needs the address spelled out', () => {
  for (const table of [OATHLINE_SIGNERS, OATHLINE_COSIGNERS]) {
    assert.deepEqual(Object.keys(table).sort(), ['8453', '84532'])                              // Base, and the Base Sepolia test server
    for (const a of Object.values(table)) assert.ok(isAddress(a, { strict: true }), `${a} is not a checksummed address`)
  }
  assert.equal(new Set([...Object.values(OATHLINE_SIGNERS), ...Object.values(OATHLINE_COSIGNERS)]).size, 4)   // four different keys
  assert.equal(officialSigner(8453), OATHLINE_SIGNERS[8453])
  assert.throws(() => officialSigner(1), /no sayso signing address is known for chain 1.*signer/s)
})

test('the wallet\'s own chain must be the chain the server answers for (review of step 1, M4)', async () => {
  // Someone who holds the server's web address answers "I am the test network", hoping the SDK will then accept
  // verdicts signed by the test server's key for a wallet that is on Base. The wallet client knows its chain: mismatch = no signature.
  const raw: string[] = []
  const transport = custom({ request: async ({ method }: any) => { if (method === 'eth_sendRawTransaction') { raw.push(method); return '0x' + '22'.repeat(32) } throw new Error(`unexpected rpc ${method}`) } })
  const account = privateKeyToAccount(generatePrivateKey())
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  const lying = apiUrl.replace('127.0.0.1', 'localhost')                 // the same fake server under another name (the chain is remembered per address)
  healthChain = 84532
  try {
    const onBase = createWalletClient({ account, chain: base, transport })
    const decisions: string[] = []
    await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl: lying, apiKey: KEY, signer: SIGNER, onDecision: (r) => decisions.push(r.reason) }).guard(onBase).sendTransaction({ to: SAVED, value: 1n, ...fees }), OathlineUnavailable)
    assert.equal(raw.length, 0); assert.match(decisions[0], /chain 8453.*chain 84532/)
    // an AgentKit-style provider that knows its network is held to the same rule
    const provider = { getAddress: () => SAVED, getNetwork: () => ({ chainId: '8453' }), sendTransaction: async (_tx: unknown) => '0xabc' as Hex }
    await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl: lying, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider).sendTransaction({ to: SAVED, data: '0x' }), OathlineUnavailable)
    // shadow mode never stops anything, but it says what is wrong
    const shadow: string[] = []
    await new Oathline({ apiUrl: lying, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (r) => shadow.push(r.reason) }).guard(onBase).sendTransaction({ to: SAVED, value: 1n, ...fees })
    assert.equal(raw.length, 1); assert.match(shadow[0], /chain 8453.*chain 84532/)
    // a wallet client that really is on the test network matches a test-network server (its verdicts are still checked as before)
    const onSepolia = createWalletClient({ account, chain: baseSepolia, transport })
    await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl: lying, apiKey: KEY, signer: SIGNER }).guard(onSepolia).sendTransaction({ to: SAVED, value: 1n, ...fees }), /receipt is for a different transaction/)   // the fake signs Base digests: refused for that reason, not for the chain
  } finally { healthChain = 8453 }
})

test('the built-in addresses cannot be changed at run time, and a Safe co-signature needs a known co-signer', async () => {
  assert.throws(() => { (OATHLINE_SIGNERS as any)[8453] = ATTACKER }, TypeError)
  assert.throws(() => { (OATHLINE_COSIGNERS as any)[1] = ATTACKER }, TypeError)
  assert.equal(OATHLINE_SIGNERS[8453], officialSigner(8453))
})

test('the position (nonce) the SDK will sign with is pinned before the check, sent with it, signed with, and part of the receipt', async () => {
  const seen: string[] = []; let expectNonce = 5
  const transport = custom({ request: async ({ method, params }: any) => {
    seen.push(method)
    if (method === 'eth_getTransactionCount') { assert.equal(params[1], 'pending'); return '0x5' }
    if (method === 'eth_sendRawTransaction') { assert.equal(parseTransaction(params[0]).nonce, expectNonce); return '0x' + '22'.repeat(32) }
    throw new Error(`unexpected rpc ${method}`)
  } })
  const account = privateKeyToAccount(generatePrivateKey())
  const guarded = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(createWalletClient({ account, chain: base, transport }))
  const fees = { gas: 60000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  await guarded.sendTransaction({ to: SAVED, value: 1n, ...fees })
  assert.equal(requests.at(-1).tx.nonce, 5)                                 // read from the wallet's node, sent with the check
  assert.ok(seen.includes('eth_getTransactionCount'))
  tamper = 'other-nonce'                                                    // a receipt for the same transaction at another position does not count
  await assert.rejects(() => guarded.sendTransaction({ to: SAVED, value: 1n, ...fees }), OathlineUnavailable)
  tamper = 'none'
  expectNonce = 9                                                           // a position the caller chose is kept and sent as is
  await guarded.sendTransaction({ to: SAVED, value: 1n, nonce: 9, ...fees }); assert.equal(requests.at(-1).tx.nonce, 9)
  const p = fakeProvider()                                                  // a provider that cannot say its position sends none
  await new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p).sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(requests.at(-1).tx.nonce, undefined); assert.equal(p.sent.at(-1).nonce, undefined)
  const p2 = { ...fakeProvider(), getPublicClient: () => ({ getTransactionCount: async () => 3 }) }   // AgentKit's viem provider can
  await new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(p2).sendTransaction({ to: SAVED, data: '0x' })
  assert.equal(requests.at(-1).tx.nonce, 3); assert.equal(p2.sent.at(-1).nonce, 3)
})

test('EIP-7702 (third review H2): an authorization list is refused before any check, signAuthorization never signs; shadow mode logs a block', async () => {
  const p = fakeProvider(); const decisions: Array<[string, string]> = []
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (r, _t, d) => decisions.push([r.verdict, d]) }).guardWalletProvider(p)
  const auth = [{ address: ATTACKER, chainId: 8453, nonce: 1, r: '0x01' as Hex, s: '0x01' as Hex, yParity: 0 }]
  const before = requests.length
  await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x', authorizationList: auth }), OathlineBlocked)
  assert.equal(requests.length, before); assert.equal(p.sent.length, 0); assert.deepEqual(decisions.at(-1), ['block', 'refused'])
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: async () => { throw new Error('no rpc') } }) })
  const guarded = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(client)
  await assert.rejects(() => guarded.signAuthorization({ contractAddress: ATTACKER, chainId: 8453, nonce: 1 }), OathlineBlocked)
  await assert.rejects(() => guarded.sendTransaction({ to: SAVED, value: 1n, nonce: 0, gas: 60000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, authorizationList: auth }), OathlineBlocked)
  assert.equal(requests.length, before)
  const shadowLog: Array<[string, string]> = []
  const shadow = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (r, _t, d) => shadowLog.push([r.verdict, d]) }).guardWalletProvider(fakeProvider())
  await shadow.sendTransaction({ to: SAVED, data: '0x', authorizationList: auth })
  assert.ok(shadowLog.some(([v, d]) => v === 'block' && d === 'shadow'))
})

test('an ask held on the position side is never put to the local hook (re-check of the third review, H1)', async () => {
  const p = fakeProvider(); let hookAsked = 0
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => { hookAsked++; return true } }).guardWalletProvider(p)
  assert.equal(await g.sendTransaction({ to: ASKER, data: '0x' }), '0xabc')                 // an ordinary ask: the hook may say yes
  await assert.rejects(() => g.sendTransaction({ to: HELD, data: '0x' }), OathlineNeedsApproval)
  assert.equal(hookAsked, 1); assert.equal(p.sent.length, 1)
})

test('step 2d (fix 7): batches, already signed transactions, raw RPC sends and deployments are refused in enforce mode; nothing reaches the node', async () => {
  const rpc: string[] = []
  const transport = custom({ request: async ({ method }: any) => { rpc.push(method); if (method === 'wallet_sendCalls') return { id: '0x1' }; if (method === 'eth_sendRawTransaction') return `0x${'22'.repeat(32)}`; throw new Error(`unexpected rpc ${method}`) } })
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport })
  const decisions: Array<[string, string, string]> = []
  const enforce = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (r, _t, d) => decisions.push([r.verdict, d, r.reason]) }).guard(client)
  const calls = [{ to: SAVED, value: 1n }, { to: ATTACKER, data: '0x' as Hex }]
  await assert.rejects(() => enforce.sendCalls({ calls }), OathlineBlocked)
  await assert.rejects(() => enforce.sendCallsSync({ calls }), OathlineBlocked)
  await assert.rejects(() => enforce.sendRawTransaction({ serializedTransaction: '0x02' }), OathlineBlocked)
  await assert.rejects(() => enforce.sendRawTransactionSync({ serializedTransaction: '0x02' }), OathlineBlocked)
  await assert.rejects(() => enforce.deployContract({ abi: [], bytecode: '0x6000' }), OathlineBlocked)
  // the raw JSON-RPC door of the client is shut the same way
  for (const method of ['wallet_sendCalls', 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_signTransaction', 'wallet_grantPermissions', 'wallet_sendPreparedCalls', 'eth_sendUserOperation']) await assert.rejects(() => enforce.request({ method, params: [] } as any), OathlineBlocked, method)
  assert.equal(rpc.length, 0)
  assert.ok(decisions.length >= 9 && decisions.every(d => d[0] === 'block' && d[1] === 'refused'), JSON.stringify(decisions))
  assert.match(decisions[0][2], /batch of calls \(sendCalls\).*cannot check/)
  // a signature asked for through the raw door follows the signatures policy like any other
  await assert.rejects(() => enforce.request({ method: 'personal_sign', params: ['0x68', SAVED] } as any), OathlineNeedsApproval)
  // the sync variants of the checked calls are checked, not passed through
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  await assert.rejects(() => enforce.sendTransactionSync({ to: ATTACKER, value: 1n, ...fees }), OathlineBlocked)
  await assert.rejects(() => enforce.writeContractSync({ address: ATTACKER, abi: parseAbi(['function transfer(address to, uint256 amount) returns (bool)']), functionName: 'transfer', args: [SAVED, 1n], ...fees }), OathlineBlocked)
  assert.equal(rpc.length, 0)
  // with no mode in code and no answer from sayso seen yet: the same, fail closed
  await assert.rejects(() => new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER }).guard(client).sendCalls({ calls }), OathlineBlocked)
  // a guarded client extended further keeps the shut door
  await assert.rejects(() => enforce.extend(() => ({})).request({ method: 'eth_sendRawTransaction', params: ['0x02'] } as any), OathlineBlocked)
  // ... and an extension that brings viem's own wallet actions back does not put an unguarded sendTransaction on top (review 2026-10-19)
  await assert.rejects(() => (enforce.extend(walletActions) as any).sendTransaction({ to: ATTACKER, value: 1n, ...fees }), OathlineBlocked)
  await assert.rejects(() => (enforce.extend(walletActions) as any).sendCalls({ calls }), OathlineBlocked)
  assert.equal(rpc.length, 0)
})

test('step 2d (fix 7): in shadow mode they go ahead, the decision says shadow, and sayso is told so the owner sees "would have blocked"', async () => {
  const rpc: string[] = []
  const transport = custom({ request: async ({ method }: any) => { rpc.push(method); if (method === 'wallet_sendCalls') return { id: '0x1' }; if (method === 'eth_sendRawTransaction') return `0x${'22'.repeat(32)}`; throw new Error(`unexpected rpc ${method}`) } })
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport })
  reports.length = 0
  const shadowLog: Array<[string, string]> = []
  const shadow = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow', onDecision: (r, _t, d) => shadowLog.push([r.verdict, d]) }).guard(client)
  assert.equal((await shadow.sendCalls({ calls: [{ to: SAVED, value: 1n }] })).id, '0x1')
  assert.equal(await shadow.sendRawTransaction({ serializedTransaction: '0x02' }), `0x${'22'.repeat(32)}`)
  await shadow.request({ method: 'wallet_sendCalls', params: [] } as any)
  await shadow.signAuthorization({ contractAddress: ATTACKER, chainId: 8453, nonce: 1 })                      // EIP-7702, only with shadow written in code
  assert.deepEqual(rpc, ['wallet_sendCalls', 'eth_sendRawTransaction', 'wallet_sendCalls'])
  assert.deepEqual(shadowLog.map(d => d.join(' ')), ['block shadow', 'block shadow', 'block shadow', 'block shadow'])
  for (let i = 0; i < 50 && reports.length < 4; i++) await new Promise(r => setTimeout(r, 20))          // reported without holding the call up
  assert.deepEqual(reports.map(r => r.kind), ['batch of calls (sendCalls)', 'already signed transaction (sendRawTransaction)', 'raw RPC call (wallet_sendCalls)', 'EIP-7702 authorization'])
  assert.equal(reports[0].detail, '1 call'); assert.equal(reports[3].to, ATTACKER)
  assert.ok(reports.every(r => !('mandate' in r) && !('apiKey' in r)))
})

test('R2 (review M1 of 2d): the guarded viem client gives out no signing account and no unguarded transport', async () => {
  const rpc: string[] = []
  const transport = custom({ request: async ({ method }: any) => { rpc.push(method); if (method === 'eth_sendRawTransaction') return `0x${'33'.repeat(32)}`; if (method === 'eth_chainId') return '0x2105'; throw new Error(`unexpected rpc ${method}`) } })
  const account = privateKeyToAccount(generatePrivateKey())   // throwaway key, never funded
  const client = createWalletClient({ account, chain: base, transport })
  const decisions: string[] = []
  const enforce = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (_r, _t, d) => decisions.push(d) }).guard(client)
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  // the account: its address and type are there, nothing that signs
  assert.equal(enforce.account.address, account.address)
  assert.equal(enforce.account.type, 'local')
  for (const m of ['signTransaction', 'signMessage', 'signTypedData', 'signAuthorization', 'sign']) assert.equal((enforce.account as any)[m], undefined, m)
  assert.equal(Object.getOwnPropertyDescriptor(enforce, 'account')?.value?.signTransaction, undefined)
  assert.equal(({ ...enforce } as any).account?.signTransaction, undefined)
  assert.ok(Object.isFrozen(enforce.account))
  // the transport: its JSON-RPC door is shut the same way as the client's, also when read through a descriptor or a copy
  await assert.rejects(() => enforce.transport.request({ method: 'eth_sendRawTransaction', params: ['0x02'] } as any), OathlineBlocked)
  await assert.rejects(() => (Object.getOwnPropertyDescriptor(enforce, 'transport')?.value as any).request({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
  await assert.rejects(() => ({ ...enforce } as any).transport.request({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
  await assert.rejects(() => (Object.getOwnPropertyDescriptor(enforce, 'request')?.value as any)({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
  await assert.rejects(() => enforce.transport.request({ method: 'personal_sign', params: ['0x68', SAVED] } as any), OathlineNeedsApproval)
  assert.equal(await enforce.transport.request({ method: 'eth_chainId' } as any), '0x2105')   // reads still pass
  // an extension sees the same shut client, so it cannot hand the account or transport out either
  const leaked = enforce.extend((c: any) => ({ leakAccount: () => c.account, leakTransport: () => c.transport, leakRequest: () => c.request }))
  assert.equal(leaked.leakAccount().signTransaction, undefined)
  await assert.rejects(() => leaked.leakTransport().request({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
  await assert.rejects(() => leaked.leakRequest()({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
  assert.equal(leaked.account.signTransaction, undefined)
  // viem's standalone actions handed the guarded client find no account that signs and a shut door: nothing is sent or signed
  await assert.rejects(() => signMessageAction(enforce as any, { message: 'hi' } as any), OathlineNeedsApproval)
  await assert.rejects(() => sendTransactionAction(enforce as any, { to: ATTACKER, value: 1n, ...fees } as any))
  assert.equal(rpc.filter(m => m === 'eth_sendRawTransaction' || m === 'eth_sendTransaction').length, 0)
  // the checked paths still sign with the real account
  assert.equal(await enforce.sendTransaction({ to: SAVED, value: 1n, ...fees }), `0x${'33'.repeat(32)}`)
  await assert.rejects(() => enforce.sendTransaction({ to: ATTACKER, value: 1n, ...fees }), OathlineBlocked)
  assert.equal(await leaked.sendTransaction({ to: SAVED, value: 1n, ...fees }), `0x${'33'.repeat(32)}`)
  // the view handed back as `account` signs with the real account on the checked path (sendViaSafe and others pass it)
  assert.equal(await enforce.sendTransaction({ account: enforce.account, to: SAVED, value: 1n, ...fees } as any), `0x${'33'.repeat(32)}`)
  const ok = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, signatures: 'allow' }).guard(client)
  assert.match(await ok.signMessage({ account: ok.account, message: 'hi' } as any), /^0x[0-9a-f]{130}$/)
  assert.deepEqual(rpc.filter(m => m === 'eth_sendRawTransaction').length, 3)
  // in shadow mode the account still signs nothing on its own (there is no door to report), the transport's sends go ahead and are reported
  reports.length = 0
  const shadow = new Oathline({ mode: 'shadow', apiUrl, apiKey: KEY, signer: SIGNER }).guard(client)
  assert.equal((shadow.account as any).signTransaction, undefined)
  assert.equal(await shadow.transport.request({ method: 'eth_sendRawTransaction', params: ['0x02'] } as any), `0x${'33'.repeat(32)}`)
  for (let i = 0; i < 50 && reports.length < 1; i++) await new Promise(r => setTimeout(r, 20))
  assert.equal(reports[0]?.kind, 'raw RPC call (eth_sendRawTransaction)')
})

test('R2 (review 2026-10-20): viem\'s own token actions go through the check; a fallback transport hands out no inner door', async () => {
  const rpc: string[] = []
  const send = async ({ method }: any) => { rpc.push(method); if (method === 'eth_sendRawTransaction' || method === 'eth_sendTransaction') return `0x${'44'.repeat(32)}`; if (method === 'eth_chainId') return '0x2105'; throw new Error(`unexpected rpc ${method}`) }
  const account = privateKeyToAccount(generatePrivateKey())   // throwaway key, never funded
  const client = createWalletClient({ account, chain: base, transport: custom({ request: send }) })
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  const refusals: string[] = []
  const enforce = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (r, _t, d) => { if (d === 'refused') refusals.push(r.verdict) } }).guard(client) as any
  if (enforce.token) {   // viem 2.5x puts a token group on the wallet client
    const before = requests.length
    // a transfer or approval is checked as the ERC-20 call it is (the fake check API blocks by the contract called:
    // here the token contract is the attacker's), and refused before anything is signed
    await assert.rejects(() => enforce.token.transfer({ token: ATTACKER, to: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
    await assert.rejects(() => enforce.token.approve({ token: ATTACKER, spender: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
    await assert.rejects(() => enforce.token.transferSync({ token: ATTACKER, to: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
    await assert.rejects(() => (Object.getOwnPropertyDescriptor(enforce, 'token')?.value as any).transfer({ token: ATTACKER, to: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
    await assert.rejects(() => enforce.extend(walletActions).token.transfer({ token: ATTACKER, to: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
    assert.equal(rpc.filter(m => m === 'eth_sendRawTransaction').length, 0)
    const asked = requests.slice(before)
    assert.deepEqual(refusals, ['block', 'block', 'block', 'block', 'block'])   // all five refused on sayso's verdict
    assert.ok(asked.length === 5 && asked.every(r => r.tx.to.toLowerCase() === ATTACKER.toLowerCase()), JSON.stringify(asked.map(r => r.tx.to)))
    assert.match(asked[0].tx.data, /^0xa9059cbb0{24}7777/)   // transfer(HELD, 1)
    assert.match(asked[1].tx.data, /^0x095ea7b30{24}7777/)   // approve(HELD, 1)
    // an allowed one is signed with the real account and sent
    assert.equal(await enforce.token.transfer({ token: SAVED, to: SAVED, amount: 1n, decimals: 6, ...fees }), `0x${'44'.repeat(32)}`)
    assert.equal(rpc.filter(m => m === 'eth_sendRawTransaction').length, 1)
  }
  // token reads added later by publicActions (built on the guarded client) still work
  const withReads = enforce.extend(publicActions)
  if (typeof withReads.token?.getBalance === 'function') assert.notEqual(withReads.token.getBalance, undefined)
  await assert.rejects(() => withReads.token.transfer({ token: ATTACKER, to: HELD, amount: 1n, decimals: 6, ...fees }), OathlineBlocked)
  // a fallback transport: only plain fields and the shut request come out, never the inner transports
  const fb = createWalletClient({ account: account.address, chain: base, transport: fallback([custom({ request: send }), custom({ request: send })]) })
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(fb) as any
  assert.equal(g.transport.transports, undefined)
  assert.deepEqual(Object.keys(g.transport).filter(k => !['key', 'name', 'type', 'retryCount', 'retryDelay', 'timeout', 'methods', 'request'].includes(k)), [])
  assert.equal(g.transport.url, undefined)
  rpc.length = 0
  await assert.rejects(() => g.transport.request({ method: 'eth_sendTransaction', params: [{}] }), OathlineBlocked)
  assert.equal(rpc.length, 0)
  // the account view is one object, so a copy made before handing it back still signs with the real account
  assert.equal(enforce.account, enforce.account)
})

test('viem scope() (2.57.10, 2026-10-23): a scoped copy of the guarded client is guarded the same', async () => {
  const sentToNode: string[] = []
  const send = async ({ method }: any) => {
    sentToNode.push(method)
    if (method === 'eth_chainId') return '0x2105'
    if (method === 'eth_getTransactionCount') return '0x0'
    if (method === 'eth_estimateGas') return '0x5208'
    if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'
    if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }
    if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`
    throw new Error(`no rpc ${method}`)
  }
  const raw = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) })
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(raw) as any
  assert.equal(typeof (raw as any).scope, 'function', 'the installed viem has scope(); this test needs viem 2.57.10 or newer')
  const signal = new AbortController().signal
  for (const s of [g.scope(), g.scope({ signal }), g.scope({ signal }).scope(), g.extend(() => ({ extra: 1 })).scope()]) {
    sentToNode.length = 0
    // the account and the transport are the same views as on the guarded client: nothing to sign with, no node URL
    assert.equal(s.account, g.account)
    assert.equal(typeof s.account.signTransaction, 'undefined')
    assert.equal(s.transport, g.transport)
    // the raw request door is shut the same way: a signing method never reaches the node
    await assert.rejects(() => s.request({ method: 'eth_sendTransaction', params: [{ to: ATTACKER }] }), OathlineBlocked)
    await assert.rejects(() => s.request({ method: 'eth_sendRawTransaction', params: ['0x02'] }), OathlineBlocked)
    // the checked actions are still the checked ones
    await assert.rejects(() => s.sendTransaction({ to: ATTACKER, value: 1n }), OathlineBlocked)
    await assert.rejects(() => s.signTransaction({ to: ATTACKER, value: 1n, gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, nonce: 0, chainId: 8453 }), OathlineBlocked)
    assert.deepEqual(sentToNode.filter(m => /send|sign/i.test(m)), [])
  }
  // and the scoped copy still works for what sayso allows
  sentToNode.length = 0
  assert.match(await g.scope().sendTransaction({ to: SAVED, value: 1n }), /^0x1{64}$/)
  assert.ok(sentToNode.includes('eth_sendRawTransaction'))
})

test('scope() review 2026-10-23: an extension\'s own scope gets the guarded client, writes are refused, descriptors stay guarded', async () => {
  const sentToNode: string[] = []
  const send = async ({ method }: any) => { sentToNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x0'; if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`; throw new Error(`no rpc ${method}`) }
  const mk = () => createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) })
  const guard = (c: any) => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(c) as any
  const g = guard(mk())
  // H1: an extension may define its own scope (viem 2.57.10); it runs with the guarded client as `this`
  const ext = g.extend(() => ({ scope(this: any) { return { acct: this.account, req: this.request } } })).scope()
  assert.equal(ext.acct, g.account)
  assert.equal(typeof ext.acct.signTransaction, 'undefined')
  await assert.rejects(() => ext.req({ method: 'eth_sendTransaction', params: [{ to: ATTACKER }] }), OathlineBlocked)
  // L2: an extension's scope may return anything; a non-client comes back as it is
  assert.equal(g.extend(() => ({ scope: () => 42 })).scope(), 42)
  // H2: no write reaches the raw client, so no property can be made to read raw through its descriptor
  assert.throws(() => Object.defineProperty(g, 'scope', { configurable: false }), TypeError)
  assert.throws(() => Object.defineProperty(g, 'account', { configurable: false }), TypeError)
  assert.throws(() => Object.freeze(g), TypeError)
  assert.throws(() => { delete g.request }, TypeError)
  assert.equal(Object.getOwnPropertyDescriptor(g, 'account')!.value, g.account)
  assert.equal(Object.getOwnPropertyDescriptor(g, 'scope')!.value().account, g.account)
  assert.equal(({ ...g }).scope().account, g.account)
  await assert.rejects(() => Object.getOwnPropertyDescriptor(g, 'request')!.value({ method: 'eth_sendTransaction', params: [{ to: ATTACKER }] }), OathlineBlocked)
  // N1: the same signal gives the same guarded copy, as viem gives the same scoped client
  const signal = new AbortController().signal
  assert.equal(g.scope({ signal }), g.scope({ signal }))
  // L1: a group of actions named scope, added before guard(), is still a guarded group
  const g2 = guard(mk().extend(() => ({ scope: { pay: async () => 'paid' } })))
  await assert.rejects(() => g2.scope.pay(), OathlineBlocked)
  assert.deepEqual(sentToNode.filter(m => /send|sign/i.test(m)), [])
})

test('scope() review 2026-10-23 (M1, H2): a guarded provider and a guarded CDP client hand out nothing raw through descriptors or writes', async () => {
  const sent: any[] = []
  const evm = { sendTransaction: async (a: any) => { sent.push(a); return '0xcdp' } }
  const provider: any = { getAddress: () => SAVED, sendTransaction: async (tx: any) => { sent.push(tx); return '0xabc' as Hex }, getClient: () => ({ evm }) }
  const gp = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider) as any
  await assert.rejects(() => Object.getOwnPropertyDescriptor(gp, 'sendTransaction')!.value({ to: ATTACKER, data: '0x' }), OathlineBlocked)
  assert.throws(() => Object.defineProperty(gp, 'sendTransaction', { configurable: false }), TypeError)
  assert.throws(() => Object.freeze(gp), TypeError)
  const c = gp.getClient().evm
  assert.throws(() => Object.defineProperty(c, 'sendTransaction', { configurable: false }), TypeError)
  await assert.rejects(() => Object.getOwnPropertyDescriptor(c, 'sendTransaction')!.value({ to: ATTACKER }), OathlineBlocked)
  // 0.6.3 (security desk F1): no prototype swap either
  assert.throws(() => Object.setPrototypeOf(gp, {}), TypeError)
  assert.throws(() => Object.setPrototypeOf(c, {}), TypeError)
  assert.deepEqual(sent, [])
})

test('R2 (review 2026-10-20), 0.6.3: every function of viem\'s wallet and public actions is known to the SDK (a new viem action fails this test until it is looked at; meanwhile the guarded client refuses it in enforce mode)', () => {
  const client = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: async () => { throw new Error('no rpc') } }) })
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(client) as any
  // checked, refused or gated by the SDK
  const GUARDED = ['sendTransaction', 'sendTransactionSync', 'signTransaction', 'writeContract', 'writeContractSync', 'sendCalls', 'sendCallsSync', 'sendRawTransaction', 'sendRawTransactionSync', 'deployContract', 'signAuthorization', 'signTypedData', 'signMessage', 'switchChain', 'addChain', 'request', 'extend', 'scope']
  const known = (k: string) => GUARDED.includes(k) || CLIENT_READS.has(k)
  const fns = (o: any) => Object.keys(o).filter(k => typeof o[k] === 'function')
  assert.deepEqual(fns(g).filter(k => !known(k)), [], 'the guarded wallet client')
  // viem's own sets of actions, read straight from the installed viem: wallet, public, and the OP Stack L2 reads used on Base
  assert.deepEqual(fns(walletActions(client as any)).filter(k => !known(k)), [], 'walletActions')
  assert.deepEqual(fns(publicActions(client as any)).filter(k => !known(k)), [], 'publicActions')
  assert.deepEqual(fns(publicActionsL2()(client as any)).filter(k => !known(k)), [], 'publicActionsL2')
  // the allow list holds no function that signs or sends
  for (const k of CLIENT_READS) assert.doesNotMatch(k, /^(send|sign|write|deploy|execute|grant|initiate|deposit|prove|finalize)/, k)
  // groups of actions: only the token group is known; each of its functions is wrapped (none is viem's own)
  const groups = Object.keys(g).filter(k => g[k] && typeof g[k] === 'object' && !['account', 'transport', 'chain', 'ccipRead', 'batch'].includes(k))
  assert.ok(groups.every(k => k === 'token'), groups.join(','))
  if (g.token) for (const k of Object.keys(g.token)) assert.notEqual(g.token[k], (client as any).token[k], k)
})

test('0.6.3 (security desk 2026-10-25, F2): a function the SDK does not know is refused in enforce mode, also from an add-on installed before guard(); reads stay allowed; add-ons installed after guard() work through the check', async () => {
  const toNode: string[] = []
  const send = async ({ method }: any) => {
    toNode.push(method)
    if (method === 'eth_chainId') return '0x2105'
    if (method === 'eth_getTransactionCount') return '0x0'
    if (method === 'eth_estimateGas') return '0x5208'
    if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'
    if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }
    if (method === 'eth_getBalance') return '0x64'
    if (method === 'eth_call') return `0x${'0'.repeat(63)}1`   // supportsExecutionMode: yes
    if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`
    throw new Error(`no rpc ${method}`)
  }
  const account = privateKeyToAccount(generatePrivateKey())   // throwaway key, never funded
  const mk = () => createWalletClient({ account, chain: base, transport: custom({ request: send }) })
  const decisions: Array<[string, string]> = []
  const enforce = (c: any) => new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (r, _t, d) => decisions.push([d, r.reason]) }).guard(c) as any
  const execute = { address: account.address, calls: [{ to: ATTACKER, value: 1n }] }
  const sends = () => toNode.filter(m => /send|sign/i.test(m))
  // viem's own ERC-7821 add-on, installed before guard(): its execute signed with the raw account before 0.6.3
  const g = enforce(mk().extend(erc7821Actions()).extend(erc7715Actions()).extend(walletActionsL2()).extend(publicActionsL2()).extend(publicActions))
  await assert.rejects(() => g.execute(execute), (e: any) => e instanceof OathlineBlocked && /execute: this wallet function is not one sayso knows; it is refused in enforce mode until sayso supports it/.test(e.message))
  await assert.rejects(() => g.executeBatches({ address: account.address, batches: [] }), OathlineBlocked)
  await assert.rejects(() => g.grantPermissions({ expiry: 1, permissions: [] }), OathlineBlocked)
  await assert.rejects(() => g.initiateWithdrawal({ request: { gas: 21000n, to: ATTACKER, value: 1n } }), OathlineBlocked)
  // the same on a scoped copy, through a property descriptor, and on a guarded client extended further
  await assert.rejects(() => g.scope().execute(execute), OathlineBlocked)
  await assert.rejects(() => Object.getOwnPropertyDescriptor(g, 'execute')!.value(execute), OathlineBlocked)
  await assert.rejects(() => g.extend(() => ({ extra: 1 })).execute(execute), OathlineBlocked)
  assert.deepEqual(sends(), [], 'nothing was signed or sent')
  assert.equal(decisions.at(-1)?.[0], 'refused')
  // a hand-written add-on before guard() that sends with the raw client: refused the same way
  const raw = mk()
  const sneaky = enforce(raw.extend(() => ({ payNow: async () => rawSend(raw, { to: ATTACKER, value: 1n }) })))
  await assert.rejects(() => sneaky.payNow(), OathlineBlocked)
  assert.deepEqual(sends(), [])
  // reads and preparation stay allowed (viem's public actions, the OP Stack fee reads, ERC-7821's mode query)
  assert.equal(await g.getBalance({ address: account.address }), 100n)
  assert.equal(await g.getChainId(), 8453)
  assert.equal(typeof g.estimateL1Fee, 'function'); assert.equal(typeof g.supportsExecutionMode, 'function')
  assert.equal(g.getBalance, g.getBalance)
  // plain object methods are not wallet functions
  assert.equal(String(g), '[object Object]'); assert.equal(g.hasOwnProperty('request'), true)
  // an add-on installed AFTER guard() is handed the guarded client: it works, and what it sends is checked
  const after = enforce(mk()).extend(erc7821Actions())
  assert.equal(typeof after.execute, 'function')
  // viem's execute calls its own sendTransaction with the client it was handed: the guarded one has no account that signs
  await assert.rejects(() => after.execute(execute), /signTransaction is not a function/)
  assert.deepEqual(sends(), [])
  // a function that sends through the client's actions goes through the check
  const viaCheck = enforce(mk()).extend((c: any) => ({ payNow: (to: Address) => c.sendTransaction({ to, value: 1n }) }))
  await assert.rejects(() => viaCheck.payNow(ATTACKER), OathlineBlocked)   // sayso's block
  assert.deepEqual(sends(), [])
  assert.match(await viaCheck.payNow(SAVED), /^0x1{64}$/)               // sayso's allow
  // a later extension cannot make an earlier raw function look like its own: the name alone does not count
  const g2 = enforce(mk().extend(erc7821Actions()))
  g2.extend(() => ({ execute: async () => 'mine' }))
  await assert.rejects(() => g2.execute(execute), OathlineBlocked)
  // no prototype swap either (security desk F1)
  assert.throws(() => Object.setPrototypeOf(g, {}), TypeError)
})

test('0.6.3 review 2026-10-27 (L1, L2): other shapes of an add-on installed before guard() are refused too, and an unawaited refusal does not take the agent down', async () => {
  const toNode: string[] = []
  const send = async ({ method }: any) => { toNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x0'; if (method === 'eth_estimateGas') return '0x5208'; if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'; if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }; if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`; throw new Error(`no rpc ${method}`) }
  const raw = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) })
  const pay = () => rawSend(raw, { to: ATTACKER, value: 1n })
  const PAY = Symbol.for('pay')
  const hidden = {}; Object.defineProperty(hidden, 'pay', { value: pay, enumerable: false })
  class Payer { pay() { return pay() } }
  const withAddOns = raw.extend(() => ({ [PAY]: pay, simulate: pay, registry: new Map([['pay', pay]]), hidden, payer: new Payer(), scope: () => ({ pay }) }) as any)
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(withAddOns as any) as any
  await assert.rejects(() => g[PAY](), OathlineBlocked)                 // a symbol-keyed function
  await assert.rejects(() => g.simulate(), OathlineBlocked)             // an allow-listed name that is not viem's own function
  await assert.rejects(() => g.scope(), OathlineBlocked)                // an add-on's own scope from before guard()
  await assert.rejects(() => g.registry.get('pay'), OathlineBlocked)   // a Map of functions: its own methods are refused before anything comes out
  await assert.rejects(async () => g.hidden.pay(), OathlineBlocked)     // a non-enumerable method
  await assert.rejects(async () => g.payer.pay(), OathlineBlocked)      // a class instance's method
  assert.deepEqual(toNode.filter(m => /send|sign/i.test(m)), [], 'nothing was signed or sent')
  // viem's own simulate and scope on a plain guarded client are still fine
  const plain = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) }).extend(publicActions)) as any
  assert.equal(plain.simulate, plain.simulate); assert.equal(typeof plain.scope().sendTransaction, 'function')
  // L2: a refusal nobody awaits is not an unhandled rejection
  const unhandled: unknown[] = []; const onUnhandled = (e: unknown) => unhandled.push(e)
  process.on('unhandledRejection', onUnhandled)
  const r = g.simulate(); assert.ok(r instanceof Promise)
  await new Promise(res => setTimeout(res, 50))
  process.off('unhandledRejection', onUnhandled)
  assert.deepEqual(unhandled, [])
  await assert.rejects(() => r, OathlineBlocked)
})

test('0.6.3 review 2026-10-27 (M3): a checked transaction is signed only for the chain sayso checked; switchChain and addChain are refused in enforce mode', async () => {
  const signed: any[] = [], toNode: string[] = []
  const send = async ({ method, params }: any) => { toNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_sendRawTransaction') { signed.push(parseTransaction(params[0])); return `0x${'66'.repeat(32)}` } throw new Error(`no rpc ${method}`) }
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) })) as any
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  const abi = parseAbi(['function transfer(address to, uint256 amount) returns (bool)'])
  await assert.rejects(() => g.sendTransaction({ to: SAVED, value: 1n, chainId: 1, ...fees }), (e: any) => e instanceof OathlineBlocked && /another chain.*chainId 1/.test(e.message))
  await assert.rejects(() => g.sendTransaction({ to: SAVED, value: 1n, chain: null, ...fees }), OathlineBlocked)
  await assert.rejects(() => g.sendTransaction({ to: SAVED, value: 1n, assertChainId: false, ...fees }), OathlineBlocked)
  await assert.rejects(() => g.writeContract({ address: SAVED, abi, functionName: 'transfer', args: [SAVED, 1n], chainId: 1, ...fees }), OathlineBlocked)
  await assert.rejects(() => g.switchChain({ id: 1 }), OathlineBlocked)
  await assert.rejects(() => g.addChain({ chain: base }), OathlineBlocked)
  assert.deepEqual(signed, [])
  // an allowed one is signed for Base, also when the call names Base's id itself
  await g.sendTransaction({ to: SAVED, value: 1n, ...fees })
  await g.sendTransaction({ to: SAVED, value: 1n, chainId: 8453, ...fees })
  assert.deepEqual((signed as any[]).map(t => t.chainId), [8453, 8453])
})

test('0.6.3 re-check 2026-10-27 (R1, R2, R3): an outage does not stop shadow mode; nested add-on functions are refused; a list on the client is not a group', async () => {
  const toNode: string[] = []
  const send = async ({ method }: any) => { toNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x0'; if (method === 'eth_estimateGas') return '0x5208'; if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'; if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }; if (method === 'eth_call') return `0x${'0'.repeat(63)}5`; if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`; throw new Error(`no rpc ${method}`) }
  const mk = (extra: any = {}) => createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }), ...extra })
  // R1: sayso unreachable, no chainId in the options: shadow mode still sends (signed for the client's chain)
  const down = (() => { throw new Error('unreachable') }) as unknown as typeof fetch
  const shadow = new Oathline({ mode: 'shadow', apiUrl: 'http://127.0.0.1:1', apiKey: KEY, fetch: down }).guard(mk()) as any
  assert.match(await shadow.sendTransaction({ to: SAVED, value: 1n }), /^0x1{64}$/)
  await assert.rejects(() => new Oathline({ mode: 'enforce', apiUrl: 'http://127.0.0.1:1', apiKey: KEY, fetch: down }).guard(mk() as any).sendTransaction({ to: SAVED, value: 1n } as any), OathlineUnavailable)
  // R2: a function nested deeper in an add-on installed before guard() is refused like a top-level one
  const raw = mk()
  const kit = raw.extend(() => ({ kit: { inner: { pay: () => rawSend(raw as any, { to: ATTACKER, value: 1n } as any) } } }) as any)
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(kit as any) as any
  toNode.length = 0
  await assert.rejects(() => g.kit.inner.pay(), OathlineBlocked)
  assert.deepEqual(toNode.filter(m => /send|sign/i.test(m)), [])
  // ... while a nested group added after guard() works (its functions were built on the guarded client)
  const after = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(mk() as any).extend((c: any) => ({ kit: { inner: { chainNow: () => c.getChainId() } } }))
  assert.equal(await after.kit.inner.chainNow(), 8453)
  // R3: viem's `tokens` option (a list) stays a list, and token reads added after guard() work
  const withTokens = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(mk({ tokens: [{ address: SAVED, symbol: 'X', decimals: 6 }] }) as any) as any
  assert.ok(Array.isArray(withTokens.tokens), 'the list is handed out as a list')
  const reads = withTokens.extend(publicActions)
  if (typeof reads.token?.getBalance === 'function') assert.notEqual(await reads.token.getBalance({ token: SAVED, account: SAVED }).catch((e: Error) => e.message), 'tokens is not iterable')
})

test('0.6.3 re-check 2026-10-26 (R4): an Array subclass with its own method, a Promise of raw functions and deep nesting are refused too', async () => {
  const toNode: string[] = []
  const send = async ({ method }: any) => { toNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x0'; if (method === 'eth_estimateGas') return '0x5208'; if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'; if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }; if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`; throw new Error(`no rpc ${method}`) }
  const raw: any = createWalletClient({ account: privateKeyToAccount(generatePrivateKey()), chain: base, transport: custom({ request: send }) })
  const pay = () => rawSend(raw, { to: ATTACKER, value: 1n } as any)
  class L extends Array { pay() { return pay() } }
  const list = new L(); list.push(1)
  let deep: any = { pay }; for (let i = 0; i < 9; i++) deep = { [`l${i}`]: deep }
  const cyclic: any = { pay }; cyclic.self = cyclic
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(raw.extend(() => ({ list, ready: Promise.resolve({ pay }), kit: { later: Promise.resolve({ pay }) }, deep, cyclic })) as any) as any
  await assert.rejects(async () => g.list.pay(), OathlineBlocked)
  await assert.rejects(async () => (await g.ready).pay(), OathlineBlocked)
  await assert.rejects(async () => (await g.kit.later).pay(), OathlineBlocked)
  let d = g.deep; for (let i = 8; i >= 0; i--) d = d[`l${i}`]
  await assert.rejects(async () => d.pay(), OathlineBlocked)
  await assert.rejects(async () => g.cyclic.self.self.self.self.self.self.self.self.pay(), OathlineBlocked)
  assert.deepEqual(toNode.filter(m => /send|sign/i.test(m)), [], 'nothing was signed or sent')
  assert.equal(g.list[0], 1)   // the data is still there
})

test('0.6.3: in shadow mode an unknown function goes ahead and sayso is told "would have blocked"; before the owner\'s switch is known it is refused', async () => {
  const toNode: string[] = []
  const send = async ({ method }: any) => { toNode.push(method); if (method === 'eth_chainId') return '0x2105'; if (method === 'eth_getTransactionCount') return '0x0'; if (method === 'eth_estimateGas') return '0x5208'; if (method === 'eth_gasPrice' || method === 'eth_maxPriorityFeePerGas') return '0x1'; if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x1', number: '0x1', timestamp: '0x1', hash: `0x${'0'.repeat(64)}` }; if (/^eth_send/.test(method)) return `0x${'1'.repeat(64)}`; throw new Error(`no rpc ${method}`) }
  const account = privateKeyToAccount(generatePrivateKey())
  const raw = createWalletClient({ account, chain: base, transport: custom({ request: send }) }).extend(() => ({ syncHelper: (x: number) => x + 1 }))
  await new Promise(r => setTimeout(r, 50)); reports.length = 0
  const log: string[] = []
  const shadow = new Oathline({ mode: 'shadow', apiUrl, apiKey: KEY, signer: SIGNER, onDecision: (r, _t, d) => log.push(`${r.verdict} ${d}`) }).guard(raw) as any
  assert.equal(shadow.syncHelper(1), 2)   // a plain function keeps its plain answer in shadow mode
  for (let i = 0; i < 50 && reports.length < 1; i++) await new Promise(r => setTimeout(r, 20))
  assert.deepEqual(log, ['block shadow'])
  assert.equal(reports[0]?.kind, 'unknown wallet function (syncHelper)'); assert.equal(reports[0]?.verdict, 'block')
  // called again and again: every call is a decision, but sayso is told once (review 2026-10-27, L3)
  for (let i = 0; i < 5; i++) shadow.syncHelper(i)
  await new Promise(r => setTimeout(r, 100))
  assert.equal(log.length, 6); assert.equal(reports.filter(r => r.kind === 'unknown wallet function (syncHelper)').length, 1)
  // the owner decides (no mode in code) and no answer from sayso yet: decided as enforce, like every call it cannot check
  // (refused as a rejected promise, whether the function was plain or async: nothing ran)
  await assert.rejects(() => new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER }).guard(raw as any).syncHelper(1), OathlineBlocked)
})

test('0.6.3 (security desk F3): the newest viem the tests ran on is written down, and a newer installed viem gets one warning', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { devDependencies: Record<string, string> }
  assert.equal(TESTED_VIEM, pkg.devDependencies.viem.replace(/^\^/, ''), 'TESTED_VIEM follows the viem in devDependencies')
  assert.match(installedViem() ?? '', /^\d+\.\d+\.\d+/)
  assert.equal(newerViem('2.57.10', '2.57.10'), false); assert.equal(newerViem('2.57.11', '2.57.10'), true); assert.equal(newerViem('2.58.0', '2.57.10'), true)
  assert.equal(newerViem('3.0.0-next.14', '2.57.10'), true); assert.equal(newerViem('2.57.1', '2.57.10'), false); assert.equal(newerViem('2.30.0', '2.57.10'), false)
  assert.equal(newerViem('2.57.10-beta.1', '2.57.10'), false); assert.equal(newerViem('nonsense', '2.57.10'), false)
  assert.equal(untestedViemWarning(TESTED_VIEM), null); assert.equal(untestedViemWarning(null), null)
  assert.match(untestedViemWarning('2.58.0') ?? '', /viem 2\.58\.0 is newer than the newest viem this SDK was tested with \(2\.57\.10\)/)
  // at most once per process, whatever the installed viem (constructing an Oathline above may already have said it)
  const said: string[] = []
  warnIfUntestedViem(m => said.push(m)); warnIfUntestedViem(m => said.push(m))
  assert.ok(said.length <= 1)
})

test('review 2026-10-20 N1/N2: what is signed is exactly what was checked (no to or data override, no suffix added after, no deployment by a missing to)', async () => {
  const sent: any[] = []
  const transport = custom({ request: async ({ method, params }: any) => { if (method === 'eth_sendRawTransaction') { sent.push(parseTransaction(params[0])); return `0x${'55'.repeat(32)}` } throw new Error(`unexpected rpc ${method}`) } })
  const account = privateKeyToAccount(generatePrivateKey())   // throwaway key, never funded
  const fees = { gas: 60000n, nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n }
  const abi = parseAbi(['function transfer(address to, uint256 amount) returns (bool)'])
  const evil = encodeFunctionData({ abi, functionName: 'transfer', args: [ATTACKER, 10n ** 24n] })
  const lastChecked = () => requests.at(-1).tx
  const same = () => { const s = sent.at(-1), c = lastChecked(); assert.equal(s.to.toLowerCase(), c.to.toLowerCase()); assert.equal(s.data ?? '0x', c.data) }
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(createWalletClient({ account, chain: base, transport })) as any
  // N1: writeContract's own to / data cannot replace the checked call
  await g.writeContract({ address: SAVED, abi, functionName: 'transfer', args: [SAVED, 1n], to: ATTACKER, data: evil, ...fees })
  same()
  await g.writeContract({ address: SAVED, abi, functionName: 'transfer', args: [SAVED, 1n], data: evil, ...fees })
  same(); assert.equal(sent.length, 2)
  assert.ok(sent.every(s => !s.data?.includes(ATTACKER.slice(2).toLowerCase())), 'the attacker\'s transfer was signed')
  // N2: a suffix is part of what is checked, per call and per client
  sent.length = 0
  await g.sendTransaction({ to: SAVED, data: '0x', dataSuffix: evil, ...fees })
  same(); assert.equal(lastChecked().data, evil)   // checked with the suffix in it, so the check sees the transfer
  const suffixed = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guard(createWalletClient({ account, chain: base, transport, dataSuffix: '0xdeadbeef' } as any)) as any
  await suffixed.sendTransaction({ to: SAVED, data: '0x1234', ...fees })
  same(); assert.equal(lastChecked().data, '0x1234deadbeef')
  await suffixed.writeContract({ address: SAVED, abi, functionName: 'transfer', args: [SAVED, 1n], ...fees })
  same(); assert.match(lastChecked().data, /^0xa9059cbb.*deadbeef$/)
  // a transaction with no `to` is a contract deployment: refused in enforce like deployContract
  await assert.rejects(() => g.sendTransaction({ data: '0x6000', ...fees }), OathlineBlocked)
  await assert.rejects(() => g.signTransaction({ data: '0x6000', ...fees }), OathlineBlocked)
  // the provider path: a suffix or a missing `to` never rides along unchecked
  const provided: any[] = []
  const provider = { getAddress: () => SAVED, sendTransaction: async (tx: any) => { provided.push(tx); return '0xabc' as Hex } }
  const gp = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider)
  await assert.rejects(() => gp.sendTransaction({ to: SAVED, data: '0x', dataSuffix: evil } as any), OathlineBlocked)
  await assert.rejects(() => gp.sendTransaction({ data: '0x6000' } as any), OathlineBlocked)
  assert.equal(provided.length, 0)
})

test('review 2026-10-20 P1/P2: a wrapped provider signs only for the checked chain, and never data the check did not see', async () => {
  const signedTx: any[] = [], sentTx: any[] = []
  const provider = { getAddress: () => SAVED, sendTransaction: async (tx: any) => { sentTx.push(tx); return '0xabc' as Hex }, signTransaction: async (tx: any) => { signedTx.push(tx); return '0xsigned' as Hex } }
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider)
  // P1: another chain is refused; no chain at all gets the checked chain, so the signature is valid on that chain only
  await assert.rejects(() => g.signTransaction({ to: SAVED, data: '0x', chainId: 1 }), OathlineBlocked)
  await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x', chainId: 1 } as any), OathlineBlocked)
  assert.equal(signedTx.length + sentTx.length, 0)
  assert.equal(await g.signTransaction({ to: SAVED, data: '0x', gasPrice: 1n }), '0xsigned')
  assert.equal(signedTx[0].chainId, 8453)
  assert.equal(await g.signTransaction({ to: SAVED, data: '0x', chainId: 8453 }), '0xsigned')
  assert.equal(await g.sendTransaction({ to: SAVED, data: '0x', chainId: '0x2105' } as any), '0xabc')
  // P2: `input` is the same field as `data` for many signers: one the check did not see is refused
  await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x', input: '0xa9059cbb' } as any), OathlineBlocked)
  await assert.rejects(() => g.signTransaction({ to: SAVED, input: '0xa9059cbb' }), OathlineBlocked)
  assert.equal(await g.sendTransaction({ to: SAVED, data: '0x1234', input: '0x1234' } as any), '0xabc')
  assert.equal(sentTx.length, 2); assert.equal(signedTx.length, 2)
  // P3: the snake_case names a provider's own API may read are held to the same rules
  await assert.rejects(() => g.signTransaction({ to: SAVED, data: '0x', chain_id: 1 }), OathlineBlocked)
  await assert.rejects(() => g.sendTransaction({ to: SAVED, data: '0x', authorization_list: [{ address: ATTACKER }] } as any), OathlineBlocked)
  assert.equal(sentTx.length, 2); assert.equal(signedTx.length, 2)
})

test('R5 part 3: the SDK names its version in every check (the server refuses an EIP-7702 wallet without a new enough one), and it equals package.json', async () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }
  assert.equal(SDK_VERSION, pkg.version); assert.match(SDK_VERSION, /^\d+\.\d+\.\d+$/)
  requests.length = 0
  await new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).check(SAVED, { to: SAVED, data: '0x' })
  assert.equal(requests.at(-1)?.sdk, SDK_VERSION)
})

test('R5 part 3 (Kernel): on an EIP-7702 wallet, typed data for Kernel or the v0.7 EntryPoint and a personal message of exactly 32 bytes (a user-operation hash) are refused outright; other messages and plain wallets keep the policy', async () => {
  const KERNEL_WALLET: Address = '0x8888888888888888888888888888888888888888'
  const ENTRY_POINT_V07: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'
  const signed: string[] = []
  const provider = (addr: Address) => ({ getAddress: () => addr, sendTransaction: async (_tx?: any) => '0x1' as Hex, signTypedData: async (td?: any) => { signed.push(`typed:${td?.primaryType}`); return '0xsig' as Hex }, signMessage: async (m?: any) => { signed.push(`msg:${typeof m === 'string' ? m.length : m?.length}`); return '0xsig' as Hex }, sign: async () => '0xsig' as Hex })
  const kernelName = { domain: { name: 'Kernel', version: '0.3.3', chainId: 8453, verifyingContract: SAVED }, primaryType: 'Anything', types: { Anything: [{ name: 'x', type: 'uint256' }] }, message: { x: 1n } }
  const kernelWrapper = { domain: { name: 'Some App', chainId: 8453, verifyingContract: SAVED }, primaryType: 'Kernel', types: { Kernel: [{ name: 'hash', type: 'bytes32' }] }, message: { hash: `0x${'ab'.repeat(32)}` } }
  const enable = { domain: { name: 'Some App', chainId: 0, verifyingContract: SAVED }, primaryType: 'Enable', types: { Enable: [{ name: 'validationId', type: 'bytes21' }, { name: 'nonce', type: 'uint32' }] }, message: { validationId: `0x01${'cd'.repeat(20)}`, nonce: 1 } }
  const userOp07 = { domain: { name: 'Something', chainId: 8453, verifyingContract: ENTRY_POINT_V07 }, primaryType: 'Thing', types: { Thing: [{ name: 'x', type: 'uint256' }] }, message: { x: 1n } }
  const usdcPermit = { domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' }, primaryType: 'Permit', types: { Permit: [{ name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }] }, message: { spender: ATTACKER, value: 10n ** 9n } }
  walletKinds[KERNEL_WALLET.toLowerCase()] = 'delegated'
  const g = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => true }).guardWalletProvider(provider(KERNEL_WALLET))
  for (const td of [kernelName, kernelWrapper, enable, userOp07]) await assert.rejects(() => g.signTypedData(td), (e: any) => e instanceof OathlineBlocked && /EIP-7702/.test(e.message), td.primaryType)
  // a 32-byte message, as bytes or as 32 characters of text, is how Kernel signs a user operation: refused, never asked
  await assert.rejects(() => g.signMessage(new Uint8Array(32)), (e: any) => e instanceof OathlineBlocked && /32 bytes.*user operation/.test(e.message))
  await assert.rejects(() => g.signMessage('x'.repeat(32)), OathlineBlocked)
  assert.deepEqual(signed, [], 'nothing reached the provider')
  // other lengths and a token permit follow the policy (the hook said yes)
  await g.signMessage('hello'); await g.signMessage(new Uint8Array(31)); await g.signMessage(new Uint8Array(33)); await g.signTypedData(usdcPermit)
  assert.deepEqual(signed, ['msg:5', 'msg:31', 'msg:33', 'typed:Permit'])
  // the viem client: signMessage({ raw }) of 32 bytes and personal_sign of 32 bytes are refused; a text message follows the policy
  const account = privateKeyToAccount(generatePrivateKey())
  walletKinds[account.address.toLowerCase()] = 'delegated'
  const rpc: string[] = []
  const client = createWalletClient({ account, chain: base, transport: custom({ request: async ({ method }: any) => { rpc.push(method); if (method === 'eth_getCode') return `0xef0100${SAVED.slice(2)}`; if (method === 'eth_chainId') return '0x2105'; if (method === 'personal_sign' || method === 'eth_signTypedData_v4') return '0xsig'; throw new Error(`unexpected rpc ${method}`) } }) })
  const gc = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER, onAsk: async () => true }).guard(client)
  await assert.rejects(() => gc.signMessage({ message: { raw: `0x${'ab'.repeat(32)}` } }), (e: any) => e instanceof OathlineBlocked && /32 bytes/.test(e.message))
  await assert.rejects(() => gc.signMessage({ message: { raw: new Uint8Array(32) } }), OathlineBlocked)
  await assert.rejects(() => gc.request({ method: 'personal_sign', params: [`0x${'ab'.repeat(32)}`, account.address] } as any), OathlineBlocked)
  await assert.rejects(() => gc.request({ method: 'personal_sign', params: ['a'.repeat(32), account.address] } as any), OathlineBlocked)   // 32 characters of text are 32 bytes too (review 2026-10-23, M2)
  assert.ok(!rpc.includes('personal_sign'), 'nothing reached the node')
  await gc.signMessage({ message: 'hello' }); await gc.request({ method: 'personal_sign', params: ['0x68656c6c6f', account.address] } as any)   // a local account signs the first itself; the second reaches the node
  assert.equal(rpc.filter(m => m === 'personal_sign').length, 1)
  // a plain wallet: the same 32-byte message follows the policy (asked, not blocked)
  const plain = privateKeyToAccount(generatePrivateKey())
  const gp = new Oathline({ mode: 'enforce', apiUrl, apiKey: KEY, signer: SIGNER }).guardWalletProvider(provider(plain.address))
  await assert.rejects(() => gp.signMessage(new Uint8Array(32)), OathlineNeedsApproval)
  await assert.rejects(() => gp.signTypedData(kernelName), OathlineNeedsApproval)
  // shadow: signed and reported as "would have blocked" on an EIP-7702 wallet
  await new Promise(r => setTimeout(r, 100)); reports.length = 0; signed.length = 0
  const sh = new Oathline({ apiUrl, apiKey: KEY, signer: SIGNER, mode: 'shadow' }).guardWalletProvider(provider(KERNEL_WALLET))
  await sh.signMessage(new Uint8Array(32)); await sh.signTypedData(kernelName)
  for (let i = 0; i < 50 && reports.length < 2; i++) await new Promise(r => setTimeout(r, 20))
  assert.equal(signed.length, 2)
  assert.deepEqual(reports.map(r => [r.kind, r.verdict]), [['signature request on an EIP-7702 wallet', 'block'], ['signature request on an EIP-7702 wallet', 'block']])
  assert.match(reports[0].detail, /32 bytes/)
})
