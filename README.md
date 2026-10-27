# saysoio

> This package was `@oathline/sdk` until 2026-10-13; same code, new name; the old package is deprecated on npm.

sayso checks every transaction an AI agent is about to sign against its owner's plain-language rules (the
mandate). It decodes and simulates the exact transaction, judges the real effect rather than the agent's
explanation, and answers **allow**, **ask** or **block** with a one-line reason.

This package wraps the agent's wallet so that check happens before anything is signed. It never sees or holds
a key, and sayso never holds funds.

**0.6.3: wallet functions sayso does not know are refused in enforce mode.** Until 0.6.2 the guarded viem client
checked the functions it knew and let any other function through: a new viem action, or the method of an add-on
installed with `.extend(...)` **before** `guard()`, which holds the raw client. viem's own ERC-7821 add-on
(`erc7821Actions().execute`) signed with the raw account that way, in enforce mode too (security desk, 25 Oct). Since
0.6.3 such a function throws `OathlineBlocked` ("execute: this wallet function is not one sayso knows; it is refused in
enforce mode until sayso supports it") in enforce mode, and goes ahead and is reported as "would have blocked" in shadow
mode. Functions that neither sign nor send stay allowed by an explicit list (viem's public actions such as `getBalance`
and `readContract`, the wallet client's reads such as `getAddresses` and `getChainId`, the OP Stack fee reads, ERC-7821's
`supportsExecutionMode`), and so does anything added **after** `guard()` (it is handed the guarded client, so what it
sends goes through the check). So: call `guard()` right after creating the client and add extensions to the guarded
client. The SDK also warns once when the installed viem is newer than the newest it was tested with (`TESTED_VIEM`,
2.57.10), and the object it returns refuses a prototype swap. Also in 0.6.3 (review of 27 Oct): a checked transaction is
signed only for the chain sayso checked (a `chainId`, `chain` or `assertChainId: false` that points elsewhere is refused
in enforce mode, and the signing call is pinned to the checked chain), and `switchChain` and `addChain` are refused in
enforce mode. **Breaking for** an agent decided as enforce (written in code, switched on by the owner, or no `mode`
written and no answer from sayso yet) that calls a sending function of an add-on installed before `guard()`,
`switchChain`/`addChain`, or a transaction for another chain: these were unchecked before and are refused now. In shadow
mode they go ahead and are reported (an unknown function once every 10 minutes). Note: viem's ERC-7821 `execute` cannot
be used on a guarded client yet (refused when installed before `guard()`, and it fails when installed after, because the
guarded client has no account that signs). No outside team runs in enforce mode today.

**0.6.2 (needed with viem 2.57.10 or newer).** viem 2.57.10 (22 Oct 2026) added `client.scope()`, which rebuilds a
copy of a client from the original one. On a guarded client before 0.6.2 that copy kept the checked actions but had
the raw `request`, `account` and `transport`, so `guarded.scope().account.signTransaction(...)` or
`guarded.scope().request({ method: 'eth_sendTransaction' })` signed without a check, in enforce mode too. Since 0.6.2
the scoped copy is guarded exactly like the client it came from (its checked actions still run through the original
client, so aborting the scope's signal does not cancel a checked send). The guarded client also refuses writes to itself
(`Object.defineProperty`, `freeze`, `delete`), and so do a guarded provider and CDP client. With viem 2.57.8 or older there is no `scope()` and
nothing changes. Update with `npm install saysoio@latest`.

**0.6.1 (EIP-7702 wallets: Kernel, the minimum version enforced, re-registration).** (1) The SDK names its version in
every check, and the server refuses a check on an **EIP-7702 wallet** from an SDK older than 0.6.1 (`sdk-too-old`), so the
minimum for such wallets is refused by the server, not only written (the SDK's claim is not verified: this catches an agent
that was not updated, not one that lies); 0.6.0 does not say its version, so **0.6.1 is the minimum for
EIP-7702 wallets**. Plain wallets are checked whatever the SDK version. (2) ZeroDev's **Kernel v3.3** joins Calibur as accepted
EIP-7702 code where the server has it on (`OATHLINE_7702_WALLETS=kernel`, or `calibur,kernel`). On any EIP-7702 wallet the
SDK now also refuses outright a **personal message of exactly 32 bytes** (`signMessage`, `personal_sign`): on Kernel that
is how a user operation is authorised, the user-operation hash signed as a personal message; other messages keep the
policy. Typed data for Kernel (domain `Kernel`, the `Enable` and `Kernel` types, the v0.7 EntryPoint) joins the refused
list. (3) New owner helper `reregisterWallet(apiUrl, owner, wallet)`: a registered wallet that was upgraded with EIP-7702
(or whose delegation was cleared) is registered again as what it now is, keeping its rules, Telegram chat, mode and API
key. (4) On a Calibur wallet the revoke-only housekeeping calls into its own code (the September build's `updateSalt()`,
`invalidateNonce`, `approveNative(spender, 0)`) now pass the guarded client, allowed by rules when the simulation shows
nothing moving; the February build's `updateSalt(prefix)` does not (it can set the salt back, which would revive voided batches).

**Breaking in 0.6.0 (EIP-7702 wallets, and refusals are blocks):** (1) a refusal by the sayso server (a 4xx answer
with its reason: `wallet-has-code`, `wallet-code-refused`, `self-call`, `batch-refused`, no mandate, a wrong wallet or
API key) now reaches the agent as `OathlineBlocked` with the server's words, whatever `failClosed` says; before 0.6.0
it was `OathlineUnavailable`, and a team with `failClosed: false` went ahead on it. Outages (a dead server, 5xx, 429 or
any "retry-after" answer) are still `OathlineUnavailable`, and an answer that does not verify (a receipt or mode
statement not signed by sayso) is never covered by the opt-out. (2) On an **EIP-7702 wallet** (an address whose code
is a delegation, today Uniswap's Calibur) the SDK refuses outright, never asks, what could let a relayer or bundler run
a batch with one signature: blind hashes (`sign`, `eth_sign`), typed data under the wallet's own domain or Calibur's, a
`SignedBatchedCall`, an ERC-7739 `TypedDataSign` / `PersonalSign` wrapper, and a user operation (domain `ERC4337`, the
EntryPoint). The SDK learns the wallet's kind from sayso's answers and from the wallet's own node. Plain wallets are not
affected: their signature requests follow the `signatures` policy as before. (3) In shadow mode a signature request
is now reported to sayso as "would have asked" (or "would have blocked" under `signatures: 'refuse'`), so the
dashboard's counts include them. See "EIP-7702 wallets" and "What is checked, and what is not".

**Breaking in 0.5.0 (server wallets):** on a wrapped Coinbase CDP provider (AgentKit's `CdpEvmWalletProvider`),
`getClient()` now returns a wrapped CDP client: price and balance lookups pass, but anything that can move money or sign
through it (AgentKit's own `swap` and `use_spend_permission` actions, `account.transfer`, the client's
`sendTransaction`, EIP-7702 upgrades, account export) throws `OathlineBlocked` in enforce mode and is reported as "would
have blocked" in shadow mode. On a wrapped Privy provider, `exportWallet()` throws in enforce mode, because it hands out
the authorization key. New: `providerSigner(provider)` for registering a server wallet. See "Server wallets".
Also in 0.5.0: the guarded viem client's `account` is its address and type only (no `signTransaction`, `signMessage`,
`signTypedData`; sign through the guarded client instead); its `transport` is a few plain fields plus a `request` shut
like the client's own (no URL, no inner transports); viem's `token.transfer` and `token.approve` (and their Sync
variants) are checked like `writeContract`; and an extension added with `.extend(...)` is handed the same guarded client.
**Fixed in 0.5.0 (please upgrade):** on the guarded viem client, a `to` or `data` passed to `writeContract`, or a
`dataSuffix` (per call or on the client), could change the transaction after it was checked. Now the checked `to` and
`data` (with any suffix in it) are exactly what is signed, and `writeContract` signs through `sendTransaction`. A
transaction with no `to` (a contract deployment) is refused in enforce mode, like `deployContract`; on a wrapped
provider, so is a transaction with a `dataSuffix`, an `input` different from its `data`, or a `chainId` other than
the chain sayso answers for; a provider's `signTransaction` always signs for that chain. Known limits: a `dataSuffix`
set on the viem client inside AgentKit's `ViemWalletProvider` is still added after the check (do not set one), and a
reverted `writeContract` now comes back as viem's transaction error rather than a decoded contract error.

**Breaking in 0.4.0:** calls sayso cannot check yet no longer pass through the guarded wallet unchecked. In enforce
mode `sendCalls` (EIP-5792 batches), `sendRawTransaction`, `deployContract`, their Sync variants and the raw
`request` door for the same JSON-RPC methods now throw `OathlineBlocked`; in shadow mode they go ahead and are reported
to sayso as "would have blocked". An agent that used any of them in enforce mode stops working until the check can
read them (planned with the EIP-7702 and smart-account work). Also new: `registerWallet` refuses an owner that is the
agent's own wallet, and the server refuses to check a registered plain wallet that has since gained code (an EIP-7702
delegation) until the owner registers it again. See "What is checked, and what is not" and "When something goes wrong".

**Breaking in 0.3.0:** leaving `mode` out no longer means enforce. It means the owner decides from the dashboard
(shadow until they turn enforce on); write `mode: 'enforce'` to keep enforce whatever the switch says. Until sayso has
answered once, an agent with no `mode` in code treats an outage and signature requests as enforce. See "Modes".

**Status: early beta, by invitation.** Start in shadow mode: it blocks nothing and shows what would have been
stopped. The full guide, with the troubleshooting table and the Safe and treasury paths, is
<https://saysoio.com/get-started>. Questions, an invite code, or anything odd: [@saysoio](https://x.com/saysoio) on X.

## Have a coding agent do it

Paste the block from https://saysoio.com/get-started into Claude Code, Cursor, Codex or OpenClaw in the agent's project:
it follows https://saysoio.com/skill.md (find the wallet, install, register once, wrap with `mode` left out, one test
check), stores the API key as a secret and never asks for the owner's key. The owner then signs the rules in the
dashboard. The steps by hand are below.

## Install

```bash
npm install saysoio viem
```

Node 20 or newer (the owner helpers use the global Web Crypto API, which Node 18 does not have in ES modules). ES
modules only: in a CommonJS project use `const { Oathline } = await import('saysoio')`.
Works with [viem](https://viem.sh) wallet clients and Coinbase AgentKit wallet providers (tested with AgentKit 0.10
and its `ViemWalletProvider`), and with server wallets where a provider signs for the agent: Coinbase CDP Server Wallet
v2, Privy and Turnkey (see "Server wallets").

## Before you start: two people, one invite code

- The **owner** sets the rules, with their own wallet, on their own computer. The owner key never goes on the
  agent's server. Signing costs no gas and moves no funds: every setup step is a signed message.
- The **builder** wires the agent: registers the agent's wallet once, then wraps it.
- **The invite code is used twice, by both of you, and counts once.** A code has a number of places (5 unless you
  were told otherwise), and a place is one agent wallet, not one use. The owner gives the code when signing rules
  for a wallet that is not registered yet; the agent gives the same code when it registers that wallet. Both count
  as the same place. If the owner signs first, the rules come into force the moment the agent registers.
- **The agent wallet must be a plain key-held account (an EOA)**, or an EOA upgraded with EIP-7702 to Uniswap's Calibur
  or ZeroDev's Kernel v3.3 where the server accepts those (see "EIP-7702 wallets"; sayso's own servers have it switched
  off until the security review of that part and one run on the hosted server). Any other wallet with contract code (a
  smart wallet, an ERC-4337 account, another delegation) cannot register as an agent wallet today: an EIP-7702 wallet
  the server does not accept is told so, and any other contract is treated as a Safe. For a Safe, see "Safe wallets" below.
- **The owner a wallet names first is permanent.** It cannot be changed later, so check the address.
- **The owner must be a different wallet from the agent's.** An agent that is its own owner could sign its own rules
  and its own mode; `registerWallet`, the server and the dashboard's setup all refuse it (since 0.4.0).

## Quickstart, part 1: the owner, on their own computer (about 5 minutes)

The easiest way is the dashboard: open <https://app.saysoio.com/setup> and sign in with the wallet that will sign the
rules (one free signature; a plain wallet such as MetaMask, Rabby or a hardware wallet: smart-contract wallets cannot
sign rules yet). Choose "My agent's own wallet", enter the agent's wallet address and the invite code, write the rules,
read what sayso understood, sign with that same wallet (it is switched to Base for you; signing is free), and link
Telegram at the end (optional in shadow mode; needed before enforce mode, and possible later from the wallet's page).

The same as a script (`owner.ts`; for a trial the owner key can be a fresh key that holds nothing):

```ts
// owner.ts: run on YOUR computer, never on the agent's server
import { privateKeyToAccount } from 'viem/accounts'
import { compileMandate, setMandate, linkTelegram } from 'saysoio'

const API = 'https://api.saysoio.com'                                          // Base mainnet
const setup = { chainId: 8453, invite: 'oi_…' }                                // pin the chain; the beta needs the code
const owner = privateKeyToAccount(process.env.OWNER_KEY as `0x${string}`)
const AGENT = '0xYourAgentWalletAddress'

const rules = 'Trade only ETH, WETH and USDC. At most 0.5 ETH per trade and 2 ETH per day. ' +
              'Money may only be sent to my saved address 0x….'
const { compiled, shownToOwner } = await compileMandate(API, rules)            // about 20 seconds
console.log(shownToOwner)                                                       // read it: this is what you sign
if (compiled.unresolved?.length) console.log('Not turned into a rule:', compiled.unresolved)
await setMandate(API, owner, AGENT, rules, compiled, setup)                     // kept until the agent registers naming you

const { url } = await linkTelegram(API, owner, AGENT, { chainId: 8453 })
console.log('Open in Telegram and press Start:', url)                           // works once, expires in 15 minutes
```

Then sign in at <https://app.saysoio.com> with the same wallet to see every decision.

To change the rules later, sign new ones the same way; the newest signed set counts.

**Your agent's own contracts.** You can write "my agent may call its own contract 0x… (only addWorker(address) and
postJob(string))". A call to a listed function is then allowed when the simulation shows nothing at stake: nothing
leaves the wallet, nothing goes to anyone but the wallet and your contracts, no permission is given, nothing changes who
controls them, and they call nothing but each other's listed functions and well-known tokens. List functions by their
full signature (or 4-byte selector) in the same sentence as the address. Do not list functions that take an address to
call, or that forward or batch calls (`execute`, `multicall`): sayso cannot see what they will call later. Each call
is judged on its own, and the agent's next call to your contracts waits until the chain shows the last one. Rules that
name contracts need SDK 0.1.1 or newer on the agent: it tells sayso which position (nonce) each transaction takes,
and every transaction must say so. While an allowed call to your contracts is not yet on the chain, the next one is
held (asked, and not approvable): the agent asks again once the chain has caught up.

**Co-signer address, 0.2.0.** Since 2026-10-12 sayso's Base co-signer key lives in two AWS regions (Frankfurt and Ireland), which meant a new key and a new address, `0x7ad359D3E76eCbf460156457cbB61f1643149841`. SDK 0.2.0 carries it; an older SDK refuses the new co-signature as "not sayso's co-signer", so update before adding sayso to a Safe on Base. The test-network address is unchanged.

**EIP-7702.** The guarded wallet never signs an authorization (`authorizationList`, `signAuthorization`): it makes the
wallet run other code, which is how a wallet is taken over. Since 0.3.0 that holds in every mode, unless the builder
wrote `mode: 'shadow'` in code and the mode is known to be shadow; then it is logged as a block, reported to sayso
(0.4.0) and goes ahead. A wallet that has gained code since it registered is refused at every check until its owner
registers it again as what it now is (0.4.0 server; since 0.6.0 the SDK surfaces that as `OathlineBlocked`; since 0.6.1
the owner does it with `reregisterWallet`, below).

### EIP-7702 wallets (Calibur and Kernel)

A plain wallet already upgraded with EIP-7702 to **Uniswap's Calibur** (both Base deployments: the September 2026 v1.1.0
build and the February 2026 one) or to **ZeroDev's Kernel v3.3** can register with its own key when the server has the
feature on for that code (`OATHLINE_7702_WALLETS=calibur`, `kernel` or `calibur,kernel`; off on sayso's servers until the
security review and a run on the hosted server). **The agent needs saysoio 0.6.1 or newer**: the server refuses a check on
such a wallet from an older SDK (`sdk-too-old`; 0.6.0 included, since it does not say its version), because an older SDK
gets allow verdicts for its transactions while its signature paths only ask. The server accepts the wallet only while nothing but its own key can act through its code, and
reads that again before every check, from the live chain first:

- **Calibur:** no extra Calibur keys, the standard EntryPoint v0.8, the same code it registered with. In the user's words:
  do not add a passkey or a second key to this wallet in the Uniswap Wallet app; from then on every check is refused until
  it is revoked.
- **Kernel v3.3:** the wallet's own key is the root (`rootValidator()` empty, Kernel's EIP-7702 mode), no validator or
  permission was ever installed (`currentNonce()` is 0; it never goes back, so a wallet that once had one is refused for
  good), the v0.7 EntryPoint. What Kernel does not let sayso read: an **executor or fallback handler** installed before
  registration, which can act for the wallet without any signature; the registration answer says so. Be sure none was ever
  installed, or use a fresh key. And know what you are buying: ZeroDev's own tooling sends every transaction as a **user
  operation** through its bundler, which sayso does not check yet and the SDK refuses on an EIP-7702 wallet; a Kernel agent
  guarded by sayso sends plain transactions and the self-call batches below through the guarded client instead.

Then:

- **Transactions** are checked as for a plain wallet. **Batches** sent to the wallet's own code (through `sendTransaction`
  to the wallet itself) are read into their calls: on Calibur `execute(BatchedCall)` or ERC-7821 `execute(mode, calls)`, on
  Kernel ERC-7579 `execute(mode, calls)` in the plain batch mode or the single-call mode (the exact mode bytes, nothing in
  the other 30). Each call is checked in the state the calls before it leave, then the batch is simulated as a whole and
  held to what the calls showed; the verdict is the strictest of the calls, and one receipt covers the batch. Up to 8
  calls, a failing call must revert the whole (no `revertOnFailure: false`, no ERC-7579 "try" mode), no call back into the
  wallet, its code contract or its EntryPoint. The batch takes the position (nonce) the SDK pinned, like a plain
  transaction: it waits while an earlier allowed call to your own named contracts is still ahead of the chain, and it is
  recorded once at that position (0.6.1). A batch that would need the owner's approval cannot be approved as a whole yet:
  the answer names the call to send on its own. Any other call into the wallet's own code (a key or module change, a
  signed batch for a relayer, a user operation, a delegatecall, multicall) is refused (`self-call`), except Calibur's three
  revoke-only housekeeping calls, which pass (next point).
- **Calibur housekeeping passes the guarded client** (0.6.1): the September build's `updateSalt()`, `invalidateNonce` and
  `approveNative(spender, 0)` are decoded exactly, simulated as the wallet and allowed by rules when nothing leaves and no
  permission is given; the reason says what the call revokes. So the clean-up below can be done through the guarded client;
  the Uniswap Wallet app can do it too. The February build's `updateSalt(uint96 prefix)` is **not** passed through: it sets
  the salt to any value, so it could restore an old one and revive the batches an earlier call voided (review 2026-10-23);
  the owner makes that call with the wallet's key outside the guard, with a prefix the wallet never used before.
- **`sendCalls` stays refused in enforce mode** on every wallet, 7702 ones included: with `wallet_sendCalls` the
  wallet provider decides how the batch is executed, so the SDK cannot bind a verdict to the exact transaction. Send
  the batch as the `execute(...)` self-call above instead, which sayso checks.
- **Signatures that would hand the wallet over** are refused outright in enforce mode, with no policy and no hook
  (blind hashes; typed data under the wallet's own domain, Calibur's or Kernel's, a `SignedBatchedCall`, an ERC-7739
  `TypedDataSign` / `PersonalSign` wrapper, a user operation for either EntryPoint; and, since 0.6.1, a personal message of
  exactly 32 bytes); in shadow mode they are signed and reported as "would have blocked". A token permit or any other
  personal message still follows the `signatures` policy ("personal messages are safe" is true for Calibur, whose user
  operations are typed data; on Kernel the 32-byte case is the user operation, hence the refusal); a Permit2 permit on
  ERC20ETH is described as a permission over the wallet's ETH, which it is.
- **What sayso cannot see, and what helps (Calibur):** a batch the key signed earlier for a relayer stays usable until it
  is used or its deadline passes (never, when it has none); an ETH allowance given with `approveNative` stays, and on the
  September build ERC20ETH has an unlimited ETH allowance by default (a Permit2 signature naming ERC20ETH then moves
  ETH). The registration answer says so (`caveat`) and reports the allowances it could read (`checks`). Before relying on
  enforce mode: call `updateSalt` (it voids **every** earlier signed batch at once; `invalidateNonce` voids only one nonce
  key) and set `approveNative` to 0 for spenders you did not mean to keep (ERC20ETH included on the September build), both
  through the guarded client or the wallet app. A **user operation** the key signed earlier cannot be voided from the
  wallet: if this key ever signed one for someone you do not trust, use a fresh wallet. (Kernel: the same about user
  operations; and executors or fallback handlers from before registration cannot be listed, see above.)
- **A plain wallet that is upgraded later** is refused at every check (`wallet-has-code`) until its owner registers it
  again as what it now is, with both signatures and nothing else changing:

```ts
import { reregisterWallet } from 'saysoio'
// owner: the owner's signer (as for setMandate); agent: the agent wallet's account, BEFORE it is wrapped
await reregisterWallet(API, owner, agentAccount)      // → { kind: 'delegated' | 'plain', delegate, caveat?, checks? }
```

The same call registers an EIP-7702 wallet whose delegation was cleared as a plain wallet again. Rules, the Telegram
chat, the mode switch and the API key stay; the owner's signature is good once and expires within the hour.

## Quickstart, part 2: the agent (about 10 minutes)

**Register the wallet once** (the agent wallet signs "this owner may set my rules"):

```ts
import { privateKeyToAccount } from 'viem/accounts'
import { registerWallet } from 'saysoio'

const API = 'https://api.saysoio.com'
const agentAccount = privateKeyToAccount(process.env.AGENT_KEY as `0x${string}`)   // the agent's own key
const OWNER = '0xOwnerAddress'                                                      // from the owner; check it twice

const { apiKey } = await registerWallet(API, agentAccount, OWNER, { chainId: 8453, invite: 'oi_…' })
// shown once: store it as a secret, e.g. OATHLINE_API_KEY. Running this again is refused (409), it does not make a new key.
```

AgentKit, or any wallet you hold no raw key for (for example a CDP server wallet): pass the wallet provider in the
account's place. Do this with the provider **before** you wrap it (a wrapped provider in enforce mode refuses to sign
typed data):

```ts
import { registerWallet, providerSigner } from 'saysoio'
// `provider`: your AgentKit wallet provider, NOT wrapped yet (ViemWalletProvider, CdpEvmWalletProvider,
// PrivyEvmWalletProvider), or a viem account whose key a provider holds (@turnkey/viem, Privy, toAccount(cdpAccount))
const { apiKey } = await registerWallet(API, providerSigner(provider), OWNER, { chainId: 8453, invite: 'oi_…' })
```

The provider's own `signTypedData` signs; no key leaves it. `providerSigner` refuses a provider that is already wrapped.
(Tested with AgentKit 0.10's `ViemWalletProvider`, and with stand-ins that copy the shape of AgentKit 0.10.4's CDP and
Privy providers and of `@turnkey/viem`; the real providers on Base Sepolia are next. CDP *smart* wallets
(`CdpSmartWalletProvider`) are contracts and cannot register yet, see above.)

**Wrap the wallet the agent uses** (shadow mode first):

```ts
import { createWalletClient, http } from 'viem'
import { base } from 'viem/chains'
import { Oathline } from 'saysoio'

let lastThought = '', lastSources: string[] = []   // set these from your agent loop (optional)

const oathline = new Oathline({
  apiUrl: 'https://api.saysoio.com',
  apiKey: process.env.OATHLINE_API_KEY!,
  chainId: 8453,                 // Base: pin it; sayso's signing address for Base is built into the SDK
  // mode left out: the owner decides. Every wallet starts in shadow (logs only, never stops anything) until the owner
  // presses "Turn on enforce" on the wallet's page in the dashboard. mode: 'enforce' fixes enforce in code.
  // Do not write mode: 'shadow': with it fixed in code, restarts, outages, signature requests and EIP-7702
  // authorizations go through shadow even after the owner turned enforce on.
  timeoutMs: 8000,               // shadow: the longest sayso may hold a transaction up; then it goes ahead
  context: () => ({ reason: lastThought, inputs: lastSources }),   // optional: what your agent was thinking and read; treated as untrusted
  onDecision: (result, tx, decision) => console.log(`[sayso] ${decision} ${result.verdict}: ${result.reason}`),
})

// the client must be created WITH the agent's account: the check is for that account's address
const walletClient = createWalletClient({ account: agentAccount, chain: base, transport: http() })
const wallet = oathline.guard(walletClient)
// from here on the agent uses `wallet`, never `walletClient` (keep the original private). Add extensions to the
// guarded client, after guard(): `oathline.guard(walletClient).extend(publicActions)`. Since 0.6.3 a sending function
// of an add-on installed before guard() is refused in enforce mode (it would hold the raw client).
await wallet.sendTransaction({ to: '0x…', value: 1n })     // checked first, then sent
```

AgentKit:

```ts
import { AgentKit, ViemWalletProvider } from '@coinbase/agentkit'

const provider = new ViemWalletProvider(walletClient)              // register with this one (above), then wrap it
const walletProvider = oathline.guardWalletProvider(provider)
const agentkit = await AgentKit.from({ walletProvider, actionProviders: [/* your actions */] })
// hand the agent only `agentkit`; keep `provider` and `walletClient` private
```

**Check that it works:**

```ts
const r = await oathline.check(agentAccount.address, { to: '0xYourSavedAddress', data: '0x', value: 0n })
console.log(r.verdict, r.reason)     // any verdict is fine: it arrived signed by sayso for this exact transaction
```

If this throws instead, see "When something goes wrong" below.

## What is checked, and what is not

| Wrapped object | Checked by sayso before signing | Follows the `signatures` policy (cannot be simulated) | Refused in enforce mode, reported in shadow mode (sayso cannot check them yet; since 0.4.0) |
| --- | --- | --- | --- |
| viem `guard(walletClient)` | `sendTransaction`, `writeContract`, `signTransaction`, `sendTransactionSync`, `writeContractSync` | `signTypedData`, `signMessage`; `request` with `personal_sign`, `eth_sign`, `eth_signTypedData*` | `sendCalls`, `sendCallsSync` (EIP-5792 batches), `sendRawTransaction`, `sendRawTransactionSync`, `deployContract`; `request` with `wallet_sendCalls`, `eth_sendRawTransaction`, `eth_sendTransaction`, `eth_signTransaction`, `wallet_grantPermissions`, `wallet_sendPreparedCalls`, `eth_sendUserOperation`; `signAuthorization` and an `authorizationList` (EIP-7702; refused in every mode unless `mode: 'shadow'` is written); `switchChain`, `addChain`, and a checked call with a `chainId`, `chain` or `assertChainId: false` for another chain (0.6.3); **any other function the SDK does not know** (0.6.3): a new viem action, or an add-on's method installed before `guard()` (`execute` and `executeBatches` of ERC-7821, `grantPermissions` of ERC-7715, the OP Stack `initiateWithdrawal`, …) |
| AgentKit `guardWalletProvider(provider)` | `sendTransaction`, `signTransaction`, `nativeTransfer` | `signTypedData`, `signMessage`, `sign`; `toSigner()` is refused in enforce mode unless `signatures: 'allow'` | `signAuthorization` and an `authorizationList`; on CDP, everything on `getClient()` but lookups (0.5.0); on Privy, `exportWallet()` when it carries the authorization key (0.5.0) |
| either, on an **EIP-7702 wallet** (0.6.0; Kernel and the 32-byte rule 0.6.1) | a batch sent to the wallet's own code through `sendTransaction`: Calibur `execute(BatchedCall)` or ERC-7821 `execute(mode, calls)`, Kernel ERC-7579 `execute(mode, calls)` in the batch or single-call mode (checked call by call and as a whole by the server, at the pinned position); Calibur's `updateSalt`, `invalidateNonce`, `approveNative(x, 0)` (allowed by rules when nothing moves) | token permits, personal messages other than exactly 32 bytes (and `signMessage`) | refused in every mode but shadow, no policy, no hook: `sign` / `eth_sign` (blind hashes); `signMessage` / `personal_sign` of exactly 32 bytes (a Kernel user-operation hash); `signTypedData` / `eth_signTypedData*` when the typed data is under the wallet's own domain, Calibur's or Kernel's, a `SignedBatchedCall`, an `Enable` or `Kernel` type, an ERC-7739 `TypedDataSign` / `PersonalSign` wrapper, or a user operation (`ERC4337`, either EntryPoint); plus everything in the column to the left for plain wallets |

A refused call throws `OathlineBlocked` with the reason ("batch of calls (sendCalls): sayso cannot check this kind of
call yet, so it is refused in enforce mode"); in shadow mode the call goes ahead, `onDecision` gets the block as
`'shadow'`, and sayso records it so the owner sees "would have blocked" on the dashboard and in the Telegram notice.
Like signature requests, these are decided on the last mode seen from sayso, and on enforce before any was seen.
A refusal by the **server** (since 0.6.0) is the same kind of block: `OathlineBlocked` whose message starts with
"refused by sayso (check API 409): …" and whose `result.code` names it (`wallet-has-code`, `wallet-code-refused`,
`self-call`, `batch-refused`); `failClosed: false` does not cover it. In shadow mode such a call goes ahead and is
reported as "would have blocked".

The guarded viem client's own `account` gives out its address, type, public key and source only, nothing that signs;
its `transport` gives out plain fields and a `request` shut like `request` above (a fallback's inner transports, a
socket and the URL stay inside); viem's `token.transfer`, `token.approve` and their Sync variants are checked like
`writeContract`, and any other function in a group of actions viem puts on the client is refused in enforce mode until
sayso knows it (since 0.5.0). An extension added with `.extend(...)` sees the same guarded client.
Since 0.6.3 every other top-level function of the guarded viem client is one of three kinds: one of the SDK's own (the
table above); one that neither signs nor sends, from a fixed list (`CLIENT_READS` in `src/viem-known.ts`: viem 2.57.10's
public actions but the two raw sends, the wallet client's reads and wallet-UI calls, the OP Stack L2 fee reads,
`supportsExecutionMode`); or one added through the guarded client's `.extend(...)`. Anything else is refused in enforce
mode and reported in shadow mode, so the next viem release that adds a sending action fails closed. An add-on installed
after `guard()` that calls viem's sending code directly (ERC-7821's `execute` does) finds no account that signs and fails;
one that sends through the client's own `sendTransaction` or `writeContract` is checked. A function added after `guard()`
is trusted as it is: an extension must never be handed a function of the original client (keep that client private).
Functions under symbols, in a `Map` or class instance, non-enumerable ones, an add-on's own `scope`, and a function
under a `CLIENT_READS` name that is not viem's own (compared with the installed viem's source) are refused the same way.

**Anything else passes straight through unchecked**: user operations (ERC-4337 smart accounts), or any other method of
a wrapped AgentKit provider. Do not give those to the agent. The account object you created yourself (`privateKeyToAccount`)
still signs by itself: keep it private, like the original client.
Anything that signs through the original client or provider, or through a library you hand a raw key to (many x402
payment clients do this), bypasses sayso.

### Server wallets (Coinbase CDP, Privy, Turnkey)

A server wallet's key stays with the provider (Coinbase's or Privy's or Turnkey's secure hardware); the agent asks the
provider to sign. sayso sits in front of that request the same way as for a plain key:

- **Coinbase CDP Server Wallet v2.** AgentKit: register with `providerSigner(provider)`, then
  `guardWalletProvider(provider)`. Plain viem: `guard(createWalletClient({ account: toAccount(cdpAccount), … }))`.
  AgentKit's built-in CDP `swap` and `use_spend_permission` actions sign through Coinbase's API, not through
  `sendTransaction`: on a wrapped provider they are refused in enforce mode and reported in shadow mode. To swap in
  enforce mode, send the swap as a transaction (for example a Uniswap or Aerodrome call through `sendTransaction`), which
  sayso checks. The swap action may first send an approval of the token to Permit2; that one is a transaction, so
  sayso checks it like any other (and may allow it) before the swap itself is refused. CDP's provider ignores the
  position (nonce) the SDK pins and lets Coinbase choose it: the SDK checks with the position the node reports, which
  is the one Coinbase uses unless another transaction from the same wallet is in flight (rules that name your own
  contracts then hold the next call until the chain catches up).
- **Privy server wallets.** AgentKit's `PrivyEvmWalletProvider`: register with `providerSigner(provider)`, then
  `guardWalletProvider(provider)`. `exportWallet()` on the wrapped provider is refused in enforce mode (it carries the
  authorization key); export from the unwrapped provider when you save your wallet's settings. Privy's viem account
  (`createViemAccount`): `guard(createWalletClient({ account, … }))`. AgentKit's Privy *embedded* (delegated) provider:
  its internal doors to Privy's API (`executePrivyRequest`, `getPrivyHeaders`, `generatePrivySignature`) are refused in
  enforce mode on the wrapped provider.
- **Turnkey.** `@turnkey/viem`'s account: `guard(createWalletClient({ account, … }))`, registered with
  `providerSigner(account)`.

**Before sayso has answered once** (after every restart), an agent with no `mode` in code treats these refusals as
enforce: a CDP swap or a Privy export at start-up is refused even if the owner's switch is on shadow. Send one checked
transaction first, or call `oathline.check(...)` once at start-up, so the SDK learns the owner's mode.
`nativeTransfer` amounts are read as AgentKit 0.10 passes them: wei, as a whole-number string.

**What still skips the guard, on every provider:** the provider's own API called with your API keys (`cdp.evm…`,
Privy's REST API with the authorization key, Turnkey activities), the unwrapped provider, the CDP account object you
got before wrapping, and Coinbase's Agentic Wallets (`awal`), which have no place for an SDK. Keep those keys and objects
away from the agent's tools. The wrapping is a guard against the agent's tools, not against hostile code in the same
process: code that can import the provider's own SDK with your keys can always sign around sayso. A provider's own policy engine (CDP policies, Privy policies, Turnkey policies) still
applies on top of sayso, and is the stronger place for a hard limit.

**Signed messages that move money** (x402 payment authorisations, Permit2 permits, Coinbase spend permissions) cannot
be simulated, so they follow the `signatures` policy: in enforce mode `'ask'` (the default) asks your local `onAsk`
hook and refuses without one, `'refuse'` never signs, `'allow'` always signs. **In shadow mode they are signed**,
logged as `'shadow'` and (since 0.6.0) reported to sayso as "would have asked" (under `'refuse'`: "would have
blocked"; under `'allow'` nothing is reported), so the owner's counts include them.

## Modes

| Mode | allow | ask | block | sayso unreachable or too slow |
| --- | --- | --- | --- | --- |
| `shadow` | proceeds | proceeds, owner gets a notice | proceeds, owner gets a notice | proceeds |
| `enforce` | proceeds | waits for the owner's answer in Telegram; without it, refused | refused (`OathlineBlocked`) | refused (`OathlineUnavailable`), unless `failClosed: false` |

**Who picks the mode (since 0.3.0).** The owner does, from the dashboard: every wallet starts in shadow, and the owner
turns enforce on (or back off) on the wallet's page with one signature. sayso refuses enforce until a Telegram chat is
linked for the wallet, because its questions travel there. The SDK learns the mode from sayso's signed answer to its
next check (`oathline.mode` says which is in force) and keeps the last one it saw for when sayso cannot be reached.
`mode` in the options is a floor: `mode: 'enforce'` keeps the agent in enforce whatever the switch says; the switch can
raise `'shadow'` to enforce, never lower `'enforce'`. **Before 0.3.0, leaving `mode` out meant enforce.** If you relied
on that, set `mode: 'enforce'` when you upgrade, or have the owner turn enforce on. Without an answer from sayso
(sayso unreachable, and signature requests, which are not checked by sayso) the SDK uses the last mode it saw; before it
has seen one, the mode written in code, and with none written, enforce, since the owner's switch may be on. The last
mode seen is kept in memory only. An agent that only signs messages (x402, permits) and never sends a transaction does
not learn the switch: give it `mode: 'enforce'` or a `signatures` policy. **Do not write `mode: 'shadow'` to start a
trial:** leave `mode` out instead. With shadow fixed in code, every restart, every outage, every signature request and
every EIP-7702 authorization goes through shadow until the first answer from sayso, even after the owner turned enforce
on; with `mode` left out, all of those fail closed.

What enforce mode protects against: it stops a **tricked** agent (a prompt injection, a poisoned page, a bad tool
result). It does not stop a **hacked** agent server: whoever controls that server holds the agent's key and can sign
without the SDK. For that, use a Safe with sayso as co-signer (below).

**When sayso is down, the agent stops.** In enforce mode the SDK signs nothing it could not check: if the server
cannot be reached, answers an error or takes longer than `timeoutMs`, the call throws `OathlineUnavailable` and no
transaction leaves (`failClosed: true`, the default). That is on purpose: an agent that keeps trading while its check is
away is unguarded exactly when something is wrong. If your team would rather keep going without a check than stop, say
so explicitly with `failClosed: false`; the transaction then proceeds and `onDecision` is called with the reason
("sayso unavailable …, failClosed=false"), so the gap is at least on your record. Shadow mode always proceeds.
The opt-out covers outages only: a refusal by the server is a block (`OathlineBlocked`, since 0.6.0), and an answer
that does not verify as sayso's is refused too, whatever `failClosed` says.

**Timeouts.** A check usually takes under a second to a few seconds: the transaction is simulated and, in unclear
cases, a decision model is asked. On our benchmark the median was 1.2 s and 1 in 10 took 7.7 s or longer; it is
slower when the server is busy. `timeoutMs` is how long one check may take (default 20000, i.e. 20 s). In shadow
mode a slower check is skipped and the transaction goes ahead; in enforce mode it is refused with
`OathlineUnavailable` (unless `failClosed: false`). So keep it short in shadow mode (8000 is
fine) and longer in enforce mode (30000 is a good start). It does not include waiting for the owner's answer.

**An "ask" holds the call open.** In enforce mode an "ask" goes to the owner's own Telegram chat with Approve and
Reject buttons, and `sendTransaction` (or `writeContract`, …) does not return until the owner answers or the
request expires: up to about 10 minutes. Set your agent framework's tool or request timeout above that, or the
framework cuts it off first. An approval comes back as a signed allow for that one exact transaction. If the owner
has not linked Telegram, an "ask" is refused at once (`OathlineNeedsApproval`), unless you pass an `onAsk` hook.

### Before you switch to enforce

- **Signatures that are not transactions** (token permits, x402 payments, logins by signed message) cannot be
  simulated, and Telegram does not cover them yet. In enforce mode they follow `signatures`:
  `'ask'` (default) calls your `onAsk(result, tx)` hook and refuses if there is none; `'refuse'` always refuses;
  `'allow'` always signs. An agent that pays or logs in with signatures breaks on the day you enforce unless you
  choose one. In shadow mode they are signed, reported to `onDecision`, and (0.6.0) recorded at sayso as "would have
  asked" so you can see how many there are before you switch; the content of the message never leaves the agent, only
  its kind, the counterparty and whom it favours.
- `onAsk` runs next to the agent, so it is weaker than the owner's own Telegram chat; it is used for transaction
  "asks" only when no chat is linked.
- Raise `timeoutMs` (see above) and your framework's tool timeout.

```ts
const oathline = new Oathline({ /* same as above */ mode: 'enforce', failClosed: true, timeoutMs: 30000,
  signatures: 'refuse',                                         // or 'ask' with an onAsk hook, or 'allow'
  onWaiting: (r, tx, a) => console.log(`waiting for the owner on ${a.channel}`) })
```

Catch `OathlineBlocked`, `OathlineNeedsApproval` and `OathlineUnavailable` in the agent and tell it why.

## When something goes wrong

| You see | What it means | Do this |
| --- | --- | --- |
| `sayso /wallets/register 403: registration is by invitation during the beta: an invite code is required` | No invite code was given | Pass `{ invite: 'oi_…' }` |
| `sayso /mandates 403: this wallet is not registered, and during the beta leaving rules for it needs an invite code` | The owner signed rules before the agent registered, without the code | Pass `{ invite: 'oi_…' }` to `setMandate` too |
| `… 403: that invite code is not valid or has been used up` | Wrong code, cancelled, or all its places are taken by other wallets | Check the code; ask [@saysoio](https://x.com/saysoio) for more places |
| `… 409: this wallet is already registered …` | Registration ran a second time (for example from a deploy script) | Nothing to do: keep the API key from the first time. Register once, not on every deploy |
| `… 409: this wallet is already linked to another owner` | Someone registered this wallet first, naming a different owner | That owner stays; use a new agent wallet |
| `… 400: this wallet is a contract (a Safe) …` | The agent wallet has contract code that is not an EIP-7702 delegation | Use a plain key-held wallet, or the Safe path |
| `… 400: this wallet cannot be registered: it is an EIP-7702 wallet … this server does not accept EIP-7702 wallets at the moment` | The wallet is upgraded with EIP-7702 and the server has `OATHLINE_7702_WALLETS` off | Use a plain wallet, or ask the operator; sayso's own servers have it off until the security review |
| `… 400: this wallet cannot be registered: … root validator other than the wallet's own key` / `… validation nonce is N, not 0` | A Kernel wallet whose root was changed, or that ever had a validator or permission installed (it cannot be undone) | Use a fresh key delegated to Kernel with nothing installed |
| `OathlineBlocked` … `refused by sayso (check API 409): this wallet is an EIP-7702 wallet and the agent's saysoio SDK … is too old` (`sdk-too-old`) | The agent runs an SDK older than 0.6.1 on an EIP-7702 wallet | Update saysoio to 0.6.1 or newer |
| `… 400: the owner must be a different wallet from the agent's …` | The agent was named as its own owner | Use a separate owner wallet (for a trial, a fresh key that holds nothing) |
| `OathlineBlocked` … `refused by sayso (check API 409): this wallet now runs code … registered as a plain wallet` | The wallet gained code after it registered (an EIP-7702 delegation, a contract); nothing is checked for it any more | Remove the delegation, or (Calibur or Kernel, where the server accepts it) have the owner register the wallet again as an EIP-7702 wallet with `reregisterWallet` (0.6.1); the agent stops in enforce mode, whatever `failClosed` says |
| `OathlineBlocked` … `refused by sayso (check API 409): this wallet runs EIP-7702 code sayso does not support yet` / `… has N extra key(s) …` / `… trusts a different EntryPoint …` / `… now points to different wallet code …` | An EIP-7702 wallet that no longer passes the server's three checks, or a server where the feature is off (`wallet-code-refused`) | Revoke the extra keys, set the standard EntryPoint back, or register again; on a server where the feature is off, use a plain wallet |
| `OathlineBlocked` … `refused by sayso (check API 409): this is a call into the wallet's own EIP-7702 code that sayso cannot read …` | A call into the wallet's own code that is not one of the two batch forms (`self-call`) | Send each call on its own, or the batch as `execute(BatchedCall)` |
| `OathlineBlocked` … `refused by sayso (check API 409): this batch cannot be checked: …` | A batch with no calls, more than 8, `revertOnFailure` false, or a call back into the wallet, its code contract or its EntryPoint (`batch-refused`) | Change the batch as the reason says |
| `OathlineNeedsApproval` … `a batch that needs the owner's approval cannot be approved as a whole yet: send call N …` | One call of the batch needs the owner's approval | Send that call on its own so the owner can approve it on Telegram |
| `OathlineBlocked` … `signature request (…) on an EIP-7702 wallet: … never signed` | On an EIP-7702 wallet the agent asked for a blind hash, a batch, a wrapped or a user-operation signature | There is no safe way to sign these for such a wallet; send transactions through the guarded client instead |
| `OathlineBlocked` … `sayso cannot check this kind of call yet` | The agent used `sendCalls`, `sendRawTransaction`, `deployContract` or a raw RPC send in enforce mode | Send plain transactions through the guarded `sendTransaction` / `writeContract`; on a Calibur wallet, a batch as `execute(BatchedCall)` to the wallet itself |
| `OathlineBlocked` … `refused by sayso (check API 401): missing or unknown API key` | The key is wrong, or the wallet was never registered (since 0.6.0 a block, not an outage: `failClosed: false` does not cover it) | Check `OATHLINE_API_KEY`; register the wallet |
| `OathlineBlocked` … `refused by sayso (check API 403): this API key belongs to a different wallet` | The key is for another agent wallet | Use each wallet's own key |
| `OathlineBlocked` … `refused by sayso (check API 409): no owner-signed mandate is registered for this wallet` | The owner has not signed rules for this exact address yet | The owner does part 1 for this address |
| `check API 429` … `too many requests for this API key` | Rate limits: about 60 checks a minute per API key | Retry after the `retry-after` seconds |
| `check API 503` … `the check server is busy` | The simulation queue is full | Retry after the `retry-after` seconds (shadow mode proceeds on its own) |
| `check API 503` … `the fork does not answer; nothing can be checked right now` | sayso's copy of the chain is down or restarting | Retry in a minute; if it lasts, tell [@saysoio](https://x.com/saysoio) |
| `receipt signature is not from sayso` | The server's signer is not the one built into the SDK | Check the `apiUrl` and `chainId` |

In shadow mode these show up in `onDecision` as "sayso unavailable (…); proceeding"; in enforce mode they are
`OathlineUnavailable`. More rows: <https://saysoio.com/get-started>.

## Keys: what to do if one is lost or leaked

- **The API key** is shown once. It lets whoever holds it ask checks for that one wallet (each lands in the
  wallet's log and dashboard, and blocks and asks reach the owner's Telegram, within the rate limits) and read the
  answers. It cannot change the rules, approve anything, sign anything or move funds. There is no self-serve
  rotation or revocation yet (it will need a request signed by the owner); registering again does not issue a new
  key. If it leaks, message [@saysoio](https://x.com/saysoio) at once.
- **The agent key stolen:** the thief can sign without the SDK (see Modes). Move the funds to a new wallet and
  register that one.
- **The owner key lost:** the rules in force stay, but nobody can sign new rules or link a new chat for that wallet,
  and the owner cannot be changed. Use a new agent wallet with a new owner.

## What is sent to sayso

For each check: the wallet address, the transaction (`to`, `data`, `value`), and whatever `context()` returns.
Nothing else. Do not put secrets in the context. Keys never leave your process.

## What comes back, and why you can trust it

Every verdict carries a receipt signed by sayso for exactly this wallet, this transaction and this chain,
with an expiry. The SDK verifies it and treats anything else as "unreachable". Since 0.3.0 the answer also carries
sayso's signed statement of the mode the owner chose (`mode`: shadow or enforce, when the owner signed it), bound to the
same transaction; the SDK refuses an answer from sayso's servers without one, and never goes back to an older switch.

Whose signature counts is built into the SDK: sayso's own signing address for the chain, and for Safes
sayso's co-signer address (`OATHLINE_SIGNERS`, `OATHLINE_COSIGNERS`). The server is never asked who its signer
is. Set `chainId` as well (8453 for Base), in `new Oathline(…)` and in the setup calls (`registerWallet`,
`setMandate`, `linkTelegram` take `{ chainId }`): then the server is not asked which chain it works on either, and
the guards refuse a server whose chain is not the wallet's own. Only for your own or a local server do you name the
addresses yourself (`signer`, `cosigner`).

Because the addresses are built in, a change of sayso's Safe co-signer key is an SDK release: the Base co-signer
moves to a key that lives in two AWS regions with SDK 0.2.0 (the address changes once, before any Safe on Base is
enforced; the Base Sepolia addresses stay). An older SDK then refuses the new co-signature as "not sayso's
co-signer", which is the SDK doing its job: update it.

What this does not cover: the one-time setup. `compileMandate` shows you the rules the server compiled, and you
sign what you read, so read it; run setup against the address you were given, over HTTPS.

## Safe wallets (sayso as co-signer)

For a 2-of-3 Safe (agent key, sayso's key, the owner's own key), the agent alone can move nothing and
sayso adds the second signature only when the transaction is allowed or the owner approved it. The owner's
key plus the agent's key can always act without sayso.

**Today this runs on the Base Sepolia test network only** (test money): the Base mainnet server refuses to register
a Safe for co-signing (HTTP 503) until the co-signer has had an outside security review. On Base mainnet a Safe can
be registered watch-only (`watchSafe`): sayso then judges proposals waiting for signatures and tells you, but
cannot stop them. Step by step for both: <https://saysoio.com/get-started>.

```ts
import { sendViaSafe, registerSafe } from 'saysoio'
// publicClient and walletClient: viem clients for the Safe's chain, walletClient with the agent's account.
// Pass the unguarded walletClient here: sayso's co-signature is the check on this path, and a guarded client would
// ask the owner for the agent's Safe signature (signatures policy) before anything is checked.
const hash = await sendViaSafe(oathline, { publicClient, walletClient }, safeAddress, { to, data, value })
```

Limits today: single calls only (no batches), plain calls only (no delegatecall), only a freshly created
Safe 1.4.1 can be registered.

## Chains

One sayso server works on one chain and names it in everything it signs. The SDK learns the chain from the
server, or you can pin it with `chainId`.

| Chain | Server | Notes |
| --- | --- | --- |
| Base (8453) | `https://api.saysoio.com` | By invitation. Agent wallets (shadow and enforce); Safes watch-only |
| Base Sepolia (84532), test money only | `https://sepolia.saysoio.com` | Open, no invite code. Agent wallets and Safe co-signing. No Telegram (an "ask" is refused unless `onAsk` is set) and not shown on the dashboard |

You can try the agent-wallet steps above on Base Sepolia first: use the Sepolia server, `chainId: 84532`, leave out
the invite code and `linkTelegram`. On Base Sepolia the check understands ETH transfers and wrapping; token prices
and exchanges are mainnet data, so swaps are not judged reliably there.

## Errors

`OathlineBlocked`, `OathlineNeedsApproval` and `OathlineUnavailable` all carry `.tx`; the first two carry
`.result` with the verdict, the reason and the facts sayso saw.

## Turning it off

Stop using the wrapped wallet (agent wallet), or remove sayso as an owner together with the agent (Safe). The
rules, the API key, the Telegram link and the decision log stay at sayso until you ask
[@saysoio](https://x.com/saysoio) to delete the wallet's rules and Telegram link; signed log entries are kept,
because they are the record that a verdict was given. Details: <https://saysoio.com/privacy>.

## Licence

MIT. The check server is a hosted service and is not part of this package.
