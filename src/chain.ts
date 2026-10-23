// Which chain a sayso server works on. One server = one chain (Base mainnet, or Base Sepolia for the public
// test Safe); it says which in GET /health, and everything signed for it names that chain.
const known = new Map<string, number>()

/** Asked once per server and remembered only when the server gave a proper answer. Never guessed: if the server
 *  cannot be reached or does not name its chain, this throws, so nothing is signed for the wrong chain by accident.
 *  Pin the chain yourself (`chainId`) to skip the question. */
export async function chainOf(apiUrl: string, f: typeof fetch = fetch): Promise<number> {
  const base = apiUrl.replace(/\/$/, '')
  const hit = known.get(base)
  if (hit !== undefined) return hit
  let res: Response
  try { res = await f(`${base}/health`, { signal: AbortSignal.timeout(20_000) }) }
  catch (e) { throw new Error(`could not reach sayso at ${base} (${(e as Error).message.slice(0, 120)})`) }
  const json = res.ok ? await res.json().catch(() => null) as any : null
  const id = json?.chainId
  if (!Number.isInteger(id) || id <= 0) throw new Error(`sayso at ${base} did not say which chain it works on (GET /health answered ${res.status}); try again, or pin it with chainId`)
  known.set(base, id)
  return id
}

/** Where a helper takes its options: a fetch function (as before), or { fetch, chainId, invite }: `chainId` pins the
 *  chain, `invite` is the invite code a server in invite-only mode asks for when a wallet registers. */
export type CallOptions = typeof fetch | { fetch?: typeof fetch; chainId?: number; invite?: string }
export const callOptions = (o?: CallOptions): { fetch?: typeof fetch; chainId?: number; invite?: string } => (typeof o === 'function' ? { fetch: o } : o ?? {})
/** the invite code as a request field, when one was given */
export const inviteField = (o?: CallOptions): { invite?: string } => { const i = callOptions(o).invite; return i ? { invite: i } : {} }
/** the chain to sign for: pinned by the caller, otherwise asked from the server */
export const chainFor = (apiUrl: string, o?: CallOptions): Promise<number> => { const c = callOptions(o); return c.chainId !== undefined ? Promise.resolve(c.chainId) : chainOf(apiUrl, c.fetch) }
