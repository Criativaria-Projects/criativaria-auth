import { beforeEach, describe, expect, it, vi } from 'vitest'

import { verify } from './crypto.js'
import worker from './index.js'

const ENV = {
  ALLOWED_ORIGINS: 'https://allowed-site.example',
  DISCORD_CLIENT_ID: 'client-id',
  DISCORD_CLIENT_SECRET: 'client-secret',
  DISCORD_GUILD_ID: 'guild-123',
  SSO_SECRET: 'sso-secret',
}

function req(path) {
  return new Request(`https://auth.example${path}`)
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('GET /health', () => {
  it('returns ok', async () => {
    const res = await worker.fetch(req('/health'), ENV)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('ok')
  })
})

describe('GET / (unknown route)', () => {
  it('returns a plain identifying response', async () => {
    const res = await worker.fetch(req('/'), ENV)
    expect(res.status).toBe(200)
  })
})

describe('GET /login', () => {
  it('rejects a "to" origin not on the allowlist', async () => {
    const res = await worker.fetch(req('/login?to=https://not-allowed.example'), ENV)
    expect(res.status).toBe(400)
  })

  it('rejects a malformed "to" URL', async () => {
    const res = await worker.fetch(req('/login?to=not-a-url'), ENV)
    expect(res.status).toBe(400)
  })

  it('rejects a non-https origin even if otherwise allowed', async () => {
    const res = await worker.fetch(req('/login?to=http://allowed-site.example'), ENV)
    expect(res.status).toBe(400)
  })

  // ── ALLOWED_ORIGIN_SUFFIXES (Cloudflare Pages preview subdomains, ADR 0002) ──
  const SFX_ENV = { ...ENV, ALLOWED_ORIGIN_SUFFIXES: 'criativaria-linkedin-34m.pages.dev' }

  it('accepts a preview subdomain matching an allowed project suffix', async () => {
    const res = await worker.fetch(req('/login?to=https://development.criativaria-linkedin-34m.pages.dev/__staging_auth'), SFX_ENV)
    expect(res.status).toBe(302)
  })

  it('accepts the bare project host equal to an allowed suffix', async () => {
    const res = await worker.fetch(req('/login?to=https://criativaria-linkedin-34m.pages.dev'), SFX_ENV)
    expect(res.status).toBe(302)
  })

  it('rejects a look-alike host that only matches the suffix without a label boundary', async () => {
    // must not match `criativaria-linkedin-34m.pages.dev` — no leading-dot boundary
    const res = await worker.fetch(req('/login?to=https://evilcriativaria-linkedin-34m.pages.dev'), SFX_ENV)
    expect(res.status).toBe(400)
  })

  it('rejects a different (unsuffixed / other-account) Pages project', async () => {
    const res = await worker.fetch(req('/login?to=https://criativaria-linkedin.pages.dev'), SFX_ENV)
    expect(res.status).toBe(400)
  })

  it('ignores a dangerous bare shared-zone suffix (pages.dev) and does not open the allowlist', async () => {
    const danglerEnv = { ...ENV, ALLOWED_ORIGIN_SUFFIXES: 'pages.dev' }
    const res = await worker.fetch(req('/login?to=https://attacker-project.pages.dev'), danglerEnv)
    expect(res.status).toBe(400)
  })

  it('does not let a userinfo trick smuggle a disallowed host past the suffix check', async () => {
    // URL.hostname is evil.example here, not the pages.dev part
    const res = await worker.fetch(req('/login?to=https://criativaria-linkedin-34m.pages.dev@evil.example'), SFX_ENV)
    expect(res.status).toBe(400)
  })

  it('redirects to Discord and sets a signed state cookie for an allowed origin', async () => {
    const res = await worker.fetch(req('/login?to=https://allowed-site.example/dashboard'), ENV)
    expect(res.status).toBe(302)

    const location = new URL(res.headers.get('Location'))
    expect(location.origin + location.pathname).toBe('https://discord.com/oauth2/authorize')
    expect(location.searchParams.get('client_id')).toBe('client-id')
    expect(location.searchParams.get('redirect_uri')).toBe('https://auth.example/callback')

    const setCookie = res.headers.get('Set-Cookie')
    expect(setCookie).toMatch(/^cri_hub_state=/)
    const stateToken = setCookie.match(/cri_hub_state=([^;]+)/)[1]

    // The state cookie must carry the same signed state Discord will echo back.
    expect(location.searchParams.get('state')).toBe(stateToken)

    // And it must decode to the requested target — this is what prevents an
    // attacker from redirecting the SSO handoff to an arbitrary origin.
    const payload = await verify(stateToken, ENV.SSO_SECRET)
    expect(payload.to).toBe('https://allowed-site.example/dashboard')
  })

  it('uses CANONICAL_ORIGIN for redirect_uri instead of the request origin, when set', async () => {
    const CANON_ENV = { ...ENV, CANONICAL_ORIGIN: 'https://auth.criativaria.workers.dev' }
    const res = await worker.fetch(req('/login?to=https://allowed-site.example/dashboard'), CANON_ENV)
    const location = new URL(res.headers.get('Location'))
    expect(location.searchParams.get('redirect_uri')).toBe('https://auth.criativaria.workers.dev/callback')
  })
})

describe('GET /callback', () => {
  it('rejects an unsigned/garbage state even when no cookie is present', async () => {
    // Missing cookie is tolerated (mobile app-handoff loses it), but the
    // state must still pass HMAC+TTL verification — garbage has no signature.
    const res = await worker.fetch(req('/callback?code=abc&state=whatever'), ENV)
    expect(res.status).toBe(400)
  })

  it('mobile: proceeds with a valid signed state when the cookie was lost in the OAuth handoff', async () => {
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://allowed-site.example/app', nonce: 'n' }, ENV.SSO_SECRET, 10 * 60 * 1000)

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'discord-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'user-1', global_name: 'Test User' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 'guild-123' }]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    // No Cookie header at all — simulates Firefox/Android returning from the
    // Discord app without cri_hub_state.
    const request = new Request(`https://auth.example/callback?code=auth-code&state=${state}`)
    const res = await worker.fetch(request, ENV)

    expect(res.status).toBe(302)
    const location = new URL(res.headers.get('Location'))
    expect(location.origin + location.pathname).toBe('https://allowed-site.example/api/auth/sso')
    expect(location.searchParams.get('token')).toBeTruthy()
  })

  it('rejects when the returned state does not match the cookie (CSRF)', async () => {
    const request = new Request('https://auth.example/callback?code=abc&state=returned-state', {
      headers: { Cookie: 'cri_hub_state=different-state' },
    })
    const res = await worker.fetch(request, ENV)
    expect(res.status).toBe(400)
  })

  it('rejects a validly-cookied but unsigned/garbage state', async () => {
    const request = new Request('https://auth.example/callback?code=abc&state=garbage', {
      headers: { Cookie: 'cri_hub_state=garbage' },
    })
    const res = await worker.fetch(request, ENV)
    expect(res.status).toBe(400)
  })

  it('fails closed if the signed state points at an origin no longer on the allowlist', async () => {
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://not-allowed.example', nonce: 'n' }, ENV.SSO_SECRET, 10 * 60 * 1000)
    const request = new Request(`https://auth.example/callback?code=abc&state=${state}`, {
      headers: { Cookie: `cri_hub_state=${state}` },
    })
    const res = await worker.fetch(request, ENV)
    expect(res.status).toBe(400)
  })

  it('redirects back to the target with no_code when Discord sends no code', async () => {
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://allowed-site.example', nonce: 'n' }, ENV.SSO_SECRET, 10 * 60 * 1000)
    const request = new Request(`https://auth.example/callback?state=${state}`, {
      headers: { Cookie: `cri_hub_state=${state}` },
    })
    const res = await worker.fetch(request, ENV)
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('https://allowed-site.example/?auth_error=no_code')
  })

  it('happy path: exchanges code, confirms guild membership, issues an SSO token scoped to the target origin', async () => {
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://allowed-site.example/app', nonce: 'n' }, ENV.SSO_SECRET, 10 * 60 * 1000)

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'discord-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'user-1', global_name: 'Test User' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 'guild-123' }]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    const request = new Request(`https://auth.example/callback?code=auth-code&state=${state}`, {
      headers: { Cookie: `cri_hub_state=${state}` },
    })
    const res = await worker.fetch(request, ENV)

    expect(res.status).toBe(302)
    const location = new URL(res.headers.get('Location'))
    expect(location.origin + location.pathname).toBe('https://allowed-site.example/api/auth/sso')
    expect(location.searchParams.get('to')).toBe('/app')

    const ssoToken = location.searchParams.get('token')
    const payload = await verify(ssoToken, ENV.SSO_SECRET)
    expect(payload.sub).toBe('user-1')
    expect(payload.name).toBe('Test User')
    // The audience MUST be the target origin — this is what stops a token
    // issued for one site being replayed against another (confused-deputy).
    expect(payload.aud).toBe('https://allowed-site.example')
  })

  it('token-exchange sends the same CANONICAL_ORIGIN redirect_uri as /login (must match exactly or Discord rejects)', async () => {
    const CANON_ENV = { ...ENV, CANONICAL_ORIGIN: 'https://auth.criativaria.workers.dev' }
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://allowed-site.example/app', nonce: 'n' }, CANON_ENV.SSO_SECRET, 10 * 60 * 1000)

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'discord-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'user-1' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 'guild-123' }]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    // Callback arrives on a DIFFERENT host than the canonical origin (e.g. a
    // custom-domain cutover in flight) — CANONICAL_ORIGIN must win over url.origin.
    const request = new Request(`https://some-other-host.example/callback?code=auth-code&state=${state}`, {
      headers: { Cookie: `cri_hub_state=${state}` },
    })
    await worker.fetch(request, CANON_ENV)

    const tokenExchangeBody = fetchMock.mock.calls[0][1].body
    expect(tokenExchangeBody.get('redirect_uri')).toBe('https://auth.criativaria.workers.dev/callback')
  })

  it('redirects with not_member when the user is not in the required guild', async () => {
    const { sign } = await import('./crypto.js')
    const state = await sign({ to: 'https://allowed-site.example', nonce: 'n' }, ENV.SSO_SECRET, 10 * 60 * 1000)

    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: 'discord-token' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'user-1' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ id: 'other-guild' }]), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    const request = new Request(`https://auth.example/callback?code=auth-code&state=${state}`, {
      headers: { Cookie: `cri_hub_state=${state}` },
    })
    const res = await worker.fetch(request, ENV)
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toBe('https://allowed-site.example/?auth_error=not_member')
  })
})
