/**
 * criativaria-auth — hub central de login por Discord para os stagings da
 * Criativaria. Um único redirect URI no app do Discord (<hub>/callback);
 * cada site de staging só precisa estar na allowlist ALLOWED_ORIGINS.
 *
 * Fluxo:
 *   site → GET /login?to=<url do site>        (valida allowlist, manda ao Discord)
 *   Discord → GET /callback                   (troca code, confere guild)
 *   hub → site /api/auth/sso?token=<HMAC 60s> (site verifica com SSO_SECRET e cria sessão própria)
 */
import * as Sentry from '@sentry/cloudflare'
import { sign, verify } from './crypto.js'

const STATE_TTL_MS = 10 * 60 * 1000
const SSO_TOKEN_TTL_MS = 60 * 1000
const RATE_LIMIT_PER_MIN = 30
const RATE_LIMIT_WINDOW_SEC = 120

const handler = {
  async fetch(request, env) {
    const url = new URL(request.url)
    switch (url.pathname) {
      case '/login':
        return login(url, request, env)
      case '/callback':
        return callback(url, request, env)
      case '/health':
        return new Response('ok', { status: 200 })
      default:
        return new Response('criativaria-auth', { status: 200 })
    }
  },
}

export default Sentry.withSentry(
  (env) => ({
    dsn: env.SENTRY_DSN,
    environment: env.ENVIRONMENT?.includes('staging') ? 'staging' : 'production',
    tracesSampleRate: 0.1,
  }),
  handler,
)

function allowedOrigins(env) {
  return (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

// Zonas multi-tenant compartilhadas: allowlistar o host pelado abriria o hub
// para QUALQUER usuário Cloudflare. Um sufixo terminando nelas precisa de um
// label de projeto à frente (>=3 labels), ex.: `projeto-hash.pages.dev` ok,
// `pages.dev` recusado.
const SHARED_TENANT_ZONES = ['pages.dev', 'workers.dev']

// Sufixos autorizados para origens de preview do Cloudflare Pages
// (`<branch>.<projeto>-<hash>.pages.dev`). Um subdomínio de um projeto Pages é
// ligado exclusivamente à conta dona (só quem tem push no repo conectado gera
// deploy; PR de fork não cria preview), então casar por sufixo do host do
// projeto é seguro — evita allowlistar cada branch na mão. Ver ADR 0002.
function allowedSuffixes(env) {
  return (env.ALLOWED_ORIGIN_SUFFIXES || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .filter((sfx) => {
      const dangerous =
        SHARED_TENANT_ZONES.includes(sfx) ||
        SHARED_TENANT_ZONES.some((z) => sfx.endsWith('.' + z) && sfx.split('.').length < 3)
      if (dangerous) {
        console.error(`ALLOWED_ORIGIN_SUFFIXES: sufixo perigoso ignorado "${sfx}" (zona compartilhada sem projeto)`)
      }
      return !dangerous
    })
}

function resolveTarget(rawTo, env) {
  let to
  try {
    to = new URL(rawTo)
  } catch {
    return null // URL inválida
  }
  if (to.protocol !== 'https:') return null
  if (allowedOrigins(env).includes(to.origin)) return to
  // Match por sufixo de projeto Pages (subdomínios de preview). Usa hostname
  // (via URL, imune a truques de userinfo/porta); o `.` inicial ancora o limite
  // de label para `evilprojeto-hash.pages.dev` NÃO casar `projeto-hash.pages.dev`.
  const host = to.hostname
  for (const sfx of allowedSuffixes(env)) {
    if (host === sfx || host.endsWith('.' + sfx)) return to
  }
  console.error(`resolveTarget: origem recusada ${to.origin}`)
  return null
}

function callbackUrl(env, url) {
  return `${env.CANONICAL_ORIGIN || url.origin}/callback`
}

function stateCookie(value, maxAge) {
  return `cri_hub_state=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`
}

function getCookie(request, name) {
  return (request.headers.get('Cookie') || '').match(new RegExp(`${name}=([^;]+)`))?.[1]
}

async function checkRateLimit(ip, kv) {
  const key = `rl:${ip}:${Math.floor(Date.now() / 60000)}`
  const count = parseInt((await kv.get(key)) || '0', 10)
  if (count >= RATE_LIMIT_PER_MIN) {
    return false
  }
  await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_SEC })
  return true
}

function getClientIp(request) {
  return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for')?.split(',')?.[0] || 'unknown'
}

async function discordApi(path, accessToken) {
  const res = await fetch(`https://discord.com/api${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (!res.ok) {
    throw new Error(`Discord API error ${res.status}`)
  }
  return res.json()
}

async function login(url, request, env) {
  const ip = getClientIp(request)
  if (!(await checkRateLimit(ip, env.RATE_LIMIT))) {
    return new Response('Muitas tentativas. Tente novamente em breve.', { status: 429 })
  }

  const target = resolveTarget(url.searchParams.get('to') || '', env)
  if (!target) return new Response('Destino não permitido.', { status: 400 })

  const state = await sign({ to: target.href, nonce: crypto.randomUUID() }, env.SSO_SECRET, STATE_TTL_MS)
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    redirect_uri: callbackUrl(env, url),
    response_type: 'code',
    scope: 'identify guilds',
    state,
  })
  return new Response(null, {
    status: 302,
    headers: {
      Location: `https://discord.com/oauth2/authorize?${params}`,
      'Set-Cookie': stateCookie(state, 600),
    },
  })
}

async function callback(url, request, env) {
  const ip = getClientIp(request)
  if (!(await checkRateLimit(ip, env.RATE_LIMIT))) {
    return new Response('Muitas tentativas. Tente novamente em breve.', { status: 429 })
  }

  const code = url.searchParams.get('code')
  const returnedState = url.searchParams.get('state')
  const cookieState = getCookie(request, 'cri_hub_state')

  // O `state` é a fonte da verdade: HMAC assinado com nonce + TTL de 10min
  // (verify() confere assinatura E validade). O cookie cri_hub_state é uma
  // defesa extra (liga o state ao navegador que iniciou o login, contra
  // login-CSRF). No mobile, o Discord entrega o fluxo ao app / reabre o
  // retorno em outro contexto de navegador e o cookie se perde — então o
  // cookie é verificado só quando presente; ausente, caímos na verificação
  // por assinatura abaixo. Sem cookie válido nem state válido => rejeita.
  if (!returnedState) {
    return new Response('Estado de login inválido. Volte ao site e tente de novo.', { status: 400 })
  }
  if (cookieState && returnedState !== cookieState) {
    return new Response('Estado de login inválido. Volte ao site e tente de novo.', { status: 400 })
  }
  const state = await verify(returnedState, env.SSO_SECRET)
  const target = state && resolveTarget(state.to, env)
  if (!target) {
    return new Response('Sessão de login expirada. Volte ao site e tente de novo.', { status: 400 })
  }
  const fail = (reason) => {
    console.error(`auth fail: ${reason}`)
    return Response.redirect(`${target.origin}/?auth=denied`, 302)
  }

  if (!code) return fail('no_code')

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: callbackUrl(env, url),
      }),
    })
    if (!tokenRes.ok) {
      return fail('provider_unavailable')
    }
    const { access_token } = await tokenRes.json()
    if (!access_token) return fail('token_failed')

    const [user, guilds] = await Promise.all([
      discordApi('/users/@me', access_token),
      discordApi('/users/@me/guilds', access_token),
    ])
    const isMember = Array.isArray(guilds) && guilds.some((g) => g.id === env.DISCORD_GUILD_ID)
    if (!isMember) return fail('not_member')

    const ssoToken = await sign(
      { sub: user.id, name: user.global_name || user.username, aud: target.origin },
      env.SSO_SECRET,
      SSO_TOKEN_TTL_MS,
    )
    const dest = new URL('/api/auth/sso', target.origin)
    dest.searchParams.set('token', ssoToken)
    dest.searchParams.set('to', target.pathname + target.search)
    const headers = new Headers({ Location: dest.href })
    headers.append('Set-Cookie', stateCookie('', 0))
    return new Response(null, { status: 302, headers })
  } catch (err) {
    console.error('hub callback error:', err.message || err.constructor.name)
    return fail('server_error')
  }
}
