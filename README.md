# criativaria-auth

Hub central de login por Discord para os ambientes de staging da Criativaria. Roda como um único [Cloudflare Worker](https://developers.cloudflare.com/workers/) (`auth.criativaria.workers.dev`).

O app do Discord tem um **único** redirect URI (`<hub>/callback`). Cada novo site de staging entra na allowlist `ALLOWED_ORIGINS` (`wrangler.toml`) e reaproveita o mesmo fluxo: o site manda a pessoa para `<hub>/login?to=<url do site>`, o hub confirma que ela está no Discord da Criativaria e devolve um token HMAC de 60 segundos que o site troca por uma sessão própria.

## Fluxo

```
site  ──GET /login?to=<url>──────────▶  hub
hub   ──redirect (state assinado)────▶  Discord OAuth
Discord ──GET /callback?code&state──▶  hub
hub   (troca code, confere guild)
hub   ──redirect ?token=<HMAC 60s>───▶  site /api/auth/sso
site  (verifica token com SSO_SECRET, cria sessão própria)
```

- O `state` do OAuth é assinado (HMAC) e guardado num cookie `HttpOnly` de curta duração (10 min) — protege contra CSRF/state fixation.
- O token SSO final também é HMAC-assinado, expira em 60s e carrega `aud` (origem de destino), então não pode ser reusado em outro site.
- `resolveTarget` valida qualquer `to=` contra `ALLOWED_ORIGINS` antes de redirecionar — bloqueia open redirect.

## Rotas

| Rota | Descrição |
|---|---|
| `GET /login?to=<url>` | Valida a origem contra a allowlist e redireciona para o Discord. |
| `GET /callback` | Troca o `code`, confere a guild (`DISCORD_GUILD_ID`) e devolve para `<origem>/api/auth/sso?token=...`. |
| `GET /health` | Verificação simples (`200 ok`). |

## Stack

- Cloudflare Workers (JS puro, sem framework — `src/index.js` + `src/crypto.js`)
- Assinatura HMAC-SHA256 via Web Crypto (`src/crypto.js`)
- Deploy via GitHub Actions + `wrangler` (`.github/workflows/deploy.yml`)

## Config

**Vars** (`wrangler.toml`):

- `ALLOWED_ORIGINS` — origens autorizadas a receber tokens SSO, separadas por vírgula.
- `DISCORD_CLIENT_ID`
- `DISCORD_GUILD_ID`

**Secrets** (organization secrets no GitHub; o deploy sincroniza via `wrangler secret put`):

- `DISCORD_CLIENT_SECRET` — app do Discord (mesmo do admin panel).
- `SSO_SECRET` — HMAC dos tokens SSO; compartilhado com os sites.
- `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` — usados só pelo workflow de deploy.

## Desenvolvimento local

```bash
npx wrangler dev
```

Requer `wrangler secret put DISCORD_CLIENT_SECRET` / `SSO_SECRET` localmente (ou `.dev.vars`) para testar o fluxo completo.

## Deploy

Push em `main` dispara `.github/workflows/deploy.yml`: `wrangler deploy` + sync dos secrets a partir dos organization secrets do GitHub. Não há passo manual.

## Adicionar um novo site de staging

1. Acrescente a origem em `ALLOWED_ORIGINS` (`wrangler.toml`) e faça push (deploy automático).
2. No site, use o middleware padrão (`clt-pj-calculator/functions/`) com `AUTH_HUB_URL` + `SSO_SECRET`.
3. Pronto. Nada de novo no portal do Discord.
