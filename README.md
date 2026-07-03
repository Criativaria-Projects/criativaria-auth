# criativaria-auth

Hub central de login por Discord para os ambientes de staging da Criativaria.

O app do Discord tem um único redirect URI (`<hub>/callback`). Cada novo site de staging entra na allowlist `ALLOWED_ORIGINS` (wrangler.toml) e reaproveita o mesmo fluxo: o site manda a pessoa para `<hub>/login?to=<url do site>`, o hub confirma que ela está no Discord da Criativaria e devolve um token HMAC de 60 segundos que o site troca por uma sessão própria.

## Rotas

- `GET /login?to=<url>`: valida a origem contra a allowlist e redireciona para o Discord.
- `GET /callback`: troca o code, confere a guild (`DISCORD_GUILD_ID`) e devolve para `<origem>/api/auth/sso?token=...`.
- `GET /health`: verificação simples.

## Config

- Vars (wrangler.toml): `ALLOWED_ORIGINS`, `DISCORD_CLIENT_ID`, `DISCORD_GUILD_ID`.
- Secrets: `DISCORD_CLIENT_SECRET`, `SSO_SECRET` (organization secrets no GitHub; o deploy sincroniza).

## Adicionar um novo site de staging

1. Acrescente a origem em `ALLOWED_ORIGINS` e faça push (deploy automático).
2. No site, use o middleware padrão (`clt-pj-calculator/functions/`) com `AUTH_HUB_URL` + `SSO_SECRET`.
3. Pronto. Nada de novo no portal do Discord.
