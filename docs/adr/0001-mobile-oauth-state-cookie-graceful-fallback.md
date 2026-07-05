# ADR 0001 — Tolerar perda do cookie de state no OAuth mobile (fallback por assinatura)

- Status: **accepted**
- Date: 2026-07-05

## Contexto

Um membro relatou que no mobile (Android, Firefox) o login por Discord travava:
entrava na página do Discord, autorizava ("connect"), mas **nunca era
redirecionado de volta** ao painel.

O hub (`criativaria-auth`) é o ponto único de OAuth para todos os sites da
Criativaria (ver ADR 0009 do `criativaria-admin-panel`). Fluxo:

```
site → hub /login (grava cookie cri_hub_state, redireciona ao Discord)
Discord → hub /callback (troca code, confere guild)
hub → site /api/auth/sso?token=<HMAC 60s>
```

O `/callback` exigia que o `state` devolvido pelo Discord fosse **exatamente
igual** ao cookie `cri_hub_state` gravado no `/login`:

```js
if (!returnedState || returnedState !== cookieState) {
  return new Response('Estado de login inválido...', { status: 400 })
}
```

No mobile, ao autorizar, o Discord entrega o fluxo ao **app do Discord** (ou
reabre a URL de retorno em outra Custom Tab / contexto de navegador). O retorno
cai num jar que nunca recebeu `cri_hub_state` → `cookieState` fica `undefined`
→ o teste estrito de igualdade falha → o hub responde **400 texto puro, sem
redirect**. É exatamente o sintoma "conecta mas não volta". No desktop há um só
contexto → o cookie sobrevive → funciona. Por isso só o mobile quebrava.

## Decisão

O `state` **já é auto-validável**: HMAC assinado com `SSO_SECRET`, nonce e TTL
de 10 min (`verify()` confere assinatura E `exp`). O cookie era defesa extra
(liga o `state` ao navegador que iniciou o login, contra *login-CSRF*) — e era a
parte frágil.

Trocamos a dependência dura do cookie por **fallback gracioso**:

- cookie presente → precisa bater (proteção login-CSRF completa; desktop
  inalterado);
- cookie ausente → cai na verificação por assinatura+TTL (destrava mobile);
- sem `state` válido em nenhum caso → ainda rejeita.

```js
if (!returnedState) return badState()
if (cookieState && returnedState !== cookieState) return badState()
const state = await verify(returnedState, env.SSO_SECRET)
if (!state) return badState()
```

## Alternativas consideradas

- **`SameSite=None; Secure` no cookie de state** — não resolve: a causa é o
  cookie estar em outro app/jar do navegador (troca de contexto no handoff do
  app do Discord), não bloqueio por SameSite.
- **Remover o cookie de vez** — mais robusto em todos os browsers, mas abre a
  superfície de login-CSRF em *todos* os caminhos, não só mobile. Preferimos
  manter a checagem quando o cookie existe.

## Consequências

- (+) Login mobile (app-handoff) volta a funcionar; desktop inalterado.
- (−) O caminho mobile (sem cookie) tem uma pequena superfície de login-CSRF —
  mitigada por `state` inforjável (HMAC + nonce + TTL de 10 min) e por ser
  ferramenta interna de ops, não crítica (ADR 0009).

## Revisit when

- O hub passar a servir superfícies sensíveis (não só ops interno) — reavaliar
  se o fallback sem cookie ainda é aceitável, ou exigir PKCE.
