# ADR 0003 — Bind SSO-token audience into the signing key (per-origin derived key)

- Status: **accepted (target architecture; execution phased & gated — see Rollout)**
- Date: 2026-07-05

## Contexto

ADR 0002 (deste hub) e a migração de login por SSO (career-tools ADR-0002, One Brain)
deixaram um **requisito distribuído não-imposto**: cada site consumidor DEVE validar
`aud === sua própria origem exata` no token SSO, senão um token cunhado para o site A
poderia ser redimido no site B. Hoje o hub assina
`{ sub, name, aud: <origem destino>, exp }` com um único `SSO_SECRET` compartilhado
(HMAC-SHA256, `@criativaria-projects/auth-crypto` `sign()`), TTL 60s.

Levantamento (survey de repos + One Brain):
- `auth-crypto` expõe só `sign`/`verify` genéricos — **sem helper ciente de audience**.
  Cada site faz o check de `aud` na mão.
- admin-panel: check estrito ✓, mas via `src/lib/ssoToken.ts` PRÓPRIO (nem usa o pacote
  compartilhado p/ SSO) — **drift concreto**.
- clt-pj-calculator: check estrito ✓, inline.
- career-tools: main NÃO tem `sso.js` (só `_lib/session.js`); o código hub-ificado vive
  só na branch `development` (não mergeada) — repo meio-migrado entre branches.

Sem vuln viva hoje (os dois sites checáveis validam estrito). O risco é DURABILIDADE:
o check é duplicado e feito à mão por site → um site novo ou um refactor pode **omitir
silenciosamente** o check. Falha ABERTA (buraco de segurança). Mesmo cheiro de
requisito-distribuído que a ADR 0009 removeu para o `redirect_uri`.

## Decisão

Adotar como arquitetura-alvo **chave de assinatura derivada por origem**: o hub assina
o token SSO com uma chave derivada do destino —
`k_origin = HMAC(SSO_SECRET, origin)` (HKDF/HMAC-SHA256) — e cada site verifica com a
chave derivada da SUA PRÓPRIA origem. Um token cunhado para A usa `k_A`; o site B
verifica com `k_B` → assinatura inválida → rejeitado. **A audiência fica embutida na
chave**, não num campo que o site precisa lembrar de conferir.

Propriedade decisiva (por que #3 e não #2): a assimetria de modo-de-falha.
- Requisito-distribuído (#2 / status quo): "esqueci de checar `aud`" → falha ABERTA (vuln).
- Chave-por-origem (#3): "derivei a chave da origem errada" → falha FECHADA (o próprio
  login do site quebra; nenhum token de outra origem é aceito). Impossível derivar para
  uma origem que o site não conhece.

Sem mudança de formato de token (payload igual; muda só a chave de assinatura). JWT segue
adiado (ver Alternativas).

## Rollout (Fase 3 — faseado, dual-accept, com gates)

1. **auth-crypto @0.2.0 (aditivo, não-quebra):** adicionar
   `deriveOriginKey(secret, origin)`, `signSsoToken(payload, secret, origin)` e
   `verifySsoToken(token, secret, expectedOrigin)` (deriva `k_expectedOrigin`, verifica
   sig+exp; `expectedOrigin` obrigatório). Testes de isolamento cross-origin. Nada vivo muda.
2. **Sites aceitam AMBOS (janela de graça):** cada site tenta `verifySsoToken` (chave
   por-origem) e, se falhar, cai no caminho atual (`verify` + check de `aud` estrito).
   Pilotar em **admin-panel** (100% local, já no pacote; deletar o `ssoToken.ts` bespoke),
   depois clt-pj-calculator.
3. **Gate career-tools:** NÃO migrar até a branch situation do repo estar limpa (main sem
   `sso.js`, código hub só em `development`). Pré-requisito fora do escopo deste hub.
4. **Hub corta p/ chave-por-origem** só depois de todos os sites vivos aceitarem os dois.
5. **Sites removem o fallback** de secret-compartilhado+aud. Fim do requisito distribuído.

Rollback: cada etapa é aditiva/reversível; sites pinam `auth-crypto@0.1.x` e o hub volta a
assinar com `SSO_SECRET`. Critério de sucesso do piloto: admin-panel loga end-to-end com
chave-por-origem E rejeita um token forjado p/ outra origem (teste).

## Alternativas consideradas

1. **Status quo** — check de `aud` à mão por site. Funciona hoje; drift real (admin-panel
   já divergiu); falha aberta. Rejeitado: é o problema.
2. **Helper compartilhado `verifySsoToken(expectedOrigin obrigatório)` no auth-crypto**
   (proposta inicial) — **REJEITADO pelo critic**: é *nudge, não enforcement*. O `verify()`
   genérico continua exportado (é primitivo de sessão também), então um site pode
   `import { verify }` e pular o `aud` — a segurança depende de disciplina do site. Não
   resolve a falha-aberta.
3. **[escolhido]** Chave de assinatura derivada por origem — enforcement estrutural
   (matemático), falha fechada.
4. **JWT/jose com `aud` imposto por lib** — o trigger de revisão da career-tools ADR-0002
   ("após migração de conta CF estável") FOI ATINGIDO (ADR 0009 Fase B, 2026-07-03).
   Mas: #3 resolve o isolamento de audiência sem trocar formato nem adicionar dependência;
   JWT é migração maior e ortogonal. **Re-adiado explicitamente** — revisita como decisão
   própria se/quando houver outra razão para JWT (claims ricos, rotação de chave padrão).
5. **Hub cunha o cookie de sessão do site direto** — inversão arquitetural, blast radius
   grande. Rejeitado.

## Consequências

- (+) Isolamento cross-origin vira propriedade estrutural: nenhum site pode driftar para
  uma vuln (drift → self-DoS do próprio login, não buraco).
- (+) Remove o requisito distribuído; um site novo não tem como "esquecer o `aud`".
- (+) Sem mudança de formato; JWT segue adiado; reconcilia com career-tools ADR-0002.
- (−) Migração coordenada em 3 sites + hub (mitigado por janela dual-accept).
- (−) `SSO_SECRET` continua o segredo-raiz único; `k_origin` é derivada dele. Comprometer
  `SSO_SECRET` ainda compromete tudo (inalterado vs. hoje).
- (−) **Fora de escopo, REGISTRADO:** o token não tem `jti`/nonce nem binding ao navegador
  que iniciou o login → replay dentro dos 60s à MESMA origem é possível (o `state` do
  OAuth protege o /callback, não o token SSO). #3 resolve audiência, NÃO replay. Tratar
  em decisão separada se virar risco (ADR futura: jti + one-time redemption).
- (−) career-tools bloqueado até limpar suas branches (main pré-hub, código em `development`).

## Estratégia de cutover do hub (decidido 2026-07-05)

Como o token é assinado num só lugar e a chave é por-origem, cabia decidir se o
cutover do hub (`sign` legado → `signSsoToken` derivado) seria **big-bang** (todos
os sites de uma vez) ou **incremental por-origem** (um env `SSO_DERIVED_ORIGINS`
allowlist; hub assina derivado só p/ origens cujos sites já fazem dual-accept).
O incremental desacoplaria admin-panel do bloqueio do career-tools.

**Decisão: ADIAR o cutover; NÃO construir o incremental por-origem.** Big-bang
quando a frota inteira estiver pronta.

Motivos (critic REVISE→wait, aceito):
- **Sem vuln viva.** admin-panel já confere `aud === origin` estrito
  (`src/worker/index.ts:183`) — a chave derivada só remove um risco FUTURO de
  "esquecer o aud" que admin-panel não tem hoje. Upgrade defensivo, não correção.
- **Dívida de caminho-duplo permanente.** O incremental deixa dois caminhos de
  assinatura no hub + um allowlist, cuja limpeza depende do career-tools (sem dono
  nem ETA) — tende a virar débito permanente.
- **Desacoplar ≠ contornar.** O bloqueio real (branches do career-tools) deve ser
  resolvido no seu próprio tempo, não roteado com dívida no hub.
- Nada se perde ao esperar: a fundação está pronta (auth-crypto@0.2.0; admin-panel
  já faz dual-accept, commit `f5ab285`, pin-testado). Quando a frota estiver
  pronta, big-bang = um só caminho de assinatura, sem allowlist, sem débito.

Se algum dia o incremental for reconsiderado: normalizar cada entrada de
`SSO_DERIVED_ORIGINS` via `new URL(x).origin` (evita mismatch por barra final /
porta / caixa que deixaria uma origem pronta silenciosamente no legado).

## Revisit when

- Um site novo entrar em produção **antes** do rollout #3 completar → aplicar #3 nele
  direto (ou pelo menos o fallback com `aud` estrito), nunca subir sem isolamento.
- Aparecer razão independente para JWT (claims ricos, rotação padrão) → reabrir Alt 4.
- Replay dentro de 60s virar risco observado (ex.: terminais compartilhados) → ADR de
  `jti` + redenção única.
- Comprometer `SSO_SECRET` → rotacionar; considerar segredo-raiz por-site em vez de derivar
  de um único.
- career-tools continuar meio-migrado por >2 semanas → escalar a limpeza de branch como
  bloqueador próprio.
- **Cutover adiado — reconsiderar quando:** career-tools ganhar dono+ETA <6 semanas;
  OU um 2º site não-bloqueado (clt-pj) ficar pronto (muda custo/benefício); OU admin-panel
  deixar de conferir `aud` (upgrade vira urgente). Gatilho de execução do big-bang: TODOS
  os sites vivos fazendo dual-accept.
