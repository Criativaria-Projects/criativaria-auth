# ADR 0002 — Autorizar origens de preview do Cloudflare Pages por sufixo de projeto

- Status: **accepted**
- Date: 2026-07-05

## Contexto

O hub valida o `to` de `GET /login` contra um allowlist exato de origens
(`ALLOWED_ORIGINS`). Sites em produção usam domínio custom (ex.:
`posicionamento.criativaria.com`) e casam direto. Mas deploys de **branch/preview**
do Cloudflare Pages têm origem `https://<branch>.<projeto>-<hash>.pages.dev`
(ex.: `development.criativaria-linkedin-34m.pages.dev`). Cada branch nova que um
dev/staff quer logar = uma origem nova, NÃO coberta pela entrada de produção →
o hub responde `Destino não permitido.` → exige editar `wrangler.toml`, commitar
e re-deployar o hub. Aconteceu 2× numa semana. Fricção operacional recorrente.

## Fatos verificados (docs Cloudflare, alta confiança)

- Quando o nome do projeto Pages já existe globalmente, o CF auto-suffixa:
  `criativaria-linkedin` → `criativaria-linkedin-34m.pages.dev`. O host suffixado
  é único de UM projeto/conta.
- **Todos** os subdomínios `<qualquer>.criativaria-linkedin-34m.pages.dev` são
  ligados exclusivamente à conta dona: deploy só por push Git de quem tem acesso
  ao repo conectado; PR de fork NÃO cria preview; não há API para criar
  subdomínio arbitrário. Um atacante **não** consegue servir conteúdo em
  `evil.criativaria-linkedin-34m.pages.dev`.
- Aliases de branch (`<branch>.<host>`) são estáveis entre redeploys.
- `pages.dev` pelado é compartilhado por TODOS os usuários Cloudflare.
  `criativaria-linkedin.pages.dev` (sem `-34m`) é OUTRO projeto (conta antiga).

## Decisão

Adicionar match por **sufixo de projeto**, opt-in, ao lado do match exato.

Novo env `ALLOWED_ORIGIN_SUFFIXES` = lista (vírgula) de **hosts de projeto Pages
completos** (ex.: `criativaria-linkedin-34m.pages.dev`). Uma origem passa se
`host === sfx` OU `host.endsWith('.' + sfx)`. Um projeto inteiro (todas as
branches) = uma entrada, uma vez, sem redeploy por branch.

Endurecimentos exigidos pela revisão crítica (critic REVISE → aceito com fixes):

1. **Guarda anti-foot-gun (crítico):** sufixos em zonas multi-tenant
   compartilhadas (`pages.dev`, `workers.dev`) sem um label de projeto (i.e.
   `pages.dev` pelado, `< 3` labels) são **recusados em código** com log de erro.
   Um único typo (`pages.dev` em vez do host completo) abriria o hub para
   qualquer usuário Cloudflare — agora é impossível por config. (A regex do
   critic `-[a-z0-9]{3,4}\.pages\.dev$` foi **rejeitada**: projetos de nome livre
   não têm hash — ex. `criativaria-clt-pj.pages.dev` — e seriam recusados por
   engano. A regra correta é "≥3 labels em zona compartilhada".)
2. **Só `https:`** — `resolveTarget` recusa qualquer esquema não-https.
3. **Match por `URL.hostname`** (não string crua) — imune a truques de
   userinfo (`https://host@evil.example`) e porta.
4. **Âncora de limite de label** — o `.` inicial em `'.' + sfx` impede
   `evilcriativaria-linkedin-34m.pages.dev` de casar `criativaria-linkedin-34m.pages.dev`.
5. **Observabilidade** — origens recusadas e sufixos perigosos são logados
   (`console.error`) para depurar config sem vazar token.

## Alternativas consideradas

1. **Status quo** (lista exata, add manual + redeploy por branch) — zero código,
   fricção recorrente. Rejeitado: é o problema.
2. **[escolhido]** Match por sufixo de projeto, endurecido.
3. **Allowlist por regex** (`ALLOWED_ORIGIN_PATTERNS`) — mais flexível, mas regex
   não-ancorada é foot-gun clássico de bypass. Rejeitado: mais perigoso que o
   sufixo ancorado, sem ganho para este caso.
4. **Injeção em deploy-time** (hook do Pages escreve a URL de preview no allowlist
   do hub via API) — sem mudança no hub, mas acopla CI cross-repo + write-back.
   Rejeitado: complexidade desproporcional.
5. **Só domínios de produção + dev-bypass** (career-tools já pula auth quando
   `SESSION_SECRET` não está setado) — mais simples/seguro, mas previews não têm
   auth Discord real (não testam o fluxo). Rejeitado: previews precisam do fluxo real.
6. **Gate de preview atrás de senha** (`__staging_auth`) — contém a escalada a
   quem destrava a senha. Guardado como fallback se o trade-off de colaborador
   piorar (ver Revisit).

## Consequências

- (+) Previews de um projeto viram self-service: nenhuma edição/redeploy do hub
  por branch. Resolve a fricção recorrente.
- (+) Superfície de config mais segura que antes contra o typo `pages.dev`
  (recusado em código; antes nem existia o vetor).
- (−) **Trade-off de escalada de privilégio (MÉDIO, aceito):** o conjunto de
  origens que recebem token SSO válido passa de "listado explicitamente" para
  "qualquer subdomínio de um projeto listado". Um colaborador com push (ou token
  GitHub vazado) pode subir uma branch com código malicioso, deployar em
  `atacante.criativaria-linkedin-34m.pages.dev`, induzir um staff a logar e
  receber um token SSO (id Discord + confirmação de guild) com
  `aud=aquela-origem`. Mitigadores: PR de fork não cria preview; o token é curto
  (60s) e o `aud` prende ao host do atacante — **inútil em produção SE os sites
  validarem `aud === própria origem exata`**; o atacante já controla aquele host
  (pode mintar sessão local de qualquer jeito). O ganho real do token seria
  reusá-lo em OUTRA origem — barrado pelo `aud` estrito.
- (−) **Requisito imposto aos sites consumidores:** todo site que usa o hub DEVE
  validar `aud === sua própria origem exata` — nunca `aud.endsWith('.pages.dev')`
  nem `aud.includes('criativaria')`. `criativaria-admin-panel` já faz
  (`payload.aud !== origin`, `src/worker/index.ts:183`). **career-tools:
  verificar na branch deployada** (checkout local em `staging` está desatualizado,
  sem o `sso.js` hub-ificado) — item em aberto abaixo.

## Revisit when

- Cloudflare mudar o modelo de preview (API para mintar subdomínio arbitrário,
  ou fim do auto-hash / rename mudando o host — a entrada de sufixo fica órfã e
  falha fechada, seguro, mas login quebra até atualizar).
- Um site validar `aud` de forma frouxa e sofrer tentativa de exploit → forçar
  validação estrita ou mover para Alt 6 (senha no preview).
- Token GitHub de colaborador comprometido usado para deploy malicioso →
  reavaliar gate de preview (Alt 6).
- Acesso de push aos repos Criativaria se abrir a contribuidores de baixa
  confiança → o trade-off de escalada deixa de ser aceitável; reavaliar.
- Logs do hub mostrarem origens recusadas repetidas → typo de config a corrigir.
