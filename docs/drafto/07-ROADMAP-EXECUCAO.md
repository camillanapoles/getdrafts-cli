# Drafto — Roadmap de Execução & Catálogo de Specs

> **Para quê este documento:** transformar o estado real do projeto (auditado em
> [`08-AUDIT-2026-11-12.md`](08-AUDIT-2026-11-12.md)) em **um plano executável por sessões Arena
> paralelas**: quem faz o quê, em qual workspace, com qual pré-requisito de início, o que pode
> rodar em paralelo e o que **não** pode.
>
> Convenção de fases/matrizes continua em [`05-ROADMAP.md`](05-ROADMAP.md) (fases) e
> [`02-FEATURE-PARITY.md`](02-FEATURE-PARITY.md) (pareamento). Este arquivo é a **camada de execução**:
> specs com `DoR` (definition of ready = critério de início), `DoD` (aceite), lane e conflitos.

---

## 1. Legenda

| Símbolo | Significado |
|---|---|
| ✅ | **Feito e integrado em `reverse/main`**, com evidência (CI/commit) |
| 🟢 | Feito **em branch paralelo**, ainda não integrado a `reverse/main` |
| 🟡 | Parcial — parte existe, critério de aceite não fecha |
| ⚪ | Pendente (não iniciado) |
| 🔒 | Serial/exclusivo — bloqueia merges alheios enquanto aberto |
| ∥ | Pode rodar em paralelo com as specs marcadas `∥` |
| S/M/L/XL | Esforço: ~1 sessão / 1–2 sessões / 2–3 sessões / >1 fase |

**Regra de ouro do status:** ✅ só com evidência citável (run de CI, teste nomeado, comando).
Sem evidência, é 🟡. Foi assim que `05-ROADMAP.md` acumulou itens falsamente concluídos (D1–D5 da auditoria).

---

## 2. Estado por fase — o que foi feito × o que está pendente

### Phase 0 — Fundação → ✅ **concluída** (v0.1.x)

| Item | Status | Evidência |
|---|---|---|
| Docs 00–04 + CODEMAP | ✅ | `docs/drafto/` no repo; PR #2/#3 mesclados |
| `core/` (model, Store, Memory, actions, template, testes) | ✅ | 1.000+ linhas; testes verdes no CI |
| Migração da CLI p/ core (aliases em `pkg/drafts`) | ✅ | `pkg/drafts/options.go`, `struct.go` |
| Scaffold Android (Gradle/Kotlin/Compose/gomobile) | ✅ scaffold / 🟢 build | fontes em `reverse/main`; **o Gradle só passa no gate de `reverse/v0.3.0-*`** (plugin Compose do Kotlin 2.0) |
| CI (build/vet/test/race + android) e release por tag | ✅ | `.github/workflows/ci.yml`, `release.yml` |
| `cmd/drafto` MVP | ✅ | 12 subcomandos em `reverse/main` — cobre 8 dos 19 métodos do `Store` |

### Phase 1 — Core nativo + storage → 🟡 **concluída no core, incompleta na superfície**

| Item | Status | Nota |
|---|---|---|
| `core/sqlitestore` (pure Go, sem CGO) | ✅ | 847 linhas + 613 de teste; integração coberta |
| CRUD create/get/query/update/replace/append/prepend | ✅ **no core** | `Store` expõe os 7; ver CLI |
| Organização inbox/archive/trash/flag/tags/sort/search | ✅ | `accessed`/`name` sort, trash expiry 30d, `purge` |
| Workspaces | 🟡 | leitura OK; **escrita fora da interface** (F1) → `SPEC-CORE-02` |
| Persistência de actions + `action_logs` + `versions` | ⚪ | tabelas nunca criadas (D4) → `SPEC-CORE-03` |
| `cmd/drafto`: JSON + **plain** + schema + **info** | 🟡 | `plain`/`info` **não existem**; `schema` é hardcoded (D1/D2) → `SPEC-CLI-01` |
| Testes de integração SQLite | ✅ | `core/sqlitestore_test.go` |
| Conformidade Memory ↔ SQLite (mesma suíte) | ⚪ | dois conjuntos separados hoje → `SPEC-CORE-01` |

### Phase 2 — App Android → 🟢 **em voo, fora do `reverse/main`** 🔒

| Item | Status | Onde |
|---|---|---|
| **G1** boundary com persistência (`NewAt`/`Close` + SQLite) | 🟢 | `reverse/v0.3.0-getdrafts-cli` (PR #13) |
| `gomobile bind` + AAR como **gate real** de CI | 🟢 | idem; causa raiz: `x/mobile` fora do grafo de módulo |
| APK compila (plugin Compose do Kotlin 2.0) + artefatos | 🟢 | idem |
| **G2** app usando o core Go de verdade (reflexão, `go.Seq.setContext`, fallback logado) | 🟢 | só `arena/26d3ae79-*` — **sem PR aberto** ⚠️ |
| Gate "APK embute `libgojni.so` + `go/drafto/Core` no dex" | 🟢 | idem |
| **G3** actions na UI (`RunAction`/`ListActions` no boundary + ActionSheet) | ⚪ | → `SPEC-AND-02` |
| Lista com pastas/sort/tags/purge (hoje hardcoded `"inbox"`) | ⚪ | → `SPEC-AND-03` |
| `ACTION_SEND` + deep links tratados (manifest declara, código ignora) | ⚪ | → `SPEC-AND-04` |
| Instalação validada em device/emulador + screenshots | ⚪ | → `SPEC-AND-05` (precisa de ambiente fora do sandbox) |
| DTO do boundary à prova de gomobile (sem `map`, sem struct exposto) | ⚪ | → `SPEC-AND-01` (D8) |

### Phase 3 — Actions & interoperabilidade → ⚪ (nada começou)

| Item | Status | Spec |
|---|---|---|
| Action groups + `after-success` rigorosos + `action_logs` | ⚪ | `SPEC-CORE-03`, `SPEC-CORE-04` |
| Export/import JSON ↔ Markdown + backup local | ⚪ | `SPEC-PROD-01` |
| `drafto://` completo + x-callback-url | ⚪ | `SPEC-PROD-03` |
| Template tags completos (`\|\|clipboard\|\|`, condicionais) | ⚪ | `SPEC-CORE-04` |
| Modelo confirmado por evidência (versions/tasks/links/syntax) | ⚪ | `SPEC-PROD-02` (depende de `rev-ios`) |

### Phase 4 — Sync & plataforma → ⚪ (deliberadamente)

Backup local → change-log de sync (`SPEC-PROD-04`) → widgets → Wear OS. **Não abrir antes de
`SPEC-PROD-02`** (sync sem versões tombstonadas corrompe dados).

### Trilha `rev-ios` (engenharia reversa do app iOS) → 🟡

Spec escrita (`SPEC-REVIOS-001`) com ledger de 58 obrigações, fases C0–C6, mapa de superfícies S1–S6,
paridade de layout — **em `arena/d07fc20f-*`, nunca integrada**. → `SPEC-REVIOS-001` §"próximo passo".

---

## 3. Marcos (gates) e o que eles destravam

| Marco | Conteúdo | Gate de saída | Destrava |
|---|---|---|---|
| **M0 — v0.2.0** | paridade P0 no core | 🟰 alcançado (tag `v0.2.0`, release "Latest") | — |
| **M1 — v0.3.0** | G1 + G2 + gates de CI Android | PR `arena/26d3ae79` → `reverse/v0.3.0` → `reverse/main`; CI Go **e** Android verdes; tag `v0.3.0` | `SPEC-AND-01..05`, `SPEC-CLI-01` (boundary estável) |
| **M2 — Phase 2 fechado** | G3 + UI completa + aceite em device | critério `05-ROADMAP.md` §Phase 2: APK instala; captura → inbox; tag/flag/archive/trash; **actions executam** | `SPEC-PROD-01` |
| **M3 — v0.4.0** | CLI paridade + export/import + actions persistentes | conformance kit verde nos 2 backends; round-trip export/import; release com binários linux+darwin | `SPEC-PROD-02/03` |
| **M4 — v0.5.0** | paridade de layout (rev-ios) + x-callback | overlay dos screenshots × tokens medidos dentro da tolerância | Phase 4 |
| **M5 — v1.0.0** | sync + rename de module path + repo transferido | `04-GOVERNANCE.md` §8 + §9 | — |

---

## 4. Catálogo de specs

> Cada spec é uma sessão. Formato e regras de escrita: [`specs/README.md`](specs/README.md).
> `Lane` = workspace de execução (§5). `∥` = paralelizável com as demais daquela linha.

### 4.1 Lane Q — Governança / operação (∥ total · zero risco de conflito · roda sem Go)

#### `SPEC-OPS-01` — Fechar o ciclo v0.3.0 (G1+G2+gates) — **S · 🔒 · URGENTE**
- **Por quê:** o trabalho Android mais avançado existe **só** em `arena/26d3ae79-*`, sem PR aberto.
  Risco de perda e de re-trabalho a cada sessão que re-abre o boundary.
- **DoR (critério de início):**
  1. `git fetch origin "+refs/heads/*:refs/remotes/origin/*"` (o refspec padrão do clone é estreito).
  2. CI do head de `arena/26d3ae79-*` **verde nos dois jobs** (Go, Android+APK+dex gate). Se vermelho, **parar aqui** e corrigir antes de abrir PR.
  3. `reverse/v0.3.0-getdrafts-cli` contém PR #13 (confirmado: `7eb9365`).
  4. Ninguém mais tem PR em voo contra `reverse/v0.3.0-*`.
- **Escopo:** PR `arena/26d3ae79-*` → `reverse/v0.3.0-getdrafts-cli`; depois PR `reverse/v0.3.0-*` → `reverse/main`; tag `v0.3.0` (dispara `release.yml`); anexar APK/AAR; atualizar `06-HANDOFF.md` §1/§6.
- **DoD:** `reverse/main` com `android/core-go/drafto.go` usando `NewAt`; tag `v0.3.0` com release; `05-ROADMAP.md` Phase 2 com G1/G2 ✅+evidência.
- **Não:** mexer em `core/` ou UI (é integração, não desenvolvimento).

#### `SPEC-OPS-02` — Higiene de docs, licença e ADRs — **S · ∥**
- **Por quê:** D1–D7 e D11 da auditoria + `LICENSE` ausente + `docs/drafto/adr/` inexistente.
- **DoR:** nenhuma dependência técnica; aprovação do dono para **criar `LICENSE` MIT** (isso é decisão jurídica do contratante, não do dev).
- **Escopo:**
  - `LICENSE` (MIT, detentor = contratante) — *abrirIssue/decisão se não aprovado*;
  - `docs/drafto/adr/ADR-001..007.md` materializados (007 = "conformidade de backends + DTO flat no boundary");
  - corrigir `05-ROADMAP.md:20-22` (trocar ✅ por 🟡 com nota de evidência);
  - `FEATURE_GAP_ANALYSIS.md` → `docs/history/` com aviso de escopo/validade (ele descreve a CLI de jan/2026);
  - `02-FEATURE-PARITY.md` §5: share sheet ✅ → 🟠 e deep links: "manifest declara, `MainActivity` não trata".
- **DoD:** nenhum item ✅ nas docs sem linha de código/teste citável; ADRs existindo como arquivos.
- **Conflito:** nenhum (só `.md`). **Rodar em paralelo com tudo.**

#### `SPEC-OPS-03` — "Como verificar sem toolchain" (CI como fonte de verdade) — **S · ∥**
- **DoR:** `curl https://proxy.golang.org/` → bloqueado no sandbox (confirmado 2026-11-12); aceitar que **build local não existe aqui**.
- **Escopo:** `Makefile` (ou `justfile`) com `build/test/vet/race/gomobile/apk` + um `.github/workflows/dryrun.yml` que publica **anotações** com o erro (lição do ciclo v0.3.0: log do Actions é cortado por egress); documentar o truque do refspec; script `scripts/ci-diag.sh` lendo `api.github.com` (permitido).
- **DoD:** um dev novo consegue, em 1 comando, saber "o que quebrou no CI" sem abrir a UI do Actions.

### 4.2 Lane C — `core/` (Go) — **serial dentro da lane** (mesmos arquivos)

#### `SPEC-CORE-01` — Suíte de conformidade de backends (`core/storetest`) — **M · ∥ com tudo que não toca `core/*.go` de produção**
- **Objetivo:** um único conjunto de testes rodando contra **`MemoryStore` e `SQLiteStore`** (create/get/update/query/search/tags/sort/trash-retention/workspaces/invariantes), falhando se os dois divergirem.
- **DoR:** CI verde no head de `reverse/main`; proibido mudar comportamento de produção (só `*_test.go` + pacote novo `core/storetest`).
- **Aceite:** `go test ./core/...` roda a mesma suíte 2×; divergências conhecidas **explicitadas** como `t.Skip("DIVERGE: …")` com referência à spec que resolve.
- **Por que vem antes das outras de core:** é a rede de segurança de CORE-02/03/04 e de CLI-01.

#### `SPEC-CORE-02` — Workspaces: contrato simétrico — **M · serial com CORE-01/03**
- **Objetivo:** capability `WorkspaceStore` na frente do `Store`: `SaveWorkspace(ctx, ws) error`, `DeleteWorkspace(ctx, name) error`, `ActiveWorkspace` coerente nos dois backends; `MemoryStore.SaveWorkspace` ganha `ctx`+`error` (quebra controlada em pacote interno ao app, mas é **breaking para o bridge gomobile** → ADR-008 + version bump `0.4.0`).
- **DoR:** CORE-01 mesclada (é o que prova paridade); `02-FEATURE-PARITY.md` atualizada com a semântica (workspace = filtro salvo + folder default + action group).
- **Aceite:** `drafto workspace list/use/save/forget` round-trip no SQLite **e** no memory; teste no kit; `go test -race ./core/...` verde.

#### `SPEC-CORE-03` — Actions & logs persistentes — **L · serial com CORE-02**
- **Objetivo:** migração cria `actions(uuid,name,group_name,config,position)`, `action_logs(id,action_uuid,ok,at,note)`, `versions(uuid,seq,content,created_at)`; capability `ActionStore` (persistir/listar/reordenar/excluir, seed idempotente de built-ins); `Run` grava log.
- **DoR:** CORE-01; decisão registrada (ADR-009) sobre **config como JSON TEXT** (nada de `map` vazar para o boundary); migração idempotente testada com DB antigo.
- **Aceite:** ações sobrevivem a restart do `drafto` (`actions list` não-vazio); log de execução consultável; sem regressão no kit.

#### `SPEC-CORE-04` — Rigor de steps + `RunOnText` transiente + sort O(n log n) — **M**
- **Objetivo:** (a) `unknown step type` → `ErrInvalidInput` com o nome do step (F3); (b) `prompt` implementado como callback de host **ou removido** (F10/D10); (c) `RunOnText` com draft **descartado** ao final ou `Transient:true` (F4/D9); (d) `applyAfterSuccess` propaga erro (F5); (e) `sortStable` → `sort.SliceStable` (F8); (f) `[[clipboard]]`/tags condicionais mínimas para paridade de template.
- **DoR:** CORE-01 e CORE-03 mescladas; contrato de saída da CLI (CLI-01) **congelado** para não quebrar envelope.
- **Aceite:** teste para cada item (a)–(f); `02-FEATURE-PARITY.md` §3 atualizado.

#### `SPEC-CORE-05` — Busca ranqueada com FTS5 (opcional, P2) — **M**
- **DoR:** CORE-01; decisão ADR sobre `porter`/`unicode61` e sobre manter `matchesSearch` como fallback de semântica idêntica.
- **Bloqueia:** nada. **Bloqueado por:** nada. Pode ser adiado; só não rodar junto com CORE-03 (mesmo `migrate()`).

### 4.3 Lane L — CLI Linux `drafto` (∥ com core, **se** o contrato for acordado antes)

#### `SPEC-CLI-01` — Paridade de superfície com `core.Store` — **M**
- **Objetivo:** `replace`, `append`, `prepend`, `edit`, `tags set`, `delete`, `empty-trash`, `workspace list/use/save/forget`, `actions list/run/run-text/register`, `--plain`, `info`, `schema` **gerado de structs** (espelhar `cmd/drafts/contracts.go` + `schema.go`, que já existem e são a referência do repo).
- **DoR:** lista de métodos do `Store` estável (i.e. CORE-02 **mesclado** para os comandos de workspace; o resto pode começar já); decisão de envelope de saída = mesmo `{success,data,error{code,message,suggestion}}` do `drafts`.
- **Aceite:** `drafto schema` cobre 100% dos subcomandos; `drafto --plain list` legível; cada comando com teste de golden JSON; `drafto info` reporta backend (`SQLite (<path>)` vs `--memory`), versão e contagens.
- **Fora:** qualquer mudança em `core/` (se precisar, vira CORE-0x e a CLI espera).

#### `SPEC-CLI-02` — DX de agente no `drafto` — **M**
- **Objetivo:** fechar em um dos clientes o `agent-dx-audit` de 2026-03-09 (score 11/21): `--dry-run` em toda mutação, validação de UUID/nome antes do storage, campo-mask (`--fields`), paginação (`--offset`/`--limit`) e `--stream` NDJSON; opcionalmente `drafto serve` (JSON-RPC local).
- **DoR:** CLI-01 mesclada (mesmo arquivo `main.go`); rubrica de score anexada à spec para medir antes/depois.
- **Aceite:** score ≥ 17/21 recomputado no mesmo formato do `docs/plans/2026-03-09-agent-dx-audit.md`.

### 4.4 Lane A — Android (Kotlin/Compose + boundary gomobile) — serial em A-01→A-02/03/05; A-04 é ∥

#### `SPEC-AND-01` — Boundary gomobile v2 (DTO flat) — **M · 🔒 bloqueia UI nova**
- **Objetivo:** reescrever `android/core-go` para **string JSON in / string JSON out** (`CreateDraftJSON(input string) (string, error)` etc.), porque gomobile **rejeita `map[string]interface{}`** e structs com campos de tipo não suportado (D8: `ActionStep.Config`, `ActionRunResult`, `core.Draft` retornado por valor); expor `Actions`, `RunAction`, `RegisterAction`, `PurgeTrash`, `QueryDrafts` com sort/desc/flaggedTop/omitTags, `Workspaces`, `Close`; manter `New()` (memory) só para preview.
- **DoR:** **OPS-01 mesclado** (não reescrever por cima do G1/G2 em voo); `x/mobile` no grafo de módulo (já em v0.3.0); decisão ADR-008; `//export` só onde for iOS — para Android `gomobile bind` ignora (higiene: remover comentários que sugerem o contrário).
- **Aceite:** `gomobile bind -target=android` **passa no CI**; gate de dex continua verde; `drafto_test.go` do boundary cobre cada método via JSON; Kotlin `GoDraftoEngine` compila contra a nova API por reflexão com `isAvailable()` false → fallback `FakeEngine` **logado**.

#### `SPEC-AND-02` — G3: ActionSheet na UI — **M**
- **DoR:** AND-01 + CORE-03 (actions persistentes) mesclados; wireframes do Drafts para a action bar (saída D4 do `rev-ios`; sem evidência, Material razóável + nota).
- **Aceite:** rodar action da lista de grupos; verificação de efeito no store (flag/archive/tags mudaram); log de execução visível; teste de UI (Robolectric) + captura manual em device.

#### `SPEC-AND-03` — Lista: pastas, sort, filtros e purge — **M**
- **DoR:** AND-01 (o `queryDrafts` atual já aceita `filter/search/tags/limit`, mas sem sort).
- **Escopo:** `DraftListViewModel` com **estado de filtro** (hoje hardcoded `"inbox"`, `DraftListViewModel.kt:29`), chips de tag, ordem (created/modified/accessed/name + desc), flagged-top, contador por pasta real, item de menu "purge trash".
- **Aceite:** os 6 itens do `05-ROADMAP.md` §Phase 2 (linha "DraftListScreen") fechados; preview com `FakeEngine` **e** teste unitário do VM.

#### `SPEC-AND-04` — Intents: share sheet + `drafto://` — **S · ∥ com AND-01**
- **DoR:** nenhuma dependência de core (usa `DraftoEngine` atual); ler `01-GETDRAFTS-INVESTIGATION.md` §4.4 (19 ações de URL scheme) para o subconjunto `create/open/search`.
- **Escopo:** `MainActivity.onNewIntent`/`onCreate` trata `ACTION_SEND` (text/plain → cria draft no inbox + abre editor) e `drafto://create|open?uuid=|search?q=`; `launchMode=singleTask`; `intent-filter` já existe — **falta só o handler**.
- **Aceite:** `adb shell am start -a android.intent.action.SEND -t text/plain --es android.intent.EXTRA_TEXT "x"` cria rascunho; deep link abre o draft; testes Robolectric para os dois caminhos; `02-FEATURE-PARITY.md` §5 atualizado com evidência (sai do ✅ falso).

#### `SPEC-AND-05` — Aceite em device + kit de screenshots — **S · ⚪ precisa ambiente fora do sandbox**
- **DoR:** AND-02/03/04 mesclados + `APK` publicado no artefato da release.
- **Escopo:** instalar em device/emulador Android 14; roteiro de 10 passos (capture → persiste após kill -9 → tag → flag → archive → trash → purge → action → share → deep link); screenshots nomeados em `docs/rev-ios/layout/shots/` (consumidos pelo `04-LAYOUT-PARITY.md`).
- **Aceite:** checklist assinado no PR; divergências viram specs novas.

### 4.5 Lane P — Produto/interoperabilidade (Phase 3–4)

| Spec | Objetivo | DoR essencial | ∥? |
|---|---|---|---|
| `SPEC-PROD-01` | Export/import JSON+Markdown, backup local, `drafto export/import` | CORE-02/03, CLI-01 | ∥ com AND-* |
| `SPEC-PROD-02` | Modelo de dados **confirmado por evidência** (`syntax`, `versions`, `tasks`, `linkedItems`, `urls`, `actionLogs`, geo, permalink) + tabela `versions` + rollback | **`SPEC-REVIOS-001` fases C2–C3 concluídas** (findings D3) | ✗ (consome saída do rev-ios) |
| `SPEC-PROD-03` | `drafto://` completo + x-callback-url como contrato **do core** (não do app desktop) | AND-04 (mesmo vocabulário de parâmetros) + ADR-010 | ✗ depois de AND-04 |
| `SPEC-PROD-04` | Sync multi-device por change-log (tombstones + `modified_at` + relógio monotônico) | PROD-02 (versions) e CORE-03 | ✗ **último** |

### 4.6 Trilha R — `rev-ios` (isolada por construção)

#### `SPEC-REVIOS-001` — Captura & extração do Get Drafts iOS — **L · ∥ total (namespace próprio)**
- **Onde vive:** `docs/rev-ios/` (escrita em `arena/d07fc20f-*`, **nunca mesclada**).
- **Próximo passo real:** (1) reabrir como `rev-ios/getdrafts-capture` sobre a base nova e abrir PR **docs-only** → `reverse/main`; (2) executar Fase **C0** (harness/toolchain, `rea doctor` hoje `healthy:false` por falta de Hopper/Ghidra/IDA) e C1 (superfícies via AppleScript/`surface/*.json`); (3) registrar cada conclusão como cartão `findings/NNNN` com nível E1–E4.
- **DoR para *consumir* a trilha:** o ledger (58 obrigações) precisa de dono e status por item.
- **DoD da trilha:** `CODEMAP.md` §11 "Evidência iOS" + matriz `02` atualizada + `PROD-02` destravado.
- **Regra dura:** **nenhum** código/asset/string proprietária entra no Drafto; só docs, findings e tokens de layout medidos.

---

## 5. Paralelismo: o que pode (e o que não pode) rodar junto

### 5.1 Mapa de lanes → arquivos

| Lane | Workspace (paths) | Specs | Conflito com |
|---|---|---|---|
| **Q** ops/docs | `docs/**`, `LICENSE`, `Makefile`, `.github/**` | OPS-01/02/03 | nada (`.github/workflows/ci.yml` **só** no OPS-01) |
| **C** core | `core/*.go` | CORE-01..05 | L (contrato), A (boundary) |
| **L** CLI | `cmd/drafto/**` | CLI-01/02 | C (quando C muda a interface) |
| **A** android | `android/**` | AND-01..05 | C (CORE-03/04 mudam o DTO) |
| **P** produto | `core/**` + `cmd/**` + `android/**` | PROD-01..04 | todas — **serial** |
| **R** rev-ios | `docs/rev-ios/**`, `skills/ios-app-security-audit/**` | REVIOS-001 | nada (isolamento deliberado) |

### 5.2 Agenda recomendada (1 sessão = 1 spec)

```
Semana 1 ── 🔒 OPS-01 (fechar v0.3.0, tag)  ◄─ ÚNICA coisa que pode tocar reverse/main
         ∥  OPS-02 (docs/LICENSE/ADRs)          ← safe: roda hoje, neste sandbox
         ∥  OPS-03 (make + ci-diag)              ← safe
         ∥  REVIOS-001 C0/C1 (trilha isolada)    ← safe

Semana 2 ── CORE-01 (storetest conformance)
         ∥  AND-01 (boundary v2)  — só depois do merge do OPS-01
         ∥  AND-04 (intents)      — não depende de core

Semana 3 ── CORE-02 (workspaces) → CLI-01 (paridade)      [serial: contrato → consumo]
         ∥  AND-03 (lista/sort/filtros)
         ∥  PROD-01 (export/import)

Semana 4 ── CORE-03 (actions persistentes) → AND-02 (ActionSheet)   [serial]
         ∥  CORE-04 (rigor de steps)  — exige CORE-03 mesclado (mesmo action.go: NÃO paralelizar)
         ∥  REVIOS-001 C2/C3 (findings)

Semana 5 ── PROD-02 (modelo confirmado) → PROD-03 → AND-05 (device) → CLI-02 (DX)
Semana 6+ ─ CORE-05 (FTS5), PROD-04 (sync), widgets
```

### 5.3 Matriz de "pode em paralelo?"

| ∥? | Q | C | L | A | P | R |
|---|---|---|---|---|---|---|
| **Q** | ✅ | ✅ | ✅ | ✅ | ⚠️ docs do PR | ✅ |
| **C** | ✅ | ❌ serial | ⚠️ congelar contrato | ⚠️ congelar DTO | ❌ | ✅ |
| **L** | ✅ | ⚠️ | ✅ (CLI-01 ⊕ CLI-02 serial) | ✅ | ❌ | ✅ |
| **A** | ✅ | ⚠️ | ✅ | ✅ AND-04 ∥; AND-02 ⊕ AND-03 serial | ⚠️ | ✅ |
| **P** | ⚠️ | ❌ | ❌ | ⚠️ | ❌ | ⚠️ PROD-02 espera R |
| **R** | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ (múltiplos *runs* de captura) |

**Regras de paralelismo (não-negociáveis):**
1. **Uma sessão por lane por vez** quando a lane toca o mesmo arquivo (`core/store.go`, `cmd/drafto/main.go`, `android/core-go/drafto.go`).
2. **Contrato primeiro, consumo depois:** mudança em `core/*.go` que altera `Store`/DTO → PR da lane C entra **antes**; as lanes L/A fazem rebase e só então seguem.
3. **`reverse/main` tem fila:** durante `SPEC-OPS-01` (merge+tag) ninguém integra.
4. Docs e specs (`docs/**`) são **sempre** paralelizáveis — é a lane de sobra para sessão sem Go.
5. **`rev-ios` nunca toca** `core/`, `cmd/`, `android/` (regra herdada da spec: "Nenhuma linha de core/ ou android/ muda aqui").
6. Um branch `arena/<id>` = **uma** spec. Misturar OPS-02 com CORE-02 num PR = review impossível e revert arriscado.

---

## 6. Instruções de início por workspace

> Copiar e colar no começo de cada sessão. Todos os caminhos são relativos à raiz do repo
> (`/home/user/getdrafts-cli`). Não existe build local de Go aqui: **o CI é o juiz**.

### 0. Bootstrap (todo workspace, toda sessão)

```bash
cd /home/user/getdrafts-cli
# 1. O refspec do clone é estreito (só reverse/main + branch da sessão). Ampliar para ver as outras trilhas:
git fetch origin "+refs/heads/*:refs/remotes/origin/*" --tags
# 2. Onde estou e o que mudou fora da minha base:
git log --oneline -5
git log --oneline HEAD..origin/reverse/main            # o que eu preciso puxar
git log --oneline HEAD..origin/reverse/v0.3.0-getdrafts-cli   # o que está em voo
# 3. Estado do CI da base (sem abrir a UI — logs são cortados por egress):
gh api repos/camillanapoles/getdrafts-cli/actions/runs?per_page=8 \
  --jq '.workflow_runs[]|[.name,.head_branch,.status,.conclusion]|@tsv'
# 4. Ler (nesta ordem): docs/drafto/08-AUDIT-2026-11-12.md → este arquivo (spec da sessão) → 04-GOVERNANCE.md §1.1
```

Guardrail de branch (ADR-005, perpétuo): `arena/<id>-getdrafts-cli` → PR → `reverse/<id>-getdrafts-cli`
→ PR → `reverse/main` → tag `vX.Y.Z`. **Nunca** push direto em `reverse/main` nem em `main`; nunca
mudar o nome do branch da sessão.

### Workspace Q — ops / docs / release

| | |
|---|---|
| **Caminhos** | `docs/drafto/**`, `docs/rev-ios/**`, `LICENSE`, `.github/**`, `Makefile` |
| **Ler antes** | `04-GOVERNANCE.md` §1.1–1.2 (fluxo + tags), §5 (CI), `06-HANDOFF.md` |
| **Comandos** | `git diff --stat origin/reverse/main...HEAD` · `gh pr create --base reverse/<id>-getdrafts-cli` · `gh pr merge <n> --squash` |
| **Para taggear (só OPS-01)** | `git tag -a v0.3.0 -m "…" && git push origin v0.3.0` — **só depois do merge em `reverse/main`** |
| **Verificação** | CI "Go build, vet, test" verde; sem toolchain local, docs são avaliadas por leitura crítica + link para evidência (`arquivo:linha`) |
| **Não** | não reformular doc alheio; não apagar `01`/`02`; cada ✅ precisa de evidência |

### Workspace C — core Go

| | |
|---|---|
| **Caminhos** | `core/*.go` (model, store, memory, sqlitestore, action, template, clock, options) |
| **Ler antes** | `03-ARCHITECTURE.md` §3–4, `CODEMAP.md` §3.1 e §8, auditoria §5 (F1–F5, F8–F10) |
| **Comandos** | `go build ./... && go vet ./... && go test ./core/... && go test -race ./core/...` (validado **no CI**) · `git ls-files core` |
| **Contrato** | mudar `Store` = breaking p/ `cmd/drafto`, `pkg/drafts` e para o boundary → ADR + `MINOR`/`MAJOR` + update de `02`/`05`/`06` no **mesmo PR** |
| **Técnica** | capabilities **opcionais** por type-assert (`TrashPruner`, `ClipboardReader`, futuro `WorkspaceStore`/`ActionStore`) em vez de métodos novos na `Store` — foi assim que ADR-006 evitou quebrar o bridge |
| **Armadilha** | `modernc.org/sqlite`: manter `go.sum` coerente (CI comita `go mod tidy` em push de branch; a falha aparece em "Commit go.sum if changed") |
| **Não** | não introduzir dependência com CGO; não tocar `cmd/`/`android/` a partir desta lane |

### Workspace L — CLI Linux `drafto`

| | |
|---|---|
| **Caminhos** | `cmd/drafto/main.go` (317 linhas; `Args` em `:151-168`, `schema()` em `:281`, `emit()` em `:300`) |
| **Referência a copiar** | `cmd/drafts/contracts.go` + `schema.go` + `output.go` + `helpers.go` — o `drafts` **já** resolveu schema tipado, `--plain`, envelope e códigos de erro |
| **Comandos** | `go run ./cmd/drafto --memory create "x" -t a` · `… list --sort modified --desc` · `… schema` · `… purge --days 30` · `GOOS=linux go build -o drafto ./cmd/drafto` |
| **Contrato** | envelope `{success,data,error{code,message,suggestion}}` **imutável**; erros mapeados de `core.Err*`; JSON é o default, `--plain` é opt-in |
| **Testes** | testes de golden JSON por comando (mesmo padrão de `docs/plans/2026-01-19-llm-first-cli-design.md`) |
| **Não** | não chamar SQLite direto — sempre via `core.Store`; não fazer mudança de `core/` aqui (abra CORE-0x) |

### Workspace A — Android

| | |
|---|---|
| **Caminhos** | `android/core-go/*.go` (boundary) · `android/app/src/main/java/com/drafto/app/**` · `android/**/build.gradle.kts` · `AndroidManifest.xml` |
| **Ler antes** | `android/README.md`, auditoria D8, `06-HANDOFF.md` §2.1 (G1/G2/G3 + as 3 causas raiz de build) |
| **Comandos (CI only)** | `go build ./android/core-go/` · `gomobile bind -target=android -o android/app/libs/drafto.aar ./android/core-go` · `cd android && gradle assembleDebug --no-build-cache --rerun-tasks` |
| **Regras de build que doeram** | (1) `x/mobile` precisa estar **no grafo de módulo** senão `gomobile bind` recusa; (2) Kotlin 2.0 exige o **plugin** `org.jetbrains.kotlin.plugin.compose` (não `composeOptions.kotlinCompilerExtensionVersion`); (3) **sem `continue-on-error`** no job Android; (4) cache do Gradle esconde erro de `:app` → rodar com `--no-build-cache --rerun-tasks` |
| **Regras de código** | gomobile: **sem `map`**, sem struct exposto que ele não suporte → DTO JSON (AND-01); `go.Seq.setContext(ctx)` antes de qualquer chamada; engine real via reflexão com `isAvailable()` e `Log.w` no fallback |
| **Aceite visual** | gate de dex (`libgojni.so` + `go/drafto/Core`) — sem isso "Gradle passou" não prova integração |

### Workspace P — produto / interop

| | |
|---|---|
| **Caminhos** | `core/` + `cmd/drafto/` + `android/` (é a única lane multi-workspace: por isso **serial**) |
| **Ler antes** | `01-GETDRAFTS-INVESTIGATION.md` §4–5, `02-FEATURE-PARITY.md` (P1/P2), `05-ROADMAP.md` Phase 3 |
| **Regra** | export/import e URL scheme têm que ser **round-trip e idempotentes**; especificar primeiro em `docs/drafto/specs/SPEC-PROD-0x.md`, implementar depois |

### Workspace R — rev-ios (análise)

| | |
|---|---|
| **Caminhos** | `docs/rev-ios/**`, `skills/ios-app-security-audit/**`, `skills/getdrafts-ios-rev/**`, artefatos em `~/.rev-ios/artifacts/<run>/` (**fora do repo**) |
| **Branch/worktree** | `rev-ios/<slug>` + worktree separado (`../getdrafts-cli-rev-ios`); tags planas `rev-ios-<slug>-<data>` (evita colisão dir-vs-file em `refs/tags`) |
| **Comandos** | `rea doctor` (esperado `missing_analysis_engine`), `ios-triage.sh`, capturas → `provenance.json` + `SHA256SUMS` |
| **Saída** | cartões `findings/NNNN-*.md` (nível E1–E4) + `LEDGER.md` atualizado; PR para `reverse/main` traz **só docs** |
| **Não** | nenhum código de produto; nenhum asset/JS proprietário; nenhum dado real de usuário; nenhuma nuvem (iCloud/CloudKit) |

---

## 7. Backlog priorizado (o que fazer nas próximas 7 sessões)

| # | Spec | Por que nesta ordem | Efeito colateral |
|---|---|---|---|
| 1 | `SPEC-OPS-01` | fecha o voo: G1/G2 integrados + tag `v0.3.0`; sem isso, todo PR de boundary conflita | trava `reverse/main` por ~1 sessão |
| 2 | `SPEC-OPS-02` | mata o false-green do roadmap e a ausência de `LICENSE`/ADRs; **roda em qualquer ambiente** | nenhum (docs) |
| 3 | `SPEC-CORE-01` | rede de segurança antes de mexer no `Store` | testes novos em `core/` |
| 4 | `SPEC-AND-01` | DTO estável = UI deixa de ser reescrita 3× | exige AND-02/03 depois |
| 5 | `SPEC-CORE-02` + `SPEC-CLI-01` | workspaces simétricos e CLI paridade (fecha D1/D2/D3) | contract bump → `0.4.0` |
| 6 | `SPEC-AND-04` | share sheet + deep links: 1 arquivo Kotlin, alto impacto de paridade, ∥ com tudo | nenhum |
| 7 | `SPEC-REVIOS-001` (C0–C3) | única fonte capaz de confirmar/invalidar o modelo — e é a trilha que destrava `PROD-02` | consome ambiente macOS/iOS |

## 8. Métricas do roadmap (o que "progredir" significa)

| Métrica | Hoje | Alvo M1 | Alvo M3 |
|---|---|---|---|
| Itens de fase com evidência ✅ | Phase 0+1 (com 3 correções) | +5 (G1,G2,3 gates) | +12 |
| Cobertura dos métodos de `core.Store` pela CLI `drafto` | **8/19** (`Create/Get/Query/Archive/Trash/SetFlagged/ListTags/Counts` + `PurgeTrash`) | 8/19 | **19/19** |
| Backends sob a mesma suíte de conformidade | 0/2 | 0/2 | **2/2** |
| Score agent-DX (`drafto`) | n/a (audit era do `drafts`: 11/21) | n/a | **≥17/21** |
| Features ✅ na matriz sem código correspondente | 5 (D1,D2,D3,D5,D9) | 0 | 0 |
| Releases | v0.2.0 | **v0.3.0** | v0.4.0 |
