# Codemap — Get Drafts CLI → Drafto

> Mapeamento estrutural do repo `getdrafts-cli`, feito com **GitNexus** (análise de grafo de conhecimento: *tree-sitter* + resolução cruzada de imports/chamadas/herança + *clustering* Leiden) e **rea** (*Reverse Engineer Anything*, para a parte binária/iOS original). Este documento é o mapa de funções, classes, relacionamentos e lógica do repo original, servindo como *single source of truth* para a construção do Drafto.
>
> Índice GitNexus: **1,507 nós | 3,449 edges | 35 *clusters* | 130+ *flows* | 81 arquivos** (commit `5b3e813`).
> *Skills* gerados em `.claude/skills/gitnexus-area-*/` (10 áreas funcionais).

## 1. Metodologia e ferramentas

### 1.1 "skill-scount" — seleção de *skills* assertivas
Não existe um tool chamado *skill-scount*. Adotamos a **disciplina de curadoria de skills**: poucos skills bem escopados, com *progressive disclosure*. Os skills gerados pelo GitNexus (`analyze --skills`) cobrem 10 áreas funcionais do repo:

| Área (*cluster*) | Símbolos | Arquivos | Coesão | Relevância para Drafto |
|---|---|---|---|---|
| **Drafts** | 117 | 13 | 80% | Bridge AppleScript macOS original — lógica de *actions*/*workspaces* a ser replicada no core Go |
| **Core-go** | 37 | 9 | 75% | *Boundary* gomobile (Core) + `core/` — **este é o motor do Drafto** |
| **Ui** | 33 | 7 | ~78% | Compose Android (DraftListScreen, EditorScreen) — *UI* do Drafto |
| **Drafto** | 32 | 7 | ~65% | CLI Linux `drafto` — cliente Linux do Drafto |
| **Components** | 11 | 5 | — | Componentes Compose (botões, etc.) |
| Cluster_17–21 | 4–7 | 1–4 | ~70% | Trechos pontuais (helpers, *schemas*, *contracts*) |

Os skills meta (`gitnexus-guide`, `gitnexus-cli`, `gitnexus-exploring`, `gitnexus-debugging`, `gitnexus-impact-analysis`, `gitnexus-refactoring`) documentam os comandos do GitNexus para uso contínuo.

### 1.2 GitNexus (codemap local)
Grafo de conhecimento local, *privacy-local*. Capacidades usadas nesta sessão:
- `analyze` / `analyze --skills` — índice + skills por área
- `context <symbol>` — chamadores/chamados de um símbolo
- `trace <from> <to>` — fluxo entre símbolos (com *budget cap*)
- `cypher <query>` — consulta direta ao grafo (schema: `Community`, `Process`, `CodeRelation`, `Class/Struct/Interface/Method/Function`)
- `status` / `detect-changes` / `check`
- **Restrição**: FTS/BM25 desativado (LadybugDB FTS extension *SSL-blocked*). `query` por texto retorna vazio — não interpretar como "sem fluxo". Reparar com `analyze --repair-fts` quando houver rede.

### 1.3 rea (Reverse Engineer Anything)
`rea doctor` = **healthy: false** — Hopper/Ghidra/IDA ausentes (`missing_analysis_engine`). Esperado: essas ferramentas são para **binários**. O Drafto está sendo escrito em **fonte** (Go/Kotlin). O `rea` se aplica à parte que ainda não está no repo:
- **Get Drafts iOS original** — binário iOS: decompilação, análise de *plist*/mach-o, captura de *calls* nativos (`rea capture_native_ui_scenario`, `rea decompile`, `rea decode-android-resources` para APKs pareados, `rea build-reconstruction-obligation-ledger` para o *ledger* de obrigações de paridade).
- **Runtime**: `rea capture-browser/electron/native-ui` para observar o app em ação.
- `rea function <symbol>` — analisa uma função com evidência.
- O `rea` é o braço de **expertise/quality**: conclusões com evidência + limitações explícitas (*evidence-backed*).

## 2. Arquitetura do repo (mapeado)

O repo contém **três sistemas distintos** convivendo, mapeados como *clusters* separados:

```
┌─────────────────────────────────────────────────────────────┐
│  cmd/drafts/*  ──►  pkg/drafts/*  ──►  AppleScript  ──►  Drafts.app (macOS)  │  cluster "Drafts"
│  (CLI original)      (bridge)           (osascript)            (iOS/macOS)      │
├─────────────────────────────────────────────────────────────┤
│  core/*  (Go engine)  ◄──  android/core-go/*  (gomobile) ──►  android/ (Compose)  │  clusters "Core-go" + "Ui"
│  (model/store/memory/   (Core binding)              (DraftoApp/MainActivity)   │
│   action/template/                                             │
│   options/clock)                                                │
├─────────────────────────────────────────────────────────────┤
│  cmd/drafto/main.go  ──►  core.Store  ──►  (Linux CLI "drafto")  │  cluster "Drafto"
└─────────────────────────────────────────────────────────────┘
```

## 3. Mapa de símbolos-chave (relações de CALLS/ACCESSES/IMPLEMENTS)

### 3.1 Core Go (`core/`) — motor do Drafto
| Símbolo | Tipo | Local | Relacionamentos |
|---|---|---|---|
| `Store` (interface) | Interface | `core/store.go:19` | **IMPLEMENTED BY** `MemoryStore`; CONSUMED BY `ActionRunner`, `cmd/drafto`, gomobile `Core` |
| `MemoryStore` | Struct/Impl | `core/memory.go` | `NewMemoryStore` cria; métodos: `Get/Update/Replace/AddTags/Archive/Trash/Query/Counts`; chama `cloneDraft`, `titleOf`, `newUUID` |
| `Draft` | Struct | `core/model.go` | `titleOf(draft)` deriva título; consumido por todos |
| `ActionRunner` | Struct | `core/action.go` | `NewActionRunner(store)`; `Run(draft, action)`; `applyAfterSuccess`; `Register`; consome `Store` + `template.RenderTemplate` |
| `RenderTemplate` | Function | `core/template.go` | Renderiza tags `[[draft_content]]` etc.; chamado por `ActionRunner` no step `*template*` |
| `Action` / `ActionStep` / `ActionRunResult` | Structs | `core/action.go` | `ActionRunResult.Copied` (clipboard), `CreatedDraft` |
| `Options` | Struct | `core/options.go` | Configurações (tag separator, etc.) |
| `NewClock` / `NowFunc` | — | `core/clock.go` | *Fluxo*: `main → NowFunc` (terminal do *flow* cross-community) |

### 3.2 Gomobile boundary (`android/core-go/`)
| Símbolo | Tipo | Local | Relacionamentos |
|---|---|---|---|
| `Core` (struct) | Struct | `android/core-go/drafto.go` | `New()` cria; **métodos `//export`**: `CreateDraft/GetDraft/QueryDrafts/SetFlagged/ArchiveDraft/TrashDraft/ReplaceDraft/AddTags/RunAction/ListTags/Counts` + `RegisterAction` |
| `ParseAction` | Function | `android/core-go/action.go` | Mapeia JSON `{"group","steps":[{"type","config"}],"after_success"}` → `core.Action` |

### 3.3 Android Compose (`android/app/...`)
| Símbolo | Tipo | Local | Relacionamentos |
|---|---|---|---|
| `DraftoEngine` (interface) | Interface | `core/DraftoEngine.kt` | Implementado por `FakeEngine` + `GoDraftoEngine`; consumido por `DraftListViewModel`/`EditorScreen` |
| `DraftListViewModel` | Class | `ui/DraftListViewModel.kt` | Chama `DraftoEngine` (List/Counts/Folder); consome `Draft` |
| `DraftListScreen` | Composable | `ui/DraftListScreen.kt` | Consumido por `MainActivity` |
| `MainActivity` | Activity | `MainActivity.kt` | *Entry point* do Compose |
| `DraftoApp` | Application | `DraftoApp.kt` | Inicializa engine via `EngineFactory` |

### 3.4 Bridge AppleScript original (`pkg/drafts/` + `cmd/drafts/`)
| Símbolo | Tipo | Local | Relacionamentos |
|---|---|---|---|
| `Create/Get/Query/Trash/Append` | Functions | `pkg/drafts/drafts.go` | Consomem `runAppleScript`; **replicar lógica no `core.Store`** |
| `runAppleScript` | Function | `pkg/drafts/applescript.go` | Terminal do *flow* `RunAppend → RunAppleScript`; chama `osascript` |
| `ActionExists/DraftExists/RunActionOnDraft` | Functions | `pkg/drafts/applescript.go` | Bridge para Drafts.app |
| `runAction` | Function | `cmd/drafts/main.go` | CLI original de *actions* |
| `handleDraftsError/parseFilter/resolveCommandUUID` | Functions | `cmd/drafts/main.go` | *Helpers* do CLI |
| `checkDraftsPro/getAvailableActions/getAvailableTags` | Functions | `cmd/drafts/info.go` | Consultam Drafts.app via AppleScript |

## 4. Fluxos mapeados (process cross-community)

| Fluxo | *Entry point* | Terminal | Comunidades | Significado |
|---|---|---|---|---|
| `Main → NowFunc` | `cmd/drafto/main.go:main` | `core/clock.go:NowFunc` | Drafto→Core-go | CLI Linux resolve *clock* no core |
| `RunAppend → RunAppleScript` | `cmd/drafts/main.go:runAppend` | `pkg/drafts/applescript.go:runAppleScript` | Drafts→Drafts | **Original**: CLI macOS → AppleScript → Drafts.app |
| `Create → RunAction` | `pkg/drafts/drafts.go:Create` | `pkg/drafts/applescript.go:runAppleScript` | Drafts→Drafts | **Original**: criar rascunho + executar *action* |
| (via `trace` com dissambiguação) | `core/store.go:Store.Create#3` | `core/memory.go:MemoryStore` | Core-go→Core-go | **Drafto**: criar rascunho no `MemoryStore` |

> **Observação crítica**: `trace Create→runAppleScript` retorna 6 candidatos porque `Create` existe em múltiplos contextos (bridge AppleScript + interface `Store` + `MemoryStore`). Isso é a **dualidade do repo** — o mesmo conceito (criar rascunho) em duas implementações. O Drafto deve seguir o caminho `Store → MemoryStore`, não o AppleScript.

## 5. Relacionamentos de imports e herança

- **`IMPLEMENTS`** (3 edges): `MemoryStore` implements `Store`; `GoDraftoEngine`/`FakeEngine` implementam `DraftoEngine`; `Core` implementa interface do gomobile.
- **`IMPORTS`** (78 edges): `cmd/drafto` → `core/`; `android/core-go` → `core/`; `pkg/drafts` → (externo, osascript); `android/app` → `android/core-go` (via AAR).
- **`MEMBER_OF`** (264 edges): métodos dentro de structs/classes.
- **`CALLS`** (629 edges) / **`ACCESSES`** (614 edges): densidade alta entre `core/action.go ↔ core/memory.go ↔ core/template.go` — confirma que o core é o *hub*.
- **`STEP_IN_PROCESS`** (495 edges): etapas dos *flows* identificados.

## 6. Mapa de arquivos (81 arquivos indexados)

### Core engine (Go, zero deps)
- `core/model.go` — `Draft`, `Folder`, `Tag`, `titleOf`
- `core/store.go` — interface `Store`
- `core/memory.go` — `MemoryStore` + helpers (`cloneDraft`, `newUUID`)
- `core/clock.go` — clock injetável
- `core/action.go` — `ActionRunner`, `Action`, `applyAfterSuccess`
- `core/template.go` — `RenderTemplate`
- `core/options.go` — `Options`
- Tests: `core/memory_test.go`, `core/action_test.go`, `core/template_test.go` (escritas, nunca rodadas)

### Bridge AppleScript (original, macOS)
- `pkg/drafts/drafts.go`, `pkg/drafts/applescript.go`, `pkg/drafts/struct.go`, `pkg/drafts/options.go` (aliases para core)
- `cmd/drafts/main.go`, `cmd/drafts/info.go`, `cmd/drafts/contracts.go`, `cmd/drafts/schema.go`, `cmd/drafts/update_check.go`, `cmd/drafts/helpers.go`, `cmd/drafts/banner.go`

### Android (gomobile + Compose)
- `android/core-go/drafto.go`, `android/core-go/action.go`, `android/core-go/build-core.sh`
- `android/app/src/main/java/com/drafto/app/DraftoApp.kt`, `MainActivity.kt`
- `core/DraftoEngine.kt`, `FakeEngine.kt`, `GoDraftoEngine.kt`, `EngineFactory.kt`
- `ui/DraftListScreen.kt`, `ui/DraftListViewModel.kt`, `ui/EditorScreen.kt`, `ui/theme/*.kt`

### Linux CLI
- `cmd/drafto/main.go` — subcomandos `new/get/list/archive/trash/flag/tag/action/counts` vs `core.Store`

### CI/build
- `.github/workflows/ci.yml`, `.goreleaser.yaml`, `build.sh`, `release.sh`

## 7. Direitos autorais e herança lógica

O repo original (`pkg/drafts/*`, `cmd/drafts/*`) implementa:
- **Modelo de dados**: `Draft {uuid, title, body, folder, tags, flagged, created, modified}` + workspaces.
- **Folders**: inbox/archive/trash/flagged/all (mapeados em `Draft.Folder`).
- **Actions**: `Action {group, steps[], after_success}` com step types (`*template*`, `*tag*`, `*archive*`, `*trash*`, `*flag*`, `*clipboard*`, etc.) — lógica em `ActionRunner.runSteps`.
- **Template tags**: `[[draft_content]]`, `[[draft_title]]`, `[[draft_uuid]]`, `[[date]]`, `[[date_created]]`, `[[date_modified]]` + `[[clipboard]]`/`[[workspace]]` (em `core/template.go`, via `RenderTemplateEnv`).
- **Workspaces**: resolução de nome → folder/tag (em `MemoryStore.resolveWorkspace`).
- **Sort/filter**: `MemoryStore.Query` aceita `sort` + `folder`/`tag` filter.
- **gomobile boundary**: `Core` expoe o store + actions para Android via JNI/AAR.

Essa herança é o **referência de lógica** que o Drafto replica em `core/` (Go) + Android/Linux, sem depender do AppleScript/macOS.

## 8. O que falta para paridade (P0, do mapeamento)

> Status atualizado na trilha `arena/b30c3d85` (gap P0 fechado no core):

1. ✅ **`[[clipboard]]`** — `core/template.go` ganhou `RenderTemplateEnv` (env de tags extras); `core/action.go` injeta `[[clipboard]]` via nova capability `ClipboardReader` (aditiva, não-quebrante) e `[[workspace]]`. Parity matrix §4: ✅.
2. ✅ **Search full-text** — `Query.Search` casa (case-insensitive) sobre **conteúdo + título + tags** (`MemoryStore.matchesSearch`). FTS5 fica para o backend SQLite (Phase 1).
3. ✅ **Sort completo** — created/modified + **accessed** (novo campo `Draft.AccessedAt`, refresh no `Store.Get`) + **name** (novo `SortName`, case-insensitive). CLI: `drafto list --sort --desc`.
4. 🟠 **Action groups via URL** — core recebeu `ActionRunner.RegisterAll([]Action)` (instalação em lote); o parse do payload JSON/URL scheme permanece no cliente (P1).
5. ✅ **Trash auto-delete (30 dias)** — novo campo `Draft.TrashedAt` (stamp/clear como invariante em `Store.Update`), retenção padrão de 30 dias (`defaultTrashRetention`), auto-purge lazy no `Query`, `PurgeTrash` manual (capability `TrashPruner`), CLI: `drafto purge --days`.
6. ⚪ **Geolocation/permalink/version history/tasks** — P1/P2 (ver `docs/drafto/02-FEATURE-PARITY.md`).

## 9. Como usar este codemap

1. **Nova feature no Drafto**: começa no `core/` (modelo + store), segue para `android/core-go` (boundary), termina na UI Compose ou CLI.
2. **Entender o original macOS**: olha `pkg/drafts/` + `cmd/drafts/` (cluster "Drafts") — a lógica de *actions* foi "traduzida" para `core/action.go`.
3. **Verificar impacto**: `gitnexus impact <target>` / `gitnexus context <symbol>`.
4. **Reverter a um cluster**: `gitnexus cypher "MATCH (c:Community) WHERE c.label='...' RETURN c"`.
5. **Skills gerados**: `.claude/skills/gitnexus-area-*/SKILL.md` — guia por área funcional.

## 10. Limitações registradas

- **FTS desativado** — `gitnexus query` por texto retorna vazio; não significa ausência de fluxo. Reparar com `analyze --repair-fts` (precisa rede).
- **`rea` para binários** — Hopper/Ghidra/IDA ausentes; a análise do Get Drafts iOS original (binário) depende de instalação futura.
- **Go toolchain indisponível** na *sandbox* — nada foi compilado; `core/*` e `cmd/drafto` são fonte não verificada (conhecido risco, documentado em PR #1).
- **Skills regeneráveis** — `.claude/` ignorado (não commitado); o codemap curado (este arquivo) é a fonte de verdade.
