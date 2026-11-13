# Drafto — Roadmap

> **Fases (o quê).** A camada de execução — specs, pré-requisitos de início (DoR), paralelismo por
> workspace e ordem recomendada de sessões — está em
> [`07-ROADMAP-EXECUCAO.md`](07-ROADMAP-EXECUCAO.md); a auditoria que motivou as correções de status
> abaixo está em [`08-AUDIT-2026-11-12.md`](08-AUDIT-2026-11-12.md).
> **Regra:** ✅ só com evidência citável (`arquivo:linha`, teste ou run de CI). Sem evidência, é 🟡.

## Phase 0 — Fundação (esta sessão)
**Objetivo:** monorepo organizado, core Go compiável, governança documentada, Android scaffold.

- [x] Investigação Get Drafts (`01`)
- [x] Matriz de pareamento (`02`)
- [x] Arquitetura (`03`)
- [x] Governança (`04`)
- [x] Pacote `core/` (model, store interface, memory store, action engine, template tags, testes)
- [x] Migração da CLI para o core (aliases de tipos)
- [x] Scaffold Android (Gradle/Kotlin/gomobile)
- [x] CI GitHub Actions (test/build/android)
- [x] `cmd/drafto` Linux MVP

## Phase 1 — Core nativo + storage
**Objetivo:** storage SQLite, CRUD completo, organização.

- [x] `core/sqlitestore` (driver puro, schema abaixo) — `core/sqlitestore.go` (847 l.) + `core/sqlitestore_test.go` (613 l.), CI verde em `77f1996`
- [x] CRUD: create/get/query/update/replace/append/prepend — **no `core.Store`** (`core/store.go:21-60`)
- [ ] 🟡 Organização — **workspaces parcial**: inbox/archive/trash/flag/tags/sort/search ✅ · `SaveWorkspace` fora da interface e com assinaturas divergentes (`core/memory.go:402` vs `core/sqlitestore.go:650`) → `SPEC-CORE-02`
- [ ] 🟡 `cmd/drafto` Linux — JSON ✅, `schema` hardcoded 🟡, **sem `--plain`**, **sem `info`**, sem `replace/append/prepend/edit/workspace/actions` → `SPEC-CLI-01`
- [x] Testes de integração (SQLite) — suíte própria; **conformidade Memory ↔ SQLite ainda não existe** → `SPEC-CORE-01`
- [ ] Schema real do SQLite = `drafts`, `tags`, `workspaces`, `settings` (`core/sqlitestore.go:92-158`). As tabelas `actions`, `action_logs` e `versions` abaixo são **propostas, não implementadas** → `SPEC-CORE-03`

### Schema SQLite (proposto)
```sql
CREATE TABLE drafts (
  uuid TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  folder TEXT NOT NULL DEFAULT 'inbox',   -- inbox|archive|trash
  flagged INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0,
  syntax TEXT NOT NULL DEFAULT '',
  workspace TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  modified_at TEXT NOT NULL,
  created_lat REAL, created_lon REAL,
  modified_lat REAL, modified_lon REAL,
  permalink TEXT
);
CREATE VIRTUAL TABLE drafts_fts USING fts5(content, title, content=drafts, content_rowid=rowid);
CREATE TABLE tags (draft_uuid TEXT REFERENCES drafts(uuid), tag TEXT);
CREATE TABLE workspaces (
  name TEXT PRIMARY KEY, folder TEXT, search TEXT,
  tags TEXT, omit_tags TEXT, sort TEXT, sort_desc INTEGER, flagged_top INTEGER, action_group TEXT
);
CREATE TABLE versions (uuid TEXT, seq INTEGER, content TEXT, created_at TEXT);
CREATE TABLE actions (uuid TEXT PRIMARY KEY, name TEXT, group_name TEXT, config TEXT);
CREATE TABLE action_logs (id INTEGER PRIMARY KEY, uuid TEXT, action TEXT, ok INTEGER, at TEXT);
```

## Phase 2 — App Android
**Objetivo:** UI Compose, captura, lista, editor, actions básicas.
**Critério de início:** ~~`SPEC-OPS-01` (G1/G2 integrados em `reverse/main` + tag `v0.3.0`)~~ ✅ **fechado
em 2026-11-13** (`#38` → squash `3f2c3b9`, tag `v0.3.0`); resta `SPEC-AND-01` (DTO do boundary à prova
de gomobile) — ver `07-ROADMAP-EXECUCAO.md` §4.4/§6.

- [x] ✅ `DraftoCore` (gomobile binding do Store/ActionRunner) — G1 `NewAt`/`Close` + SQLite no boundary
  e G2 `GoDraftoEngine` (reflexão) + `EngineFactory` **integrados em `reverse/main`** pelo PR **#38**
  (squash `3f2c3b9`); *gate* de dex/AAR (`verifyGoBinding`) no CI; testes do boundary na API JSON
  (`23988b2`, inclui `TestBoundMethodsAreGomobileSafe` por reflexão). Evidência: run `43337984272`
  (Go ✅ / Android ✅). Release: [`v0.3.0`](https://github.com/camillanapoles/getdrafts-cli/releases/tag/v0.3.0)
- [ ] 🟡 assets Android **na release** — `drafto.aar` e `drafto-debug.apk` só existem como artefatos de
  CI (run `43337984272`); `release.yml` não os anexa → [#42](https://github.com/camillanapoles/getdrafts-cli/issues/42)
- [ ] `DraftListScreen` (inbox/archive/trash/flagged/all, search, sort) — hoje fixo em `"inbox"` (`android/…/ui/DraftListViewModel.kt:29`) → `SPEC-AND-03`
- [ ] 🟡 `EditorScreen` (capture ✅, save ✅, flag ✅, archive/trash ✅, **tag ✗**) — `ui/EditorScreen.kt` não expõe tags nem `addTags` → incluir em `SPEC-AND-03`
- [ ] `ActionSheet` (copy/share/move/tag/archive/trash/template) — não existe → `SPEC-AND-02` (G3)
- [ ] Deep links `drafto://` + share sheet — manifest declara (`AndroidManifest.xml:24-35`), `MainActivity` **não trata intent** → `SPEC-AND-04`
- [ ] Material 3 + tema dark 🟡 (`ui/theme/Theme.kt` existe; sem validação em device) → `SPEC-AND-05`

## Phase 3 — Actions & interoperabilidade
**Critério de início:** `SPEC-CORE-03` (actions persistentes) + `SPEC-CORE-04`; export/import depende de
`SPEC-CLI-01`; modelo confirmado depende do `rev-ios` (C2–C3).

- [ ] Action groups
- [ ] After-success (archive/trash/tag)
- [ ] Template tags completos
- [ ] Export/import (JSON/Markdown)
- [ ] x-callback-url / URL scheme completo
- [ ] Compatibilidade parcial com templates de Drafts

## Phase 4 — Sync & plataforma
**Critério de início:** `SPEC-PROD-02` (versions/tombstones confirmados por evidência) — sync sem
modelo de versões corrompe dados. Widgets/Wear só depois do aceite de `SPEC-AND-05`.

- [ ] Backup local
- [ ] Sync multi-device (change-log)
- [ ] Widgets Android
- [ ] Wear OS

## Critérios de acceptance por fase
- Phase 1: `go test ./...` verde; `drafto create/get/list/search/flag/archive` funcionando no SQLite.
  > ✅ evidência: CI do `77f1996` — "Go build, vet, test" pass (45 testes nomeados + `-race`).
  > 🟡 a **superfície** da CLI (plain/info/append/prepend/replace/workspace/actions) não fecha: ver Phase 1 acima.
- Phase 2: APK installa; captura → inbox; tag/flag/archive/trash funcionam; actions básicas executam.
  > ✅ **G1+G2 integrados e taggeados** — `reverse/main` `3f2c3b9` (PR #38), CI `43337984272` (Go ✅,
  > Android ✅ com `verifyGoBinding` provando `libgojni.so` + `go/drafto/Core` no dex), release `v0.3.0`.
  > ⚠️ O critério **não** fecha aqui: G3 (ActionSheet → `SPEC-AND-02`) e aceite em device
  > (`SPEC-AND-05`) seguem pendentes — o APK é *buildado* no CI, nunca *instalado*.
- Phase 3: URL scheme responde; export/import round-trip.
- Phase 4: sync entre dois devices.

## Rastreamento
Cada item vira **spec** (`docs/drafto/specs/`) + issue/tarefa com owner + fase + status. A matriz
`02-FEATURE-PARITY.md` é a fonte de verdade de *pareamento*; `07-ROADMAP-EXECUCAO.md` é a fonte de
verdade de *sequência* (paralelismo, pré-requisitos de início, gates de release).
