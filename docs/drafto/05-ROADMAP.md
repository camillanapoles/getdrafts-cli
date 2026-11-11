# Drafto — Roadmap

## Phase 0 — Fundação (esta sessão)
**Objetivo:** monorepo organizado, core Go compiável, governança documentada, Android scaffold.

- [x] Investigação Get Drafts (`01`)
- [x] Matriz de pareamento (`02`)
- [x] Arquitetura (`03`)
- [x] Governança (`04`)
- [x] Pacote `core/` (model, store interface, memory store, action engine, template tags, testes)
- [x] Migração da CLI para o core (aliases de tipos)
- [x] Scaffold Android (Gradle/Kotlin/gomobile)
- [ ] CI GitHub Actions (test/build/android)
- [ ] `cmd/drafto` Linux MVP

## Phase 1 — Core nativo + storage
**Objetivo:** storage SQLite, CRUD completo, organização.

- [ ] `core/sqlitestore` (driver puro, schema abaixo)
- [ ] CRUD: create/get/query/update/replace/append/prepend
- [ ] Organização: inbox/archive/trash/flag/tags/workspaces/sort/search
- [ ] `cmd/drafto` Linux (JSON + plain, schema, info)
- [ ] Testes de integração (SQLite)

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

- [ ] `DraftoCore` (gomobile binding do Store/ActionRunner)
- [ ] `DraftListScreen` (inbox/archive/trash/flagged/all, search, sort)
- [ ] `EditorScreen` (capture, tag, flag, archive/trash)
- [ ] `ActionSheet` (copy/share/move/tag/archive/trash/template)
- [ ] Deep links `drafto://`
- [ ] Material 3 + tema dark

## Phase 3 — Actions & interoperabilidade
- [ ] Action groups
- [ ] After-success (archive/trash/tag)
- [ ] Template tags completos
- [ ] Export/import (JSON/Markdown)
- [ ] x-callback-url / URL scheme completo
- [ ] Compatibilidade parcial com templates de Drafts

## Phase 4 — Sync & plataforma
- [ ] Backup local
- [ ] Sync multi-device (change-log)
- [ ] Widgets Android
- [ ] Wear OS

## Critérios de acceptance por fase
- Phase 1: `go test ./...` verde; `drafto create/get/list/search/flag/archive` funcionando no SQLite.
- Phase 2: APK installa; captura → inbox; tag/flag/archive/trash funcionam; actions básicas executam.
- Phase 3: URL scheme responde; export/import round-trip.
- Phase 4: sync entre dois devices.

## Rastreamento
Cada item vira issue/tarefa com owner + fase + status. A matriz `02-FEATURE-PARITY.md` é a fonte de verdade.
