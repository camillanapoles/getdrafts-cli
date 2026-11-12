# Drafto — Matriz de Pareamento de Features (Get Drafts → Drafto)

> Status: ✅ Mature · 🟡 Partial · 🟠 Planned · ⚪ Deferred · ⛔ N/A
> Clientes primários: Android + Linux. iOS/macOS não são clientes Drafto.

## 1. Captura & Editor

| Get Drafts feature | Drafto (Android) | Drafto (Linux) | Prioridade | Notas |
|---|---|---|---|---|
| Quick capture (inbox) | ✅ | ✅ | P0 | Fluxo central. |
| Editor plain-text | ✅ | ✅ | P0 | Compose Editor / terminal editor. |
| Markdown rendering preview | 🟡 | 🟡 | P1 | Android: Compose markdown; Linux: mdcat. |
| Taskpaper tasks (`- [ ]`) | 🟠 | 🟠 | P2 | Task listtoggle. |
| Syntax/grammar select | 🟠 | 🟠 | P2 | Plain/Markdown/Taskpaper. |
| Themes/dark mode | ✅ | ✅ | P1 | Material 3 + CLI colors. |
| Custom fonts/spacing | ⚪ | ⚪ | P3 | Personalização avançada. |
| Link Mode (auto-links) | 🟠 | 🟠 | P2 | URLs/emails/wiki-links. |
| Arrange Mode (multi-draft) | 🟠 | 🟠 | P2 | Seleção em lote. |
| Version history / rollback | 🟠 | 🟠 | P2 | Histórico de edições. |
| Dictação | ⚪ | ⚪ | P3 | Android: STT; Linux: dict. |

## 2. Organização

| Get Drafts feature | Drafto (Android) | Drafto (Linux) | Prioridade | Notas |
|---|---|---|---|---|
| Inbox | ✅ | ✅ | P0 | |
| Archive | ✅ | ✅ | P0 | |
| Trash (+ 30d expiry) | ✅ | ✅ | P1 | Auto-delete 30 dias no core (`TrashedAt` + `TrashPruner.PurgeTrash`); CLI `drafto purge`. |
| Flagged | ✅ | ✅ | P0 | |
| All (inbox+archive) | ✅ | ✅ | P0 | |
| Tags (multiplas) | ✅ | ✅ | P0 | |
| Tag filters (+/-) | ✅ | ✅ | P1 | |
| #tagged / #untagged | 🟠 | 🟠 | P2 | |
| Workspaces | 🟡 | 🟡 | P1 | Configuração de filtro/sort/group. |
| Workspace import/export | 🟠 | 🟠 | P2 | JSON. |
| Full-text search | ✅ | ✅ | P0 | Conteúdo + título + tags (case-insensitive, substring) — mesma semântica em `MemoryStore` e `SQLiteStore` (`matchesSearch`). Índice FTS5 mantido para busca ranqueada futura. |
| Sort (created/modified/accessed) | ✅ | ✅ | P1 | `accessed` via `AccessedAt` (refresh no `Get`); + sort por nome (`SortName`); CLI `list --sort/--desc`. |
| Sort flagged to top | ✅ | ✅ | P1 | |

## 3. Actions Engine

| Get Drafts feature | Drafto (Android) | Drafto (Linux) | Prioridade | Notas |
|---|---|---|---|---|
| Action steps: Copy | ✅ | ✅ | P0 | |
| Share / open URL | ✅ | ✅ | P0 | Intents (Android) / xdg-open. |
| Move to folder | ✅ | ✅ | P0 | |
| Assign tags | ✅ | ✅ | P0 | |
| Archive / Trash | ✅ | ✅ | P0 | |
| Template step | ✅ | ✅ | P1 | Template tags próprios. |
| Script step (JS) | ⚪ | ⚪ | P4 | Out of scope inicial. |
| After-success (archive/trash/tag) | 🟠 | 🟠 | P2 | |
| Action groups | 🟡 | 🟡 | P1 | Lista/action bar. |
| Run action on text (transient) | ✅ | ✅ | P1 | |
| Run action on draft | ✅ | ✅ | P1 | |

## 4. Template Tags (Drafto próprios, inspirados em Drafts)

| Tag | Semântica | Status |
|---|---|---|
| `[[draft_content]]` | conteúdo do draft | ✅ |
| `[[draft_title]]` | primeira linha | ✅ |
| `[[draft_uuid]]` | uuid | ✅ |
| `[[date]]` / `[[date_created]]` / `[[date_modified]]` | datas | ✅ |
| `[[clipboard]]` | clipboard (via injeção de `ClipboardReader` no `ActionRunner`) | ✅ |
| `[[workspace]]` | workspace ativo (env de `RenderTemplateEnv`) | ✅ |

## 5. Interoperabilidade

| Get Drafts feature | Drafto | Prioridade | Notas |
|---|---|---|---|
| URL scheme (`drafto://`) | 🟠 | P1 | Análogo a `drafts://`. |
| x-callback-url | 🟠 | P2 | |
| Share sheet (Android) | ✅ | P0 | |
| Deep links / App Links | 🟠 | P2 | |
| Export drafts (JSON/Markdown) | 🟡 | P1 | |
| Import drafts | 🟡 | P1 | |
| CLI (`drafto` bin) | ✅ | P0 | Linux primário. |
| JSON output (LLM/agents) | ✅ | P0 | Herança da CLI. |

## 6. Plataforma & Sync

| Get Drafts feature | Drafto | Prioridade | Notas |
|---|---|---|---|
| Storage local (SQLite) | ✅ | P0 | `core.SQLiteStore` (modernc.org/sqlite, pure Go, sem CGO); CLI `drafto` persiste em `--db` (`drafto.db` por padrão). |
| Backup local | 🟠 | P2 | |
| Multi-device sync | ⚪ | P4 | Phase 4. |
| Widgets | ⚪ | P4 | Android widgets. |
| Watch / Wear OS | ⚪ | P4 | |

## 7. Prioridades cumulativas

- **P0 (MVP):** capture, inbox/archive/trash/flag, tags, search, sort, actions básicas (copy/share/move/tag/archive/trash), template step, CLI, JSON output.
- **P1:** workspaces, markdown preview, themes, sort flagged-top, action groups, run-on-text, export/import, URL scheme.
- **P2:** taskpaper, link mode, arrange mode, versions, after-success, workspace import/export, x-callback-url, trash expiry.
- **P3:** custom fonts/typography, dictação.
- **P4:** JS script step, sync multi-device, widgets, Wear OS.

## 8. Rastreamento

Cada feature deve ser uma issue/tarefa no roadmap com: status, owner, fase, acceptance criteria.
Esta matriz é a fonte de verdade para o *pareamento* e deve ser atualizada a cada fase.
