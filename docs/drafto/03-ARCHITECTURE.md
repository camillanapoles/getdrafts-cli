# Drafto — Arquitetura

## 1. Visão geral

Drafto é um **monorepo** com um **Go core** compartilhado entre todos os clientes.
O core é platform-agnostic; cada cliente é uma *shell* sobre ele.

```
                         ┌──────────────────────────────┐
                         │         core/ (Go)            │
                         │  model · store · actions ·    │
                         │  template · workspace        │
                         └───────┬──────────────────┬───┘
                                 │                  │
            ┌────────────────────┼──────────────────┼───────────────────┐
            ▼                    ▼                  ▼                     ▼
   ┌────────────────┐   ┌────────────────┐  ┌────────────────┐   ┌────────────────┐
   │ Android (Kotlin)│   │ Linux CLI      │  │ macOS bridge   │   │ iOS (futuro)   │
   │ via gomobile   │   │ (drafto bin)   │  │ (pkg/drafts)   │   │ (gomobile)     │
   │ Compose UI     │   │ TUI/JSON       │  │ AppleScript    │   │                │
   └────────────────┘   └────────────────┘  │ → Drafts.app   │   └────────────────┘
                                              └───────────────┘
```

## 2. Por que Go core?

- **Reutilização real da base CLI:** o modelo `Draft`, filtros, sorts, workspaces e o engine de actions
  vivem em Go — a mesma linguagem da CLI existente.
- **Android sem CGO:** `gomobile bind` gera um AAR a partir do Go core; Kotlin consome via binding.
- **Linux nativo:** o binário `drafto` é o core + CLI, compiled para linux/amd64, arm64.
- **Testes portáteis:** o core é testado com `go test`, backend in-memory, sem device/emulator.
- **Interoperabilidade:** saída JSON estável (herança LLM-first da CLI).

## 3. Abstração de backend (Store)

O core define uma interface `Store`. Cada ambiente implementa:

| Backend | Emprego | Store impl |
|---------|---------|-----------|
| **AppleScript** | macOS,控制a o Drafts.app real | `pkg/drafts` (existente) |
| **SQLite** | Android + Linux (storage nativo) | `core/sqlitestore` (implementado; Phase 1) |
| **Memory** | testes / demo | `core/memory` (já presente) |

> A CLI macOS continua apontando para o AppleScript backend (compatibilidade com Drafts.app).
> Android/Linux usam SQLite. O `Store` é a fronteira — o CLI/UI nunca toca no storage diretamente.

## 4. Divisão de responsabilidades

- **core/model.go** — `Draft`, `Folder`, `Filter`, `Sort`, `Workspace`, `Action`, `Counts` (fonte única de verdade).
- **core/store.go** — interface `Store` + erros + options.
- **core/memory.go** — Store em memória (thread-safe) para testes.
- **core/action.go** — `ActionRunner`: executa steps (copy, share, move, tag, archive, trash, template).
- **core/template.go** — renderer de template tags.
- **pkg/drafts/** — backend AppleScript (macOS) + aliases para os tipos do core.
- **cmd/drafts/** — CLI macOS (existente) → `pkg/drafts`.
- **cmd/drafto/** — CLI Linux/Android (futuro) → `core.Store` (SQLite/memory).
- **android/** — app Kotlin + Compose + binding gomobile.

## 5. Fluxo de dados (captura → destino)

```
[Compose Editor] → DraftoCore.create(content, tags) → core.Store.Create → SQLite
                          ↓
                 core.ActionRunner.Run(action, uuid)
                          ↓
                 steps: move/tag/archive/trash/template/share
                          ↓
                 [Intent / clipboard / outro app]
```

## 6. Reutilização do repositório da CLI (mapa)

| Recurso da CLI | Reutilizado em Drafto? | Como |
|----------------|-----------------------|------|
| `Draft` model | ✅ | Canônico em `core`, alias em `pkg/drafts`. |
| Filters/Sorts/Folders | ✅ | `core`. |
| Options (Create/Modify/Query) | ✅ | `core`. |
| Action engine | ✅ (reimplementado) | `core.ActionRunner`. |
| Template tags | ✅ (subset) | `core/template.go`. |
| Error codes | ✅ | `DRAFT_NOT_FOUND`, `ACTION_NOT_FOUND`, … |
| JSON output contract | ✅ | Envelope `{success, data, error}`. |
| `schema` introspection | ✅ | Útil para agents/LLM no Android. |
| AppleScript backend | ⚠️ | Apenas macOS; Drafto usa SQLite/memory. |
| `info` diagnostics | ✅ | Análogo em Drafto. |
| goreleaser/CI | ✅ | Estende para linux + Android. |

## 7. Android (gomobile)

- `gomobile bind -target=android -o=android/app/libs/drafto.aar ./core` (API exportada via `//export`).
- Binding gera Kotlin/Java a partir do `Store`/`ActionRunner` exportados.
- UI em **Jetpack Compose** (Material 3): `DraftListScreen`, `EditorScreen`, `ActionSheet`.
- Storage: SQLite via `core/sqlitestore` (driver puro, sem CGO).
- Deep links: `drafto://create`, `drafto://open`, etc.

## 8. Linux CLI

- Binário `drafto` (Go) com subcomandos análogos à CLI macOS, apontando para `core.Store` (SQLite).
- Saída JSON por padrão (agents), `--plain` opcional.
- `drafto schema` para agentes/LLM (herança da CLI).

## 9. Sincronização (Phase 4)

- Começar com storage local SQLite.
- Estratégia futura: sync baseado em change-log (draft_id + modifiedAt) com backend remoto opcional.
- O `Store` deve permanecer a fronteira, permitindo um backend de sync sem tocar nos clientes.

## 10. Segurança & privacidade

- Dados locais por padrão; nenhum envio a servidores da Drafto.
- Permissões mínimas no Android (clipboard apenas quando a action solicita).
- Export/import via arquivos locais.
