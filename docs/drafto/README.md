# Drafto — Documentação

App Android + Linux, idêntico em escopo ao Get Drafts (iOS/macOS). Baseado no repositório `getdrafts-cli`.

## Estado em um relance (2026-11-12)

| Fase | Estado | Detalhe |
|---|---|---|
| Phase 0 — Fundação | ✅ | docs 00–04 + `core/` + scaffold Android + CI, tudo em `reverse/main` |
| Phase 1 — Core + SQLite | 🟡 | core/backends ✅; **superfície da CLI `drafto` incompleta** (sem plain/info/append/prepend/replace/workspace/actions), workspaces sem contrato de escrita, `actions`/`versions` não persistidas |
| Phase 2 — Android | 🟢 em voo | G1 (SQLite no boundary) + G2 (app usa o core Go) existem em `reverse/v0.3.0-*`/`arena/26d3ae79-*`, **fora de `reverse/main`**; G3 (actions na UI) ⚪ |
| Phase 3 — Actions & interop | ⚪ | specs prontas (`07` §4.5); bloqueadas por CORE-03/CLI-01 |
| Phase 4 — Sync & plataforma | ⚪ | deliberado; não abrir antes de PROD-02 |
| Trilha `rev-ios` (eng. reversa iOS) | 🟡 | spec + ledger (58 obrigações) escritos em `arena/d07fc20f-*`, **nunca integrados** |

Release atual: **v0.2.0** (`Latest`). Próximo gate: tag `v0.3.0` → `SPEC-OPS-01`.

## Índice

| Doc | Conteúdo |
|-----|----------|
| [00-MANDATE](00-MANDATE.md) | Mandato, valores, escopo, sucesso, riscos. |
| [01-GETDRAFTS-INVESTIGATION](01-GETDRAFTS-INVESTIGATION.md) | Investigação das features do Get Drafts. |
| [02-FEATURE-PARITY](02-FEATURE-PARITY.md) | Matriz de pareamento Get Drafts → Drafto. |
| [03-ARCHITECTURE](03-ARCHITECTURE.md) | Monorepo, Go core, backends, Android, Linux. |
| [04-GOVERNANCE](04-GOVERNANCE.md) | Branches, semver, releases, CI, handoff. |
| [05-ROADMAP](05-ROADMAP.md) | Fases, schema SQLite, acceptance criteria. |
| [06-HANDOFF](06-HANDOFF.md) | Estado atual e como continuar. |
| [07-ROADMAP-EXECUCAO](07-ROADMAP-EXECUCAO.md) | **Plano de execução:** specs, status feito×pendente por fase, pré-requisitos de início (DoR) por spec, paralelismo por workspace, gates de release. |
| [08-AUDIT-2026-11-12](08-AUDIT-2026-11-12.md) | Auditoria de estado com evidência (`arquivo:linha`), divergências doc↔código (D1–D11), defeitos (F1–F10), restrições de ambiente. |
| [specs/README](specs/README.md) | Sistema de specs: índice de status, regras de abertura, [template](specs/_TEMPLATE.md). |

## Resumo da arquitetura

```
core/ (Go, platform-agnostic)
   ├── model · store · memory · action · template
   ├── Android (gomobile) → Kotlin/Compose
   ├── Linux CLI (drafto) → JSON/plain
   └── macOS bridge (pkg/drafts) → AppleScript → Drafts.app
```

O **Go core** é a reutilização real da base da CLI. Os clientes são shells sobre ele.
