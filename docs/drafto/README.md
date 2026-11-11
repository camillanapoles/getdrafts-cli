# Drafto — Documentação

App Android + Linux, idêntico em escopo ao Get Drafts (iOS/macOS). Baseado no repositório `getdrafts-cli`.

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

## Resumo da arquitetura

```
core/ (Go, platform-agnostic)
   ├── model · store · memory · action · template
   ├── Android (gomobile) → Kotlin/Compose
   ├── Linux CLI (drafto) → JSON/plain
   └── macOS bridge (pkg/drafts) → AppleScript → Drafts.app
```

O **Go core** é a reutilização real da base da CLI. Os clientes são shells sobre ele.
