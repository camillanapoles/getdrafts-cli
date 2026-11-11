# Drafto — Handoff / Estado atual

## 1. Onde o projeto está (esta sessão)

- **Repositório:** `getdrafts-cli` (monorepo Drafto). Branch de sessão: `arena/b30c3d85-getdrafts-cli`.
- **Trilha canônica (ADR-005):** namespace `reverse/`. `reverse/main` = staging/production (o "origin"). Fluxo: `arena/<id>` → PR → `reverse/<id>` → PR/merge → `reverse/main` → tag `vX.Y.Z` (dispara `release.yml`). Tags são gatilho de automação.
- **Progresso nesta sessão:** gap **P0 de paridade fechado no core** — `[[clipboard]]`/`[[workspace]]` (`RenderTemplateEnv` + `ClipboardReader`), search full-text (conteúdo/título/tags), sort completo (`AccessedAt` + `SortName`, CLI `--sort/--desc`), trash auto-delete 30 dias (`TrashedAt`, `TrashPruner.PurgeTrash`, CLI `purge`) e `ActionRunner.RegisterAll` (grupos em lote). Automação por tag implementada (`release.yml`) + template de PR perpetuando o fluxo `reverse/`.
- **Base:** CLI Go (macOS/AppleScript) já existente e estável (commit `8b43a14`).
- **Novo:** pacote `core/` (Go, platform-agnostic) — o engine compartilhado.
- **Documentação:** `docs/drafto/00..06` + `CODEMAP.md`.

## 2. Como continuar (próximos passos óbvios)

1. **Validar o build** (necessita toolchain Go — a CI valida em cada PR):
   ```bash
   go build ./... && go test ./... && go vet ./...
   ```
2. **Iniciar Phase 1:** implementar `core/sqlitestore` (com FTS5 para search + purge equivalente ao `MemoryStore`) + persistência do `cmd/drafto`.
3. **Iniciar Phase 2:** Android — `gomobile bind` + UI Compose (expor sort/purge na UI).
4. **CI:** já configurada — `ci.yml` (build/vet/test/race + android best-effort) e `release.yml` (disparada por tag `v*`/`drafto-v*` em `reverse/main` → goreleaser).

## 3. Comandos úteis

```bash
# Build CLI macOS
go build ./cmd/drafts
# Testes do core
go test ./core/...
# Build Linux (CLI nativo, futuro)
GOOS=linux GOARCH=amd64 go build -o drafto ./cmd/drafto
# Android AAR (gomobile)
cd core && gomobile bind -target=android -o=../android/app/libs/drafto.aar .
# Android APK
cd android && ./gradlew assembleDebug
```

## 4. Decisão de projeto (ADRs)

- **ADR-001 — Go core + gomobile:** aprovado. Reutiliza a base CLI, Android sem CGO.
- **ADR-002 — Store interface:** backends plugáveis (AppleScript/SQLite/Memory). Aprovado.
- **ADR-003 — Template tags próprios:** reimplementar, não copiar JS proprietário. Aprovado.
- **ADR-004 — Module path:** manter original por continuidade; rename no 1º release oficial.
- **ADR-005 — Estrutura paralela `reverse/` (canônica, perpétua):** aprovado. A trilha canônica do Drafto é o namespace `reverse/`. `reverse/main` é a linha de staging/production (o "origin" do projeto). Todo PR vai de `arena/<id>` → `reverse/<id>`; todo merge para produção vai → `reverse/main`. Tags `v*`/`drafto-v*` são criadas **somente em `reverse/main`** e são o gatilho de automação canônico. A trilha `reverse/` é independente de `main` histórico (não mistura). Esta regra é **perpétua** — novos branches/PRs seguem o fluxo `reverse/`.
- **ADR-006 — Paridade P0 no core (aditiva, não-quebrante):** aprovado. Campos novos em `Draft` (`AccessedAt`, `TrashedAt`) são `omitempty`; `SortName` acrescentado ao fim do enum `Sort` (estabilidade numérica para o boundary gomobile); capabilities **opcionais** (`TrashPruner`, `ClipboardReader`) em vez de métodos novos na `Store` interface — o bridge AppleScript e o boundary Android não quebram. Trash retention padrão = 30 dias (paridade Drafts), desativável com `SetTrashRetention(0)`.

## 5. Riscos atuais

- Go não compila neste sandbox (rede restrita). Primeira ação do dev: `go build ./...`.
- SQLite backend ainda não implementado (Phase 1).
- Android não compilado (sem SDK/network). Scaffold pronto, precisa de ambiente Android.

## 6. Checklist de continuidade

- [ ] `go build ./...` verde
- [ ] `go test ./...` verde
- [ ] `go vet ./...` limpo
- [x] CI configurada (`ci.yml`) + release por tag (`release.yml`)
- [ ] `core/sqlitestore` implementado (com FTS5 + purge)
- [ ] `cmd/drafto` Linux funcional com persistência
- [ ] Android APK installa e captura funciona
