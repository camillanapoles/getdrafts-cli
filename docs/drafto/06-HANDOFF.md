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
2. ~~**Phase 1:** `core/sqlitestore` + persistência do `cmd/drafto`.~~ ✅ **Concluída** (`core/sqlitestore.go`, pure Go via `modernc.org/sqlite`, sem CGO; CLI `drafto --db`).
3. **Phase 2 (Android)** — em andamento. Estado auditado e ordem de execução em **§2.1** abaixo.
4. **CI:** já configurada — `ci.yml` (build/vet/test/race + android best-effort) e `release.yml` (disparada por tag `v*`/`drafto-v*` em `reverse/main` → goreleaser).

### 2.1 Phase 2 — gap analysis (auditado em 2026-11-12)

Critério de aceitação (`05-ROADMAP.md`): *APK instala; captura → inbox; tag/flag/archive/trash
funcionam; actions básicas executam.*

O scaffold Compose existe (~478 linhas em `android/`), mas **três gaps impedem o critério**:

| # | Gap | Evidência | Impacto |
|---|---|---|---|
| **G1** | Boundary sem persistência | `android/core-go/drafto.go:22` usa `core.NewMemoryStore()` | Dados somem ao fechar o app |
| **G2** | App não usa o Go core | `EngineFactory.kt:11` retorna `FakeEngine()` | UI roda em mock, não no engine real |
| **G3** | Sem acesso ao `ActionRunner` na UI | 13 `//export`, nenhum expõe actions | Critério "actions básicas executam" não fecha |

**Ordem de execução (incremental, cada passo verificável no CI):**

1. **G1** — `NewAt(path string)` no boundary usando `core.NewSQLiteStore`, mantendo `New()` para preview.
   *Verificação:* teste Go do boundary em `android/core-go/` + `go build ./android/core-go/`.
2. **G1** — Ponte Kotlin para o caminho do banco: `context.getDatabasePath("drafto.db")`.
3. **G2** — `EngineFactory` escolhe `GoDraftoEngine` quando o AAR existe; `FakeEngine` fica como fallback de preview.
4. **G2** — `.aar` gerado no CI (artefato) para o app consumir sem `gomobile` local.
5. **G3** — Expor `RunAction`/`ListActions` no boundary e a ActionSheet na UI.

**Risco conhecido:** `go.mod` declara `go 1.26.0`; o gomobile costuma ficar atrás do
toolchain. Validar `gomobile bind` **antes** de investir em G2/G3 — se falhar, fixar a
versão do Go no job do Android (matriz), não no `go.mod`.

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

## 3.1 Estado do backend SQLite (Phase 1 — corrigido na revisão do PR #11)

`core.SQLiteStore` é o backend de produção para Linux/Android (pure Go, sem CGO).
Paridade com `MemoryStore` verificada por testes de integração (`core/sqlitestore_test.go`):

| Área | Comportamento |
|---|---|
| `Get` | Atualiza `accessed_at` **e devolve** o valor atualizado (sort por acesso). |
| `Update` | Persiste todo campo devolvido (`created_at`, geo, `permalink`); `created_at`/`permalink` são imutáveis. |
| Search | `matchesSearch` em Go (substring, case-insensitive, conteúdo+título+tags) — resultados idênticos ao `MemoryStore`. Índice FTS5 mantido para busca ranqueada futura. |
| Tags | `loadTagsQuery` em lotes de 500 UUIDs (limite de parâmetros do SQLite). |
| Workspaces | Tags serializadas em CSV (tags com vírgula sobrevivem); linhas legadas continuam lendo. |
| `:memory:` | Conexão única + shared cache; cursores fechados antes de novas consultas. |
| `activeWorkspace` | Erros de leitura são propagados (só "setting ausente" = workspace vazio). |
| CLI `drafto` | SQLite é o default; falha ao abrir é erro fatal (`exit 1`) — memória só com `--memory`. |

> **Nota de segurança/supply chain:** o `go.sum` versionado precisa conter os hashes
> do `modernc.org/sqlite`. O CI regenera com `go mod tidy` e commita em push de branch
> (nunca em `pull_request`). Qualquer divergência aparece como falha em "Commit go.sum if changed".

## 4. Decisão de projeto (ADRs)

- **ADR-001 — Go core + gomobile:** aprovado. Reutiliza a base CLI, Android sem CGO.
- **ADR-002 — Store interface:** backends plugáveis (AppleScript/SQLite/Memory). Aprovado.
- **ADR-003 — Template tags próprios:** reimplementar, não copiar JS proprietário. Aprovado.
- **ADR-004 — Module path:** manter original por continuidade; rename no 1º release oficial.
- **ADR-005 — Estrutura paralela `reverse/` (canônica, perpétua):** aprovado. A trilha canônica do Drafto é o namespace `reverse/`. `reverse/main` é a linha de staging/production (o "origin" do projeto). Todo PR vai de `arena/<id>` → `reverse/<id>`; todo merge para produção vai → `reverse/main`. Tags `v*`/`drafto-v*` são criadas **somente em `reverse/main`** e são o gatilho de automação canônico. A trilha `reverse/` é independente de `main` histórico (não mistura). Esta regra é **perpétua** — novos branches/PRs seguem o fluxo `reverse/`.
- **ADR-006 — Paridade P0 no core (aditiva, não-quebrante):** aprovado. Campos novos em `Draft` (`AccessedAt`, `TrashedAt`) são `omitempty`; `SortName` acrescentado ao fim do enum `Sort` (estabilidade numérica para o boundary gomobile); capabilities **opcionais** (`TrashPruner`, `ClipboardReader`) em vez de métodos novos na `Store` interface — o bridge AppleScript e o boundary Android não quebram. Trash retention padrão = 30 dias (paridade Drafts), desativável com `SetTrashRetention(0)`.

## 5. Riscos atuais

- Go não compila neste sandbox (rede restrita). Primeira ação do dev: `go build ./...`.
- ~~SQLite backend ainda não implementado (Phase 1).~~ ✅ Implementado e coberto por testes de integração.
- Android não compilado (sem SDK/network). Scaffold pronto, precisa de ambiente Android.

## 6. Checklist de continuidade

- [x] `go build ./...` verde
- [x] `go test ./...` verde
- [x] `go vet ./...` limpo
  > Evidência: CI do PR #11 (`77f1996`) — job "Go build, vet, test" pass, 45 testes nomeados + `-race`.
- [x] CI configurada (`ci.yml`) + release por tag (`release.yml`)
- [x] `core/sqlitestore` implementado (com FTS5 + purge)
- [x] `cmd/drafto` Linux funcional com persistência
- [ ] Android APK installa e captura funciona
