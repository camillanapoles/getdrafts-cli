# Contributing — Drafto (`getdrafts-cli`)

> **Fonte canônica:** `docs/drafto/04-GOVERNANCE.md`. Este arquivo resume as regras
> **perpétuas** para qualquer contribuidor (humano ou agente). Em caso de dúvida, vale a governança.

## 1. Fluxo de branches `reverse/` (PERPÉTUO — ADR-005)

A trilha canônica do Drafto é o namespace **`reverse/`** — estrutura paralela criada para **não misturar** o desenvolvimento do Drafto com o `main` histórico da CLI macOS.

```
arena/<id>-getdrafts-cli  ──PR──►  reverse/<id>-getdrafts-cli  ──PR/merge──►  reverse/main  ──tag vX.Y.Z──►  staging/production
     (trabalho)                    (canônico do feature)                       (canônico "main", versionado)
```

Regras de ouro:

1. **Todo PR** parte de um branch de trabalho (`arena/<id>-getdrafts-cli`, `feat/*`, `fix/*`, `chore/*`) **para um branch `reverse/<...>`** — nunca direto para `reverse/main`.
2. **`reverse/main` é o "origin" do projeto** (staging/production). Integração para produção = PR `reverse/<id>` → `reverse/main`, com CI verde + review.
3. **`main` histórico não mistura**: não recebe merges da trilha `reverse/` (e vice-versa).
4. **Tags `v*` / `drafto-v*` só em `reverse/main`**, após merge aprovado. A tag é o **gatilho canônico de automação**: dispara `.github/workflows/release.yml` (goreleaser + changelog).
5. Versionamento SemVer: MAJOR = quebra de contrato (JSON/CLI/Store), MINOR = feature backward-compatible, PATCH = fix.
6. Branches `reverse/<...>` nascem de `reverse/main` e são removidos após o merge (squash).

## 2. Commits

Convenção `<type>(<scope>): <description>` — types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build`, `ci`, `perf`, `style`, `revert`.
Ex.: `feat(core): trash auto-delete after 30 days (Drafts parity)`.

## 3. Validação

A sandbox de desenvolvimento normalmente **não tem toolchain Go** — a CI é a validação oficial:

```bash
go build ./... && go vet ./... && go test ./...   # local (se Go disponível)
# senão: abra o PR e acompanhe as checks (gh pr checks <n> / gh run watch)
```

Estabelecido: PRs com erro de build são corrigidos em commits `fix(drafto): ... (CI)` — ver histórico PRs #4–#6.

## 4. Mudanças no `core/` (contrato compartilhado)

- O modelo `core.Draft` e a interface `core.Store` são consumidos por **todos os clientes** (CLI macOS bridge `pkg/drafts`, CLI Linux `cmd/drafto`, Android via gomobile `android/core-go`).
- **Nunca quebre a `Store` interface** em um PR comum. Prefira **capabilities opcionais** (`TrashPruner`, `ClipboardReader`) e campos `omitempty`.
- Novos valores de enums (`Sort`, `Filter`, `Folder`) vão **ao final** do `iota` (estabilidade numérica para o binding gomobile) e devem ser aliasados em `pkg/drafts/struct.go`.
- Toda feature nova no `core/` ganha testes em `core/*_test.go` (o `MemoryStore` documenta as semânticas de referência que o SQLite/AppleScript devem reproduzir).

## 5. Documentação como código

- Estado do projeto: `docs/drafto/06-HANDOFF.md` (atualizar a cada fase/sessão).
- Paridade de features: `docs/drafto/02-FEATURE-PARITY.md` (fonte de verdade).
- Mapa estrutural: `docs/drafto/CODEMAP.md`.
- Decisões: ADRs em `docs/drafto/06-HANDOFF.md` §4.
