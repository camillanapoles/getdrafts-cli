# Drafto — Governança

## 1. Modelo de branches (trunk-based + feature branches)

> **Estrutura paralela `reverse/` (canônica, a partir de 2026-11-11)** — decisão do cliente para **não misturar** a trilha de desenvolvimento com a linha de releases. O namespace `reverse/` é a **trilha canônica** do Drafto; o `main` original permanece como base histórica. Veja a seção **1.1** abaixo — esta regra é **perpétua**.

- **Branch principal protegida (canônica):** `reverse/main`. Linha de staging/production, sempre estável, pronto para release. **Este é o "origin" do projeto.**
- **Branch de sessão/Arena (trabalho incremental):** `arena/<id>-getdrafts-cli`. Usada para trabalho incremental.
- **Branches canônicas de feature:** `reverse/<ponteiro>` — um branch `reverse/<...>` por cada branch de trabalho (ex: `reverse/6e14a37f-getdrafts-cli`).
- **Branch original:** `main` — base histórica, não recebe trabalho novo direto; a trilha canônica é `reverse/main`.
- **Branches de feature (histórico/opcional):** `feat/<scope>-<slug>`, `fix/<scope>-<slug>`, `chore/<scope>-<slug>`.
- **Branches de release:** `release/<semver>`.
- **Trilha de análise (paralela, isolada):** `rev-ios/<slug>` — ver **§1.4**. É o namespace da engenharia
  reversa do app iOS original (captura/extração/layout). **Não** é trilha de produto: não desenvolve o Drafto.
  Nasce de `reverse/main` (ou do branch de sessão que carrega a spec), é destruída após integrar os docs.

### 1.1 Fluxo canônico `reverse/` (perpétuo)

> **Regra de ouro:** todo PR é do branch de trabalho (`arena/...`) **→** um branch `reverse/<...>`; e todo merge para produção vai **→ `reverse/main`**. A integração/staging/production é sempre `reverse/main`, versionada por *tags*.

```
arena/6e14a37f-getdrafts-cli ──PR──► reverse/6e14a37f-getdrafts-cli ──PR/merge──► reverse/main ──tag vX.Y.Z──► staging/production
        (trabalho)                      (canônico feature)                        (canônico main, versionado)

main ──────────────●──────────────────────────────────────────────────────────────────── (base histórica, não mistura)
                     \
                      \  (trilha canônica independente)
                       reverse/main ────────────●────────────●────────────●──────────── (staging/production)
                                                 \            \            \
                                          reverse/6e14...    reverse/...  reverse/...
```

**Fluxo de um feature:**
1. Trabalho no branch `arena/<id>-getdrafts-cli` (commits de fato).
2. **PR #1 (canônico):** `arena/<id>-getdrafts-cli` **→** `reverse/<id>-getdrafts-cli` (cria/atualiza o branch canônico do feature).
3. **Merge:** o PR é mesclado; o branch `reverse/<id>-getdrafts-cli` agora contém o trabalho.
4. **PR #2 (integração):** `reverse/<id>-getdrafts-cli` **→** `reverse/main` (leva o feature para staging/production).
5. **Tag:** após merge em `reverse/main`, tag `vX.Y.Z` (ou `drafto-vX.Y.Z`) para automação (CI, goreleaser, release).

### 1.2 Regras da trilha `reverse/` (perpétuas)

1. **Todo PR vai para um branch `reverse/<...>`**, nunca direto para `reverse/main` (exceto hotfix com aprovação).
2. `reverse/main` só recebe merge via PR com CI verde + 1 review (mesma regra de `main`).
3. Branches `reverse/<...>` nascem de `reverse/main` e são destruídos após o merge (squash).
4. O branch da sessão Arena é o branch de trabalho; commits nele são commits de fato, que entram no branch `reverse/<...>` via PR.
5. **Nunca push direto em `reverse/main`** (nem em `main`).
6. **Tags `v*` só em `reverse/main`** após release aprovado (ver seção 3/4).
7. **Versionamento por tag para automação:** cada merge em `reverse/main` deve gerar/propor uma tag (`vX.Y.Z` ou `drafto-vX.Y.Z`) que dispara CI/CD (build, test, goreleaser, release). Tags são o mecanismo de automação canônico.
8. **Não misturar:** a trilha `reverse/` é independente da `main` histórica. `main` não recebe merges da trilha `reverse/` (e vice-versa), exceto por rebase/cherry-pick explícito para alinhamento.

### 1.4 Trilha `rev-ios/` (análise — isolada da trilha de produto)

Regra criada em 2026-11-11 com a spec [`docs/rev-ios/00-SPEC.md`](../rev-ios/00-SPEC.md). Objetivo: a
extração do app iOS (skill vendored, *runs* de captura, *ledger* de evidência) não pode contaminar a linha
de produto, e o produto não pode depender de binários/recursos proprietários no repositório.

| Item | Regra |
|---|---|
| Branch | `rev-ios/<slug>` (ex.: `rev-ios/getdrafts-capture`); slug `kebab-case` ASCII ≤ 40 chars |
| Worktree | `../getdrafts-cli-rev-ios` — `git worktree add ../getdrafts-cli-rev-ios -b rev-ios/<slug>` |
| Commits | escopo `rev-ios` (ex.: `docs(rev-ios): …`, `feat(tools/rev-ios): …`) — filtrável por `git log --grep '(rev-ios)'` |
| Tags | **planas**: `rev-ios-<slug>-<yyyymmdd>`. **Nunca** criar a tag `rev-ios` e também `rev-ios/x`: `refs/tags/` não permite file-vs-directory (verificado). Tags `v*`/`drafto-v*` continuam só em `reverse/main` |
| Conteúdo permitido | `docs/rev-ios/**`, `skills/**`, `tools/rev-ios/**` e as seções de destino em `docs/drafto/*` |
| Proibido | `.ipa`, `Payload/`, `.app`, `.sqlite`, `.car`, screenshots do alvo, dumps, strings/transcrição do binário (ver §7 do SPEC; `.gitignore` já cobre) |
| Código do Drafto | **não** muda aqui. Muda em `reverse/<slug>` com o PR referenciando o cartão de evidência (`docs/rev-ios/findings/NNNN-*.md`) |
| Integração | `rev-ios/<slug>` → PR → `reverse/main` (docs) → os itens de ledger viram PRs de produto |
| Fim de vida | branch removido após o merge dos docs; *tags* `rev-ios-*` permanecem como checkpoint de análise |

```
rev-ios/getdrafts-capture ●──●──●  (C0..C5: runs, findings, ledger)
        │  PR (só docs/tools/skills)
        ▼
reverse/main ─────────────●  (CODEMAP §11 + paridade + roadmap)
        │  abre PRs de produto por obrigação resolvida
        ▼
reverse/drafto-<feature> ●  (core/, android/, cmd/)
```

### 1.3 Fluxo original (mantido para contexto)

```
main ──────────────●────────────●────────────●────────
                     \          \             \
  feat/core-store     ●──●        ●──●          \
  feat/android-ui                  ●──●           \
  release/v0.1.0                     ●────●───────● (tag)
```

## 2. Convenção de commits

```
<type>(<scope>): <description>

<body>
<footer>
```
Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build`, `ci`, `perf`, `style`, `revert`.
Exemplo: `feat(core): add memory store with query filters`.

## 3. Versionamento (SemVer)

- `MAJOR.MINOR.PATCH` (semver).
- `MAJOR`: quebra de contrato de saída (JSON envelope, schema, CLI).
- `MINOR`: feature backward-compatible.
- `PATCH`: correção backward-compatible.
- Build metadata: `+go<commit>` via `ldflags` (goreleaser já faz isso).
- **Tags na trilha `reverse/`:** todas as tags `v*` (e `drafto-v*`) são criadas **em `reverse/main`** apenas, após release aprovado. As tags são o **mecanismo de automação canônico** — cada tag `vX.Y.Z` dispara CI/CD (build, test, goreleaser, release notes).

## 4. Release process (na trilha `reverse/`)

1. Agrupar PRs da fase no branch `reverse/<feature>`; integrar em `reverse/main` via PR (CI verde + review).
2. CI: build + test (linux/darwin/windows) + vet + lint.
3. `goreleaser` para binários (darwin, linux; Android via gomobile script).
4. **Tag `vX.Y.Z` em `reverse/main`** + release notes (com changelog automático por tipo de commit). A tag dispara a automação de release.
5. Asteróides: binário Android (`drafto.apk`) attachado à release.
6. **Hotfix:** branch `reverse/hotfix/<slug>` nasce de `reverse/main`, merge de volta via PR, tag `vX.Y.Z+1`.

## 5. CI/CD

- GitHub Actions (disparam em push/PR/tag):
  - `test`: `go test ./...`, `go vet ./...`, lint.
  - `build`: `go build ./...`, goreleaser snapshot.
  - `android`: gradle assembleDebug + gomobile bind (opcional, com cache).
  - **`release` (on tag `v*`/`drafto-v*` em `reverse/main`):** goreleaser release + upload de binários/APK + changelog.
- Regras de proteção: `reverse/main` (e `main`) requerem CI verde + review; lançamentos requerem tag.
- **Automação por tag:** workflows de release são triggers por tag — a tag `vX.Y.Z` é o gatilho canônico, garantindo que toda release seja versionada e auditável.

## 6. Handoff & continuidade

- **Documentação é código:** docs em `docs/drafto/` são mantidos com o repo.
- **ADRs** (Arquitetura Decision Records): registrar decisões não-óbvias em `docs/drafto/adr/`.
- **Estado do projeto:** `06-HANDOFF.md` atualizado a cada fase.
- **Onboarding:** novo dev lê `06-HANDOFF.md` + `03-ARCHITECTURE.md` e consegue buildar.
- **Commit messages** e PRs descrevem intent, não só mudança.

## 7. Code review

- 1 reviewer mínimo; 2 para mudanças de contrato (Store interface, schema, CLI).
- Checklist: testes, docs, sem breaking change sem version bump, segurança/privacidade.

## 8. Procedimento de rename do module path (opcional, no 1º release oficial)

```bash
# Definir path definitivo, ex: github.com/<org>/drafto
sed -i 's#github.com/nerveband/drafts-applescript-cli#github.com/<org>/drafto#g' \
  go.mod go.sum $(git ls-files '*.go') README.md skills/SKILL.md
go mod tidy
```
> No momento, mantém-se o path original por continuidade. Fazer o rename junto do 1º release oficial.

## 9. Regras de propriedade

- Repo: `camillanapoles/getdrafts-cli` (no momento). Transferir/renomear para o dono do Drafto no 1º release.
- Ações/templates de Drafts: reimplementar; não copiar código proprietário.
- Licença do repo base: MIT (manter atribuição).
