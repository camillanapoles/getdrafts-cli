# Drafto — Governança

## 1. Modelo de branches (trunk-based + feature branches)

- **Branch principal protegida:** `main`. Siempre estável, pronto para release.
- **Branch de sessão/Arena:** `arena/<id>-getdrafts-cli` (atual). Usada para trabalho incremental.
- **Branches de feature:** `feat/<scope>-<slug>`, `fix/<scope>-<slug>`, `chore/<scope>-<slug>`.
- **Branches de release:** `release/<semver>`.

### Fluxo
```
main ──────────────●────────────●────────────●────────
                     \          \             \
  feat/core-store     ●──●        ●──●          \
  feat/android-ui                  ●──●           \
  release/v0.1.0                     ●────●───────● (tag)
```

### Regras
1. `main` só recebe merge via PR com CI verde + 1 review.
2. Branches de feature nascem de `main` e são destruídas após o merge (squash).
3. O branch da sessão Arena é o branch de trabalho incremental; commits nele são commits de fato.
4. Nunca push direto em `main`.
5. Tags `v*` só em `main` após release aprovado.

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

## 4. Release process

1. Agrupar PRs da fase no branch `release/<ver>`.
2. CI: build + test (linux/darwin/windows) + vet + lint.
3. `goreleaser` para binários (darwin, linux; Android via gomobile script).
4. Tag `vX.Y.Z` + release notes (com changelog automático por tipo de commit).
5. Asteróides: binário Android (`drafto.apk`) attachado à release.

## 5. CI/CD

- GitHub Actions:
  - `test`: `go test ./...`, `go vet ./...`, lint.
  - `build`: `go build ./...`, goreleaser snapshot.
  - `android`: gradle assembleDebug + gomobile bind (opcional, com cache).
- Regras de proteção: `main` requer CI verde + review; lançamentos requerem tag.

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
