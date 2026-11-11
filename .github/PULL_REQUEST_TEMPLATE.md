<!--
Fluxo canônico `reverse/` — ADR-005 (docs/drafto/04-GOVERNANCE.md §1.1/§1.2).
Regra PERPÉTUA: todo PR é do branch de trabalho → um branch reverse/<...>;
todo merge para produção (staging/production) vai → reverse/main; tags v*
só em reverse/main e são o gatilho de automação de release.
-->

## Fluxo `reverse/` (obrigatório)

- [ ] **Head** = branch de trabalho (`arena/<id>-getdrafts-cli` ou `feat|fix|chore/<scope>-<slug>`)
- [ ] **Base** = `reverse/<id>-getdrafts-cli` (nunca `main` direto — `main` é base histórica, não mistura)
- [ ] Integração staging/production = PR separado `reverse/<id>` → `reverse/main`

## Versionamento & automação

- [ ] Sem breaking change sem version bump (SemVer: MAJOR.MINOR.PATCH)
- [ ] Tag `vX.Y.Z` (ou `drafto-vX.Y.Z`) proposta/criada **somente após merge em `reverse/main`** — ela dispara o workflow `release.yml` (goreleaser)

## Qualidade

- [ ] `go build ./... && go vet ./... && go test ./...` verde (CI valida; sandbox local não tem toolchain Go)
- [ ] Docs atualizadas (`docs/drafto/06-HANDOFF.md` quando muda o estado do projeto; `02-FEATURE-PARITY.md` quando muda paridade)
- [ ] Commits seguem convenção `<type>(<scope>): <description>` (§2 da governança)
