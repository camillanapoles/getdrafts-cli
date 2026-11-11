# Drafto — Handoff / Estado atual

## 1. Onde o projeto está (esta sessão)

- **Repositório:** `getdrafts-cli` (monorepo Drafto). Branch de sessão: `arena/6e14a37f-getdrafts-cli`.
- **Trilha canônica (ADR-005):** namespace `reverse/`. `reverse/main` = staging/production (o "origin"). Fluxo: `arena/<id>` → PR → `reverse/<id>` → PR/merge → `reverse/main` → tag `vX.Y.Z`. Tags são gatilho de automação.
- **Base:** CLI Go (macOS/AppleScript) já existente e estável (commit `8b43a14`).
- **Novo:** pacote `core/` (Go, platform-agnostic) — o engine compartilhado.
- **Documentação:** `docs/drafto/00..06` + `CODEMAP.md`.

## 2. Como continuar (próximos passos óbvios)

1. **Validar o build** (necessita toolchain Go):
   ```bash
   go build ./... && go test ./... && go vet ./...
   ```
2. **Iniciar Phase 1:** implementar `core/sqlitestore` + `cmd/drafto` Linux.
3. **Iniciar Phase 2:** Android — `gomobile bind` + UI Compose.
4. **CI:** adicionar GitHub Actions (test/build/android).

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
- **ADR-006 — Trilha de análise `rev-ios/` + skill vendored (2026-11-11):** aprovado. A engenharia
  reversa do Get Drafts iOS vive em `rev-ios/<slug>` com spec própria em `docs/rev-ios/00-SPEC.md`, skill
  `ios-app-security-audit` (DragonJAR, Apache-2.0) **vendored e pinned** em `skills/ios-app-security-audit/`,
  skill de procedimento local em `skills/getdrafts-ios-rev/` e harness em `tools/rev-ios/`. Padrão de
  trabalho: *run* com cadeia de custódia → cartão de evidência (E1–E4) → linha no `LEDGER.md` → doc de
  produto → **só então** código. Binários/recursos/dados nunca entram no repo. Tags planas `rev-ios-*`.
- **ADR-005 — Estrutura paralela `reverse/` (canônica, perpétua):** aprovado. A trilha canônica do Drafto é o namespace `reverse/`. `reverse/main` é a linha de staging/production (o "origin" do projeto). Todo PR vai de `arena/<id>` → `reverse/<id>`; todo merge para produção vai → `reverse/main`. Tags `v*`/`drafto-v*` são criadas **somente em `reverse/main`** e são o gatilho de automação canônico. A trilha `reverse/` é independente de `main` histórico (não mistura). Esta regra é **perpétua** — novos branches/PRs seguem o fluxo `reverse/`.

## 4.1 Trilha de evidência (rev-ios)

- Spec/plano/mapas/ledger: [`docs/rev-ios/`](../rev-ios/README.md) · harness: [`tools/rev-ios/`](../../tools/rev-ios/README.md)
- Estado: **C0 fechada** (ferramenta validada em Linux com *fixture*; nada do app-alvo capturado ainda).
- Se você tem um Mac: comece por `CAP-003` (backup sintético → `triage --kind user-backup`) e `S2`
  (`DraftStore.sqlite`) — são os dois caminhos que **respondem o modelo de dados sem jailbreak**.
- Nunca: editar `skills/ios-app-security-audit/**` (o pin quebra), commitar artefato, usar
  bypass/repackaging do skill (fora de escopo).

## 5. Riscos atuais

- Go não compila neste sandbox (rede restrita). Primeira ação do dev: `go build ./...`.
- SQLite backend ainda não implementado (Phase 1).
- Android não compilado (sem SDK/network). Scaffold pronto, precisa de ambiente Android.

## 6. Checklist de continuidade

- [ ] `go build ./...` verde
- [ ] `go test ./...` verde
- [ ] `go vet ./...` limpo
- [ ] CI configurada
- [ ] `core/sqlitestore` implementado
- [ ] `cmd/drafto` Linux funcional
- [ ] Android APK installa e captura funciona
