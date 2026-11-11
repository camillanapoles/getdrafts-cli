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
- **ADR-005 — Estrutura paralela `reverse/` (canônica, perpétua):** aprovado. A trilha canônica do Drafto é o namespace `reverse/`. `reverse/main` é a linha de staging/production (o "origin" do projeto). Todo PR vai de `arena/<id>` → `reverse/<id>`; todo merge para produção vai → `reverse/main`. Tags `v*`/`drafto-v*` são criadas **somente em `reverse/main`** e são o gatilho de automação canônico. A trilha `reverse/` é independente de `main` histórico (não mistura). Esta regra é **perpétua** — novos branches/PRs seguem o fluxo `reverse/`.

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
