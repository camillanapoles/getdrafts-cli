# SPEC-<ÁREA>-<NN> — <Título curto, verbo no infinitivo>

| | |
|---|---|
| **Status** | `draft` \| `ready-for-execution` \| `in-progress` \| `done` \| `blocked` \| `deferred` |
| **Data** | YYYY-MM-DD |
| **Autor/sessão** | `arena/<id>-getdrafts-cli` |
| **Ramo canônico** | `reverse/<id>-getdrafts-cli` → `reverse/main` |
| **Lane / Workspace** | C `core/` · L `cmd/drafto/` · A `android/` · Q `docs/**` · R `rev-ios` |
| **Arquivos tocados** | `path/a.go`, `path/b.kt` *(conflito com outras specs? qual?)* |
| **Depende de** | `SPEC-…` (motivo técnico, não burocrático) |
| **Bloqueia** | `SPEC-…` |
| **Esforço** | S \| M \| L \| XL (≈ nº de sessões) |
| **Docs que atualiza no fim** | `02-FEATURE-PARITY.md`, `05-ROADMAP.md`, `06-HANDOFF.md` |

---

## 1. Contexto (por que agora)

<2–6 linhas. O problema do usuário/agente, não a solução.>

**Evidência** (obrigatório — `arquivo:linha` ou comando + saída):

| # | Alegação | Onde verificar |
|---|---|---|
| E1 | | `core/store.go:00` |
| E2 | | `gh api …` / captura / log de CI |

## 2. DoR — critérios de início (o que precisa ser verdade para **começar**)

> Cada item tem um comando/consulta verificável. Alguém só abre código depois de marcar todos.

- [ ] **Base:** `git fetch origin "+refs/heads/*:refs/remotes/origin/*"` e `git log --oneline HEAD..origin/reverse/main` vazio (ou lista o que será rebasado).
- [ ] **CI:** job "Go build, vet, test" verde no head da base (`gh api repos/…/actions/runs?per_page=3`).
- [ ] **Contrato:** <nenhuma spec aberta tocando `arquivo` → `gh pr list --state open`>.
- [ ] **Dependências:** <spec X mesclada; evidência: commit/tag>.
- [ ] **Ambiente:** <Go/gradle só existem no CI; precisa device? precisa macOS+Drafts? precisa iOS/ipa?>
- [ ] **Decisão de contrato:** <sem mudança de `Store`/envelope/schema/boundary **ou** ADR-NNR aprovada>.

## 3. Escopo

1. …
2. …

## 4. Não-escopo (para onde olhar depois)

- … → `SPEC-…`

## 5. Contrato

<Definições que os consumidores lêem: struct Go, JSON de saída, comando de CLI, schema SQL, método do
boundary gomobile. Incluir exemplo real de saída e os erros possíveis/códigos. É aqui que se decide o
que é breaking change.>

```go
// exemplo
```
```json
{ "success": true, "data": {} }
```

## 6. Plano de implementação (incrementos verificáveis)

| # | Incremento | Verificação (CI) | PR |
|---|---|---|---|
| 1 | | `go test ./core/... -run TestX` | |
| 2 | | | |

## 7. DoD — critérios de aceite

- [ ] Teste(s) novo(s) nomeado(s) e verdes no CI: `TestX`, `TestY`.
- [ ] `go build ./... && go vet ./... && go test ./... && go test -race ./core/...` verdes.
- [ ] Comando de demonstração (colado no PR com a saída real):
      ```bash
      drafto --memory create "…" && drafto --memory list --json
      ```
- [ ] Docs atualizadas: `02` (status da feature), `05` (checkbox com evidência), `06` (estado/checklist).
- [ ] Sem ✅ novo em doc sem linha de código/teste citável.

## 8. Riscos & rollback

| Risco | Mitigação | Rollback |
|---|---|---|
| | | revert do PR + `PATCH` bump |

## 9. Notas de execução (preencher durante o trabalho)

- Hipóteses testadas e o que morreu (evita repetir os "3 ciclos de CI" da lição de 2026-11-12).
- Diagnóstico de CI: expor erro como **anotação/artefato**, não depender do log (egress corta).
