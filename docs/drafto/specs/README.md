# Drafto — Sistema de Specs

> Onde cada trabalho de produto é **especificado antes de ser codado**. A matriz de fases está em
> [`../05-ROADMAP.md`](../05-ROADMAP.md); o plano de execução, paralelismo e pré-requisitos por spec
> está em [`../07-ROADMAP-EXECUCAO.md`](../07-ROADMAP-EXECUCAO.md). Esta pasta guarda **uma spec por
> arquivo** (e é o lugar onde a spec nasce, não o commit de implementação).

## Por que spec antes de código

A auditoria de 2026-11-12 ([`../08-AUDIT-2026-11-12.md`](../08-AUDIT-2026-11-12.md)) encontrou 11
divergências doc↔código — quase todas nascem do mesmo padrão: item marcado como pronto **sem critério
de aceite escrito**. Spec é o contrato que torna o "pronto" verificável. Além disso, o sandbox onde o
projeto roda **não tem toolchain Go/Java** (egress bloqueia `go.dev` e `proxy.golang.org`): a única
validação possível é a CI, e a CI só é útil se houver um critério objetivo escrito.

## Anatomia (obrigatória)

Esqueleto: [`_TEMPLATE.md`](_TEMPLATE.md). Campos mínimos:

| Campo | Conteúdo |
|---|---|
| ID / Título / Status | `SPEC-<ÁREA>-<NN>`, `draft` → `ready-for-execution` → `in-progress` → `done` |
| Workspace & lane | `core/` · `cmd/drafto/` · `android/` · `docs/**` · `rev-ios` (ver 07 §5.1) |
| Contexto | problema, evidência (`arquivo:linha`), o que muda para o usuário/agente |
| DoR (**critério de início**) | pré-requisitos **verificáveis** — comando/consulta por item; "ninguém começa sem marcar todos" |
| Escopo / Não-escopo | lista explícita do que fica fora (evita drift de fase) |
| Contrato | tipos, JSON, CLI, migração — o que outros consumidores vão ler |
| Plano de implementação | passos incrementais, cada um verde no CI antes do próximo |
| DoD (aceite) | testes + comando de demonstração + docs atualizadas |
| Riscos & rollback | como reverter, o que quebra se errar |

## Status de todas as specs

| ID | Título | Lane | Status | Bloqueado por |
|---|---|---|---|---|
| `SPEC-OPS-01` | Fechar ciclo v0.3.0 (G1+G2+gates) → tag | Q | `ready-for-execution` 🔒 | CI do `arena/26d3ae79` verde |
| `SPEC-OPS-02` | Higiene de docs, `LICENSE`, ADRs | Q | `ready-for-execution` | — |
| `SPEC-OPS-03` | `Makefile` + diagnóstico de CI por anotações | Q | `draft` | — |
| `SPEC-CORE-01` | Suíte de conformidade Memory ↔ SQLite (`core/storetest`) | C | `draft` | — |
| `SPEC-CORE-02` | `WorkspaceStore` (contrato simétrico de workspaces) | C | `blocked` | CORE-01 |
| `SPEC-CORE-03` | Actions & `action_logs` & `versions` persistentes | C | `blocked` | CORE-01, ADR-009 |
| `SPEC-CORE-04` | Rigor de steps, `RunOnText` transiente, sort estável | C | `blocked` | CORE-03 |
| `SPEC-CORE-05` | FTS5 ranqueado | C | `deferred` | — |
| `SPEC-CLI-01` | Paridade de superfície `drafto` ↔ `Store` | L | `blocked` | CORE-02 (workspaces) |
| `SPEC-CLI-02` | DX de agente (`--dry-run`, mask, NDJSON, score ≥17/21) | L | `blocked` | CLI-01 |
| `SPEC-AND-01` | Boundary gomobile v2 (DTO flat JSON) | A | `blocked` | OPS-01 |
| `SPEC-AND-02` | G3 — ActionSheet + actions na UI | A | `blocked` | AND-01, CORE-03 |
| `SPEC-AND-03` | Lista: pastas, sort, filtros, purge | A | `blocked` | AND-01 |
| `SPEC-AND-04` | `ACTION_SEND` + deep links `drafto://` | A | `ready-for-execution` ∥ | — |
| `SPEC-AND-05` | Aceite em device + kit de screenshots | A | `blocked` | AND-02/03/04 |
| `SPEC-PROD-01` | Export/import + backup local | P | `draft` | CORE-03, CLI-01 |
| `SPEC-PROD-02` | Modelo de dados confirmado por evidência + versions/rollback | P | `blocked` | `SPEC-REVIOS-001` C2–C3 |
| `SPEC-PROD-03` | `drafto://` completo + x-callback-url (contrato do core) | P | `blocked` | AND-04, ADR-010 |
| `SPEC-PROD-04` | Sync multi-device (change-log + tombstones) | P | `deferred` | PROD-02 |
| `SPEC-REVIOS-001` | Captura & extração do Get Drafts iOS | R | `ready-for-execution` (C0) ∥ | ambiente macOS/iOS |

## Regras de abertura de spec

1. **Uma spec = uma sessão = um branch `arena/<id>`** → PR para `reverse/<id>` (ADR-005). Não misturar
   duas specs no mesmo PR.
2. Nome do arquivo: `SPEC-<ÁREA>-<NN>-<slug>.md`. `ÁREA ∈ {CORE, CLI, AND, PROD, OPS, REVIOS}`.
3. A spec entra como `draft`; vira `ready-for-execution` **somente** quando todos os `DoR` têm comando
   de verificação. Marcar `blocked` + `bloqueado por <ID>` é preferível a começar e brigar no merge.
4. Se a spec muda `Store`, o envelope JSON da CLI, o schema SQLite ou o boundary gomobile → exige
   **ADR nova** (`docs/drafto/adr/`) e 2 reviews (governança §7).
5. Toda spec concluída atualiza, **no mesmo PR**: `../05-ROADMAP.md` (checkbox com evidência),
   `../02-FEATURE-PARITY.md` (status da feature) e `../06-HANDOFF.md` (§1 estado, §6 checklist).
6. Paralelismo: siga a matriz 07 §5.3. Duas specs na mesma lane **não** rodam juntas se tocam o mesmo
   arquivo; `docs/**` roda sempre em paralelo com tudo.
7. **Produção paralela e merge:** [`../09-WORKSPACES-PARALELOS.md`](../09-WORKSPACES-PARALELOS.md) define a
   posse de arquivo por workspace (W1–W6), o claim com `automation:lane-lock` como mutex da lane, o rebase na
   base de destino antes do PR de integração e a fila de `reverse/main`. A versão curta dessas regras está na
   seção **§9** de cada issue de spec — começar sem ler o §9 da sua lane é apostar que ninguém tocou no
   mesmo arquivo.
