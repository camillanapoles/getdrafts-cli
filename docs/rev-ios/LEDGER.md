# LEDGER — Obrigações de paridade (evidência iOS → Drafto)

> Artefato **vivo** desta trilha. É a única lista cujo *status* muda sem reescrever a spec.
> Uma linha só sai de `open` com **evidência linkada** ([00-SPEC.md](00-SPEC.md) §6, [03-CODEMAP-BRIDGE.md](03-CODEMAP-BRIDGE.md) §2).
> Formato dos cartões: [FINDINGS-TEMPLATE.md](FINDINGS-TEMPLATE.md).

**Vocabulário de status**

| Status | Significado |
|---|---|
| `ready` | dá para executar agora (Tier A) |
| `open` | pendente, executável em Tier B/C |
| `blocked-env` | exige ambiente que não existe aqui (Mac/device); decisão explícita, não esquecimento |
| `in-progress` | alguém está com isso agora |
| `evidence` | cartão aceito → libera PR de produto na trilha `reverse/` |
| `adapt` | confirmado, mas a mecânica Android é diferente (justificativa obrigatória) |
| `reject` | confirmado e decidido não fazer (justificativa obrigatória) |
| `informational` | não gera código, gera entendimento |
| `deferred` | vai para Phase >2 do roadmap |

**Colunas**: Superfície/Fonte conforme [01-CAPTURE-PLAN.md](01-CAPTURE-PLAN.md) §2 · Fase conforme
[00-SPEC.md](00-SPEC.md) §5 · Alvo = arquivo no Drafto (ver [02-EXTRACTION-MAP.md](02-EXTRACTION-MAP.md) §6).

---

## 1. Captura (pré-requisito de tudo)

| ID | Obrigações | Surf | Fase | Alvo no Drafto | Evidência | Status |
|---|---|---|---|---|---|---|
| `CAP-001` | Confirmar `bundle_id`, `build` e `min iOS` do alvo (não confiar na tabela do 01 §1) | S3 | C1 | `docs/rev-ios/01` (atualizar tabela) | E2 | `ready` (precisa `ipatool`) |
| `CAP-002` | Adquirir IPA + `SHA256SUMS` + `provenance.json` num *run* novo | S3 | C1 | — | — | `ready` (`capture.sh acquire`) |
| `CAP-003` | Backup/export **sintético** do Drafts (20 drafts, 3 actions, 2 workspaces) extraído em JSON | S6 | C1 | `import/shape.json` do *run* | E2 | `ready` ← **melhor ROI; instrumento validado em F-0001, só falta o arquivo** |
| `CAP-004` | Cópia de `DraftStore.sqlite` da instância sintética no Mac | S2 | C1 | `db/` | — | `blocked-env` (Tier B) |
| `CAP-005` | Decifrar binário iOS **somente se** houver pergunta nomeada que só S4 responde | S4 | C1 | — | — | `deferred` (decisão: não abrir sem pergunta) |

## 2. Modelo de dados (o que muda `core/model.go` + schema do roadmap)

| ID | Pergunta | Surf | Fase | Alvo | Evidência | Status |
|---|---|---|---|---|---|---|
| `OB-MODEL-001` | Lista completa de campos do draft, tipos, nullabilidade e defaults | S2/S6 | C3 | `core/model.go`, schema [`05-ROADMAP.md`](../drafto/05-ROADMAP.md) | E3 | `blocked-env` |
| `OB-MODEL-002` | `folder`: nomes exatos dos estados (`inbox`/`archive`/`trash`/…?) e onde fica *flagged* | S2 | C3 | `core/model.go` `Folder` | E3 | `blocked-env` |
| `OB-MODEL-003` | `content`: texto puro? RTF/attributed? onde vivem atributos de formatação? | S2/S6 | C3 | `core/model.go`, `EditorScreen` | E3 | `blocked-env` |
| `OB-MODEL-004` | `title`: derivado (1ª linha) ou persistido? truncamento? | S2 | C3 | `core/model.go` `titleOf` | E3 | `ready` (via S6) |
| `OB-MODEL-005` | `tags`: separador real, *case*, `#`/`@`, espaços, sub-tags (`>` ou `/`) | S2/S6 | C3 | `core/options.go` `Options` | E3 | `ready` (via S6) |
| `OB-MODEL-006` | `syntax`/grammar: como o app escolhe a gramática do editor por draft | S2/S5 | C3 | `core/model.go`, `EditorScreen` | E3 | `blocked-env` |
| `OB-MODEL-007` | `created/modified/accessed`: quais timestamps existem de verdade | S2 | C3 | `core/model.go` | E3 | `blocked-env` |
| `OB-MODEL-008` | `permalink`: formato (`drafts://open?uuid=` vs outro) | S2/S5 | C2 | `drafto://` | E2+E4 | `open` |
| `OB-MODEL-009` | Geolocalização: `created_lat/lon`, `modified_lat/lon` existem? opt-in? | S2 | C3 | `AndroidManifest` (permissão!) | E3 | `blocked-env` |
| `OB-MODEL-010` | *Version history*: granularidade, limite, *pruning*, API de rollback | S2 | C3 | `versions` table, `EditorScreen` | E3 | `blocked-env` |
| `OB-MODEL-011` | Tasks (`- [ ]`, Taskpaper): persistidas ou derivadas? estado por tarefa? | S2/S6 | C3 | `core/model.go`, syntax | E3 | `ready` (via S6) |
| `OB-MODEL-012` | `linkedItems` (wiki-links) e `urls`: derivados ou materializados (tabela?) | S2 | C3 | Phase 3 (`linked`) | E3 | `blocked-env` |
| `OB-MODEL-013` | Anexos/URLs de arquivo no draft (Drafts aceita URLs de arquivo) | S2/S6 | C3 | `core` + *FileProvider* | E3 | `open` |

## 3. Ações, templates e automação (o coração do produto)

| ID | Pergunta | Surf | Fase | Alvo | Evidência | Status |
|---|---|---|---|---|---|---|
| `OB-ACTION-001` | *Step types* aceitos pelo parser (enum completo) + config por tipo | S6/S3/S5 | C3/C4 | `core/action.go`, `android/core-go/action.go` `ParseAction` | E2→E4 | `ready` ← S6 responde |
| `OB-ACTION-002` | `afterSuccess`: opções exatas (`archive`/`trash`/`keep`/`move`?) | S6 | C4 | `core/action.go` `applyAfterSuccess` | E2 | `ready` |
| `OB-ACTION-003` | Formato serializado de *action group* (`.actionset`/JSON) e instalação por URL | S3/S6 | C3 | `RegisterAction` (gomobile) | E2 | `open` |
| `OB-ACTION-004` | Ordem/estabilidade de grupos na *action bar* | S5/S2 | C4 | `core/action.go` | E3 | `blocked-env` |
| `OB-TPL-001` | **P0 do codemap §8.1**: lista completa de template tags (`[[clipboard]]` existe?) | S3/S5 | C4 | `core/template.go` | E2+E4 | `ready` (strings) / `blocked-env` (confirmação) |
| `OB-TPL-002` | Sintaxe das tags: argumentos, default, *filters*, escape | S6 | C4 | `core/template.go` | E2 | `open` |
| `OB-TPL-003` | `[[date]]` formatos aceitos | S6/S5 | C4 | `core/template.go` | E3 | `open` |
| `OB-RUN-001` | O que acontece em erro de step (rollback? log? *partial*) | S5 | C4 | `core/action.go` | E4 | `blocked-env` |
| `OB-RUN-002` | `actionLogs`: o que é gravado por execução | S2 | C3 | `action_logs` table | E3 | `blocked-env` |
| `OB-SCR-001` | JS API (`Draft`, `Editor`, `App`, `Action`, `Workspace`): o **conjunto de métodos** que precisamos expor no `drafto` (não o runtime JS) | S1/docs+S3 | C2 | `core` API surface | E2 | `ready` (S1 no Mac; docs já mapeados em `01-GETDRAFTS-INVESTIGATION.md` §4.3) |

## 4. Organização: workspaces, busca, ordenação, *arrange*

| ID | Pergunta | Surf | Fase | Alvo | Evidência | Status |
|---|---|---|---|---|---|---|
| `OB-WS-001` | Campos de um *workspace* (nome, folder, tags, omit, search, sort, *action group*, *default*) | S2/S6 | C3 | `core.Workspace`, `workspaces` table | E3 | `ready` (via S6) |
| `OB-WS-002` | Comportamento de *default workspace* e *applyWorkspace* | S1/S5 | C4 | `MemoryStore.resolveWorkspace` | E4 | `blocked-env` |
| `OB-SEARCH-001` | **P0 §8.2**: FTS5? `LIKE`? *Core Data predicate*? índices existentes | S2 | C3 | `sqlitestore`, `drafts_fts` | E3 | `blocked-env` |
| `OB-SEARCH-002` | *Quick search* vs busca plena: escopo (content/title/tags), realce | S5 | C4 | `DraftListScreen` | E4 | `blocked-env` |
| `OB-SORT-001` | **P0 §8.3**: lista exata de *sorts* + `SortFlaggedToTop` + default por workspace | S2/S5 | C3/C4 | `core/memory.go` `Query` | E3 | `blocked-env` |
| `OB-TRASH-001` | **P0 §8.5**: auto-delete 30 dias — mecanismo, campo-fonte, onde roda | S2/S4/S5 | C4 | `sqlitestore` + *worker* Android | E4 | `blocked-env` |
| `OB-ARR-001` | *Arrange mode*: operações em lote (merge, tag, move) e semântica de merge | S5 | C4 | Phase 3 | E4 | `deferred` |
| `OB-IMP-001` | Formato de *backup* (para o Drafto importar/exportar compatível com o usuário migrando) | S6 | C3 | `drafto import/export` | E2 | `ready` ← **diferencial de adoção** |

## 5. Superfície de captura e interoperabilidade

| ID | Pergunta | Surf | Fase | Alvo | Evidência | Status |
|---|---|---|---|---|---|---|
| `OB-URL-001` | Confirmar os ~19 comandos `drafts://` + parâmetros + quais são indocumentados | S3/S5 | C2 | `cmd/drafto`, `drafto://` | E2+E4 | `open` |
| `OB-URL-002` | `x-callback-url` (`x-success`, `x-error`, `x-cancel`) suportado? | S5 | C4 | `drafto://` | E4 | `blocked-env` |
| `OB-EXT-001` | Extensões do app (Share, Quick Look, Widget, Watch, Keyboard) e o que cada uma faz | S3 | C2 | `AndroidManifest` (`ACTION_SEND`), Glance widget, `Tiles` | E2 | `ready` |
| `OB-CAP-001` | *Quick capture*: Siri, widget, *share sheet*, ditado, *file import* → equivalentes Android | S3/S5 | C2 | `MainActivity` + *shortcuts* + `ACTION_SEND` | E2 | `open` |
| `OB-APP-001` | *URL schemes* que o app **consulta** (`LSApplicationQueriesSchemes`) → *intent queries* Android | S3 | C2 | `<queries>` no manifest | E2 | `ready` |
| `OB-PERM-001` | `NS*UsageDescription` → permissões Android equivalentes (location, microphone, …) | S3 | C2 | `AndroidManifest.xml` | E2 | `ready` |
| `OB-GRP-001` | App Groups usados (contêiner compartilhado) → análogo Android (arquivo em app-specific storage/*FileProvider*) | S3/S5 | C2 | `DraftoApp` | E2 | `open` |
| `OB-PRO-001` | O que é *gated* por assinatura (Drafts Pro) → informar divisão free/paid do Drafto | S3/S4 | C2 | decisão de produto | E2 | `informational` |

## 6. Layout (detalhe em [04-LAYOUT-PARITY.md](04-LAYOUT-PARITY.md))

| ID | Pergunta | Surf | Fase | Alvo | Evidência | Status |
|---|---|---|---|---|---|---|
| `OB-LAY-001` | Paleta real (light + dark) por `Assets.car` + *dump* de runtime | S3/S5 | C5 | `ui/theme/Color.kt` | E2+E4 | `blocked-env` |
| `OB-LAY-002` | Escala tipográfica do editor e da lista (tamanhos, pesos, *leading*) | S3/S5 | C5 | `ui/theme/Theme.kt` | E4 | `blocked-env` |
| `OB-LAY-003` | Métricas da célula da lista (altura, *insets*, nº de linhas de *preview*, data à direita) | S5 | C5 | `ui/DraftListScreen.kt` | E4 | `blocked-env` |
| `OB-LAY-004` | Métricas do *action bar* acima do teclado | S5 | C5 | `ui/EditorScreen.kt` | E4 | `blocked-env` |
| `OB-LAY-005` | Fontes empacotadas + *font picker* do usuário (o que é configurável) | S3 | C2 | *settings* do Drafto | E2 | `open` |
| `OB-LAY-006` | Estados: *empty state*, busca, seleção múltipla, *archive/trash* (rótulos e ícones **próprios**) | S5 | C5 | `ui/*` | E4 | `open` |
| `OB-LAY-007` | Comportamento no iPad/*split* → decisão de *window size class* | S3/S5 | C5 | `MainActivity` | E2 | `open` |
| `OB-LAY-008` | `layout-dump.js` (nossa) escrito e versionado em `tools/rev-ios/frida/` | — | C5 | ferramenta | — | `open` |

## 7. Ferramental & housekeeping

| ID | Obrigações | Fase | Status |
|---|---|---|---|
| `TOOL-001` | `capture.sh` cobre `preflight`/`new-run`/`acquire`/`triage`/`surface`/`hash`/`purge` | C0 | `evidence` → [F-0001](findings/0001-harness-e-toolchain.md) |
| `TOOL-002` | `install-skill.sh` instala/valida o skill vendored em `~/.agents/skills/` | C0 | `evidence` → [F-0001](findings/0001-harness-e-toolchain.md) |
| `TOOL-003` | `layout-dump.js` ✅ entregue (validado com mock) · `layout/measure.py` + `layout-diff.py` pendentes | C5 | `in-progress` |
| `TOOL-004` | Seção §11 "Evidência iOS" no `CODEMAP.md` (D6) | C6 | `open` |
| `TOOL-005` | Re-rodar `gitnexus analyze` após D6 (e registrar FTS ainda quebrado, se for o caso) | C6 | `open` |
| `TOOL-006` | Verificar ausência de artefatos proprietários antes do PR (§7.5 do SPEC) | C6 | `open` |

---

## 8. Como atualizar este arquivo

1. **Uma linha por pergunta.** Pergunta composta divide-se.
2. Status muda **só** com link para `findings/<cartão>.md` (ou para `surface/*.json` com `_meta`).
3. `evidence`/`adapt`/`reject`/`deferred` exigem a frase *"Impacto no Drafto: …"* no cartão — senão a
   evidência não vira decisão.
4. Novas linhas nascem de: (a) perguntas que o *run* abriu; (b) P0/P1 novos no `CODEMAP.md`; (c) itens da
   `02-FEATURE-PARITY.md` que estão `Partial` sem motivo técnico.
5. Nada é apagado. Linhas resolvidas vão para o fim da tabela em **§9 Archive** com `→ PR #<n>`.

## 9. Archive

*(vazio — nenhuma obrigação resolvida até 2026-11-11)*

---

## 10. Próxima ação concreta (para quem assume a trilha hoje)

```bash
export REV_IOS_ARTIFACTS_DIR="$HOME/.rev-ios/artifacts"
./tools/rev-ios/install-skill.sh --check          # TOOL-002
./tools/rev-ios/capture.sh preflight              # C0 — confirma que o tier A é este mesmo
./tools/rev-ios/capture.sh acquire --dry-run      # CAP-002 — mostra o plano, não baixa nada
# CAP-003 (Tier A, sem Mac): pedir ao cliente UM backup sintético do Drafts e rodar:
./tools/rev-ios/capture.sh triage ~/path/Drafts-Backup.zip --kind user-backup
# → abre os cartões: OB-MODEL-004, OB-MODEL-005, OB-MODEL-011, OB-ACTION-001, OB-TPL-002, OB-IMP-001
```

Isto fecha **7 linhas** do ledger sem nenhum ambiente Apple — é por onde se começa.
