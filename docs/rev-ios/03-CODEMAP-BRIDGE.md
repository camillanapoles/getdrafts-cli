# 03 — Ponte: evidência iOS ↔ `CODEMAP.md` ↔ obrigações no Drafto

> O `docs/drafto/CODEMAP.md` é o **mapa do que já existe** (Go core, bridge AppleScript, gomobile,
> Compose). Esta trilha produz **mapa do que é verdade no app original**. Este documento é a
> *junção*: define como uma evidência iOS entra no codemap e no código — e o que bloqueia a entrada.

---

## 1. Por que a ponte é necessária (o problema atual do codemap)

O codemap foi construído **de dentro para fora**: GitNexus indexou o repo (1.507 nós / 3.449 edges /
35 clusters / 81 arquivos) e descreveu *o que o Drafto faz*. A §1.3 e a §10 registram a lacuna com
honestidade:

- **`rea doctor` = `healthy: false`** (`missing_analysis_engine`: Hopper/Ghidra/IDA ausentes). Ou seja, o
  braço que deveria analisar **o binário iOS** — a fonte de verdade do comportamento — **não existia**.
  O `rea` é a ambição; não era a ferramenta disponível.
- **FTS/BM25 desativado** no GitNexus → `query` por texto retorna vazio → impossibilidade de perguntar
  "onde aparece `workspace`?" ao grafo.
- Consequência: a §8 (*"O que falta para paridade (P0)"*) é uma **lista de perguntas**, cada uma com
  zero meios de resposta atribuídos.

A trilha `rev-ios` é o **meio** que faltava: ela entrega ao projeto, versionado no branch,
94 referências + 73 scripts + 6 fases determinísticas + um *harness*, que rodam onde o `rea` não roda
(Linux faz a triagem estática inteira; Mac faz dados e assets; device faz runtime). Não substitui
Ghidra/Hopper para descompilação profunda — substitui a **espera** por elas, com o que responde as
perguntas concretas do §8.

**Linha de política:** `rea` continua sendo o caminho para descompilação de função individual quando o
ambiente existir. O skill vendored é o caminho para **extração de estrutura, formato e layout** — que é
o que o Drafto precisa. Ver [VENDOR.md](../../skills/ios-app-security-audit/VENDOR.md).

---

## 2. Fluxo (obrigatório, em duas direções)

```
       (1) captura            (2) triagem            (3) cartão            (4) ledger
raw/ ───────────────► surface/ db/ layout/ ─────► findings/*.md ─────► LEDGER.md (evidence)
   [rev-ios run]      [rev-ios run]              [E1–E4 + limits]         │
                                                                            │ (5) PR de doc
                                                                            ▼
                                          docs/drafto/CODEMAP.md  §11 "Evidência iOS" (novo)
                                                                            │
                                                                            │ (6) PR de produto (trilha reverse/)
                                                                            ▼
                              core/*.go · android/core-go · android/app/** · cmd/drafto
```

Regras do fluxo:

1. **Nenhuma linha do codemap muda sem um cartão** em `docs/rev-ios/findings/*.md` (formato
   [FINDINGS-TEMPLATE.md](FINDINGS-TEMPLATE.md)).
2. **Nenhuma linha do código do Drafto muda sem uma linha de ledger** em status `evidence` apontando o
   cartão. Isto é o *gate* anti-invencão (§1.1.1 do [00-SPEC.md](00-SPEC.md)).
3. Cartão que **contradiz** doc anterior: não apaga o anterior — marca `superseded_by:` e explica o
   motivo. A história do entendimento é parte do produto de uma empresa de RE.
4. Passos 5 e 6 acontecem em **PRs separados** (doc no `rev-ios/<slug>`; código no `reverse/<slug>`),
   porque a auditoria de docs é diferente da auditoria de código.
5. Ao integrar (passo 5), re-rodar o índice: `gitnexus analyze` (e `analyze --skills` para regenerar os
   skills por área; `.claude/` continua ignorado). Se o FTS ainda estiver quebrado, registrar na §10 do
   codemap — **não** assumir que "zero hits" significa "zero fluxo".

## 3. Tabela de attachment: nó do codemap → evidência que o valida

Lado esquerdo = o que o codemap já afirma (com referência de arquivo). Lado direito = o que a trilha
produz para confirmar, refinar ou derrubar.

| Nó do codemap | Afirmação atual | Risco (sem evidência) | Evidência que resolve | Linha no ledger |
|---|---|---|---|---|
| `core/model.go` `Draft` | `{uuid, title, body, folder, tags, flagged, created, modified}` | **incompleto por construção** — derivado da bridge AppleScript, que não expõe `syntax`, `versions`, `tasks`, `linkedItems`, `urls`, `actionLogs` (ver `01-GETDRAFTS-INVESTIGATION.md` §2) | `db/schema.sql` (2.1) + `db/tables.json` (2.2) | `OB-MODEL-*` |
| `core/store.go` `Store` (interface) | CRUD + `Query(sort, folder/tag)` | `Query` reflete o que a CLI sabe, não o que o app faz | `runtime/sqlite.ndjson` (2.9) — as *queries* reais por interação | `OB-QUERY-*` |
| `core/memory.go` `MemoryStore.Query` | `sort` + filter `folder`/`tag` | sort order, `flagged_to_top`, *default sort* por workspace desconhecidos | `db/indexes.json` (2.6) + `db/workspaces.json` (2.8) | `OB-SORT-*` |
| `core/action.go` `Action{group, steps[], after_success}` | shape "traduzido" do AppleScript | **step types incompletos**; config por tipo inexistente | `import/` do backup (3.5 do 01) + `surface/action-schema.json` (2.7) + trace do *runner* (5.3) | `OB-ACTION-*` |
| `core/template.go` `RenderTemplate` | 6 tags; **P0 #1 falta `[[clipboard]]`** | lista pode estar subestimada | `rg -o '\[\[[a-z_]+\]\]'` no binário/JS (4.6) + teste por `drafts://runAction` | `OB-TPL-001` |
| `android/core-go/drafto.go` `Core` (`//export`) | 12 métodos expostos ao Kotlin | método faltando = feature impossível no Android | matriz dos ~19 `drafts://` (1.3) × `Core` — o que não tem *binding* | `OB-BIND-*` |
| `android/.../ui/*` Compose | "UI Compose do Drafto" — layout próprio, não pareado | paridade de UX **zero verificado** | `layout/tokens.json` + `layout/screens/` ([04](04-LAYOUT-PARITY.md)) | `OB-LAYOUT-*` |
| `pkg/drafts/applescript.go` `runAppleScript` | caminho original (fluxo `RunAppend → RunAppleScript`) | nenhum — é o *proxy* oficial | `drafts.sdef` (S1) para confirmar tipos/propriedades | `OB-SDEF-*` |
| codemap §4 "dualidade" (`Create` em 3 contextos) | ambiguidade de símbolo na CLI × core | iOS é um **terceiro** `Create` (o real) | `binary-class-dump.js` (5.2): `createDraft…`/`saveDraft…` seletores | `OB-CREATE-*` |
| codemap §7 "herança lógica" | "referência de lógica que o Drafto replica" | hoje a referência é a **CLI**, não o **app** | este §3 inteiro | — |

## 4. Crosswalk de símbolos (hipóteses de trabalho — **E1**)

Isto **não é resultado**: é a lista de nomes a confirmar em 5.1/5.2. A coluna iOS contém *hipóteses de
nomenclatura* formadas a partir da bridge AppleScript e da API de scripting. Se o `nm`/`dsdump`/Frida
disser outro nome, o outro nome vence e a linha é reescrita. Nunca escrever código a partir desta tabela.

| Conceito | Símbolo iOS *esperado* (a confirmar) | Nó do codemap | Alvo no Drafto |
|---|---|---|---|
| Entidade rascunho | `Draft` / `DraftModel` / `…DraftStore` | `core/model.go:Draft` | `core.Draft`, tabela `drafts` |
| Persistência | `DraftStore`, ` CoreDataStack`, `SQLPersist…` | `core/store.go:Store` | `core/sqlitestore` (Phase 1) |
| Ação | `Action`, `ActionStep`, `ActionGroup` | `core/action.go` | `core.Action`, `ParseAction` |
| Execução | `ActionRunner`, `runAction…` | `core/action.go:ActionRunner.Run` | idem + `cmd/drafto action` |
| Workspace | `Workspace`, `WorkspacesManager` | `MemoryStore.resolveWorkspace` | `core.Workspace` + `workspaces` table |
| Tags | `tagging…`, `…tagsDelimiter` | `core/options.go:Options` | `Options.TagSeparator` |
| Editor | `EditorViewController`, `DraftEditor…` | `ui/EditorScreen.kt` | `EditorScreen` |
| Lista | `DraftListViewController`, `…TableView` | `ui/DraftListScreen.kt` | `DraftListScreen` |
| URL scheme | `handleURL…`, `x-callback-url` | `cmd/drafts` (CLI) | `drafto://` + manifest Android |
| Backup | `…BackupManager`, `DraftsBackup…` | — (não existe) | Phase 4; `deferred` |

Cada confirmação move a linha para `evidence` com o símbolo real + *source* (`dsdump`/Frida).

## 5. Como o §8 do codemap fecha (mapeamento direto P0 → meio)

| P0 (`CODEMAP.md` §8) | Superfície | Fase | Saiu daqui? |
|---|---|---|---|
| 1 `[[clipboard]]` template tag | S3 strings + S5 `pasteboard-monitor.js` | C4/C5 | **sim** (lista completa de tags) |
| 2 Full-text search | S2 `db/indexes.json` | C3 | **sim** (FTS5? `LIKE`? Core Data predicate?) |
| 3 Opções de *sort* completas | S2 `SELECT DISTINCT` + S5 `coredata-interceptor` (fetch sort descriptors) | C3/C5 | **sim** |
| 4 *Action groups* por URL de instalação | S6 backup + S3 `*.plist`/`*.actionset` | C3 | **sim** (JSON aceito pelo parser) |
| 5 Auto-delete do *trash* (30 d) | S4 strings + S5 trace de `BackgroundTask` | C4 | **parcial** — precisa runtime; sem device, fica `deferred` |
| 6 Geolocation / permalink / versions / tasks | S2 schema | C3 | **sim** para colunas; **não** para semântica de coleta (precisa S5) |

## 6. Escrevendo o §11 do codemap (o entregável D6)

Formato fixo da seção nova, para o PR de doc (passo 5). Manter a voz do arquivo (tabela + observação
crítica + limitações).

```markdown
## 11. Evidência iOS (trilha rev-ios)

> Run: `<run-id>` · build do alvo `<version> (<build>)` · sha256 `<…>` · executado em `<data>` por `<actor>`.
> Ferramenta: skill `ios-app-security-audit` @ `<pin>`; fases 0–4 (5 e "Mod" desligadas).

### 11.1 Modelo de dados — confirmado
| Campo do Draft (iOS) | Tipo SQLite | Null | Default | Onde no Drafto | Evidência |
|---|---|---|---|---|---|
| … | … | … | … | `core/model.go` | E3 `db/schema.sql#L12` |

### 11.2 Deltas detectados vs §7 (herança lógica)
…
### 11.3 Coisas que o iOS faz e o Drafto não vai fazer
…(com motivo)
### 11.4 Limitações deste run
…(o que não pôde ser observado: sem device, cryptid=1, etc.)
```

A seção **reafirma** os números do índice GitNexus apenas se o índice foi re-rodado; caso contrário
declara `índice: commit <x>, não re-gerado`.

## 7. Anti-padrões da ponte (recorrentes em trabalho de RE → produto)

1. **Copiar o nome interno** para o código do Drafto (`DraftStore`, `GTFQ98J4YG…`). Nome interno é
   evidência, não vocabulário do produto.
2. **Tratar schema como contrato**: o schema interno iOS pode mudar amanhã; o contrato do Drafto é o
   seu `Store`. Paridade é **comportamental**.
3. **"Não encontrei = não existe"** — em `cryptid=1`, `absent` deve ser lido `unreadable`. O cartão
   precisa da coluna *limitação*.
4. **Transformar hipótese de §4 em TODO de código.** A tabela §4 é de *busca*, não de *decisão*.
5. **Fechar a P0 sem evidência** porque "o roadmap precisava". O ledger aceita `blocked-env` — é
   resposta legítima e mais barata que um bug em produção.
