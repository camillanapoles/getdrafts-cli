# Get Drafts — Investigação de Features (base para Drafto)

> Baseada no código da CLI (`pkg/drafts`, `cmd/drafts`), nos planos do repo, e na documentação pública
> de Get Drafts (docs.getdrafts.com, scripting.getdrafts.com). Objetivo: extrair o modelo conceitual
> que Drafto deve replicar. **Não é cópia de código proprietário** — é mapeamento de comportamento.

## 1. Filosofia do app

Drafts é um "ponto de partida para texto":
- **Captura rápida** — texto entra no Inbox sem forçar decisão de folder/formato.
- **Organizar depois** — tags, flag, archive/trash, workspaces, search.
- **Automação via Actions** — transforma texto e o envia para outros apps/serviços.
- **Editor simples** — focado em texto plain (Markdown, Taskpaper, etc.), com personalização de tipografia.

> Drafts: "where text starts". Drafto deve preservar esse fluxo: **inbox → ação → destino**.

## 2. Modelo de dados (Draft)

O modelo já está refletido em `pkg/drafts/struct.go` (`Draft`). Atributos conceituais:

| Atributo | Tipo | Observação |
|----------|------|-----------|
| `uuid` | string | Identificador único (gerado pelo app). |
| `content` | string | Corpo do texto. |
| `title` | string | Primeira linha (display title). |
| `tags` | []string | Multiplas tags. |
| `flagged` | bool | Flag independente do folder. |
| `folder` | enum(inbox/archive/trash) | Localização. |
| `createdAt` / `modifiedAt` | string/date | Timestamps. |
| `permalink` | string | `drafts://open?uuid=...`. |
| lat/long created/modified | float | Geolocalização opcional. |
| `syntax` | string | Linguagem/grammar do editor (Markdown, Taskpaper, Plain Text). |
| `versions` | [] | Histórico de versões do draft. |
| `tasks` / `incompleteTasks` / `completedTasks` | [] | Tasks Taskpaper (`- [ ]`). |
| `linkedItems` | [] | Wiki-links / cross-links. |
| `urls` | [] | URLs extraídas do conteúdo. |
| `actionLogs` | [] | Histórico de execuções de ações. |

## 3. Organização

### 3.1 Folders
- **Inbox** — novos drafts.
- **Flagged** — flag é propriedade independente (um draft flaggado pode estar no inbox ou archive).
- **Archive** — armazenamento a longo prazo.
- **Trash** — exclusão; draft no trash > 30 dias é removido permanentemente.
- **All** — inbox + archive (com filtros).

### 3.2 Tags
- Etiquetas *ad hoc*; múltiplas por draft.
- Filters por tag (incluir/excluir) na lista e em workspaces.
- Tag especial `#tagged#` / `#untagged#` (inverso).

### 3.3 Workspaces
- Conjuntos de drafts filtrados por critérios: folder, tags, texto (search), seleção manual.
- Cada workspace pode definir: sort, folder padrão, action group carregada.
- Workspaces são parte do backup; podem ser importados/exportados (via URL/file).
- `applyWorkspace`, `loadFolder`, `loadActionListGroup`, `loadActionBarGroup` (scripting).

### 3.4 Search & Sort
- Full-text search no conteúdo.
- Sorts: created, modified, accessed.
- `SortFlaggedToTop` — flaggados no topo.

## 4. Actions (sistema de automação)

### 4.1 Estrutura
- Uma **Action** é uma sequência de **steps**.
- Steps típicos: Copy, Share, Move to Folder, Assign Tags, Template, Script (JavaScript), Prompt, Open URL, Run Workflow, etc.
- **Action Group** — conjunto de actions exibido na lista lateral e/ou na action bar (teclado).
- Cada action pertence a exatamente um grupo.

### 4.2 "After success"
Após executar uma action com sucesso, pode-se:
- Arquivar, apagar (trash), atribuir tags, mover — automatizando o *processamento* do inbox.

### 4.3 JavaScript API (Drafts Scripting)
Objetos principais: `Draft`, `Editor`, `App`, `Action`, `ActionGroup`, `Workspace`.
- `Draft`: content, title, tags, flagged, folder, uuid, permalink, languageGrammar, save(), trash(), archive(), move(), etc.
- `Editor`: texto ativo, seleção, inserção, formatação.
- `App`: workspaces, action groups, UI (show/hide lists), loadActionGroup, applyWorkspace.
- Template tags: `[[draft_content]]`, `[[draft_title]]`, `[[draft_uuid]]`, `[[date]]`, `[[date_created]]`, `[[date_modified]]`, `[[clipboard]]`, etc.

### 4.4 URL Schemes (drafts://)
As ações expuestas (19):
`/create`, `/prepend`, `/append`, `/replace`, `/replaceRange`, `/open`, `/search`, `/quickSearch`,
`/commandPalette`, `/actionSearch`, `/runAction`, `/workspace`, `/loadActionGroup`, `/loadActionBarGroup`,
`/capture`, `/dictate`, `/arrange`, `/select`, `/getCurrentDraft`.
> Drafto deve expor análogos em `drafto://`.

## 5. Editor & Capture

- **Invisible interface** — foco no texto; UI minimalista.
- **Captura** — teclado, dictação, Apple Watch, share extension, widgets.
- **Personalização** — fonts, spacing, line height, margins, themes, ícones.
- **Link Mode** — links automáticos (URLs, emails, wiki-links).
- **Arrange Mode** — manipulação de múltiplos drafts (merge, move, tag em lote).
- **Keyboard action bar** — actions acima do teclado.
- **Version history** — rollback de edições.

## 6. Plataformas & Sync

- iOS, iPadOS, macOS, Apple Watch.
- Sync via iCloud (transparente), backups periódicos (incluem workspaces), export/import.
- Ações de terceiros (Action Directory), Zapier, Shortcuts.

## 7. Engenharia reversa — como extrair o modelo

> A empresa é especialista em engenharia reversa. A CLI AppleScript é o **proxy de extração** oficial
> usado para descobrir o surface disponível. Estratégia proposta:

1. **AppleScript dictionary** (via `drafts info`) — surface disponível para automação.
2. **URL schemes** — ações documentadas; mapped em `drafto://`.
3. **Scripting API** (`Draft`, `Editor`, `App`) — objetos conceituais.
4. **Dados do app** — banco SQLite local do Drafts (iOS) para extração de schema de drafts/workspaces/actions.
   - *Não depender do schema interno não documentado*; usar o modelo conceitual acima como fonte de verdade.
5. **Actions instaladas** — extrair via `installURL` (JSON) para entender steps; reimplementar os passos
   comuns em Drafto (não copiar JS proprietário).

## 8. O que a CLI já revela (feats implementadas)

Commands: `new/create`, `prepend`, `append`, `replace`, `edit`, `get`, `select`, `list`, `flag/unflag`,
`workspace`, `actions`, `run`, `info`, `schema`, `upgrade`, `version`.
Output: JSON por padrão (LLM-first), `--plain` opcional. Erros estruturados com codes.

## 9. Riscos & lacunas

- **Syntax/grammar** não exposto via AppleScript → Drafto define seu próprio set (Markdown, Taskpaper, Plain Text).
- **Versions/tasks/linkedItems/urls/actionLogs** não expostos pela CLI → modelar como campos extensíveis.
- **Sync multi-device** → Phase 4; começar com storage local.
- **Actions JS** → reimplementar passos nativos; compatibilidade parcial com templates.

## 10. Conclusão

O núcleo replicável é: **Draft + Inbox/Flag/Archive/Trash + Tags + Workspaces + Actions engine + Template tags + Editor plain-text**.
Drafto implementa esse núcleo em Go (core) e expõe para Android (gomobile) e Linux (CLI).
