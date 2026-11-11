# Trilha `rev-ios` — Especificação de Captura & Extração (Get Drafts iOS → Drafto Android)

> Ramo de trabalho dedicado a **entender o app Get Drafts no iOS** — captura do artefato, extração de
> modelo de dados, superfície de automação, comportamento em runtime e **layout** — e a **alimentar o
> [`CODEMAP.md`](../drafto/CODEMAP.md)** da CLI/repo com evidência real, em vez de inferência.
>
> Esta pasta é a *spec* do worktree/branch `rev-ios/<slug>`. O código produzido por ela não é código
> do Drafto: são **evidências, mapas e obrigações** que o Drafto consome.

## Por que uma trilha separada

`docs/drafto/` descreve **o que construir** (produto). A trilha `rev-ios/` descreve **como sabemos o que
construir** (método forense). Misturar as duas coisas faz a doc de engenharia virar anexo de engenharia
reversa — e vice-versa. Por isso: isolamento por *namespace* de branch, *tag* própria e *worktree*
próprio (ver [`00-SPEC.md`](00-SPEC.md) §2).

## Índice

| Doc | Conteúdo | Quem lê |
|-----|----------|---------|
| [00-SPEC.md](00-SPEC.md) | **A spec.** Objetivo, isolamento do ramo, escopo, entregáveis, fases, critérios de aceite, riscos, limites legais. | todos (obrigatório) |
| [01-CAPTURE-PLAN.md](01-CAPTURE-PLAN.md) | Plano de **coleta**: superfícies S1–S6, aquisição do IPA (ipatool / device / SimForge), cadeia de custódia, instalação do toolchain (macOS + Linux). | quem executa |
| [02-EXTRACTION-MAP.md](02-EXTRACTION-MAP.md) | **O que extrair** de cada artefato, com comando, arquivo de saída e nível de evidência. | quem executa |
| [03-CODEMAP-BRIDGE.md](03-CODEMAP-BRIDGE.md) | Ponte evidência → `docs/drafto/CODEMAP.md` → arquivo no Drafto; *ledger* de obrigações de paridade. | quem implementa |
| [04-LAYOUT-PARITY.md](04-LAYOUT-PARITY.md) | Extração de **layout/tokens de design** (Assets.car, view tree, screenshots medidos) → Compose/Material 3. | UI |
| [LEDGER.md](LEDGER.md) | *Ledger* vivo de obrigações (a única lista que deve mudar de status sem re-escrever a spec). | todos |
| [FINDINGS-TEMPLATE.md](FINDINGS-TEMPLATE.md) | Cartão de evidência (formato de toda conclusão desta trilha). | todos |

## Ferramental

| Item | Onde | Papel |
|------|------|-------|
| Skill **`ios-app-security-audit`** (vendored, pinned) | [`skills/ios-app-security-audit/`](../../skills/ios-app-security-audit/VENDOR.md) | knowledge + execução: 6 fases, 94 referências, 73 scripts Frida, scripts utilitários |
| Skill **`getdrafts-ios-rev`** (nossa) | [`skills/getdrafts-ios-rev/SKILL.md`](../../skills/getdrafts-ios-rev/SKILL.md) | procedimento específico de Get Drafts; chama o skill vendored |
| Driver **`capture.sh`** | [`tools/rev-ios/capture.sh`](../../tools/rev-ios/capture.sh) | `preflight` · `acquire` · `triage` · `surface` — gera a árvore de artefatos + manifestos |
| Instalador do skill | [`tools/rev-ios/install-skill.sh`](../../tools/rev-ios/install-skill.sh) | instala/valida/atualiza o skill em `~/.agents/skills/` a partir da cópia vendored |
| *Codemap* da CLI | [`docs/drafto/CODEMAP.md`](../drafto/CODEMAP.md) | destino da evidência (GitNexus + rea) |

Artefatos binários **não entram no git**. Ficam em `$REV_IOS_ARTIFACTS_DIR`
(padrão `~/.rev-ios/artifacts/`), com manifesto e SHA-256 por *run*.

## Estado

`preparada` — **C0 fechada**: spec, plano, mapas, *ledger* inicial e **ferramenta executável**, validadas em
Linux contra *fixture* sintético (`install-skill.sh --check` ✅ · `capture.sh preflight/new-run/triage/
surface/purge` ✅ → [F-0001](findings/0001-harness-e-toolchain.md)). **Nada do app-alvo foi capturado**:
sem `ipatool`/`frida`/Mac/device neste host, então C1 real ainda não aconteceu.

Começar por: [LEDGER.md](LEDGER.md) §10 — `CAP-003` (backup **sintético** do cliente) é Tier A e libera
7 linhas do ledger sem nenhum ambiente Apple.

Censo do *ledger* em 2026-11-11: **58 linhas** (`CAP-*` 5 · `OB-*` 47 · `TOOL-*` 6) —
2 `evidence` · 1 `in-progress` · 15 `ready` (Tier A, executáveis hoje) · 15 `open` · 22 `blocked-env`
(Tier B/C) · 2 `deferred` · 1 `informational`.

| Trilha | Doc de produto | O que a evidência iOS altera |
|---|---|---|
| `rev-ios` (aqui) | [`CODEMAP.md`](../drafto/CODEMAP.md) | nova §11 "Evidência iOS" (D6) + re-leitura da §10 |
| | [`02-FEATURE-PARITY.md`](../drafto/02-FEATURE-PARITY.md) | status `Confirmed/Partial` por feature, com nível de evidência |
| | [`05-ROADMAP.md`](../drafto/05-ROADMAP.md) | schema SQLite e acceptance criteria da Phase 1 |
