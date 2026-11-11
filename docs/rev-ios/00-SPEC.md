# `rev-ios` — Spec de Captura & Extração do Get Drafts (iOS)

| | |
|---|---|
| **ID** | `SPEC-REVIOS-001` |
| **Status** | `ready-for-execution` (Fase C0 pendente) |
| **Data** | 2026-11-11 |
| **Ramo de origem** | `arena/d07fc20f-getdrafts-cli` (base `50470811`) |
| **Ramo canônico desta trilha** | `rev-ios/getdrafts-capture` |
| **Tag desta trilha** | `rev-ios-getdrafts-capture-20261111` (ver §2.3) |
| **Worktree** | `../getdrafts-cli-rev-ios` (ver §2.4) |
| **Consumidor** | [`docs/drafto/CODEMAP.md`](../drafto/CODEMAP.md), [`02-FEATURE-PARITY.md`](../drafto/02-FEATURE-PARITY.md), [`05-ROADMAP.md`](../drafto/05-ROADMAP.md) |
| **Ferramenta** | skill `ios-app-security-audit` (DragonJAR, vendored em [`skills/ios-app-security-audit/`](../../skills/ios-app-security-audit/VENDOR.md)) |

---

## 1. Objetivo (o "para quê" não-negociável)

**Entender o app original Get Drafts (iOS) — modelo de dados, superfície de automação, comportamento em
runtime e layout — para reconstruí-lo no Android como Drafto, com paridade funcional e, na medida do
possível, paridade de layout.**

A trilha `rev-ios` **não** produz features. Ela produz **evidência** que elimina três classes de erro no
Drafto:

1. **Invenção de modelo** — hoje `core/model.go`, o schema SQLite proposto em
   [`05-ROADMAP.md`](../drafto/05-ROADMAP.md) §Phase 1 e `01-GETDRAFTS-INVESTIGATION.md` são
   *inferências* a partir da bridge AppleScript + docs públicas. Campos, enums e semântica
   (folders, flag, workspace, action steps, version history, tasks) precisam de confirmação.
2. **Lacuna silenciosa** — `CODEMAP.md` §8 lista 6 itens P0 "faltantes" sem dizer **como** descobri-los
   no app real. Cada item do ledger (§03) passa a ter um *meio de extração* nomeado.
3. **UI genérica** — `DraftListScreen`/`EditorScreen` atuais são um layout "Material razoável", não o
   layout do Drafts. Paridade visual exige métricas reais (tipo, espaçamento, hierarquia, barra de ação,
   *invisible interface*), não palpite.

### 1.1 Resultado esperado (saída da trilha)

| # | Entregável | Forma | Validação |
|---|-----------|-------|-----------|
| D1 | *Run* de captura com cadeia de custódia | `~/.rev-ios/artifacts/<run>/` + `provenance.json` + `SHA256SUMS` | `capture.sh triage` termina com `evidence:` não-vazio |
| D2 | *Corpus* de superfície do app | `surface/*.json` (Info.plist, URL schemes, entitlements, classes, selectors, keys de defaults, tabelas do SQLite) | todo JSON *parse-ável* e com fonte anotada |
| D3 | **Modelo de dados confirmado** | `findings/*.md` (um cartão por conclusão) | cada cartão tem evidência + nível E1–E4 (ver [FINDINGS-TEMPLATE.md](FINDINGS-TEMPLATE.md)) |
| D4 | **Layout medido** | `layout/tokens.json` + `layout/screens/` | tokens com valor **medido** e referência ao screenshot |
| D5 | **Ledger atualizado** | [`LEDGER.md`](LEDGER.md) | cada obrigação P0/P1 sai de `open` para `evidence` ou `rejected+motivo` |
| D6 | **CODEMAP atualizado** | seção nova em `docs/drafto/CODEMAP.md` §11 "Evidência iOS" | dif em PR `rev-ios/getdrafts-capture → reverse/main` |

D3, D4 e D5 são o produto. D1/D2 são a infra que os torna auditáveis.

### 1.2 Não-objetivos (fora de escopo — *hard lines*)

- **Nenhum relatório de vulnerabilidade.** As Fases 4/5 do skill (bypass de RASP/pinning/jailbreak, CVSS,
  templates de pentest) ficam desligadas. Usamos o skill como **kit de extração**, não de ofensiva.
- **Nenhum *repackaging*/re-signing/**injeção permanente** no app do alvo (Fase "Mod" do skill): não
  alteramos o binário do Drafts; observar basta.
- **Nenhum código, recurso gráfico, fonte, string ou asset proprietário** entra no Drafto. Ver §7.
- **Nenhuma engenharia reversa de serviço de nuvem** (iCloud/CloudKit, App Store, servidores da
  Agile Tortoise). Sync multi-device continua Phase 4 do roadmap e **não** é meta desta trilha.
- **Nenhum dado real de usuário** no corpus. Só conta/instância sintética (§7.4).

---

## 2. Isolamento do ramo (a regra que dá nome à trilha)

### 2.1 Namespace

A trilha vive no namespace `rev-ios/` — **paralelo e independente** das trilhas `arena/` (sessão) e
`reverse/` (canônica de produto; ver [`04-GOVERNANCE.md`](../drafto/04-GOVERNANCE.md) §1). Nada da
trilha `reverse/` é feito neste branch além do que já foi feito; e **nenhum trabalho de produto do Drafto
é feito no branch `rev-ios/`** — ele é de análise. Essa separação é o motivo de existir.

```
reverse/main ──────────●──────────●───────────  (produto, canônico, versionado)
                        \
                         \  arena/d07fc20f-getdrafts-cli ● ← esta spec nasce aqui (docs + skill + tools)
                          \
                           rev-ios/getdrafts-capture ●──●──  (análise: findings, ledger, mapas)
                             │
                             └─ PR → reverse/main só traz docs/*.md + LEDGER + atualização de CODEMAP
                                (nunca artefatos binários)
```

| Ramo | Conteúdo | Vive enquanto |
|------|----------|---------------|
| `rev-ios/getdrafts-capture` | esta spec + execução das Fases C0–C5 | até D6 ser integrado |
| `rev-ios/drafts-<surface>` | ex.: `rev-ios/drafts-sqlite-schema`, `rev-ios/drafts-layout` — quando uma superfície precisa de sessão própria | idem |
| `rev-ios/mac-bridge` | extração via macOS (`DraftStore.sqlite` + dicionário AppleScript) — o atalho barato | idem |

Nome do slug: `<alvo>-<superfície>` em kebab-case ASCII, ≤ 40 chars. Ex.: `getdrafts-capture`.

### 2.2 Marker nos commits

Todo commit desta trilha usa `rev-ios` como **escopo** da convenção
[`04-GOVERNANCE.md`](../drafto/04-GOVERNANCE.md) §2 — assim a história fica filtrável sem depender do
nome do branch:

```
docs(rev-ios): add capture plan §S3 ipatool acquisition
feat(tools/rev-ios): triage stage for Info.plist + entitlements
fix(rev-ios): quote plistutil output in surface stage
```

Filtro: `git log --grep '(rev-ios)' --oneline`.

### 2.3 Tags (e o detalhe que morde)

Marcos desta trilha são taggeados `rev-ios-<slug>-<yyyymmdd>` (ex.: `rev-ios-getdrafts-capture-20261111`),
**hífens, sem barra**. Verificado neste repo (2026-11-11):

| Combinação | Resultado |
|---|---|
| branch `rev-ios/foo` + tag `rev-ios-foo-20261111` | ✅ ok — namespaces de ref diferentes |
| branch `rev-ios/foo` + tag `rev-ios` | ✅ ok |
| tag `rev-ios` + tag `rev-ios/foo` | ❌ `fatal: cannot lock ref 'refs/tags/rev-ios/foo': 'refs/tags/rev-ios' exists` |

Ou seja: o conflito é *file-vs-directory* **dentro de `refs/tags/`**. Consequência normativa: **ou** se usa
uma tag-marcador plana `rev-ios-<slug>-<data>`, **ou** um sub-namespace `rev-ios/<slug>` em
`refs/tags/` — nunca os dois. Padronizamos o plano, porque os `git describe`/filtros de CI do projeto já
assumem tags planas (`vX.Y.Z`, `drafto-vX.Y.Z`).

- Tags **de release** (`v*`) continuam **só** em `reverse/main` (§1.2 da Governança). `rev-ios-*` não é
  tag de release: é *checkpoint* de análise, e por isso não dispara goreleaser.
- Fluxo de integração da trilha: `rev-ios/<slug>` → PR → `reverse/main`, com os commits da sessão
  (`arena/…`) entrando via PR para `rev-ios/<slug>` (A regra do ADR-005 se mantém; aqui só muda o
  namespace do branch de trabalho).

### 2.4 Worktree (isolamento físico, não só lógico)

A captura de iOS vai sujar o diretório (bundles extraídos, dumps, screenshots). Nada disso deve vazar
para o worktree do produto. Use um *worktree* irmão:

```bash
# a partir do repo principal (git: origin=https://github.com/camillanapoles/getdrafts-cli)
git worktree add ../getdrafts-cli-rev-ios -b rev-ios/getdrafts-capture

# no sandbox atual o nome do ramo de sessão é fixo; cortar o ramo rev-ios é ação do dev:
cd ../getdrafts-cli-rev-ios
export REV_IOS_ARTIFACTS_DIR="$HOME/.rev-ios/artifacts"   # padrão; fora do repo, de propósito
./tools/rev-ios/install-skill.sh
./tools/rev-ios/capture.sh preflight
```

O **branch da sessão Arena é fixo** (`arena/d07fc20f-getdrafts-cli`) — Arena rastreia a sessão por ele, e
esta spec é escrita/entregue nele. O ramo `rev-ios/<slug>` é cortado **a partir deste commit** por quem
executa a captura; a spec é a mesma cópia, versionada junto.

---

## 3. Método: onde o skill entra

O skill `ios-app-security-audit` foi escolhido porque ele é **determinístico por fases** (Phases 0–5) e
*source-of-truth local* (`references/*.md`) — o formato exato que uma trilha de evidência precisa: cada
passo tem comando, saída e limitação escrita. A leitura obrigatória para nós é o README do skill
(§"Installation", §"Quick Setup", §"Limitations") e **`references/linux-ios-analysis-workarounds.md`**,
que define o que é viável **neste host Linux** (ver §4).

Re-mapeamento das fases do skill para os objetivos desta trilha:

| Fase do skill | Nome original | O que vira aqui | Prioridade |
|---|---|---|---|
| 0 | Extract & detect framework | **Captura**: obter o IPA/bundle, extrair, identificar framework (Drafts é nativo Swift/UIKit — confirmar, não assumir) | C1 |
| 1 | Attack surface mapping | **Superfície de interoperabilidade**: Info.plist (47 keys), URL schemes `drafts://`, entitlements, extensões (Share/Widget/Quick Look), App Groups | C2 |
| 2 | Targeted triage (storage & crypto) | **Modelo de dados**: SQLite/Core Data (`DraftStore.sqlite`), NSUserDefaults, Keychain (só estrutura), pasteboard | C3 |
| 3 | Data flow tracing | **Semântica**: source→sink de `content`/`tags`/`folder`/`flagged`; fluxo de *actions* e *workspaces*; template tags | C4 |
| 4 | Dynamic (Frida/Objection/SimForge) | **Runtime & layout**: `sqlite-query-logger`, `objc-method-tracer`, `binary-class-dump`, `url-scheme-monitor`, `nsuserdefaults-dumper`, `snapshot-overlay-check`, screenshots | C5 |
| 5 | Reporting (CVSS/MASTG) | **Descartado** para o Drafto; fica o *formato* de cartão de evidência (adaptado em [FINDINGS-TEMPLATE.md](FINDINGS-TEMPLATE.md)) | — |
| Mod (repackaging) | patch/re-sign | **Descartado** (§1.2) | — |

Scripts do skill usados diretamente: `scripts/preflight_check.py` (capacidades),
`scripts/screenshot-extractor.sh` (snapshots do app-switcher → layout), `scripts/quick-static-analysis.sh`
e `scripts/auto-audit-static-ios.sh` (Fases 0–3 como driver, lendo só a parte estrutural),
`scripts/sbom_generator.py` (se o cliente quiser registrar dependências do app — opcional, fora do
caminho crítico). Frida: ver [02-EXTRACTION-MAP.md](02-EXTRACTION-MAP.md) §5.

### 3.1 Níveis de evidência (herdados das "Critical Rules" do skill)

Toda conclusão carrega nível. Nada abaixo de **E2** justifica mudar o `core/` do Drafto; E1 vira
*hipótese de trabalho* no ledger.

| Nível | Fonte | Exemplo válido |
|---|---|---|
| **E1** | doc pública / anúncio | "Drafts tem version history" (docs) |
| **E2** | artefato estático do bundle lido com comando | `plistutil -i Info.plist` mostra `CFBundleURLSchemes = [drafts]` |
| **E3** | dado do próprio app, lido localmente | `sqlite3 DraftStore.sqlite '.schema'` em instância sintética |
| **E4** | runtime observado (trace/hook) com valor real | `sqlite-query-logger` registra o `UPDATE drafts SET flagged=...` ao tocar o botão |

Regra do skill aplicada ao pé da letra: **"NEVER report bare grep hits without traced context"** — no
nosso caso: nenhuma string encontrada no binário vira campo de modelo sem um E3/E4 ou uma nota
explícita de `needs dynamic confirmation`.

---

## 4. Capacidade real do ambiente (medido, não assumido)

`tools/rev-ios/capture.sh preflight` reimprime esta tabela na máquina de quem executa.

| Capacidade | Sandbox atual (Linux x86_64, 2026-11-11) | Consequência |
|---|---|---|
| `unzip` / `zip` / `rg` / `strings` / `python3 3.11` | ✅ | Fases 0–2 de **texto/estrutura** rodam aqui |
| `plistutil`/`plutil` | ❌ · *fallback* `python3.plistlib` ✅ | triagem de `Info.plist` **funciona aqui** (harness usa o módulo) — [F-0001](findings/0001-harness-e-toolchain.md) |
| `llvm-objdump` / `jtool2` | ❌ | sem leitura de `LC_ENCRYPTION_INFO`, load commands |
| `nm` (binutils, Mach-O) | ❌ (ELF-only) | sem lista de símbolos |
| `ipatool` | ❌ | aquisição do IPA precisa de host próprio |
| `frida` / `objection` | ❌ + sem device | Fase C5 exige Mac/device jailbroken/Corellium |
| `idevice*` (libimobiledevice) | ❌ + sem device | idem |
| `sqlite3` (CLI) | ❌ · módulo Python ✅ | `capture.sh surface --from-db` roda aqui (read-only) |
| Xcode / `simctl` / SimForge | ❌ (macOS only, por definição) | screenshots de simulador e `dsdump` são FASE-B/C |
| Go toolchain | ❌ | sem compilar nada — irrelevante para esta trilha |

Conclusão honesta, e ela é o motivo de a trilha existir como ramo próprio: **este sandbox não consegue
executar a captura sozinho.** O que ele consegue fazer é tudo o que não exige Apple: escrever/afinar a
spec, o *harness* de scripts, o *ledger*, e analisar **qualquer artefato que seja colocado dentro de
`$REV_IOS_ARTIFACTS_DIR`** (bundle já extraído, dump de schema, screenshots, backup export do usuário).
O mapa de trabalho por tier:

| Tier | Ambiente | Fases | Observação |
|---|---|---|---|
| **A — agora** | Linux sem device (este sandbox) | C0 completa; C1 *triage* de IPA/backup; C2 *surface* (plist, URL schemes, extensões, frameworks); C3 com `--from-db` | **medido** em [F-0001](findings/0001-harness-e-toolchain.md): a triagem não precisa de Mac; o que falta é aquisição autenticada e runtime |
| **B — Mac sem jailbreak** | macOS 14+/Apple Silicon | C1 (ipa) C2 (Info.plist, entitlements, Assets.car) **S2: `DraftStore.sqlite` do Drafts Mac** C5 parcial (simulador com SimForge se o binário estiver decifrado) | o **melhor custo/valor**: a base de dados local é lida sem qualquer bypass |
| **C — device jailbroken / Corellium** | física ou cloud | decifração (`frida-ios-dump` / `dump-ios.js`), `dsdump`/`class-dump`, Frida E4, snapshots do device | necessário só para **binário** iOS decifrado e traces em runtime |
| **D — sem Mac nenhum** | Corellium / runner `macos-latest` / MacStadium | alternativas do skill: `references/linux-ios-analysis-workarounds.md` §6 | re-signing e Simulator são os únicos becos reais |

> **Atalho estratégico (importante):** o **Drafts para macOS** compartilha o App Group
> `GTFQ98J4YG.com.agiletortoise.Drafts` e mantém a base **`DraftStore.sqlite`** em
> `~/Library/Group Containers/GTFQ98J4YG.com.agiletortoise.Drafts/`. Isso dá o **modelo de dados real
> (E3)** com `sqlite3`/Python puro, sem jailbreak, sem decifração e sem tocar no iOS. É o Tier B/S2 e é o
> primeiro caminho a executar — o binário iOS (Tier C) vem depois, para *API interna* e *layout* fino.
> (Corroborado por projetos de terceiros que leem exatamente esse caminho; reconfirmar em E2 antes de
> confiar — ver [01-CAPTURE-PLAN.md](01-CAPTURE-PLAN.md) §3.2.)

---

## 5. Fases de execução

Critério de avanço: a fase só fecha com **artefato gravado** + **cartões de evidência** + **linhas de
ledger atualizadas**. Sem artefato, a fase não aconteceu.

| Fase | Nome | Entrada | Saída | Tier | Criterial de "feito" |
|---|---|---|---|---|---|
| **C0** | Preparação | este branch | skill instalado, preflight verde, diretório de *run* criado | A | `capture.sh preflight` reporta capacidades sem erro; `install-skill.sh --check` ok |
| **C1** | Captura & custódia | IPA (`ipatool`) ou bundle macOS; **e** backup/export de Drafts | `raw/`, `provenance.json`, `SHA256SUMS`, `bundle/` | A/B | `capture.sh triage <ipa>` produz `triage.md` com `encrypted: yes/no` |
| **C2** | Superfície | `bundle/` | `surface/*.json` (plist, URL schemes, entitlements, extensões, App Groups, frameworks) | A/B | toda chave relevante tem valor **ou** `absent` explícito |
| **C3** | Modelo de dados | `DraftStore.sqlite` (S2) **ou** dump extraído do device (S5) | `db/schema.sql`, `db/tables.json`, `findings/model-*.md` | B/C | os 6 gaps do `CODEMAP.md` §8 ganham veredito E3+ |
| **C4** | Semântica & fluxo | C2+C3 + docs de scripting | `findings/semantics-*.md`, matriz ações→steps | B/C | cada *action step type* mapeado: suportar / adaptar / rejeitar |
| **C5** | Runtime & layout | decifrado + Frida (C) **ou** simulador (B) | `layout/tokens.json`, `layout/screens/`, `runtime/traces/*` | B/C | cada token com medida + screenshot; ≥1 trace E4 por fluxo crítico |
| **C6** | Integração | D3–D5 | PR `rev-ios/<slug>` → `reverse/main` atualizando `CODEMAP.md`, `02-FEATURE-PARITY.md`, `05-ROADMAP.md` | A | PR aberto, dif só em `docs/` + `tools/` + `skills/` |

Paralelismo permitido: C2 e C3 são independentes; C5 não depende de C4.

---

## 6. Critérios de aceite (a trilha acabou quando…)

1. **Cadeia de custódia fechada**: para cada *run*, sabe-se **o quê** (versão/build do Drafts), **de onde**
   (App Store / device / backup do usuário), **com que ferramenta/versão**, **por quem**, **quando**, e o
   **SHA-256**. `provenance.json` presente e legível.
2. **Modelo de dados confirmado em E3+** para: `Draft` (todos os campos + nullabilidade + defaults),
   `Folder` (valores enum reais), `flag`, `tags` (sep./normalização/case), `Workspace`, `Action`
   (`steps[].type` + config), `afterSuccess`, version history, tasks. Cada um com cartão próprio.
3. **Os 6 P0 de `CODEMAP.md` §8** têm veredito explícito no ledger: `evidence` (vira PR no Drafto) ou
   `rejected` (com motivo).
4. **Superfície de URLs** coberta: os 19 comandos `drafts://` de `01-GETDRAFTS-INVESTIGATION.md` §4.4
   confirmados em E2 (Info.plist + dispatch em runtime quando possível), com análogo `drafto://`
   proposto por comando.
5. **Layout**: `tokens.json` com paleta (light/dark), escala tipográfica, leading, margens, altura de
   linha da lista, *action bar*, *editor*; cada valor com screenshot de referência. O suficiente para
   reimplementar `DraftListScreen`/`EditorScreen` **medindo, não chutando**.
6. **Zero vazamento proprietário**: `git ls-files` não contém `.ipa`, `.app`, `Payload/`, `*.sqlite`,
   `*.car`, imagens extraídas do bundle, nem strings copiadas (grep de confirmação no §7.5).
7. **Reprodutível**: um dev com Mac + `REV_IOS_ARTIFACTS_DIR` vazio consegue refazer C0→C2 só seguindo
   01 e 02 (executar, não decifrar de intuição), e chega nos mesmos `surface/*.json` para o mesmo build.

---

## 7. Legal, ética e higiene (parte da spec, não rodapé)

O cliente é especialista em engenharia reversa; ainda assim, esta trilha opera com limites escritos,
porque o alvo é **software comercial de terceiros** (Drafts, Agile Tortoise) com EULA própria.

### 7.1 Base de permissão

- Analisar uma **cópia adquirida/possuída legitimamente** pelo cliente, em ambiente controlado, para
  **interoperabilidade e estudo** — postura padrão de RE defensiva/compatibilidade. Não é crack, não é
  redistribuição, não é bypass de licenciamento.
- **Sem contornar DRM para obter o app** que não se possui. `ipatool` é usado com conta do cliente para
  baixar o **app gratuito** que a própria conta já pode instalar. A decifração (Tier C) é para permitir
  análise estática local de uma cópia **já possuída**, nunca para instalar fora da loja.
- Bypass de RASP/pinning/jailbreak-detection é **fora de escopo por decisão de projeto** (§1.2), o que
  também remove a discussão de "alteramos o app".

### 7.2 O que pode ser transcrito para o Drafto

| Pode (é o que a trilha produz) | Não pode |
|---|---|
| Fatos: nomes/tipos/nullabilidade de campos, valores de enum, chaves de JSON, lista de comandos de URL scheme, existência de features, métricas de layout | Código-fonte / pseudo-código do binário (Swift/ObjC), trechos descompilados, scripts JS de actions proprietárias |
| Nomes de símbolos quando necessários para *crosswalk* (documentar, não reusar) | `Assets.car`, ícones, imagens, fontes empacotadas, sons |
| Comportamento descrito em português | `Localizable.strings` copiado (texto é criação autoral) — reescrever microcopy |
| Valores de tokens medidos (hex, pt/sp, raio) | Strings internas, *private keys*, tokens de API encontrados no bundle |

Fluxo recomendado: **extração (esta trilha) → cartões de evidência → implementação limpa no Drafto**.
A evidência entra por *review*, e o código do Drafto é escrito a partir da descrição — *clean-room* de
fato, documentado no ledger.

### 7.3 Propriedade do *run*

Os **artefatos** (IPA, `bundle/`, dumps, screenshots) são da conta/infra do cliente, em
`$REV_IOS_ARTIFACTS_DIR`. Nunca no repositório, nunca em issue/PR anexo, nunca em nuvem compartilhada
fora do controle do cliente. Só entram no git: `.md`, `.json` de **descrição** (sem blobs) e os
`screenshots` **quando o cliente autorizar explicitamente** uso interno no doc — padrão: **não commitar**,
referenciar por caminho + SHA-256.

### 7.4 Privacidade (dado pessoal)

O banco do Drafts é texto de usuário. Regras:

1. Instância de análise com **conta descartável** e **corpus sintético** (ex.: `Lorem`/frases geradas,
   nunca notas reais suas, de colegas ou de clientes).
2. Backup/export usado para análise: sanitizado antes de qualquer cópia; **sem** anexar a tickets.
3. Keychain/cookies/tokens: **ler estrutura, não valor**. Se um valor cair em `surface/*.json`, o
   `capture.sh` tem de riscar (`[REDACTED]`) e o cartão de evidência registra que houve segredo, sem o
   segredo.
4. Screenshots podem conter notas reais ao fundo: antes de usar, revisar e censurar; capturar sempre na
   instância sintética.

### 7.5 Auto-verificação (rodar antes de abrir PR)

```bash
cd "$(git rev-parse --show-toplevel)"
git ls-files | rg -i '\.(ipa|car|sqlite|sqlite-wal|png|jpg|mobileprovision|dylib|app|dSYM)$' || echo "OK: nenhum artefato binário versionado"
git ls-files | rg 'Payload/|\.rev-ios/' && echo "FAIL: caminho de artefato no git" || echo "OK: sem caminhos de artefato"
# strings/segredos do bundle não devem aparecer em docs:
git grep -nE "(com\.agiletortoise\.Drafts[0-9A-Za-z.-]*|GTFQ98J4YG)" -- 'docs/**' 'android/**' 'core/**' \
  | rg -v 'docs/rev-ios' || true   # ocorrências só são aceitáveis em docs/rev-ios (contexto forense)
```

### 7.6 Nome e marca

Divergência obrigatória (já é o mandato, §6 de `00-MANDATE.md`): o app é **Drafto**, o scheme é
`drafto://`. Nada desta trilha justifica reuso de marca, ícone, *trade dress* ou texto da Agile Tortoise
— inclusive no *marketing*. Layout *inspirado em métricas* é paridade de UX; *trade dress* copiado é
outra coisa. Manter a fronteira.

---

## 8. Riscos e mitigação

| # | Risco | Imp | Prob | Mitigação / gatilho de saída |
|---|-------|-----|------|------|
| R1 | **Nenhum Mac/device disponível** → trilha trava | alta | alta | Tier A + S2 (backup/export do usuário) e S6 (documentação pública) ainda entregam C2/C3 parciais; escalar para Corellium/runner macOS só para o binário. Decisão de *stop*: se em 2 sprints não houver Tier B, fecha-se a trilha com o que há e o restante vira `unknown` no ledger (não vira chute). |
| R2 | Binário **FairPlay-criptografado** (ipa baixado) → `strings`/class-dump inúteis | alta | alta | Esperado e documentado no skill (`references/ipa-extraction-guide.md` §"FairPlay DRM"): analisar primeiro o que **não** depende do binário (plist, Assets, plists embutidos, JS, *resources*); decifração em Tier C. Nunca reportar "não existe" por não conseguir decifrar — o status é `encrypted`. |
| R3 | **App muda** (Drafts 53 → 54) e o *run* envelhece | média | alta | Todo achado carrega `build` + `sha256`. O ledger referencia o *run*. Ao atualizar, re-rodar só C1–C2 e `diff` de `surface/`. |
| R4 | Confundir **schema interno não-documentado** com contrato | alta | média | Regra do projeto (idêntica a `01-GETDRAFTS-INVESTIGATION.md` §7.4): o schema interno é **evidência**, nunca dependência. Drafto define o seu `core/model.go`; a paridade é **comportamental**. |
| R5 | **Frida version mismatch** host↔device | média | alta | `scripts/preflight_check.py` do skill + `references/tool-versions.md` (fonte de verdade). Pin explícito no *run* `provenance.json`. |
| R6 | Skill vendored **desatualiza/quebra links** ou carrega literal que ativa o *push protection* do GitHub | baixa | **média (já ocorreu)** | `VENDOR.md` (commit + hashes) + `PATCHES.md` declarando cada desvio com SHA-256 pós-patch; `install-skill.sh --check` é gate (arquivos exigidos, *pin*, hashes, patch conferido, varredura de credenciais, edição local não declarada). Update = PR próprio, com re-leitura do README e re-aplicação dos patches. Ver [01 §4](01-CAPTURE-PLAN.md). |
| R7 | Vazamento de artefato proprietário no repo | alta | baixa | §7.5 obrigatório no checklist do PR + `.gitignore` (`artifacts/`, `*.ipa`, `Payload/`). |
| R8 | **Falso positivo de paridade**: ver uma classe/campo no iOS e assumir que o Android precisa dele | média | média | Toda linha do ledger precisa de `drafto_target` **e** `acceptance`. Sem alvo, fica `informational`. |
| R9 | Custo de tempo: RE profunda é infinita | média | alta | Fases com *criterial* (§5). Nada de "mais um trace". Prazo-alvo por fase: C0/C1 = 1 dia; C2 = 2; C3 = 3; C4 = 3; C5 = 5; C6 = 1. |

---

## 9. Governança desta trilha (o mínimo)

- **Docs são código**: toda mudança de entendimento mexe em `LEDGER.md` e, se contradiz, atualiza o
  cartão de evidência correspondente (nunca apagar um cartão; adicionar `superseded_by`).
- **Um commit = uma fase ou um artefato**; mensagens com escopo `rev-ios` (§2.2).
- **PRs desta trilha** só tocam `docs/rev-ios/**`, `skills/**`, `tools/rev-ios/**`, e as **seções de
  destino** em `docs/drafto/*` (CODEMAP, paridade, roadmap). Se um PR `rev-ios/...` tocar `core/` ou
  `android/`, está no branch errado.
- **Sem CI nova**: os jobs Go/Android de `.github/workflows/ci.yml` não são afetados (só `.md`/scripts).
  O *harness* desta trilha é offline e não tem gate.
- **Handoff**: ao fim de cada sessão, atualizar §1 "Estado" do [README.md](README.md) e o bloco
  `status` desta spec. Um leitor novo tem de conseguir retomar em C\<n\> sem perguntar nada.

---

## 10. Começar por aqui (roteiro de 20 minutos)

```bash
# 0. no worktree da trilha (ver §2.4)
export REV_IOS_ARTIFACTS_DIR="$HOME/.rev-ios/artifacts"; mkdir -p "$REV_IOS_ARTIFACTS_DIR"

# 1. skill instalado e capaz?
./tools/rev-ios/install-skill.sh --check
./tools/rev-ios/capture.sh preflight

# 2. o que dá para fazer SEM Mac e SEM device (Tier A) — triagem de um IPA já baixado
./tools/rev-ios/capture.sh acquire --dry-run          # mostra o que seria baixado e onde autenticar
./tools/rev-ios/capture.sh new-run --target getdrafts --build <v>   # abre o run (custódia)
./tools/rev-ios/capture.sh triage ~/.rev-ios/artifacts/raw/Drafts-<build>.ipa
./tools/rev-ios/capture.sh surface --from-bundle ~/.rev-ios/artifacts/<run>/bundle/Payload/Drafts.app

# 3. registrar o resultado
$EDITOR docs/rev-ios/LEDGER.md      # status + evidência + próximo passo
```

Leitura antes de digitar: [01-CAPTURE-PLAN.md](01-CAPTURE-PLAN.md) (quem coleta, como, com que prova),
[`references/linux-ios-analysis-workarounds.md`](../../skills/ios-app-security-audit/references/linux-ios-analysis-workarounds.md)
(o que o Linux permite), e o §7 desta spec (o que **não** se faz).
