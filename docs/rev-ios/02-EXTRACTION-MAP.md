# 02 — Mapa de Extração (o que extrair, com que comando, para onde vai)

> Fases **C2–C5**. Cada linha é um contrato: artefato de entrada → comando (com a fase do skill
> correspondente) → arquivo de saída → pergunta que responde → nível de evidência exigido.
> O harness que executa a maior parte é [`tools/rev-ios/capture.sh`](../../tools/rev-ios/capture.sh).

Legenda de ambiente: **[A]** Linux sem device · **[B]** Mac sem jailbreak · **[C]** device JB/Corellium.

---

## 1. C2 — Superfície do bundle (Fase 0/1 do skill)

Objetivo: saber **exatamente** o que o app declara. É o que vira contrato de interoperabilidade
(`drafto://`, extensões, permissões) no Drafto.

| # | Alvo | Comando | Saída | Responde | Nível |
|---|------|---------|-------|----------|-------|
| 1.1 | Estrutura do `.app` | `unzip -o raw/*.ipa -d bundle/` ; `find bundle/Payload/*.app -maxdepth 2 -type d` | `bundle/`, `triage.md` | layout do bundle, extensões, frameworks | E2 [A] |
| 1.2 | `Info.plist` | `plutil -convert json -o - Info.plist` · Linux: `plistutil -i Info.plist -o surface/plist.json` | `surface/plist.json` | versão, build, mínima iOS, permissions, *scene*, *url types* | E2 [A/B] |
| 1.3 | URL schemes | `jq '.CFBundleURLTypes' surface/plist.json` + `rg -o 'drafts://[a-zA-Z/?=&._-]*' bundle -S` | `surface/url-schemes.json` | os ~19 comandos `drafts://` documentados existem mesmo? quais não são documentados? | E2 [A] |
| 1.4 | *Universal links* | `plutil -p` + procurar `associated-domains` no entitlements | `surface/entitlements.json` | domínio AASA, paths aceitos | E2 [B] |
| 1.5 | Entitlements | macOS: `codesign -d --entitlements :- bundle/Payload/Drafts.app` · Linux: `ldid -e` | `surface/entitlements.json` | App Group id, Keychain access groups, *shared containers* | E2 [B/C] |
| 1.6 | Extensões | `find bundle -name '*.appex' -maxdepth 5` + `plutil -p` de cada `Info.plist` | `surface/extensions.json` | Share/Quick Look/Widget/Watch — **quais entry points de captura existem** (mandato: captura rápida) | E2 [A/B] |
| 1.7 | Frameworks | `ls bundle/Payload/Drafts.app/Frameworks`; `otool -L`/`llvm-objdump -p` | `surface/frameworks.json` | RN/Flutter/SwiftUI-only? (Fase 0 *framework detection*) — define a estratégia de hook | E2 [A/B] |
| 1.8 | Encrypted? | `otool -l Drafts \| rg -A3 LC_ENCRYPTION` · Linux: `jtool2 -l` | `triage.md` | `cryptid` 0/1 → decide se S4 é preciso | E2 [B/C] |
| 1.9 | Versão de build | `jq '{version:.CFBundleShortVersionString, build:.CFBundleVersion}'` | `provenance.json` | R3 (envelhecimento do run) | E2 [A] |

**Formato de saída canônico** (`surface/*.json`): objeto com `_meta` (`source`, `cmd`, `at`,
`evidence`) + o dado. O harness garante o envelope; assim um `.json` de 2026 pode ser reliado em 2028
sabendo **como** foi produzido.

```json
{ "_meta": {"source":"bundle/Payload/Drafts.app/Info.plist","cmd":"plistutil -i Info.plist -o -",
            "at":"2026-11-11T12:00:00Z","evidence":"E2","run":"20261111-getdrafts-53.0"},
  "url_schemes": [{"name":"drafts","schemes":["drafts"],"roles":["Editor"]}] }
```

## 2. C3 — Modelo de dados (Fase 2 do skill: storage)

Objetivo: o **contrato real** do `Draft`. É o que muda `core/model.go` + o schema SQLite do
[roadmap](../drafto/05-ROADMAP.md).

| # | Alvo | Fonte | Saída | Nível |
|---|------|-------|-------|-------|
| 2.1 | Schema SQL completo | `sqlite3 db/DraftStore.copy.sqlite '.schema'` | `db/schema.sql` | E3 [B] |
| 2.2 | Tabelas + tipos + contagem | `PRAGMA table_info(t)` por tabela; `SELECT count(*)` | `db/tables.json` | E3 [B] |
| 2.3 | Migração/usabilidade | `PRAGMA user_version; PRAGMA journal_mode;` | `db/meta.json` | E3 [B] |
| 2.4 | Enums reais | `SELECT DISTINCT folder FROM drafts` (nomes conforme 2.1) | `db/enums.json` | E3 [B] |
| 2.5 | Defaults/nullabilidade | `SELECT * FROM drafts LIMIT 5` em conta sintética + `INSERT` observado em 2.9 | `db/defaults.json` | E3 [B] |
| 2.6 | Índices/busca | `SELECT name, sql FROM sqlite_master WHERE type='index'` | `db/indexes.json` | E3 [B] — responde "tem FTS? como?" (gap P0 #2) |
| 2.7 | Actions serializadas | tabela de actions / `*.actionset` / JSON do backup (`import/`) | `db/actions.json` + `surface/action-schema.json` | E3 [B]/E2 [A] — responde o P0 #4 (*action groups* + steps) |
| 2.8 | Workspaces serializados | idem, tabela/JSON de workspaces | `db/workspaces.json` | E3/E2 |
| 2.9 | **Escritas observadas** | `sqlite-query-logger-ios.js` durante interação manual | `runtime/sqlite.ndjson` | **E4** [B/C] |
| 2.10 | Preferências globais | `plutil -p ~/Library/Preferences/com.agiletortoise.Drafts*.plist` / `nsuserdefaults-dumper.js` | `surface/defaults-keys.json` | E2/E4 |
| 2.11 | Chaves de *state restoration* | `rg -o 'key[sS]tring' ` no plist + trace `objectForKey:` | `runtime/keys.txt` | E4 [B/C] |

**Redação obrigatória (2.2/2.5/2.9):** valores de texto de usuário são descartados; só **nomes de
coluna, tipos, enums curtos e JSON estrutural** vão para os arquivos. O `capture.sh surface --from-db`
redige `content`/`title` automaticamente (§7.4 do SPEC).

## 3. C4 — Semântica (Fase 3: *source-to-sink*)

Objetivo: transformar *presença de campo* em *regra de comportamento*. Cada linha vira um cartão de
evidência; sem cartão, não vira código no Drafto.

| # | Pergunta | Método | Evidência mínima |
|---|----------|--------|------------------|
| 4.1 | O que é `flagged` em relação a `folder`? Um draft arquivado pode estar flagado? Onde aparece na lista? | 2.4 (SELECT cruzado) + trace 2.9 ao tocar a estrela | E3 + E4 |
| 4.2 | `trash` apaga em 30 dias? Quem faz a limpeza (app, tarefa agendada, iOS `BGAppRefreshTask`)? | procurar `dateDeleted`/`deletedAt`; `rg -i 'trash\|purge\|expire'` strings (E2) **ou** observação direta em runtime | E4 para afirmar; E2 no máximo `hypothesis` |
| 4.3 | Como se normaliza tag? (case, separador, `#`, `@`, espaços, sub-tags `>`/`/`) | entrada controlada na instância sintética + `SELECT tags` + `defaults` | E3 |
| 4.4 | Título: primeira linha *com* ou *sem* prefixo de markdown? truncado? em que byte? | comparar `title` vs `substr(content,1,n)` | E3 |
| 4.5 | Steps aceitos por action (`type` enum completo) + `afterSuccess` | `import/` do backup + parser em runtime (`objc-method-tracer` na classe de *action runner*) | E2 shape + E4 enum |
| 4.6 | Template tags `[[...]]` suportadas | `rg -o '\[\[[a-z_]+\]\]'` no binário decifrado / no JS embutido; testar via `drafts://runAction` | E2/E4 — responde o P0 #1 (`[[clipboard]]`) |
| 4.7 | `permalink`/URL scheme: parâmetros aceitos, `x-callback-url`, erros | `url-scheme-monitor.js` + chamadas controladas | E4 [B/C] |
| 4.8 | Version history: granularidade, limite, *pruning* | tabela de versões + `count(*)/draft` | E3 |
| 4.9 | Tasks (checkbox) e `linkedItems`: derivados em runtime ou persistidos? | schema (coluna?) + trace ao editar | E3 + E4 |
| 4.10 | Sync: o que o app escreve em CloudKit/iCloud Drive (backup) | `ls` do container, `Library/Application Support/CloudKit`, backup files | E3 [B] — *só inventário*, nada de protocolo |

Cada veredito tem de dizer **uma** de: `support` (Drafto implementa igual), `adapt` (implementa com
mecânica Android análoga), `reject` (não faz sentido em Android — dizer por quê), `defer` (Phase >2).

## 4. C5 — Estrutura interna (Fase 0/2 no binário; só Tier C)

| # | Alvo | Comando | Responde | Nível |
|---|------|---------|----------|-------|
| 5.1 | Símbolos ObjC/Swift | `nm -gU <bin>`; `jtool2 -d objc`; `dsdump -H <bin>` | nomes de classes de modelo (`*Draft*`, `*Action*`, `*Workspace*`) → **crosswalk** no [03](03-CODEMAP-BRIDGE.md) | E2 |
| 5.2 | Classes em runtime | Frida `binary-class-dump.js` / `class-explorer-ios.js` | o modelo real em memória; *properties* e *ivars* | E4 |
| 5.3 | Métodos de uma classe | `objc-method-tracer.js` (filtro no namespace do app, não nos frameworks — *Critical Rule 2* do skill) | o que é chamado quando (gatilho → efeito) | E4 |
| 5.4 | Selector de interesse | `rg -o 'set[A-Z][A-Za-z]+:' strings` | setters que o modelo expõe (ordem de escrita) | E2 |
| 5.5 | Persistência | `coredata-interceptor.js` | Core Data vs SQLite cru (muda nossa decisão de `store`) | E4 |
| 5.6 | *Secrets*/strings | `strings -a` + `rg` de padrões do skill (Fase 2) | **não** é alvo de achado aqui; serve para achar chaves de formato (ex.: nomes de chave JSON) | E2 |

> Anti-padrão que a trilha proíbe: usar `strings` como prova de comportamento. String presente ≠ feature
> ativa. Regra do skill: *never report bare grep hits without traced context*. Nosso uso legítimo de
> `strings` é **descobrir nomes de chave/enum para depois confirmar em E3/E4**.

## 5. Scripts Frida relevantes (do skill) e por que exatamente estes

`assets/frida-scripts/` tem 73 scripts; a trilha usa **nove**. Os demais são de ofensiva/bypass e ficam
desligados ([VENDOR.md](../../skills/ios-app-security-audit/VENDOR.md)).

| Script | Uso aqui | Fase |
|---|---|---|
| `sqlite-query-logger-ios.js` | o **SQL real** que o app emite: confirma schema usado, transações de flag/archive/trash, ordenação | C3/C4 |
| `coredata-interceptor.js` | decide Core Data × SQLite; captura `fetch request` (sort/limit!) | C4 |
| `nsuserdefaults-dumper.js` | chaves de configuração (sintaxe, fontes, tema) — alimenta layout | C4/C5 |
| `binary-class-dump.js` | dump de classes/properties em runtime (substituto de `dsdump` em Linux) | C5 |
| `class-explorer-ios.js` | exploração interativa por prefixo (`Draft`, `Action`, `Workspace`) | C5 |
| `objc-method-tracer.js` | fluxo método→método num gesto específico | C5 |
| `url-scheme-monitor.js` | quais comandos `drafts://` o app aceita e como responde | C2/C4 |
| `pasteboard-monitor.js` | comportamento de copiar/colar (template `[[clipboard]]`) | C4 |
| `snapshot-overlay-check.js` | se o app borra o conteúdo ao ir para *background* → explica o que os screenshots capturáveis mostram | C5 |

Uso (host Linux/Mac + device jailbroken; **nunca** em dispositivo de terceiros):

```bash
cd "$SKILL_DIR"   # ~/.agents/skills/ios-app-security-audit
frida -U -f <bundle_id> -l assets/frida-scripts/sqlite-query-logger-ios.js \
      2>&1 | tee "$REV_IOS_ARTIFACTS_DIR/<run>/runtime/sqlite.ndjson"
```
*(no simulador com gadget: `frida -H 127.0.0.1:27042 …` — ver `references/frida-ios-simulator-workflow.md`)*

## 6. Saída → consumidor (a tabela que ninguém deve esquecer)

| Extraído | Consumidor no Drafto | Tipo de mudança |
|---|---|---|
| `db/schema.sql` | [`05-ROADMAP.md`](../drafto/05-ROADMAP.md) schema SQLite (proposto) | **confirmar/corrigir** o `CREATE TABLE drafts` |
| `db/enums.json` | `core/model.go` (`Folder`, `Sort`) | adicionar/renomear constantes + testes |
| `surface/action-schema.json` | `core/action.go`, `android/core-go/action.go` (`ParseAction`) | aceitar os `type` reais + `after_success` |
| `runtime` template tags | `core/template.go` | **P0 #1** — `[[clipboard]]` et al. |
| `db/indexes.json` | `core/memory.go`/`sqlitestore` `Query(sort)` | ordem real + FTS |
| `surface/url-schemes.json` | `cmd/drafto`, `drafto://` no Android | paridade de comando + `x-callback-url` |
| `layout/tokens.json` | `android/.../ui/theme/`, `DraftListScreen`, `EditorScreen` | tema Material 3 com valores medidos |
| `surface/extensions.json` | `AndroidManifest.xml` (`ACTION_SEND`, share sheet) | **captura**: o ponto central do app |

## 7. Saída da fase (checklist)

- [ ] Cada linha marcada como *feita* tem arquivo **e** cartão de evidência (ou está `blocked` com motivo).
- [ ] `triage.md` e `surface/*.json` têm `_meta` válido (source+cmd+evidence).
- [ ] Segredos/PII: `rg -i 'token|secret|password' surface/ runtime/` revisado à mão; achados → `[REDACTED]` + cartão.
- [ ] Todo `support/adapt/reject/defer` de C4 registrado no [LEDGER.md](LEDGER.md).
- [ ] `git ls-files | rg -i '\.(ipa|car|sqlite|png)$'` vazio (§7.5 do SPEC).
