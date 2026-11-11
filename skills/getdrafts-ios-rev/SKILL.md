---
name: getdrafts-ios-rev
description: Procedimento de engenharia reversa para ENTENDER o app Get Drafts (iOS) — captura do artefato, extração de modelo de dados, superfície de automação e layout — e converter isso em obrigação de paridade para o Drafto (Android/Linux). Use quando for pedido "engenharia reversa do Drafts", "entender o app iOS original", "capturar/extract o Get Drafts", "extrair o schema do Drafts", "layout idêntico ao Drafts", "abrir um run de captura rev-ios", ou ao atualizar docs/drafto/CODEMAP.md com evidência do iOS. Envolve o skill `ios-app-security-audit` (Fases 0–4) e os harnesses tools/rev-ios/*. NÃO usar para pentest/divulgação de vulnerabilidades, bypass de DRM/RASP/pinning, re-sign/repackage, nem para escrever código do Drafto a partir de código descompilado.
homepage: https://github.com/camillanapoles/getdrafts-cli
metadata: {"drafto":{"track":"rev-ios","target":"Drafts (Agile Tortoise)","ios":"15.6+","bundle_hint":"com.agiletortoise.Drafts5","os":["darwin","linux"],"requires_bins":["bash","unzip","python3"],"optional_bins":["ipatool","frida","idevice_id","plutil","plistutil","llvm-objdump","jtool2","sqlite3","dsdump"],"skill_dep":"ios-app-security-audit","skill_pin":"fadac2b"}}
---

# Get Drafts (iOS) → evidência para o Drafto

Procedimento da **trilha `rev-ios`**. Este skill é a camada de *como fazer aqui*; o conhecimento genérico
de iOS (comandos, limitações, troubleshooting) está no skill vendored `ios-app-security-audit`.
A spec é [`docs/rev-ios/00-SPEC.md`](../../docs/rev-ios/00-SPEC.md).

## Regras invioláveis (lidas antes de qualquer comando)

1. **Observar, não alterar.** Proibido: patch, re-sign, injeção permanente, bypass de pinning/RASP/
   jailbreak-detection, Contornar DRM para **obter** o app. Tier C (binário decifrado) só para analisar
   cópia **já possuída** pelo cliente, e só com uma pergunta nomeada.
2. **Não há código do alvo no produto.** O Drafto recebe *descrição* (cartão de evidência), nunca código
   descompilado, assets, fontes, `Localizable.strings`, ícones ou *trade dress*.
3. **Sem PII.** Instância sintética. Nunca dados reais de usuário. Nunca anexar dumps/screenshots a
   issue/PR. Só texto de *placeholder* conhecido em exemplos.
4. **Artefatos fora do repo.** `REV_IOS_ARTIFACTS_DIR` (padrão `~/.rev-ios/artifacts`). `git status` limpo
   além de `docs/`, `skills/`, `tools/`.
5. **Evidência com nível.** E1 doc · E2 estático · E3 dado local · E4 runtime. `<  E2` é hipótese e fica
   no ledger como `open`/`blocked-env`. **"não consegui ler" ≠ "não existe"**.
6. **Uma conclusão = um cartão** em `docs/rev-ios/findings/NNNN-*.md`
   ([formato](../../docs/rev-ios/FINDINGS-TEMPLATE.md)) + **linha atualizada no
   [ledger](../../docs/rev-ios/LEDGER.md)**. Sem os dois, nada entra em `CODEMAP.md` nem em `core/`.

## Fluxo (executar em ordem, parar quando o critério da fase fecha)

```bash
export REV_IOS_ARTIFACTS_DIR="$HOME/.rev-ios/artifacts"
./tools/rev-ios/install-skill.sh --check     # skill no lugar, pin confere, cópia não editada
./tools/rev-ios/capture.sh preflight         # o que este host habilita (Tier A/B/C)
```

**C0 — ambiente.** Se `plutil`/`plistutil` faltarem em Linux: o harness cai em `python3.plistlib`, então a
triagem de `Info.plist` ainda funciona. Ferramentas ausentes **declaradas** no `triage.md` são aceitáveis;
resultados "vazios" sem declaração são bug.

**C1 — captura.** Preferir a superfície mais barata que responde:
`S6 backup/export do usuário` → `S2 DraftStore.sqlite (macOS)` → `S3 IPA (ipatool, criptografado)` →
`S1 dicionário AppleScript` → só então `S4/S5` (binário decifrado / runtime).

```bash
./tools/rev-ios/capture.sh new-run --target getdrafts --build <v>
./tools/rev-ios/capture.sh acquire --dry-run               # Tier A/B: mostra o plano, não autentic
./tools/rev-ios/capture.sh triage <Drafts.ipa>             # C1/C2 (bundle, plist, extensões, strings, cryptid)
./tools/rev-ios/capture.sh triage <Drafts-Backup.zip> --kind user-backup   # shape-only: chaves de contrato
```

**C2 — superfície.** `surface/{plist,url-schemes,extensions,frameworks,layout-artifacts}.json|txt`.
Perguntas a responder: quais `drafts://` o app declara, o que as extensões (Share/Widget/Quick Look/Watch)
fazem, quais App Groups, o que é configurável (`UIAppFonts`, `NS*UsageDescription`). Cada achado →
analogia Android no `AndroidManifest`/deep links do Drafto.

**C3 — modelo de dados.**

```bash
./tools/rev-ios/capture.sh surface --from-db <DraftStore.copy.sqlite>   # schema/tables/enums redigidos
```
Foco: campos + tipos + defaults, enums de `folder`/`flagged`, índices (existe FTS?), tabela de versions,
tarefas (Taskpaper), `tags` serializadas. É o que muda `core/model.go` e o schema SQLite do
[`05-ROADMAP.md`](../../docs/drafto/05-ROADMAP.md).

**C4 — semântica.** Cada campo vira regra: normalização de tags (case, separador, sub-tags), derivação de
título, `flag` × `folder`, `afterSuccess`, escopo de busca, auto-delete do trash, e o JSON de actions
(`steps[].type` completos + `config` por tipo). Veredito obrigatório por item:
`support` / `adapt` / `reject` / `defer` + *Impacto no Drafto*.

**C5 — runtime & layout** (Tier B/C):

```bash
frida -U -f <bundle> -l "$SK/assets/frida-scripts/sqlite-query-logger-ios.js" | tee runtime/sqlite.ndjson
frida -U -f <bundle> -l "$SK/assets/frida-scripts/binary-class-dump.js"       | tee runtime/classes.ndjson
frida -U -f <bundle> -l tools/rev-ios/frida/layout-dump.js                    | tee runtime/layout.ndjson
"$SK/scripts/screenshot-extractor.sh" <bundle> layout/screens/
```
Layout só com a **instância sintética** nos estados definidos em
[`04-LAYOUT-PARITY.md`](../../docs/rev-ios/04-LAYOUT-PARITY.md) §2 (idioma, tema, Dynamic Type, régua de "M").

**C6 — integração.** PR `rev-ios/<slug>` só com docs; as seções de destino (`CODEMAP.md` §11,
`02-FEATURE-PARITY.md`, `05-ROADMAP.md`) atualizam no mesmo PR. O **código** do Drafto muda em PR
separado na trilha `reverse/`, referenciando o cartão.

## Saída por fase (o "pronto")

| Fase | Artefatos | Critério |
|---|---|---|
| C1 | `provenance.json`, `SHA256SUMS`, `triage.md` | alvo confirmado em E2; `encrypted` declarado; `consent.*` preenchido |
| C2 | `surface/*` | cada chave relevante com valor **ou** `ABSENT` explícito |
| C3 | `db/*`, cartões `model-*` | 13 linhas `OB-MODEL-*` com veredito |
| C4 | cartões `semantics-*` | todo `type` de action step classificado |
| C5 | `layout/tokens.json`, `layout/screens/`, `runtime/*` | todo token com medida + screenshot + evidência |
| C6 | PR + `LEDGER.md` | §7.5 do SPEC verde (nenhum artefato no git) |

## Anti-padrões desta trilha

| Não faça | Faça |
|---|---|
| `strings` achou `[[clipboard]]` → adicionar no `core/template.go` | confirmar E4 (`pasteboard-monitor.js`/`drafts://runAction`) antes |
| Copiar schema `DraftStore.sqlite` como schema do Drafto | usar como *evidência de semântica*; o schema do Drafto é decidido em `core/store.go` |
| Anexar screenshot do Drafts no PR | referenciar `layout/screens/…png` por caminho + SHA-256 |
| "O app não tem X" porque o IPA está criptografado | `encrypted:true` + `unobservable-here` |
| Rodar `simforge_*`/`patch_*`/`rasp-*`/`*-bypass-*` | fora de escopo: a trilha não altera o alvo |
| Editar `skills/ios-app-security-audit/**` | deltas em `skills/getdrafts-ios-rev/` e `docs/rev-ios/` (o *pin* precisa bater) |
| Decidir layout de memória | medir (screenshot + `layout-dump.js`) → `tokens.json` |

## Ferramentas (o que usar do skill vendored)

`references/getting-started-ios.md` (orientação) · `references/linux-ios-analysis-workarounds.md`
(**obrigatório em Linux**: tabela de substituições e o que é impossível) ·
`references/ipa-extraction-guide.md` (§"Container vs Binary", §5 `ipatool`, §"FairPlay DRM") ·
`references/tool-versions.md` (pin de versão do Frida) · `scripts/preflight_check.py` ·
`scripts/quick-static-analysis.sh` (Fases 0–2 como driver) · `scripts/screenshot-extractor.sh` ·
`assets/frida-scripts/{sqlite-query-logger-ios,coredata-interceptor,nsuserdefaults-dumper,binary-class-dump,class-explorer-ios,objc-method-tracer,url-scheme-monitor,pasteboard-monitor,snapshot-overlay-check}.js`.

Nossos scripts próprios: [`tools/rev-ios/capture.sh`](../../tools/rev-ios/capture.sh) (captura/triagem),
[`install-skill.sh`](../../tools/rev-ios/install-skill.sh) (instalação/validação do skill),
[`frida/layout-dump.js`](../../tools/rev-ios/frida/layout-dump.js) (árvore de views read-only).

## Version

v0.1.0 (2026-11-11) — criado na sessão `arena/d07fc20f-getdrafts-cli`; skill dep `ios-app-security-audit`
@ `fadac2b` (Apache-2.0, DragonJAR SAS — atribuição obrigatória, ver
[`VENDOR.md`](../../skills/ios-app-security-audit/VENDOR.md)).
