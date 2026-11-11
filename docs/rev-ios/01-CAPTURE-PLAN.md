# 01 — Plano de Captura (aquisição do app + ambiente + custódia)

> Fase **C1** do [00-SPEC.md](00-SPEC.md) §5. Responde a uma pergunta só: **como obtemos o app e os seus
> dados, com prova, sem criar passivo jurídico?** Tudo depois disto é [02-EXTRACTION-MAP.md](02-EXTRACTION-MAP.md).

---

## 1. Alvo (identificado)

| Campo | Valor | Confiança |
|-------|-------|-----------|
| App | **Drafts** ("where text starts") | E1 |
| Editor | Agile Tortoise | E1 |
| Loja | App Store (iOS/iPadOS) + Mac App Store | E1 |
| App ID (iOS) | `1236254471` | E2-*a verificar* |
| Bundle ID (iOS) | `com.agiletortoise.Drafts5` | E2-*a verificar* |
| Bundle ID (macOS) | `com.agiletortoise.Drafts` (container `com.agiletortoise.Drafts-OSX`) | E2-*a verificar* |
| App Group | `GTFQ98J4YG.com.agiletortoise.Drafts` (+ `…Drafts-Dev`) | E2-*a verificar* |
| Base local (macOS) | `~/Library/Group Containers/GTFQ98J4YG.com.agiletortoise.Drafts/DraftStore.sqlite` | E1→**confirmar E3** |
| Requisitos (iOS) | iOS 15.6+, watchOS 8.5+; ~79 MB; v53.0 (Jun/2026) | E1 |
| Preço | gratuito + assinatura "Drafts Pro" | E1 |

> Os campos `a verificar` vieram de listagem pública de App Store e de testes de terceiros localizados em
> 2026-11-11. **Não** são fatos do repo. A Fase C1 os confirma com `ipatool search --format json`,
> `plistutil -i Info.plist` (E2) e `ls` do container (E3), e aí sim viram E2/E3 em cartões próprios.
> Nenhum valor dos campos acima entra em `core/` ou `android/` — servem para **localizar** o alvo.

---

## 2. As seis superfícies de captura (ordenadas por custo real)

A regra de decisão: **superfície mais barata que responde a pergunta primeiro.** A pergunta da trilha é
*modelo + comportamento + layout*; segurança não está na tabela.

| ID | Superfície | Tier | Custo | O que entrega | O que **não** entrega |
|----|-----------|------|-------|----------------|----------------------|
| **S1** | **Dicionário AppleScript** (`drafts info --verbose` / `sdef`) | B | ~0 | superfície de automação oficial, tipos/propriedades expostos, *actions* instaladas, workspaces | modelo interno, editor, layout |
| **S2** | **`DraftStore.sqlite` do Drafts para macOS** | B | baixo (1 Mac, sem jailbreak) | **o modelo de dados real**: tabelas, colunas, tipos, defaults, enums, índices/FTS, JSON de actions/workspaces | UI do iOS, código, semântica de runtime |
| **S3** | **IPA da App Store via `ipatool`** (binário FairPlay-criptografado) | A/B | baixo | Info.plist, entitlements do profile, extensões (`.appex`), `Assets.car`, plists embutidos, *frameworks list*, localizações (nomes), `Assets` de cores/fontes | **o binário** (simbologia, classes) — criptografado |
| **S4** | **IPA decifrado** (device jailbroken ou Corellium: `frida-ios-dump`, `dump-ios.js`) | C | alto | Mach-O lido: `nm`/`dsdump`/`class-dump` → classes, seletores, assinaturas de métodos, *strings* de chaves | dados do usuário, comportamento dinâmico |
| **S5** | **Runtime com Frida/Objection** (device JB **ou** simulador via SimForge) | B/C | alto | **E4**: `sqlite-query-logger-ios.js` (o SQL real), `objc-method-tracer.js`, `binary-class-dump.js`, `url-scheme-monitor.js`, `nsuserdefaults-dumper.js`, `coredata-interceptor.js` | — (é o teto do conhecimento; só em ambiente controlado) |
| **S6** | **Backup/export do próprio usuário** (`iCloud Drive > Drafts > Backups`, "Export Archive…", `drafts://` + Shortcuts) | A | **~0** | corpus JSON/CSV de drafts, actions (JSON completo com `steps[]`) e **workspaces** — i.e., o contrato serializado que o app aceita ler/escrever | schema interno, layout, código |

**Recomendação de execução:** `S6 → S2 → S3 → S1` fecham C2/C3/C4 (modelo, serialização, superfície) sem
Tier C. `S4/S5` entram **só** por uma razão pontual e nomeada (ex.: "confirmar se `flagged` é coluna ou
bitmask", "listar os `type` de step aceitos pelo parser"). Não se faz S4/S5 "por garantia".

> S6 é barato e é o melhor *proxy de contrato* que existe: o formato que o Drafts **importa** é o formato
> que o Drafto precisa saber ler para ser compatível, e é dado do **usuário**, não código da editora.
> Um *backup* sintético (20 notas, 3 actions, 2 workspaces, 1 flag, 1 tag multi-word, 1 task) criado na
> instância de análise e exportado vale mais que 10 h de descompilação para as decisões de modelo.

---

## 3. Aquisição — procedimento

### 3.1 Host e identidade

- Máquina **do cliente**, conta **descartável** do cliente, ambiente limpo. O README do skill é explícito:
  *"Use a throwaway Apple ID"*. Nada de conta pessoal em ferramenta não-oficial da Apple
  (`references/ipa-extraction-guide.md` §5).
- Credenciais ficam no *keychain* do host. **Nunca** em `provenance.json`, em log, em variável de ambiente
  gravada em arquivo, ou no commit.

### 3.2 Comandos (Tier A/B, `ipatool`)

```bash
# instalado via brew (macOS) ou binário de release (Linux/Windows) — ver §4
ipatool auth login -e <apple-id-descartavel@exemplo.com>
ipatool auth info                                  # prova de qual conta

ipatool search "Drafts" --format json | tee "$REV_IOS_ARTIFACTS_DIR/raw/search.json"

# app gratuito: --purchase registra a licença na própria conta e baixa o IPA
ipatool download -b com.agiletortoise.Drafts5 --purchase \
  --output "$REV_IOS_ARTIFACTS_DIR/raw/Drafts-<build>.ipa"
ipatool list-versions -b com.agiletortoise.Drafts5   # para capturar um build específico (reprodutibilidade)
```

Atalho no harness (não executa nada sem o binário presente e sem `--yes`):

```bash
./tools/rev-ios/capture.sh acquire --dry-run
./tools/rev-ios/capture.sh acquire --bundle com.agiletortoise.Drafts5 --yes
```

**Expectativa correta:** o IPA vem **com `cryptid=1`** (FairPlay). Isso não é falha da captura — é o
estado natural. O `capture.sh triage` grava `encrypted: true` e o plano segue para o que é legível
(plist/Assets/extensões) — `references/ipa-extraction-guide.md` §"FairPlay DRM".

### 3.3 Alternativas sem `ipatool`

| Método | Como | Quando |
|---|---|---|
| Apple Configurator (Mac) | dispositivo → Apps → botão direito no Drafts → *Export* | você tem o app instalado num iPhone/iPad |
| Xcode → *Devices and Simulators* → *Show in Finder* | o `.app` instalado no device é acessível | bundle structure, sem binário decifrado |
| `ideviceinstaller -l` + `afcclient --house-arrest` | lista apps; sandbox do app via House Arrest | **container** (dados de runtime), não binário |
| Backup do device (`idevicebackup2`) + parser | backup **não** inclui Keychain sem criptografia; inclui app data | último caso |
| SimForge (`scripts/simforge_apply.py`) | patch `LC_BUILD_VERSION` → roda no simulador Apple Silicon | **exige binário decifrado** (S4) — para UI/traces |

Decisão de ambiente documentada no skill: `references/linux-ios-analysis-workarounds.md` §5–§6 —
*re-signing* para device de fábrica e Simulator são os dois únicos becos reais em Linux.

### 3.4 S2 — macOS (o atalho de maior valor)

```bash
# no Mac do cliente, com Drafts instalado e a instância SINTÉTICA populada (§7.4 do SPEC)
D="$HOME/Library/Group Containers/GTFQ98J4YG.com.agiletortoise.Drafts"
ls -la "$D"                                   # confirma nome real do arquivo .sqlite (E3)
cp "$D/DraftStore.sqlite" "$REV_IOS_ARTIFACTS_DIR/db/DraftStore.copy.sqlite"   # nunca abrir o original
sqlite3 "$REV_IOS_ARTIFACTS_DIR/db/DraftStore.copy.sqlite" '.schema' > $REV_IOS_ARTIFACTS_DIR/db/schema.sql
sqlite3 ... "SELECT name, sql FROM sqlite_master ORDER BY type, name" > tables.json
# dicionário AppleScript (S1), no mesmo Mac:
sdef /Applications/Drafts.app > drafts.sdef   # superfície oficial de automação
```

O `capture.sh surface --from-db <sqlite>` faz esta parte (com `.schema`, `PRAGMA user_version`, contagem
de linhas por tabela e *redação* de texto de usuário).

### 3.5 S6 — backup/export do usuário (Tier A, roda em qualquer lugar)

Drafts exporta/importa backup. O que queremos do arquivo é **a forma**, não o conteúdo:

```bash
# dentro de artifacts/<run>/import/
unzip -o Drafts-Backup-<date>.zip -d backup/
find backup -type f \( -name '*.json' -o -name '*.txt' -o -name '*.csv' \) | sort
jq 'keys' backup/drafts/0001.json 2>/dev/null      # chaves do draft serializado
# extrair só o ESQUELETO (chaves + tipos), descartando valores de texto:
python3 - <<'PY'
import json,glob,sys
def shape(v):
    if isinstance(v,dict):  return {k:shape(x) for k,x in v.items()}
    if isinstance(v,list):   return [shape(v[0])] if v else []
    return type(v).__name__
for f in sorted(glob.glob("backup/**/*.json", recursive=True))[:20]:
    print(f, json.dumps(shape(json.load(open(f))), ensure_ascii=False, sort_keys=True))
PY
```

Isto é 100% Tier A: sem Mac, sem device, sem binário. E responde a perguntas que o `CODEMAP.md` §8
deixa em aberto (formato de action, campos de workspace).

---

## 4. Ambiente — instalação conforme o README do skill

O skill declara suporte **macOS e Linux (~90%)**. Instalação local (o que o README upstream manda fazer):

```bash
# upstream manda clonar para o diretório de skills do agente:
cd ~/.agents/skills/ && git clone https://github.com/DragonJAR/iOS-Pentesting-Skill ios-app-security-audit

# NÓS NÃO CLONAMOS. A cópia é o branch (vendored + pinned em skills/ios-app-security-audit/):
./tools/rev-ios/install-skill.sh            # cria ~/.agents/skills/ios-app-security-audit -> cópia do branch
./tools/rev-ios/install-skill.sh --check    # valida pin (commit + SHA-256 de SKILL.md/README.md)
./tools/rev-ios/install-skill.sh --update   # só com aprovação: re-clone upstream, re-pin, re-leitura
```

> **Vendoring × push protection (já mordeu).** `install-skill.sh --check` varre a cópia vendored e
> **falha** se houver literal em formato de credencial real (Stripe `sk_live_…`, AWS `AKIA…`, GitHub
> `ghp_…`, Slack `xox…`, Google `AIza…`) ou se um arquivo divergir do upstream sem estar declarado em
> [`PATCHES.md`](../../skills/ios-app-security-audit/PATCHES.md). Motivo concreto: um exemplo *fictício*
> de chave no doc upstream bloqueou o push deste branch (GitHub `GH013`). Política: neutralizar o literal,
> declarar o patch com SHA-256 pós-patch, e **re-aplicar** os patches a cada `--update --force`.

### 4.1 Toolchain por host

```bash
# macOS (Tier B — recomendado; é onde quase tudo acontece)
brew install python@3.11 git wget jq tree ripgrep ipatool libimobiledevice ideviceinstaller plist
pip3 install frida-tools objection dsdump swift-demangle

# Linux/Debian (Tier A — o que roda aqui)
sudo apt update && sudo apt install -y \
  python3 python3-pip python3-dev clang git wget jq tree ripgrep unzip zip \
  libimobiledevice-utils libplist-utils ideviceinstaller ldid llvm binutils
pip3 install frida-tools objection

# verificação (do próprio skill)
python3 skills/ios-app-security-audit/scripts/preflight_check.py
./tools/rev-ios/capture.sh preflight          # nosso resumo: capacidades → fases habilitadas
```

### 4.2 Substituições Linux (o essencial, do skill)

| macOS | Linux | Nota |
|---|---|---|
| `plutil` | `plistutil -i X.plist -o -` **ou** `python3 -c 'import plistlib'` | bin→XML. **Delta desta trilha:** o *fallback* Python lê/escreve plist binário sem instalar nada — é o que `capture.sh:plist_to_json` usa, e por isso C2 roda em Tier A ([F-0001](findings/0001-harness-e-toolchain.md)) |
| `otool -l/-L` | `llvm-objdump -p`, `jtool2 -l` | `LC_ENCRYPTION_INFO` só com `jtool2` |
| `lipo` | `llvm-lipo` | LLVM ≥ 12 |
| `codesign` | `ldid -e` / `jtool2 --sign` | *pseudo-sign*: só em device jailbroken |
| `class-dump` | `jtool2 -d objc` (parcial) ou Frida `binary-class-dump.js` | runtime é melhor |
| `dsdump` | — (sem build Linux) | Frida `objc-api-explorer.js` ou Mac |
| `sqlite3` (CLI) | `python3 -c 'import sqlite3'` | o harness abre o banco **read-only** pelo módulo: `surface --from-db` não exige o CLI |
| `xcrun simctl` | — | **macOS only**; sem substituto |

Fonte: [`references/linux-ios-analysis-workarounds.md`](../../skills/ios-app-security-audit/references/linux-ios-analysis-workarounds.md)
§1–§7 (ler inteiro antes de prometer um resultado em Linux). Workflow recomendado lá: estático local →
dinâmico via device → MobSF em Docker → só o *macOS-only* para nuvem/runner.

### 4.3 O que **não** tentar

- Instalar/atualizar `frida-server` sem conferir o *pin* de versão (`references/tool-versions.md`) — R5.
- Rodar `scripts/install-mobsf-*.sh` nesta máquina: é conveniência de auditoria (Fase 2 automática) e traz
  ruído de vulnerabilidade que a trilha não quer. Se o cliente pedir um *scan*, roda-se MobSF em Docker
  fora do repo e o resultado vai como `informational`.
- Qualquer coisa dos scripts `patch_*.py`, `simforge_*` (exceto para instalar no simulador com binário
  decifrado **do cliente**), `rasp-*`, `*-bypass-*`, `repackaging`. Ver [VENDOR.md](../../skills/ios-app-security-audit/VENDOR.md)
  §"Restrições de escopo".

---

## 5. Cadeia de custódia (formato obrigatório)

Árvore de um *run* (`$REV_IOS_ARTIFACTS_DIR/<run-id>/`, `run-id = <yyyymmdd>-<alvo>-<build>`):

```
0000/
├── provenance.json        # o quê/de onde/com quê/por quem/quando — escrito por capture.sh
├── SHA256SUMS             # de raw/ e de cada artefato gerado
├── artifacts.jsonl        # 1 linha JSON por artefato (path/sha256/bytes/at) — anexado pelo harness
├── purge.log              # existe se você rodar `capture.sh purge …`: hashes do que foi destruído
├── raw/                   # ipa, zip de backup, sqlite copy (NUNCA no git)
├── bundle/                # Payload/Drafts.app extraído
├── surface/               # plist.json, url-schemes.json, entitlements.json, extensions.json,
│                          # frameworks.json, classes.txt, selectors.txt, defaults-keys.json
├── db/                    # schema.sql, tables.json, enums.json, user_version.txt
├── import/                # esqueletos JSON vindos de backup/export (shape-only)
├── runtime/               # traces frida (ndjson), dumps de hooks
├── layout/                # screens/*.png (+ .md com medidas), tokens.json, assets-car/*.json
└── triage.md              # sumário legível por humano gerado por capture.sh
```

`provenance.json` mínimo (o harness escreve; você completa `actor`):

```json
{
  "run_id": "20261111-getdrafts-53.0",
  "target": {"app": "Drafts", "bundle_id": "…", "build": "…", "source": "app-store|device|user-backup"},
  "acquired_at": "2026-11-11T00:00:00Z",
  "actor": "<quem>",
  "host": {"os": "linux|macos", "arch": "x86_64|arm64", "tools": {"ipatool": "…", "frida": "…"}},
  "artifacts": [{"path": "raw/Drafts.ipa", "sha256": "…", "bytes": 0, "encrypted": true}],
  "consent": {"licensed_copy": true, "synthetic_corpus": true, "no_redistribution": true}
}
```

Sem `provenance.json`, **o run não conta** para os critérios D1/§6.1. É esse o preço de entrar na doc.

---

## 6. Checklist de saída da Fase C1

- [ ] `bundle_id`/`build` **confirmados em E2** (não os valores da tabela §1).
- [ ] `raw/` com IPA (ou cópia do `.app`/backup) + `SHA256SUMS` verificado duas vezes (pós-cópia).
- [ ] `encrypted: true|false` registrado; se `true`, a decisão "analisa recursos / adia binário" escrita.
- [ ] `provenance.json` completo, incluindo `consent`.
- [ ] Instância de análise **sintética** populada (20 drafts, 3 actions, 2 workspaces) antes de qualquer
      leitura de container/screenshot — §7.4 do SPEC.
- [ ] Nada dentro do repo: `git status --porcelain` vazio exceto `docs/`, `skills/`, `tools/`.
- [ ] Próxima fase escolhida e anotada no [LEDGER.md](LEDGER.md) (C2 e C3 em paralelo).
