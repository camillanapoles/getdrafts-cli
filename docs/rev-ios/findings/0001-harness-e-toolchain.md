# F-0001 — O *harness* de captura é executável em Linux sem device; o gap real é aquisição/binário, não triagem

| | |
|---|---|
| **Obrigações** | `TOOL-001`, `TOOL-002`, `TOOL-003` (parcial), e habilita `CAP-002/003` |
| **Pergunta** | a trilha `rev-ios` consegue produzir evidência utilizável num host Linux x86_64 sem Mac e sem device iOS? |
| **Nível** | E2 (execução local do tooling + leitura do skill vendored) |
| **Veredito** | `confirmed` para C0–C3 parciais; `unobservable-here` para C5-runtime e binário decifrado |
| **Run** | sintético (fixture próprio, **não** o app-alvo) · skill `fadac2b` · harness `tools/rev-ios@arena/d07fc20f` |
| **Quando** | 2026-11-11 por Arena (`arena/d07fc20f-getdrafts-cli`) |
| **Tempo-de-vida** | `stable` (ferramenta), `build-specific` (nada — alvo não foi tocado) |

## Contexto

[`CODEMAP.md`](../../drafto/CODEMAP.md) §10 registra como limitação do projeto que *"a análise do Get Drafts
iOS original (binário) depende de instalação futura"* (Hopper/Ghidra/IDA ausentes, `rea doctor` não-healthy),
e o workaround upstream ([`linux-ios-analysis-workarounds.md`](../../../skills/ios-app-security-audit/references/linux-ios-analysis-workarounds.md))
trata Linux como ~90% capaz mas dependente de `plistutil`/`llvm-objdump` instaláveis. Se a triagem estática
inteira depende de pacotes que não estão no host, a trilha não começa. Este cartão mede o que de fato roda.

## Método (reprodutível)

    ./tools/rev-ios/install-skill.sh --check          # integridade do skill vendored
    ./tools/rev-ios/capture.sh preflight              # capacidades → fases
    # fixture sintético (IPA-like com Info.plist BINÁRIO real gerado por plistlib, PII plantada no "código"):
    ./tools/rev-ios/capture.sh new-run --target fakedrafts --build 5300
    ./tools/rev-ios/capture.sh triage /tmp/fix/fake-drafts.ipa
    ./tools/rev-ios/capture.sh triage /tmp/drafts-backup.zip --kind user-backup
    ./tools/rev-ios/capture.sh surface --from-db /tmp/dbsim/DraftStore.sqlite
    ./tools/rev-ios/capture.sh purge import raw
    node --check tools/rev-ios/frida/layout-dump.js   # + smoke com mock de ObjC

## Evidência

- `capture.sh preflight` (2026-11-11, Linux x86_64): presentes `unzip`, `zip`, `rg`, `strings`, `python3 3.11`,
  `python3-sqlite3`; ausentes `plutil`, `plistutil`, `otool`, `llvm-objdump`, `jtool2`, `assetutil`,
  `sqlite3` (CLI), `ipatool`, `frida`, `idevice_id`, `xcrun`.
- `triage` no IPA sintético produziu: `bundle/`, `surface/plist.json`, `surface/plist-summary.json`,
  `surface/url-schemes.json` (com `CFBundleURLSchemes:[drafts]` extraído do plist **binário**),
  `surface/extensions.txt` (1 `.appex`), `surface/frameworks.txt`, `surface/layout-artifacts.txt`,
  `surface/template-tags.txt` (6 tags), `surface/drafts-urls.txt` (4), `triage.md`, `SHA256SUMS`,
  `artifacts.jsonl` (9 linhas JSON válidas) e `provenance.json` com `identity.evidence = "E2:Info.plist"` e
  `bundle_matches_claim: true`.
- `surface --from-db` extraiu `db/schema.sql` (4 tabelas + 2 índices), `db/tables.json` (colunas, tipos,
  defaults, `pk`, contagem, `PRAGMA user_version/journal_mode/page_size/encoding`) e `db/enums.json` com
  `folder=[archive,inbox,trash]`, `flagged=[1,0]`, `syntax=[markdown,plain,taskpaper]`,
  `workspaces.sort=[modified]`, `actions.kind=[user]` — e **zero** ocorrência do marcador de PII plantado
  (`grep -rl` só achou o material bruto em `import/backup/`, que é o esperado).
- `purge import raw` removeu os bytes e manteve os hashes em `purge.log` + `SHA256SUMS` → a custódia
  sobrevive à destruição do material sensível.
- `install-skill.sh --check` valida: 28 arquivos exigidos presentes, pin `fadac2b`, coerência com
  `VENDOR.md`, SHA-256 de `SKILL.md`/`README.md` batendo com o publicado, e ausência de edição local da
  cópia vendored.
- `git` (ref testing, repo descartável): branch `rev-ios/foo` + tag plana `rev-ios-foo-20261111` **coexistem**;
  já `tag rev-ios` + `tag rev-ios/foo` falham com `fatal: cannot lock ref 'refs/tags/rev-ios/foo': 'refs/tags/rev-ios' exists`.
  Isto é o que fundamenta a regra de tag do [00-SPEC.md](../00-SPEC.md) §2.3.

## Conclusão

1. **C0–C3 rodam em Linux sem nada instalado além de `unzip`+`python3`.** O `Info.plist` binário é lido via
   `plistlib` (*fallback* implementado em `capture.sh:plist_to_json`), e o schema SQLite via módulo
   `sqlite3` do Python — **não** é preciso o CLI `sqlite3`. Isto melhora o quadro do skill upstream
   (que exige `plistutil` e lista `sqlite3` no `apt install`).
2. **O gargalo real é (a) aquisição autenticada e (b) binário/runtime** — `cryptid` fica `unknown` sem
   `otool`/`jtool2`/`llvm-objdump`, e C5 exige simulador (macOS) ou device (Frida).
3. **O formato de *run* do [01-CAPTURE-PLAN.md](../01-CAPTURE-PLAN.md) §5 é executável**, não só descritivo:
   `provenance.json` + `SHA256SUMS` + `artifacts.jsonl` são gerados automaticamente e a identidade do alvo é
   confirmada em E2 a partir do bundle quando o IPA está disponível.
4. `layout-dump.js` (C5) está escrito e validado contra um mock de runtime ObjC: emite `_meta`
   (pid/arch/locale/screen/scale/orientation/darkMode), mantém sub-árvores, e publica apenas
   `text_len` — nunca o texto.

## Impacto no Drafto

- Nenhum campo de modelo foi decidido aqui — **deliberadamente**. O que muda: `tools/rev-ios/**`,
  `skills/getdrafts-ios-rev/**`, `skills/ios-app-security-audit/**` (vendored), `docs/rev-ios/**`.
- `docs/drafto/CODEMAP.md` §10: a frase *"a análise do Get Drafts iOS original (binário) depende de
  instalação futura"* deve ser lida como **"só o binário decifrado e o runtime dependem de Tier C;
  superfície, formato e layout estático rodam hoje em Linux"** — pendente de PR de doc (passo 5 do
  [03-CODEMAP-BRIDGE.md](../03-CODEMAP-BRIDGE.md) §2).
- `01-CAPTURE-PLAN.md` §4.2: adicionar a linha de substituição `plutil|plistutil → python3 -c 'import plistlib'`
  (já refletida no harness).
- Ledger: `TOOL-001`, `TOOL-002` → `evidence`; `TOOL-003` → parcialmente entregue (dump de views pronto;
  `measure.py`/`layout-diff.py` ainda abertos); `CAP-003` passa a ser *executável hoje* (só precisa do
  arquivo de backup do cliente).

## Limitações / o que NÃO foi estabelecido

- **Absolutamente nada sobre o Drafts real** foi aferido: todo o teste usou fixture sintético construído
  neste sandbox. O cartão prova o *instrumento*, não o *alvo*.
- Não verificado: comportamento com `cryptid=1` real (strings só devem ser lidas em binário decifrado; no
  fixture o "binário" é texto plano — o `cryptid=unknown` do teste **não** representa o IPA da loja).
- `preflight --strict` não foi exercitado em cenário de ambiente quebrado (só o caminho feliz).
- Tier B/C não testados: `ipatool`, `frida`, `idevice*`, `simctl`, `assetutil`, `dsdump` **não** existem aqui.
- A confirmação de `bundle_id`/App ID por fonte secundária (listagem de App Store + posts de terceiros,
  2026-11-11) continua **E1→E2 pendente**: não se escreva `com.agiletortoise.Drafts5` em lugar nenhum do
  código, apenas como alvo de busca.

## Risco de regressão

Re-escrever `plist_to_json` sem o *fallback* `plistlib` reintroduz a dependência de `libplist` e derruba C2
em Linux. `install-skill.sh --check` é o detector dessa regressão (arquivos exigidos + pin + hash).

## Próximos passos

`CAP-002` (rodar `acquire` em host com `ipatool`), `CAP-003` (backup sintético real do cliente →
`triage --kind user-backup`), `OB-ACTION-001` (espera `steps[].type` do `import/shape.json`), `TOOL-003`
(resto: `layout/measure.py`, `layout-diff.py`).
