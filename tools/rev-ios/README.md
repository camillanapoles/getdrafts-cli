# `tools/rev-ios` — harness da trilha de captura

Ferramentas de **captura/extração** do Get Drafts (iOS) para a trilha `rev-ios/*`.
Spec: [`docs/rev-ios/00-SPEC.md`](../../docs/rev-ios/00-SPEC.md). Nenhum destes scripts escreve no repositório.

| Arquivo | O que faz |
|---|---|
| [`install-skill.sh`](install-skill.sh) | instala / valida / atualiza o skill `ios-app-security-audit` (cópia vendored do branch) em `~/.agents/skills/`. `--check` é gate: arquivos exigidos pela spec, *pin*, SHA-256 de `SKILL.md`/`README.md`, cada patch de `PATCHES.md` conferido por hash, **varredura de literais de credencial** e ausência de edição local não declarada |
| [`capture.sh`](capture.sh) | `preflight` · `new-run` · `acquire` · `triage` · `surface` · `hash` · `purge` |
| [`frida/layout-dump.js`](frida/layout-dump.js) | snapshot read-only da árvore de views (frames/font/cores/`safeArea`) → `layout/tokens.json` |

## Regras transversais

1. **Fora do repo.** Raiz de artefatos = `REV_IOS_ARTIFACTS_DIR` (padrão `~/.rev-ios/artifacts`).
   IPA, `bundle/`, dumps, screenshots e `.sqlite` nunca são commitados
   ([00-SPEC.md](../../docs/rev-ios/00-SPEC.md) §7.3).
2. **Sem credenciais.** `capture.sh acquire` só imprime o plano; o `ipatool` autenticado é do host.
3. **Observação pura.** Nada de patch, re-sign, injeção permanente, bypass.
4. **PII.** Só saem nomes de coluna/chave e enums curtos; `content`/`title` de usuário ficam para trás.
   `purge import raw` destrói os bytes mantendo os hashes (custódia continua auditável).

## Fluxo mínimo

```bash
export REV_IOS_ARTIFACTS_DIR="$HOME/.rev-ios/artifacts"

./tools/rev-ios/install-skill.sh --check          # C0: skill presente, pin confere, nada editado
./tools/rev-ios/capture.sh preflight               # o que este host habilita (Tier A/B/C)

./tools/rev-ios/capture.sh new-run --target getdrafts --build 5300
./tools/rev-ios/capture.sh acquire --dry-run        # plano de aquisição (nada de rede)
./tools/rev-ios/capture.sh triage  caminho/Drafts.ipa          # C1/C2
./tools/rev-ios/capture.sh triage  caminho/Drafts-Backup.zip --kind user-backup
./tools/rev-ios/capture.sh surface --from-db  caminho/DraftStore.sqlite   # C3
./tools/rev-ios/capture.sh hash    caminho/arquivo            # p/ provenance.json
./tools/rev-ios/capture.sh purge import raw             # higienizar após análise (hashes ficam)
```

## O que cada comando produz (e onde pisa na spec)

| Comando | Saídas | Fase / ref |
|---|---|---|
| `preflight [--json] [--strict]` | matriz de capacidades + fases habilitadas | C0 · [00-SPEC §4](../../docs/rev-ios/00-SPEC.md) |
| `new-run` | `provenance.json` + árvore do run | C1 · [01 §5](../../docs/rev-ios/01-CAPTURE-PLAN.md) |
| `acquire [--dry-run\|--yes]` | `raw/*.ipa` + registro no manifesto | C1 · [01 §3.2](../../docs/rev-ios/01-CAPTURE-PLAN.md) |
| `triage <ipa>` | `bundle/`, `surface/{plist,plist-summary,url-schemes,extensions,frameworks,layout-artifacts,strings,template-tags,drafts-urls}`, `triage.md`, `SHA256SUMS`, `artifacts.jsonl`; confirma identidade (E2) no `provenance.json` | C1/C2 · [02 §1](../../docs/rev-ios/02-EXTRACTION-MAP.md) |
| `triage <zip> --kind user-backup` | `import/{files.txt,shape.json}` (shape-only, sem PII) | C1/C3 · [01 §3.5](../../docs/rev-ios/01-CAPTURE-PLAN.md) |
| `surface --from-db <sqlite>` | `db/{schema.sql,tables.json,enums.json}` (read-only, enums redigidos) | C3 · [02 §2](../../docs/rev-ios/02-EXTRACTION-MAP.md) |
| `frida/layout-dump.js` | 1 linha JSON/dump → `runtime/layout.ndjson` | C5 · [04 §3.4](../../docs/rev-ios/04-LAYOUT-PARITY.md) |

## Notas de implementação

- **Sem dependências obrigatórias.** `bash` + `unzip` + `python3` chegam. `plutil`/`plistutil` são
  opcionais: há *fallback* para `python3.plistlib` (lê plist binário) — o que torna o Tier A útil de
  fato, ao contrário do que o workaround do skill sugere. `jq`/`otool`/`jtool2` ausentes viram `skip`
  declarado, nunca resultado falso-negativo.
- **Falha é registrada, não escondida.** "não consegui ler" ≠ "não existe" (R2 do [00-SPEC §8](../../docs/rev-ios/00-SPEC.md)).
- **Idempotente por run**: `SHA256SUMS` é deduplicado (`sort -u`), `artifacts.jsonl` é enfileirado por append.
- O `cryptid` só é lido com `otool`/`jtool2`/`llvm-objdump`; sem eles, `unknown` (e o plano segue).

## Testado

`preflight`, `new-run`, `acquire --dry-run`, `triage` (IPA sintético com `Info.plist` binário real),
`triage --kind user-backup`, `surface --from-db` (SQLite sintético com PII plantada → **não** vazou),
`hash`, `purge`, `install-skill.sh --check` e o smoke-test de `layout-dump.js` contra um mock de ObjC
— tudo em Linux x86_64, 2026-11-11, sem device. Os caminhos Tier B/C (`ipatool`, `frida`, `idevice*`,
`simctl`, `dsdump`) **não** foram exercitados: não há ambiente aqui ([00-SPEC §4](../../docs/rev-ios/00-SPEC.md)).
