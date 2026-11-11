# Cartão de evidência — template

> Formato único desta trilha. **Toda** conclusão que pretenda tocar `docs/drafto/CODEMAP.md`,
> `LEDGER.md` ou o código do Drafto nasce como um cartão em `docs/rev-ios/findings/NNNN-<slug>.md`.
> O nome do arquivo é estável: `0001-model-fields.md`. Numeração sequencial, sem reuso.

## Por que um formato fixo

A disciplina é a do skill upstream (*Critical Rules*): uma conclusão sem contexto rastreado é um *grep
hit*; um achado sem limitação declarada é uma mentira útil. Aqui a consequência é direta: o que entra
neste repo vira decisão de produto para o Drafto. O cartão existe para que um revisor consiga
**refutar** a conclusão sem repetir o trabalho.

---

## Template (copiar daqui para baixo)

````markdown
# F-NNNN — <título curto: o que foi estabelecido>

| | |
|---|---|
| **Obrigações** | `OB-MODEL-004`, … (IDs do [LEDGER.md](../LEDGER.md)) |
| **Pergunta** | a pergunta exata, em uma frase |
| **Nível** | E1 doc · E2 estático · E3 dado local · E4 runtime (ver [00-SPEC.md](../00-SPEC.md) §3.1) |
| **Veredito** | `confirmed` \| `partially-confirmed` \| `hypothesis` \| `refuted` \| `unobservable-here` |
| **Run** | `<run-id>` · target `<Drafts x.y (build)>` · sha256 `<…>` |
| **Quando** | <YYYY-MM-DD> por <actor> |
| **Tempo-de-vida** | `stable` \| `build-specific` (muda com o app) |

## Contexto (1 parágrafo)
Por que isto importa para o Drafto. O que estava em dúvida. Qual linha de doc/código é afetada.

## Método (reprodutível)
Passos exatos, com comando e saída relevante. O revisor tem de conseguir chegar ao mesmo resultado.

```bash
$ sqlite3 db/DraftStore.copy.sqlite '.schema drafts'
CREATE TABLE drafts (uuid TEXT PRIMARY KEY, …);
```

## Evidência
- `db/schema.sql#L10-L24` (`capture.sh triage` / comando acima)
- `runtime/sqlite.ndjson` linha N (trace) — se E4
- print/medida, se layout: `layout/screens/01-inbox-light-M.png`, px=…, scale=3 → dp=…

## Conclusão
A frase que entra na doc. Específica e verificável: *"o título do draft é persistido, não derivado em
runtime"* — não *"o app parece salvar o título"*.

## Impacto no Drafto (obrigatório para fechar o ledger)
- `core/model.go`: <campo> → `Title string` (persistido; `titleOf` vira fallback, não fonte)
- `05-ROADMAP.md` schema: `title TEXT NOT NULL DEFAULT ''` continua correto / muda para …
- `02-FEATURE-PARITY.md`: status de "Title" → `Confirmed`
- Testes: adicionar `core/model_test.go` com …

## Limitações / o que NÃO foi estabelecido
O que o método não cobre, o que poderia ser explicação alternativa, o que depende de ambiente ausente.
Escrever `nada-a-notar` só quando for verdade.

## Risco de regressão
O que muda no app-alvo e invalida este cartão (ex.: migração de schema no `PRAGMA user_version`).

## Próximos passos
`OB-…` novos abertos por este achado.
````

---

## Regras de escrita

1. **Um cartão = uma conclusão.** Cartão com três conclusões não é revisável.
2. **Código é citação, não transcrição.** Blocos do binário/JS do alvo **não** entram (LICENÇA + §7.2 do
   [00-SPEC.md](00-SPEC.md)); cita-se o **comportamento** e o **comando**.
3. **Sem PII.** Exemplos de dados: apenas os da instância sintética; texto de usuário fora.
4. `unobservable-here` **é resposta válida** — e melhor que invenção. Descreve o ambiente que falta e
   deixa a `OB-…` como `blocked-env`.
5. **Nunca apagar um cartão.** Refutado → `Veredito: refuted` + `supersedes/superseded_by` + motivo.
6. Layout: `px`, `scale` e `dp` sempre juntos; senão a medida não é transportável.

## Exemplo (mini-cartão preenchido, nível E2, para calibrar o formato)

```markdown
# F-0000 — Skill `ios-app-security-audit` presente no branch e utilizável em Linux para Fases 0–2

| | |
|---|---|
| **Obrigações** | `TOOL-002` |
| **Pergunta** | existe ferramenta de extração iOS operável **neste** host, sem Mac? |
| **Nível** | E2 (leitura do próprio skill) |
| **Veredito** | `partially-confirmed` |
| **Run** | n/a (preparação de ambiente) · skill `fadac2b` @ 2026-10-23 |
| **Quando** | 2026-11-11 por arena/d07fc20f |
| **Tempo-de-vida** | `stable` |

## Contexto
`docs/drafto/CODEMAP.md` §10 registra `rea doctor = healthy:false` (`missing_analysis_engine`) como
limitação do projeto: sem meio de analisar o app original. O skill vendored cobre estática/estrutura.

## Método
    ls skills/ios-app-security-audit/references/linux-ios-analysis-workarounds.md
    python3 skills/ios-app-security-audit/scripts/preflight_check.py | head
    ./tools/rev-ios/capture.sh preflight

## Evidência
`references/linux-ios-analysis-workarounds.md` §1 ("IPA extraction, string/secret scanning, Mach-O
inspection, plist reading … works natively on Linux") e §7 (workflow recomendado em Linux).

## Conclusão
Fases 0–2 (extração, plist, strings, símbolos via `llvm-*`) e a maior parte de 3 rodam em Linux sem
Mac. Re-signing para device de fábrica, `simctl`/SimForge e `dsdump` estático **não** rodam em Linux.

## Impacto no Drafto
- `docs/drafto/CODEMAP.md` §10: limitar a afirmação "análise do iOS original depende de instalação
  futura" → "depende apenas de Mac/device para binário decifrado e Simulator".
- Fases C1/C2/C3 parciais executáveis em Tier A (ledger: `CAP-003`, `OB-ACTION-001`, `OB-TPL-002`).

## Limitações / o que NÃO foi estabelecido
Nada foi ainda extraído do app-alvo: este cartão fala da **ferramenta**, não do Drafts. `plistutil`,
`llvm-objdump`, `ipatool`, `frida`, `sqlite3` **não** estão instalados neste sandbox (medido por
`capture.sh preflight` em 2026-11-11) — sem eles, só `unzip`+`rg`+`strings`+Python funcionam.

## Risco de regressão
Mudança de layout do bundle do Drafts (ex.: SwiftUI) reduz o valor da estática; depende de C2.

## Próximos passos
`CAP-002` (adquirir IPA num host com `ipatool`), `CAP-003` (backup sintético → `capture.sh triage --kind user-backup`).
```
