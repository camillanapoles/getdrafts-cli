# PATCHES — deltas locais aplicados na cópia vendored

Único lugar onde **esta cópia** pode divergir do upstream. Cada linha é uma exceção declarada e
auditável; `tools/rev-ios/install-skill.sh --check` exige que (a) todo arquivo modificado esteja listado
aqui e (b) nenhum padrão de credencial em formato **real** exista na árvore.

| # | Arquivo | Linha | Motivo | Antes | Depois | SHA-256 (depois) |
|---|---------|-------|--------|-------|--------|------------------|
| P1 | `references/commoncrypto-analysis.md` | 569 | GitHub **push protection** recusava o push: o exemplo de API key *fictícia* tinha formato de credencial Stripe de produção (`sk_live_` + 32 alfanuméricos — o literal não é reproduzido aqui, de propósito). Material didático, não segredo real; ainda assim, manter literal com formato válido num repo é ruído de segurança. Neutralizado preservando o sentido da lição (o problema é "hardcoded", não o valor). | `"sk_live_" + 32 chars` | `"sk_live_EXAMPLE_REDACTED"` | `abdfecdae8e35b1fa3652c4a298d1b5327603ec004f3871c3ed9d3e2bbea548a` |

## Não-emitidos (já inertes no upstream, verificados)

| Padrão | Onde | Por que não precisa de patch |
|---|---|---|
| `AIzaXXXX…` (6×) | `references/reporting-templates-ios.md` | placeholder de `X` |
| `AKIAIOSFODNN7EXAMPLE` | `references/memory-analysis-ios.md` | chave de exemplo documentada da AWS |

## Regra para novos patches

1. Só por um motivo **mecânico** (bloqueio de CI/push protection, path do ambiente, correção de link do
   branch). Mudança de conteúdo/entendimento → vai para `docs/rev-ios/**`, não para cá.
2. Registrar aqui: arquivo, linha, motivo, antes/depois e o SHA-256 **pós-patch**.
3. Rodar `../../tools/rev-ios/install-skill.sh --check` — ele falha se houver arquivo alterado não
   listado aqui, ou se aparecer literal de credencial em formato real.
4. Ao rodar `install-skill.sh --update --force`, **re-aplicar** os patches desta tabela (o update copia o
   upstream por cima) e atualizar o SHA-256.
