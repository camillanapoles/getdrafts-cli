# VENDOR — iOS-Pentesting-Skill (cópia local, trilha `rev-ios`)

Este diretório é uma **cópia de trabalho (vendoring)** do skill upstream, feita para que a trilha
`rev-ios/*` tenha a *knowledge* e a capacidade de execução **offline, dentro do branch**, sem depender
de `~/.agents/skills/` existir na máquina de quem continua o projeto.

## Proveniência (pin)

| Campo | Valor |
|-------|-------|
| Upstream | https://github.com/DragonJAR/iOS-Pentesting-Skill |
| Branch no momento do pino | `main` |
| Commit | `fadac2bddddfec2be4aba43a4b664bd7eb330b0e` |
| Data do commit | 2026-10-23T07:06:07-05:00 |
| Versão declarada no `SKILL.md` | `1.0.0` |
| Licença | **Apache-2.0** (ver [`LICENSE`](LICENSE) — obrigatório redistribuir) |
| Autor | DragonJAR SAS (https://www.DragonJAR.org) |
| Snapshot em | 2026-11-11 |
| Conteúdo copiado | tudo, **exceto** `.git/`, `.github/`, `.gitignore`, `.gitattributes` |
| Arquivos | 217 (+ `VENDOR.md`, `.rev-ios-pin`, `PATCHES.md` desta cópia) |
| Patches locais | 1 — ver [`PATCHES.md`](PATCHES.md) (neutralização de literal `sk_live_…` que ativava o push protection do GitHub) |

Hashes SHA-256 dos arquivos de entrada do skill (o que o agente lê primeiro):

```
c04b1d60e846e23e5958ea09111285b3da05e12b21c6b47c6ada5f3db4679f38  SKILL.md
e3c0b4cfeae15389a4680a01d44197f6a723309b0c119a2477d0917be1a5a7ba  README.md
```

## Regras desta cópia

1. **Não editar arquivos upstream** — exceto os declarados em [`PATCHES.md`](PATCHES.md) (motivo
   mecânico, com hash pós-patch registrado; `install-skill.sh --check` é o gate). Deltas de conteúdo vão em:
   - `skills/getdrafts-ios-rev/SKILL.md` — procedimento específico de Get Drafts (nossa skill, invoca a vendored);
   - `docs/rev-ios/*` — spec, plano de captura, mapa de extração, ledger de evidências.
2. **Atualizar o pino** (raro; exige revisão de licença e re-leitura do README):
   ```bash
   ./tools/rev-ios/install-skill.sh --update            # só mostra o delta (dry-run)
   ./tools/rev-ios/install-skill.sh --update --force    # aplica e re-escreve .rev-ios-pin
   ```
   `--force` atualiza o *pin* e imprime os SHA-256 novos; **este `VENDOR.md` é re-escrito à mão**
   (commit, data, contagem de arquivos, hashes) — de propósito, para que a releitura do README do
   upstream seja um ato humano e não um efeito colateral de script.
3. **Instalação "de verdade" no agente** (o upstream espera `~/.agents/skills/`):
   ```bash
   ./tools/rev-ios/install-skill.sh              # linka/copi p/ ~/.agents/skills/ios-app-security-audit
   ```
   Instrução original do README upstream: `git clone … ~/.agents/skills/ios-app-security-audit`.
   Nós substituímos o clone por um *link* para a cópia vendored, de forma que **o branch é a fonte**.
4. **Artefatos nunca vão para cá.** IPAs, bundles extraídos, dumps, screenshots e bancos `.sqlite`
   ficam fora do repositório (`$REV_IOS_ARTIFACTS_DIR`, padrão `~/.rev-ios/artifacts`). Ver
   [`docs/rev-ios/00-SPEC.md`](../../docs/rev-ios/00-SPEC.md) §7.

## Restrições de escopo que herdamos do upstream

O upstream é um skill de **auditoria de segurança** (ofensiva). Nós o usamos aqui como
** toolkit de extração/engenharia reversa para interoperabilidade**. Consequências:

- Fases 0–3 (extração, superfície, armazenamento, fluxo de dados) → **usar**, adaptado.
- Fase 4 (dinâmica/Frida) → **usar** apenas para observação de comportamento (tracers, dumper de esquema,
  screenshots), não para exploração.
- Fase 5 (CVSS/report de vulnerabilidade) → **não usar** no fluxo Drafto→Android, exceto se o cliente
  pedir um relatório de risco. Não há achado de segurança a reportar aqui.
- Scripts de *bypass* (SSL pinning, jailbreak, RASP, biometria) e de *repackaging* → **não usar**;
  não há alvo a desproteger: o objetivo é ler estrutura e layout, não alterar o app.
