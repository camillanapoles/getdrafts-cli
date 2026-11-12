# Drafto — Workspaces de Produção Paralela & Regras de Merge

> **Para quê:** o plano (`07-ROADMAP-EXECUCAO.md`) define *o quê* e *em que ordem*. Este documento define
> **como várias sessões trabalham ao mesmo tempo sem se destruírem**: quem é dono de qual arquivo, o que
> cada workspace pode começar agora, e o **protocolo de merge/conflito** — inclusive os conflitos que não
> aparecem no git (semânticos) e que só o CI em `reverse/main` revela.
>
> **Invariante que torna o paralelismo seguro:** a fronteira é `core.Store`. Enquanto um PR não muda a
> fronteira, ele não tem o que conflitar com outro workspace além de texto no mesmo arquivo.

---

## 1. Workspaces e posse de arquivo (a regra que evita 90% dos conflitos)

| WS | Nome | Posse exclusiva (só este WS edita) | Só lê / consome |
|---|---|---|---|
| **W1** | `core` | `core/*.go` (exceto `*_test.go` de `storetest`), `core/storetest/` | `pkg/drafts` (aliases), `cmd/drafto`, `android/core-go` |
| **W2** | `cli` | `cmd/drafto/*.go`, `cmd/drafto/contracts.go` | `core` (via `Store`) |
| **W3** | `android` | `android/**` (Kotlin, gradle, `core-go/`) | `core` (via boundary), `docs/rev-ios/layout/` |
| **W4** | `bridge-macos` | `pkg/drafts/*.go`, `cmd/drafts/*.go` — **área congelada** (hotfix com aprovação) | `core` (aliases) |
| **W5** | `ops-docs` | `docs/**`, `.github/**`, `Makefile`, `LICENSE`, `scripts/**` | tudo (para citar evidência) |
| **W6** | `rev-ios` | `docs/rev-ios/**`, `skills/**` | `core` (para dizer o que a evidência confirma) |

**Regras de posse:**

1. **Um arquivo, um dono por onda.** Se dois PRs tocam o mesmo arquivo, o segundo **espera** — não
   "resolve no merge". Conflito de merge em contrato (`Store`, envelope JSON, `migrate()`, boundary) é
   sinal de que dois trabalhos nasceram sem combinar, não de que falta técnica de merge.
2. **A fronteira só muda por W1.** W2/W3/W4 consumindo `Store` nunca editam `core/` "só pra passar":
   abre-se spec na lane C (`SPEC-CORE-0x`) e o consumo espera o merge.
3. **W4 está congelado por decisão:** o bridge AppleScript é o produto antigo; mudanças só com
   `fix(drafts):` pontual. Refactor de W4 em paralelo com mudança de W1 = conflito garantido.
4. **Posse não é propriedade de doc:** W1/W2/W3 editam as **próprias linhas** em `02`/`05`/`06` (§4.5).
5. **Arquivos sem dono = campo minado:** `go.mod`/`go.sum` (W5 por default; quem precisa de dep nova
   avisa antes), `.github/workflows/ci.yml` (W5; demais lanes pedem por issue), `assets/`, `remotion-demo/`.

## 2. Contrato comum de sessão (todos os W1–W6)

```bash
# 0) chegar atualizado (o refspec do clone é estreito por padrão!)
git fetch origin "+refs/heads/*:refs/remotes/origin/*" --tags
git log --oneline HEAD..origin/reverse/main          # o que falta eu puxar

# 1) claim da spec = mutex da lane (label no issue; sem claim não há branch)
gh issue edit <n> --add-label automation:lane-lock,status:in-progress \
                --remove-label status:ready,status:blocked \
                --comment "claim: arena/<id>-getdrafts-cli · W<n> · <data>"

# 2) trabalhar em incrementos; cada um verde no CI antes do próximo
#    (não existe build local aqui: sem Go/Java, egress bloqueia go.dev e proxy.golang.org)

# 3) PR #1 (canônico): branch da sessão → reverse/<id>-getdrafts-cli
git push -u origin HEAD:arena/<id>-getdrafts-cli
gh pr create --base reverse/<id>-getdrafts-cli --head arena/<id>-getdrafts-cli \
  --title "<type>(<scope>): …" --body-file /tmp/pr.md
gh pr merge <n> --squash                      # ← nunca --merge no branch reverse/<id>

# 4) PR #2 (integração): reverse/<id>-getdrafts-cli → reverse/main  (CI verde + 1 review; 2 se muda contrato)

# 5) liberar a lane
gh issue edit <n> --remove-label automation:lane-lock,status:in-progress
gh issue close <n> --comment "evidência: <run ids> · sha <…> · demo: <comando + saída>"
```

**Antes do PR #2, sempre:** `git fetch origin && git rebase origin/reverse/main` (ver §4.1 por que
rebase e não merge) e re-verificar CI. Um PR verde **contra a base antiga** não é verde: é uma
hipótese.

**Comunicação entre sessões** (o que substitui o "grito no corredor"): comentário no issue da spec com
(a) arquivos que vou tocar, (b) se mudo a fronteira, (c) estimativa de ondas. Um `W1` que anuncia
mudança de `Store` antes de codar economiza o re-trabalho de dois outros workspaces.

## 3. Por workspace — o que começa, o que roda junto, onde dói

### W1 · `core` (a lane-gargalo)

| | |
|---|---|
| **Começa quando** | nenhum outro `automation:lane-lock` em `lane:core`; suíte `storetest` verde (CORE-01) antes de qualquer mudança de comportamento |
| **Roda junto com** | W2 (se o contrato estiver congelado), W5, W6, W3 (arquivos disjointes) |
| **Nunca junto** | outra spec de W1; `PROD-04` com qualquer mudança de `Store` |
| **Arquivos quentes** | `core/store.go` (contrato), `core/sqlitestore.go` (`migrate()`), `core/model.go` (struct/enum), `core/action.go`, `core/memory.go` (espelho do SQLite) |
| **Anti-padrão que já queimou o projeto** | `MemoryStore` e `SQLiteStore` divergindo porque cada um ganhou seu teste. Regra: **caso novo primeiro em `storetest`, depois nos dois backends.** |

**Regras de merge do W1**
1. **`Store`: aditivo ou nada.** Nova capacidade entra como capability opcional + type-assert
   (`TrashPruner`, `ClipboardReader`, `WorkspaceStore`, `ActionStore`) — nunca método novo na interface
   (quebra `pkg/drafts` e o boundary). Breaking declarado ⇒ ADR + `MINOR`/`MAJOR` + os 3 consumidores
   atualizados **no mesmo PR**.
2. **`core/model.go`: só append.** Campos novos no fim do struct com `omitempty`; enums **nunca
   reordenados** (o boundary gomobile depende da estabilidade numérica — ADR-006). Conflito em `model.go`
   = `git checkout --ours` na ordem dos campos antigos + seus campos no fim.
3. **`migrate()`: aditivo e idempotente.** `PRAGMA user_version` incrementado por PR; nunca renomear ou
   apagar coluna no mesmo release em que se passa a ler a nova. Dois PRs mexendo `migrate()` ⇒ sequenciar
   (o 2º rebaseia e **reordena** sua migração depois da do 1º, nunca "mescla" as duas no mesmo `if`).
4. **`go.sum` nunca é editado à mão** — ver §4.3.
5. Todo PR de W1 inclui `docs/**` (paridade + roadmap + handoff) na mesma mudança; doc atrasada é
   o que produziu D1–D5 da auditoria.

### W2 · `cli` (`cmd/drafto`)

| | |
|---|---|
| **Começa quando** | os métodos que a spec consome já estão em `reverse/main` (contrato congelado durante a onda) |
| **Roda junto com** | W1 (com contrato congelado), W3, W5, W6 |
| **Nunca junto** | outro PR em `cmd/drafto/main.go` (o `Args` de subcomandos é um único bloco de struct — conflita 100%) |
| **Arquivos quentes** | `cmd/drafto/main.go` (`Args`, `switch` de despacho, `emit`), `cmd/drafto/schema` |
| **Regra de ouro** | **copiar o padrão de `cmd/drafts`** (`contracts.go` + `schema.go` + `output.go`), não inventar superfície nova |

**Regras de merge do W2**
1. **Envelope imutável:** `{success,data,error{code,message,suggestion}}`. Campo aditivo ok; renomear ou
   mudar tipo ⇒ `MAJOR` + ADR + update de `skills/SKILL.md` no mesmo PR.
2. **`--plain` nunca é o default** (JSON é o contrato para agentes).
3. Split obrigatório quando um PR passa de ~250 linhas em `main.go`: `chore(cli): extrair contracts.go`
   primeiro (PR pequeno, quase sem conflito), features depois. Isso elimina o conflito de `Args`.
4. Todo comando novo chega com **golden test** do JSON e entrada em `drafto schema`; sem os dois, o PR
   não abre.

### W3 · `android`

| | |
|---|---|
| **Começa quando** | `SPEC-AND-01` (DTO flat do boundary) mesclado para mudanças na fronteira; caso contrário só UI sobre `DraftoEngine` (ex.: `AND-04`) |
| **Roda junto com** | W1 (arquivos disjointes), W2, W5, W6 — **e outra sessão de W3 se os arquivos `.kt` forem diferentes** |
| **Nunca junto** | duas specs mexendo em `android/core-go/drafto.go` (a assinatura do boundary) ou no mesmo `.kt` |
| **Arquivos quentes** | `android/core-go/drafto.go`, `android/app/build.gradle.kts` (plugin/dependência), `MainActivity.kt`, `EngineFactory.kt`, `ci.yml` (job Android) |
| **Contrato do bridge** | só `string`/`int`/`bool` + JSON; **`map` e struct do `core` não atravessam** (gomobile rejeita) |

**Regras de merge do W3**
1. **Nada de `continue-on-error` no job Android** — se o `gomobile bind`/APK não é gate, o "verde" não
   prova nada (foi exatamente assim que o APK ficou quebrado por vários ciclos).
2. Mudança de **plugin/dependência Gradle** = PR próprio `chore(android-build)`, sem código de UI junto
   (é o que mais gera conflito em `build.gradle.kts` e o que mais exige cache-busting).
3. Build com `--no-build-cache --rerun-tasks` ao validar qualquer correção de `:app` (cache do Gradle
   escondeu 4 erros de `FakeEngine.kt` atrás de tarefas `up-to-date`).
4. `go.Seq.setContext(ctx)` antes de qualquer chamada; fallback para `FakeEngine` sempre com `Log.w`
   (degradação silenciosa = o pior tipo de "funciona").
5. UI nova nunca nasce antes de o bridge ter o formato estável; se nascer, nasce contra
   `DraftoEngine` (interface Kotlin) e não contra o AAR.

### W4 · `bridge-macos` (área congelada)

| | |
|---|---|
| **Começa quando** | hotfix de bug real, ou quando `PROD-02`/`PROD-03` exigirem paridade de saída |
| **Roda junto com** | W5, W6 |
| **Nunca junto** | W1 mudando `pkg/drafts/struct.go`/`options.go` (aliases do `core`) ao mesmo tempo |
| **Arquivos quentes** | `pkg/drafts/drafts.go`, `cmd/drafts/main.go`, `pkg/drafts/struct.go` |
| **Regra** | o bridge **não ganha features do Drafto**; ganha só o que `core` já define, via aliases |

**Regras de merge do W4:** mudanças em `pkg/drafts/struct.go`/`options.go` são *aliases* — o tipo
verdadeiro vive em `core`. Se um PR de W4 define campo no bridge, está errado: mover para W1 e reabrir.
Testes `pkg/drafts` são `//go:build darwin`: em CI linux eles só **compilam** (skip declarado) — nunca
remover o guard para "aumentar cobertura".

### W5 · `ops-docs` (a lane sempre disponível)

| | |
|---|---|
| **Começa quando** | sempre |
| **Roda junto com** | **todos** — é a única lane sem lock efetivo (não edita contrato) |
| **Nunca junto** | dois PRs reformulando o mesmo doc (ver §4.5); `ci.yml` é exceção: é código de gate e muda a experiência de todas as lanes |
| **Arquivos quentes** | `.github/workflows/ci.yml`, `docs/drafto/02-FEATURE-PARITY.md`, `05-ROADMAP.md`, `06-HANDOFF.md` |
| **Regra** | ✅ só com evidência; doc que descreve código cita `arquivo:linha` |

**Regras de merge do W5:** `ci.yml` — uma mudança de job por PR, aditiva (novo step no fim do job), sem
reordenar jobs existentes no mesmo PR que muda um step (diff ilegível ⇒ revisão inútil). `Makefile` é
espejo do CI: se CI muda, `make` muda no mesmo PR.

### W6 · `rev-ios` (isolado por construção)

| | |
|---|---|
| **Começa quando** | sempre (namespace/worktree/tag próprios) |
| **Roda junto com** | todos — não compartilha arquivo com ninguém |
| **Nunca junto** | — (mas **nunca** toca `core/`, `cmd/`, `android/`: regra da própria spec) |
| **Fluxo** | `rev-ios/<slug>` (+ worktree `../getdrafts-cli-rev-ios`), tags planas `rev-ios-<slug>-<data>`; PR para `reverse/main` traz **só docs/skills** |
| **Saída que os outros esperam** | `findings/*` (níveis E1–E4) e `layout/tokens.json` → consomem W1 (`PROD-02`) e W3 (`04-LAYOUT-PARITY`) |

**Regra de merge do W6:** artefatos binários **nunca** entram (`~/.rev-ios/artifacts/<run>/` fica fora do
repo). Se um finding exigir mudança de modelo, isso **não** é feito no branch de análise: vira issue na
lane `core` com o link do finding.

## 4. Regras de merge (protocolo canônico)

### 4.1 Rebase na sessão, squash no merge — e nada além disso

- **Durante o trabalho (sessão → `reverse/<id>`):** rebase no branch da sessão
  (`git rebase origin/reverse/main`). Branch de sessão é descartável, então reescrever histórico é barato
  e mantém o PR sem merge-commits de ruído. Usar `--force-with-lease` **somente** no branch da própria
  sessão: `git push --force-with-lease origin HEAD:arena/<id>-getdrafts-cli`. Nunca em `reverse/*` nem `main`.
- **`reverse/<id>` → `reverse/main`:** squash (`gh pr merge <n> --squash`) — a Phase 2 de um feature
  entra como **um** commit por PR de integração, e o branch `reverse/<id>` morre depois (governança §1.2.3).
- **Nunca** merge direto em `reverse/main` e **nunca** `main` recebe merge da trilha `reverse/` (ADR-005,
  regra perpétua). `gh pr merge` com `--merge` só é aceitável em `reverse/<id>` → `reverse/main` quando o
  PR carrega >1 feature deliberadamente sequencial (raro; justificar no corpo).

### 4.2 Fila de integração (merge train, manual)

`reverse/main` é **um funil**: várias sessões em paralelo, mas a integração é serial.

1. Antes de abrir o PR de integração, confira quem está na frente:
   `gh pr list --repo camillanapoles/getdrafts-cli --base reverse/main --json number,title,headRefName`.
2. Um por vez: **mescla → CI em `reverse/main` verde → o próximo rebaseia → mescla**. Nunca dois PRs
   "aprovados" mesclados em sequência sem revalidar o segundo na base nova.
3. `SPEC-OPS-01` (ciclo de release + tag) tem prioridade absoluta na fila e a trava com o label
   `automation:lane-lock` na lane `ops-docs`: **nenhum PR de código entra** em `reverse/main` enquanto ele
   estiver no meio (mescla + tag).
4. PR parado >2 dias na fila: feche o `reverse/<id>` antigo, reabra de `reverse/main` atual e cherry-pick —
   branch velho na fila é convite para conflito de doc (todos já mudaram `05`/`06` depois dele).

### 4.3 `go.mod` / `go.sum` (o conflito que aparece em 100% das ondas)

O CI roda `go mod tidy` e **comita `go.sum` no push de branch**; duas lanes tocando módulos
colidem sempre. Protocolo:

```bash
# na sessão, depois do rebase: aceite a versão da base e regere
git checkout origin/reverse/main -- go.sum go.mod
go mod tidy                    # (ou deixe o CI fazer isto e não commit go.sum no seu PR)
git add go.mod go.sum && git commit -m "chore(deps): reconciliar go.sum com a base"
```

- **Dependência nova = PR próprio** `chore(deps): …` **antes** do PR da feature (é o que destravou o
  `x/mobile` do gomobile — ver o handoff do ciclo v0.3.0). Nunca "só um require" junto com feature.
- `go.mod` com `tool` directive (gomobile) ou `// indirect`: nunca editar a mão; `go mod tidy` é o autor.
- Divergência aparece como falha em **"Commit go.sum if changed"** — leia o diff desse step antes de
  suspeitar do seu código.

### 4.4 `.github/workflows/ci.yml` (gate compartilhado)

Quem precisa mexer no CI (new gate, skip, artifact) faz **em PR pequeno próprio** e avisa no issue da
spec. Conflito aqui é mais caro que em código: afeta todas as sessões. Regra de decisão: *step novo no
fim do job > step reordenado*; *job novo aditivo > job reescrito*; e **`continue-on-error` é proibido**
em gate que se diz "real" (a lista de lições do projeto começa aí).

### 4.5 Docs de estado (`02`, `05`, `06`) — o conflito que ninguém espera

Todos os workspaces atualizam os mesmos três docs. Regra que funciona:

1. **Edite a sua linha, não o parágrafo.** Em `02-FEATURE-PARITY.md` a unidade é a linha da feature; em
   `05-ROADMAP.md` é o checkbox da fase; em `06-HANDOFF.md` é o §1 "esta sessão".
2. **Reformulação de doc é PR só de doc** (W5), e ninguém mexe na estrutura do doc durante a onda.
3. Conflito de tabela = unir as linhas dos dois lados (nunca escolher um lado). Conflito de
   `06-HANDOFF.md` §1 = **os dois textos entram**, em ordem cronológica, com data; duplicação se resolve
   no próximo ciclo de W5.
4. Todo item ✅ cita `arquivo:linha` ou run de CI — se o merge tirou sua evidência, reponha a evidência,
   não o entusiasmo.

### 4.6 Conflito semântico (verde + verde = vermelho)

É o único que o git não mostra. Acontece quando dois PRs em lanes diferentes passam no CI **cada um na sua
base** e quebram juntos (ex.: W1 muda `Folder`/`Sort` enquanto W2/W3 codificam o valor antigo).

- **Detecção:** CI pós-merge em `reverse/main` é o detector oficial. `gh run list --branch reverse/main
  --limit 3` logo depois de mesclar; se quebrou, o dono do **segundo** merge conserta (não reverte).
- **Prevenção:** antes do PR #2, rode o CI **contra a base nova** (rebase + push no branch
  `reverse/<id>` → CI no branch) — só então peça review. Regra das specs: "incremento verde" significa
  verde **na base de destino**, não verde histórico.
- **Contrato sob disputa:** se dois PRs tocam `Store`/envelope/schema/boundary, o segundo **não rebaseia
  resolvendo conflito**: espera, e o ADR decide. Conflito resolvido por quem chegou depois já criou duas
  leituras do contrato no mesmo release.

### 4.7 Revert e correção de rota

- Quebrou `reverse/main`? **Revert em PR** (`gh revert <sha> --pr`), não hotfix heroico no branch morto.
  A trilha `reverse/` permite hotfix: `reverse/hotfix/<slug>` nasce de `reverse/main`, volta por PR,
  tag `vX.Y.Z+1` (governança §4.6).
- Revert de doc que marcou ✅ errado não é cosmético: reabra a spec com `status:blocked` e a causa no
  comentário.

### 4.8 Regras de tag e release (não negocie)

- Tags `v*`/`drafto-v*` **somente** em `reverse/main`, após merge aprovado — elas disparam `release.yml`
  (goreleaser: `drafts` darwin + `drafto` linux).
- Nenhuma tag em branch de sessão nem em `reverse/<id>` de feature (a release sai antes da hora e o
  changelog vem incompleto).
- Semver do projeto Drafto começa em `0.x`; breaking de contrato ⇒ `0.MINOR+1` com ADR; `1.0.0` reservado
  para o release oficial com rename de module path + transferência de repo (governança §8/§9).

## 5. Exemplo de ciclo real (3 sessões em paralelo, dia a dia)

```
T0  Sessão A (W1, #19 CORE-01)   claim lane:core           → só *_test.go + core/storetest/
T0  Sessão B (W3, #21 AND-04)    claim lane:android         → MainActivity.kt + IntentRouter.kt + Robolectric
T0  Sessão C (W5, #16 OPS-02)    claim lane:ops-docs        → 02/adr/LICENSE
    (nenhum dos três toca o arquivo dos outros → zero conflito de texto)

T1  B abre PR#1 → reverse/<idB>      (CI: Go ✅ / Android APK ✅)
T1  C abre PR#1 → reverse/<idC>      (CI: docs ✅)
T2  A abre PR#1 e PR#2 → reverse/main  → mescla squash → CI em reverse/main ✅  → A libera lane:core
T3  C rebaseia em origin/reverse/main (pegou as correções de 05 que A fez) → PR#2 → mescla → CI ✅
T4  B rebaseia em origin/reverse/main → roda CI no reverse/<idB> ANTES do PR#2 → mescla → tag v0.3.1? não: tag só na onda fechada (W5/OPS-01)
```

Falha esperada e como se trata: se em T3 o `05-ROADMAP.md` de C conflitar com o de A → §4.5 item 3
(juntar linhas, evidência de cada lado). Se `go.sum` de B conflitar com o `x/mobile` de A → §4.3.

## 6. Checklist de fim de sessão (o que evita cavar buraco para os outros)

- [ ] Lane liberada (`automation:lane-lock` removido) **mesmo se o PR ficou aberto** — o lock é do
      trabalho, não do merge; se você vai dormir com o PR aberto, troque o lock por um comentário
      `handoff: …` e remova o lock.
- [ ] `06-HANDOFF.md` §1 atualizado: o que mudou, o que ficou para trás, o que a próxima sessão deve fazer
      primeiro (uma frase por item, com `arquivo:linha`).
- [ ] `05-ROADMAP.md`: checkbox só mudou se houver evidência citável.
- [ ] Nada de ✅/paridade nova sem linha na `02-FEATURE-PARITY.md` correspondente.
- [ ] Se você mudou `Store`/envelope/schema/boundary: ADR aprovado + os 3 consumidores atualizados no
      mesmo PR + `drafto schema` regenerated.
- [ ] Se adicionou dependência: PR `chore(deps)` separado, e ninguém da sua onda com `go.sum` sujo.
- [ ] CI **na base de destino** verde (não no branch de quando você começou).
- [ ] `go.mod`/`go.sum` reconciliados (§4.3) e nada de `go.sum` editado à mão.
- [ ] Se algo foi adiado: abriu-se a issue/spec nova com `blocked` + motivo (não um "depois eu vejo").

## 7. Matriz de compatibilidade de produção paralela

| ∥ | W1 core | W2 cli | W3 android | W4 bridge | W5 ops-docs | W6 rev-ios |
|---|---|---|---|---|---|---|
| **W1 core** | ❌ (serial) | ⚠️ congelar contrato | ⚠️ congelar DTO do bridge | ❌ (aliases) | ✅ | ✅ |
| **W2 cli** | ⚠️ | ❌ (`main.go`/`Args`) | ✅ | ⚠️ (saída compartilhada) | ✅ | ✅ |
| **W3 android** | ⚠️ | ✅ | ⚠️ (`.kt`/gradle diferentes ok; `core-go` não) | ✅ | ✅ | ✅ |
| **W4 bridge** | ❌ | ⚠️ | ✅ | ❌ (área congelada) | ✅ | ✅ |
| **W5 ops-docs** | ✅ | ✅ | ✅ | ✅ | ⚠️ (mesmo doc/`ci.yml`) | ✅ |
| **W6 rev-ios** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

⚠️ = só com anúncio no issue + rebase obrigatório antes do PR #2.

## 8. Se der ruim (escape hatches, em ordem de preferência)

1. **Esperar a lane** e trabalhar em W5 (docs/Makefile/diagnóstico) enquanto o contrato assenta — nunca
   "começar em cima do que está em voo".
2. **`git worktree` separado** para experimentar em paralelo sem tocar o branch claimado:
   `git worktree add ../drafto-exp -b exp/<slug> origin/reverse/main`.
3. **Cherry-pick cirúrgico** para integrar só o incremento que não depende do contrato disputado
   (`git cherry-pick -x <sha>` no `reverse/<id>`), deixando o resto para a onda seguinte.
4. **PR só de teste** (green + `t.Skip("DIVERGE(<spec>): …")`) para registrar divergência sem bloquear as
   outras lanes — o skip documentado vale mais que um merge apressado.
5. Reabrir o branch de feature de `reverse/main` novo (§4.2.4) — é mais barato que brigar com um conflito
   de 4 dias em `05-ROADMAP.md`.

---
**Fontes:** posse de arquivo e gates — `07-ROADMAP-EXECUCAO.md` §5; obrigações de fluxo — `04-GOVERNANCE.md`
§1.1–1.2 (ADR-005); lições de build/CI — `06-HANDOFF.md` §2.1 (ciclo v0.3.0); defeitos que as regras
fecham — `08-AUDIT-2026-11-12.md` §5 (F1–F10).
