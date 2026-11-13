# Drafto — Handoff / Estado atual

## 1. Onde o projeto está (esta sessão)

- **Repositório:** `getdrafts-cli` (monorepo Drafto). Branch de sessão: `arena/b30c3d85-getdrafts-cli`.
- **Trilha canônica (ADR-005):** namespace `reverse/`. `reverse/main` = staging/production (o "origin"). Fluxo: `arena/<id>` → PR → `reverse/<id>` → PR/merge → `reverse/main` → tag `vX.Y.Z` (dispara `release.yml`). Tags são gatilho de automação.
- **Progresso nesta sessão:** gap **P0 de paridade fechado no core** — `[[clipboard]]`/`[[workspace]]` (`RenderTemplateEnv` + `ClipboardReader`), search full-text (conteúdo/título/tags), sort completo (`AccessedAt` + `SortName`, CLI `--sort/--desc`), trash auto-delete 30 dias (`TrashedAt`, `TrashPruner.PurgeTrash`, CLI `purge`) e `ActionRunner.RegisterAll` (grupos em lote). Automação por tag implementada (`release.yml`) + template de PR perpetuando o fluxo `reverse/`.
- **Base:** CLI Go (macOS/AppleScript) já existente e estável (commit `8b43a14`).
- **Novo:** pacote `core/` (Go, platform-agnostic) — o engine compartilhado.
- **Documentação:** `docs/drafto/00..06` + `CODEMAP.md`.

## 2. Como continuar (próximos passos óbvios)

1. **Validar o build** (necessita toolchain Go — a CI valida em cada PR):
   ```bash
   go build ./... && go test ./... && go vet ./...
   ```
2. ~~**Phase 1:** `core/sqlitestore` + persistência do `cmd/drafto`.~~ ✅ **Concluída** (`core/sqlitestore.go`, pure Go via `modernc.org/sqlite`, sem CGO; CLI `drafto --db`).
3. **Phase 2 (Android)** — em andamento. Estado auditado e ordem de execução em **§2.1** abaixo.
4. **CI:** já configurada — `ci.yml` (build/vet/test/race + android best-effort) e `release.yml` (disparada por tag `v*`/`drafto-v*` em `reverse/main` → goreleaser).

### 2.1 Phase 2 — gap analysis (auditado em 2026-11-12)

Critério de aceitação (`05-ROADMAP.md`): *APK instala; captura → inbox; tag/flag/archive/trash
funcionam; actions básicas executam.*

O scaffold Compose existe (~478 linhas em `android/`), mas **três gaps impedem o critério**:

| # | Gap | Evidência | Impacto |
|---|---|---|---|
| **G1** | ~~Boundary sem persistência~~ | ✅ resolvido: `NewAt(path)` abre `core.NewSQLiteStore`; `New()` fica para preview | Dados sobrevivem ao fechar o app |
| **G2** | ~~App não usa o Go core~~ | ✅ resolvido: `EngineFactory` → `GoDraftoEngine` (reflexão sobre o AAR) | UI roda no engine persistente; `FakeEngine` só como fallback logado |
| **G3** | Falta a ActionSheet na UI | `RunActionJSON`/`RegisterAction` já cruzam o boundary | Só falta a tela; o engine executa actions |

**Ordem de execução (incremental, cada passo verificável no CI):**

1. **G1** — `NewAt(path string)` no boundary usando `core.NewSQLiteStore`, mantendo `New()` para preview.
   *Verificação:* teste Go do boundary em `android/core-go/` + `go build ./android/core-go/`.
2. **G1** — Ponte Kotlin para o caminho do banco: `context.getDatabasePath("drafto.db")`.
3. ✅ **G2** — `EngineFactory` escolhe `GoDraftoEngine` quando o AAR existe; `FakeEngine` fica como fallback de preview.
4. ✅ **G2** — `.aar` gerado no CI (artefato) para o app consumir sem `gomobile` local.
5. **G3** — `RunActionJSON`/`RegisterAction` já estão no boundary (feito no G2); falta a ActionSheet na UI.

**Resolvido no ciclo v0.3.0 — `gomobile bind` funciona:**

O bloqueio **não** era a versão do Go (testado 1.24, 1.25 e 1.26: todos falhavam igual).
O erro real era:

```
gomobile bind requires golang.org/x/mobile in the current module,
but it is not in the module dependency graph.
```

Correção: `x/mobile` entrou no grafo de módulo (`tool golang.org/x/mobile/cmd/gomobile`
+ dependências indiretas). O job Android do `ci.yml` agora roda `gomobile bind`,
**falha de verdade** se o AAR não for gerado e publica o artefato `drafto-aar`.

> Lição: diagnosticar por hipótese ("é a versão do Go") custou 3 ciclos de CI.
> O erro real só apareceu quando o log passou a ser exposto como **anotação**
> (os logs completos são bloqueados por egress no sandbox).

**Dívidas quitadas neste ciclo:**

| Dívida | Estado |
|---|---|
| `gomobile bind` nunca executado no CI | ✅ agora é gate + artefato |
| Sem NDK no CI | ✅ `nttld/setup-ndk@v1` (r26d) |
| `x/mobile` fora do grafo | ✅ `tool` directive no `go.mod` |
| Hipótese errada registrada como risco | ✅ substituída pela causa real |
| **APK nunca compilava** | ✅ Compose plugin do Kotlin 2.0 + gate real |
| `continue-on-error` mascarava o APK | ✅ removido de todo o job Android |

**Build Android — segunda causa raiz (ciclo v0.3.0):**

O Gradle falhava em `:app` com:

```
Starting in Kotlin 2.0, the Compose Compiler Gradle plugin is required
when compose is enabled.
```

O build declarava Kotlin 2.0.21 mas ainda usava o mecanismo do 1.9
(`composeOptions.kotlinCompilerExtensionVersion = "1.5.14"`). Em Kotlin 2.0 o
Compose compiler é um **plugin Gradle próprio** e sua versão segue a do Kotlin.

Correção: `org.jetbrains.kotlin.plugin.compose` 2.0.21 no root (`apply false`) e
aplicado no `:app`; `composeOptions` removido. Resultado: **`gradle assembleDebug`
passa e o APK é publicado** como artefato `drafto-debug-apk`.

> O `continue-on-error` no job Android foi o que escondeu isso por vários ciclos:
> o job "passava" enquanto o Gradle falhava. Agora bind, AAR e APK são gates reais.

**Build Android — terceira causa raiz (`FakeEngine.kt`):**

Com o gate ligado, o `:app:compileDebugKotlin` revelou 4 erros que o cache do Gradle
vinha mascarando (tarefas `up-to-date` com código quebrado):

| Erro | Correção |
|---|---|
| `import kotlin.concurrent.synchronized` | não existe — `synchronized` é builtin de `kotlin` |
| `Draft(...)` sem `isArchived`/`isTrashed` | os campos não têm default |
| `archiveDraft`/`trashDraft` retornando `Draft` | contrato é `Unit` → corpo em bloco |
| `mutate` `inline` com `return@synchronized` | agora não-inline, `return` simples |

Resultado: **APK 15,9 MB e AAR 24,2 MB publicados** como artefatos, com
`--no-build-cache --rerun-tasks` e `cache-disabled` no `setup-gradle`.

> Lição de build: cache do Gradle + `continue-on-error` = dois mecanismos
> independentes de mascarar falha. Um CI sem gate real não prova nada.

**G2 resolvido — o app usa o core Go de verdade:**

`GoDraftoEngine.kt` deixou de ser um stub comentado. A ponte é feita por
**reflexão** sobre o binding do gomobile:

| Decisão | Motivo |
|---|---|
| Reflexão em vez de `import drafto.Core` | O AAR não está no repo (CI e `build-core.sh` geram); import direto quebraria todo build que não bindasse antes |
| `Class.forName("drafto.Core")` em `isAvailable()` | Ativa o engine real **só** quando o binding está no classpath |
| `InvocationTargetException` desembrulhado | Erro do Go chega à UI com a mensagem original |
| `go.Seq.setContext(Context)` antes de qualquer chamada | Runtime Go precisa do context Android (exigência do gomobile) |
| Travessia em **JSON** | Ver abaixo: é a única forma de passar struct por esse boundary |

`EngineFactory.create(context)` devolve
`GoDraftoEngine.openAt(context, getDatabasePath("drafto.db"))` e cai em
`FakeEngine` **com `Log.w` explícito** — a degradação silenciosa era justamente
o que fazia o app parecer integrado. `DraftoApp` passa o `applicationContext`
e expõe `isPersistent`.

**O que o `javap` do AAR revelou (e invalidou a primeira tentativa):**

```
public abstract class drafto.Drafto {          // funções de pacote
  public static native drafto.Core new_();
  public static native drafto.Core newAt(java.lang.String) throws Exception;
}
public final class drafto.Core {               // a struct exportada
  public drafto.Core();
  public native void archiveDraft(String) throws Exception;
  public native void close() throws Exception;
  ...
}
```

1. **Não existe `go/drafto/`.** O pacote gerado é `drafto`, e `go/` contém só o
   runtime (`go.Seq`, `go.Universe`). A classe estática chama-se `drafto.Drafto`.
2. **Nomes viram lowerCamel:** `NewAt` → `newAt`, `New` → `new_` (porque `new`
   é palavra reservada Java), `Close` → `close`.
3. **A causa raiz de G2 estar "quase pronto" e não funcionar:** o gomobile
   **descarta em silêncio** qualquer método exportado cuja assinatura mencione
   um tipo de outro pacote. Com `(core.Draft, error)` no retorno, sobraram
   apenas `archiveDraft`, `trashDraft`, `close` e `registerAction` — o app não
   tinha como criar nem listar draft algum, sem erro nenhum no build.

Por isso o boundary (`android/core-go/drafto.go`) cruza a fronteira como
`string`: `CreateDraftJSON`, `GetDraftJSON`, `QueryDraftsJSON`, `SetFlaggedJSON`,
`ReplaceDraftJSON`, `AddTagsJSON`, `RunActionJSON`, `ListTagsJSON`, `CountsJSON`.
O Kotlin converte com `org.json`; o lado Go devolve `""` para "sem resultado" e
`errors.Is(err, core.ErrDraftNotFound)` vira `null`, não exceção.

**Gates que impedem a regressão:**

| Gate | Onde | O que pega |
|---|---|---|
| `verifyGoBinding` | `preBuild` (`app/build.gradle.kts`) | AAR presente mas sem `drafto/Core`, `drafto/Drafto`, `go/Seq` **ou sem algum dos 13 métodos** (via `javap`) |
| `Verify APK embeds the Go core` | `ci.yml` | APK sem `libgojni.so` ou sem `drafto/Core`/`drafto/Drafto` no dex |
| `TestBoundMethodsAreGomobileSafe` | `android/core-go/drafto_test.go` | Método que voltou a expor tipo de outro pacote (some do AAR sem aviso) |
| `TestNewAtPersistsAcrossInstances` | idem | Regressão de persistência SQLite (G1) |

> Lição: os gates do Gradle/CI precisam falhar com a **mensagem da exceção**,
> não só com log — os logs completos são bloqueados por egress. Foi um
> `GradleException` carregando a lista de classes que revelou o pacote real.

## 3. Comandos úteis

```bash
# Build CLI macOS
go build ./cmd/drafts
# Testes do core
go test ./core/...
# Build Linux (CLI nativo, futuro)
GOOS=linux GOARCH=amd64 go build -o drafto ./cmd/drafto
# Android AAR (gomobile) — o pacote é ./android/core-go, não ./core
./android/core-go/build-core.sh
# ou direto:
gomobile bind -target=android -androidapi 24 -o android/app/libs/drafto.aar ./android/core-go
# Android APK
cd android && ./gradlew assembleDebug
```

## 3.1 Estado do backend SQLite (Phase 1 — corrigido na revisão do PR #11)

`core.SQLiteStore` é o backend de produção para Linux/Android (pure Go, sem CGO).
Paridade com `MemoryStore` verificada por testes de integração (`core/sqlitestore_test.go`):

| Área | Comportamento |
|---|---|
| `Get` | Atualiza `accessed_at` **e devolve** o valor atualizado (sort por acesso). |
| `Update` | Persiste todo campo devolvido (`created_at`, geo, `permalink`); `created_at`/`permalink` são imutáveis. |
| Search | `matchesSearch` em Go (substring, case-insensitive, conteúdo+título+tags) — resultados idênticos ao `MemoryStore`. Índice FTS5 mantido para busca ranqueada futura. |
| Tags | `loadTagsQuery` em lotes de 500 UUIDs (limite de parâmetros do SQLite). |
| Workspaces | Tags serializadas em CSV (tags com vírgula sobrevivem); linhas legadas continuam lendo. |
| `:memory:` | Conexão única + shared cache; cursores fechados antes de novas consultas. |
| `activeWorkspace` | Erros de leitura são propagados (só "setting ausente" = workspace vazio). |
| CLI `drafto` | SQLite é o default; falha ao abrir é erro fatal (`exit 1`) — memória só com `--memory`. |

> **Nota de segurança/supply chain:** o `go.sum` versionado precisa conter os hashes
> do `modernc.org/sqlite`. O CI regenera com `go mod tidy` e commita em push de branch
> (nunca em `pull_request`). Qualquer divergência aparece como falha em "Commit go.sum if changed".

## 4. Decisão de projeto (ADRs)

- **ADR-001 — Go core + gomobile:** aprovado. Reutiliza a base CLI, Android sem CGO.
- **ADR-002 — Store interface:** backends plugáveis (AppleScript/SQLite/Memory). Aprovado.
- **ADR-003 — Template tags próprios:** reimplementar, não copiar JS proprietário. Aprovado.
- **ADR-004 — Module path:** manter original por continuidade; rename no 1º release oficial.
- **ADR-005 — Estrutura paralela `reverse/` (canônica, perpétua):** aprovado. A trilha canônica do Drafto é o namespace `reverse/`. `reverse/main` é a linha de staging/production (o "origin" do projeto). Todo PR vai de `arena/<id>` → `reverse/<id>`; todo merge para produção vai → `reverse/main`. Tags `v*`/`drafto-v*` são criadas **somente em `reverse/main`** e são o gatilho de automação canônico. A trilha `reverse/` é independente de `main` histórico (não mistura). Esta regra é **perpétua** — novos branches/PRs seguem o fluxo `reverse/`.
- **ADR-006 — Paridade P0 no core (aditiva, não-quebrante):** aprovado. Campos novos em `Draft` (`AccessedAt`, `TrashedAt`) são `omitempty`; `SortName` acrescentado ao fim do enum `Sort` (estabilidade numérica para o boundary gomobile); capabilities **opcionais** (`TrashPruner`, `ClipboardReader`) em vez de métodos novos na `Store` interface — o bridge AppleScript e o boundary Android não quebram. Trash retention padrão = 30 dias (paridade Drafts), desativável com `SetTrashRetention(0)`.

## 5. Riscos atuais

- Go não compila neste sandbox (rede restrita). Primeira ação do dev: `go build ./...`.
- ~~SQLite backend ainda não implementado (Phase 1).~~ ✅ Implementado e coberto por testes de integração.
- Android não compilado (sem SDK/network). Scaffold pronto, precisa de ambiente Android.

## 6. Checklist de continuidade

- [x] `go build ./...` verde
- [x] `go test ./...` verde
- [x] `go vet ./...` limpo
  > Evidência: CI do PR #11 (`77f1996`) — job "Go build, vet, test" pass, 45 testes nomeados + `-race`.
- [x] CI configurada (`ci.yml`) + release por tag (`release.yml`)
- [x] `core/sqlitestore` implementado (com FTS5 + purge)
- [x] `cmd/drafto` Linux funcional com persistência
- [~] Android APK instala e captura funciona
  > **G1 e G2 fechados e verificados no CI** (run `43335981699`): o boundary
  > persiste em SQLite via `NewAt`, o app usa o engine real
  > (`drafto.Drafto.newAt`), e os gates provam que o APK carrega
  > `libgojni.so` + `drafto.Core` no dex, com os 13 métodos presentes no AAR.
  > Pendente: teste em device (não há emulador no sandbox) e G3 (ActionSheet).
