# Drafto — Mandate & Scoping

> App Android + Linux, idêntico em escopo e comportamento ao **Get Drafts** (iOS/macOS) da Agile Tortoise.
> Não é um cliente de Drafts. É um app diferente, com identidade própria, que pode reutilizar
> bibliotecas, padrões e templates da mesma família, mas cujos clientes primários são **Android e Linux**.

## 1. Contexto do projeto

- **Contratante:** empresa de desenvolvimento de software, especialista em engenharia reversa de apps.
- **Objetivo contratado:** converter e criar, identitariamente, o app Get Drafts do iOS para Android.
- **Repositório base:** `getdrafts-cli` (CLI em Go que conversa com Drafts.app via AppleScript).
- **Regra obrigatória:** o repositório da CLI deve ser usado desde o início, garantindo *handoff*,
  continuidade, governança, gestão de versionamento e branches para a criação lateral do app.
- **Regra de reutilização:** a base da CLI pode ser usada para a construção do Android. Pode-se até
  usar a mesma lib, plugins e templates de Get Drafts, mas **é um app completamente outro**.

## 2. Definição de sucesso

1. **App Android "Drafto"** com o fluxo de *quick capture* (inbox → tag → flag → archive/trash) funcionando localmente.
2. **Cliente Linux** (CLI nativo ou app desktop) com o mesmo comportamento do app móvel.
3. **Pareamento de features** documentado e rastreado (ver `02-FEATURE-PARITY.md`), com status claro por feature.
4. **Governança operante**: branches, versionamento semver, releases e *handoff* documentados e seguidos.
5. **Continuidade garantida**: qualquer novo dev consegue entender o estado do projeto a partir dos docs e do código.

## 3. Princípios (valores do contrato)

| Princípio | Como se aplica |
|-----------|----------------|
| **Entrega real** | Entregar funcionamento estável antes de features espetaculares. MVP compiável e testável. |
| **Satisfação do usuário** | UI Android com navegação um-toque, captura rápida, gestos esperados do Material 3. |
| **Qualidade impecável** | Testes automatizados, tipos fortes, contratos de saída estáveis (JSON), CI verde. |
| **Interoperabilidade** | Suporte a URL schemes (`drafto://`), *share sheet*, x-callback-url, export/import de drafts. |
| **Padrão e engenharia atual** | Monorepo, Go core compartilhado, backends plugáveis, gomobile para Android, CI/CD. |

## 4. Escopo (in / out)

### In scope (Phase 0–2)
- Modelo de dados nativo (Draft, tags, flag, folders, workspaces, versions).
- Engine de storage local (SQLite) + backend in-memory para testes.
- CRUD de drafts: create, get, list, search, append, prepend, replace.
- Organização: inbox/archive/trash/all, flag, tags, workspaces, sort.
- Engine de actions (passos: copy, share, move, tag, archive, trash, template, script).
- Template tags (`[[draft_content]]`, `[[title]]`, `[[date]]`, …).
- App Android (Kotlin + Jetpack Compose) com lista de drafts + editor.
- Cliente Linux (CLI) apontando para o core nativo.

### Out of scope (por fase, mas rastreado)
- Sincronização iCloud/Dropbox de aplicação (Phase 4 — ver roadmap).
- Watch app, widgets Android avançados (Phase 4).
- Importação de ações/JS de Drafts iOS (Phase 3 — compatibilidade parcial).
- Widgets iOS, Shortcuts, Apple Watch.

## 5. Riscos principais

| Risco | Mitigação |
|-------|-----------|
| Engenharia reversa do schema de Drafts é complexa/limitado | Usar a CLI AppleScript como "proxy de extração"; documentar atributos disponíveis; não depender de schema interno não documentado. |
| Go não compila no sandbox atual | Manter core com zero deps externas; validar em CI na primeira exec; fornecer script de build. |
| Android/iOS têm diferenças inevitáveis | Pareamento por feature com status "Partial" explícito; priorizar fluxo de capture que é universo. |
| Licença/propriedade de templates de Drafts | Reimplementar templates em template tags próprios; não copiar código proprietário. |
| Sincronização multi-device | Estratégia de sync tratada em Phase 4, com sync local primeiro. |

## 6. Decisões de identity

- **Nome:** Drafto (app), `drafto` (binário Linux), `drafto://` (URL scheme).
- **Dono do repositório:** empresa contratante (`camillanapoles/getdrafts-cli` no momento; renomear/transferir no primeiro release oficial).
- **Module path Go:** manter `github.com/nerveband/drafts-applescript-cli` internamente por continuidade;
  documento de governança inclui o procedimento de rename para o path definitivo do Drafto.

## 7. Próximos passos

1. Investigar Get Drafts → `01-GETDRAFTS-INVESTIGATION.md`.
2. Matriz de pareamento → `02-FEATURE-PARITY.md`.
3. Arquitetura → `03-ARCHITECTURE.md`.
4. Governança → `04-GOVERNANCE.md`.
5. Roadmap → `05-ROADMAP.md`.
6. Fundação de código: pacote `core/`, scaffold Android, migração da CLI.
