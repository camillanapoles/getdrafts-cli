# 04 — Paridade de Layout (iOS → Compose/Material 3)

> Fase **C5** da perspectiva da UI. O objetivo do contrato é *"idêntico, inclusive layout, se possível"*.
> Este documento define **o que é possível**, **como se mede** e **onde a linha está**.
>
> **Linha:** medimos *geometria, ritmo e hierarquia*; não copiamos *expressão* (arte, ícones, fontes
> proprietárias, microcopy). Ver [00-SPEC.md](00-SPEC.md) §7.2.

---

## 1. Por que isto é difícil (e onde o ganho real está)

Um `.ipa` **não** contém o layout de forma acessível quando o app é construído em código:

| Técnica de UI do alvo | Artefato estático útil? | Como medir de fato |
|---|---|---|
| Storyboard/XIB | ✅ `*.storyboardc`/`*.nib` (compiled) | `ibtool`/`nib` parsing — ruidoso |
| SwiftUI | ❌ nada declarativo no bundle | runtime: dump da árvore + screenshots |
| UIKit em código (caso provável do Drafts) | ❌ | runtime: `-recursiveDescription` + screenshots |
| **Assets.car** | ✅ cores, *named colors*, *text styles* (símbolos tipográficos), imagens | `assetutil --info` (macOS) / `carthief`·`ac-tool` (terceiros, verificar antes de usar) |
| `Localizable.strings` | ✅ chaves/textos (para *inventário*, não para copiar) | `plutil -convert json` |
| `Info.plist` | ✅ *interface-related keys* | ver §3.1 |

Ou seja: **o layout verdadeiro é runtime + screenshot**. O bundle entrega **tokens de cor/tipo**
(frequentemente o item mais valioso, porque o designer os definiu ali) e as chaves de interface.

Ordem de custo/valor:

1. **`tokens.json` a partir de `Assets.car`** [B] — cores e estilos de texto nomeados.
2. **Screenshots medidos** [B/C] — geometria (alturas, margens, leading) e estados.
3. **Árvore de views em runtime** [C] — valores numéricos exatos de *frame*, *insets*, *font*, *spacing*.
4. **`Info.plist` + chaves de `UserDefaults`** [A/B] — o que é configurável (fonte, tamanho, tema)
   define os *slots* do nosso tema.

---

## 2. Protocolo de captura (fixo — comparar medidas exige controlar as variáveis)

| Parâmetro | Valor de referência | Por quê |
|---|---|---|
| Dispositivo/simulador | 1 iPhone de referência (ex. 6.1", 1179×2556 @3x, 402×874 pt) | ponto de partida único; as demais telas são derivação |
| Segunda tela | 1 iPad (para *split view*/multitarefa) e 1 tela pequena (compact width) | o Drafts é forte em iPad; a UI Android tem de decidir o *fallback* |
| Idioma | `en` | medir sem *truncation* de PT-BR |
| Tema | **claro** e **escuro** (mesmos passos) | tokens de cor ×2 |
| *Dynamic Type* | `M` (default) + `AX1` (grande) | define a escala tipográfica fluida |
| Conteúdo da instância sintética | rascunho-régua de **largura conhecida**: linhas com `MMMMMMMMMM` (10× "M") | a largura de 10 "M" dá a **medida da fonte** em px → converte em pt |
| Conteúdo de estado | inbox com ≥20 drafts (1 flag, 1 com tags, 1 multi-linha, 1 archive, 1 vazia) | lista, *empty state*, *cell* alta |
| Zoom | *Display zoom* padrão | escala de *points* |

Captura:

```bash
# [B] simulador (melhor: controlado, reprodutível, sem PII)
xcrun simctl io booted screenshot "$RUN/layout/screens/01-inbox-light-M.png"

# [C] device (jailbroken: SnapBoard snapshots — o truque do skill, sem automação de UI)
"$SKILL_DIR/scripts/screenshot-extractor.sh" <bundle_id> "$RUN/layout/screens/"

# [C] device, screenshots ao vivo (se disponível para a versão do iOS)
idevicescreenshot "$RUN/layout/screens/live-01.png"
```

> O `screenshot-extractor.sh` do skill lê os *snapshots* do app-switcher
> (`Library/SplashBoard/Snapshots/`) — capturáveis **sem** controlar o app, e portanto o jeito mais
> barato de ver telas reais em device. Limitação: estado da tela no momento em que o app foi para
> *background* e resolução do *snapshot*. E `snapshot-overlay-check.js` responde se o app **borra** o
> conteúdo nesse momento (muitos apps o fazem; se o Drafts o fizer, screenshots de device são inúteis
> e o caminho passa a ser o simulador).

### 2.1 Medição (repetível, sem olho nu)

Toda medida vem de script, não de régua em imagem:

```python
# measure.py — alturas/larguras por diferença de cor contra o fundo
# (rodar com Pillow; entrada = png; saída = json com px e pt)
from PIL import Image
im = Image.open("01-inbox-light-M.png").convert("RGB")
scale = 3                                     # @3x do dispositivo de referência
def first_row_with(y0, y1, pred):              # varre linhas e devolve a 1ª que satisfaz pred
    ...
# 1) largura de 10×"M" na régua  →  tamanho de fonte aproximado (pt = px/scale / 10 * fator do glifo)
# 2) y do topo de cada célula     →  rowHeight (Δy constante em células de 1 linha)
# 3) x da borda esquerda do texto →  layoutMargins.leading
# 4) y da baseline do título       →  titleToTop
```

Regra: **cada número em `tokens.json` referencia `screenshot` + `px` + `scale`**. Sem referência, é
chute e não entra no tema.

---

## 3. O que extrair, tela a tela (o inventário a preencher)

### 3.1 Do bundle (antes de ver qualquer screenshot)

| # | Fonte | Comando | O que dá |
|---|---|---|---|
| 3.1.1 | `Assets.car` | `assetutil --info Payload/Drafts.app/Assets.car > layout/assets.json` | cores nomeadas (light/dark), *text styles*, imagens (só *nomes*+*sizes*) |
| 3.1.2 | `Fonts` / `UIAppFonts` | `jq '.UIAppFonts' surface/plist.json` | quais fontes o app **empacota** (→ saber o que *não* podemos usar) |
| 3.1.3 | `UIUserInterfaceStyle`, `UIUserInterfaceSize`, `UIApplicationSceneManifest` | `surface/plist.json` | dark mode, suporte a *multi-scene*/*split* no iPad |
| 3.1.4 | `UILaunchStoryboardName`, `UIMainStoryboardFile` | idem | se há XIB (facilita) ou UI em código (dificulta) |
| 3.1.5 | `CFBundleURLTypes`, `LSApplicationQueriesSchemes` | idem | *entry points* (o botão de captura vive aqui) |
| 3.1.6 | `NS*UsageDescription` | idem | permissões → espelhar no `AndroidManifest` |
| 3.1.7 | `Settings.bundle` / chaves de `UserDefaults` | `surface/defaults-keys.json` (2.10) | **o que o usuário pode mudar** = os *slots* do nosso tema/preferências |
| 3.1.8 | `*.appex` (Share/Widget) | `surface/extensions.json` (1.6) | *layout* de widget/share (paridade de captura) |

### 3.2 Da UI (o que cada tela precisa responder)

| Tela | Perguntas que a evidência tem de responder |
|---|---|
| **Inbox / lista** | estrutura da célula (título, preview, data, tags, flag); alturas; *trailing* de data; separador? contagem de linhas de preview; comportamento de *tap* vs *long-press*; *swipe* (ações); pull-to-refresh; *empty state*; *search bar* |
| **Header/navegação** | título, *workspace* selecionado, botão de *compose*, botão de *organize*, *segmented* inbox/all? alturas de *nav bar* e *status bar* |
| **Editor** | margens de texto; tamanho/linha da fonte; *caret*; realce de sintaxe (cores por token); *format bar*; *action bar* acima do teclado (altura, ícones, scroll horizontal); contagem de *word/char*; *scroll* do texto; o que acontece ao digitar `#tag` |
| **Action sheet / lista de actions** | agrupamento, *headers* de grupo, ícones, atalhos numéricos, *destructive* styling |
| **Workspaces** | *picker* (estilo, ordem, seleção, "Edit Workspaces"), como o header reflete o workspace |
| **Tags** | *tag filter bar*: chips? tokens? cores? ordenação, contagem |
| **Search** | campo, *scope* (content/title/tags), *quick search*, realce de *matches* |
| **Arrange mode** | multi-seleção (checkmarks, toolbar inferior, ações em lote) |
| **Archive / Trash / Flagged** | o que muda na célula (data de arquivamento? "Deleted in N days"?) |
| **Settings** | grupos, *rows*, fontes disponíveis, temas, *licenses* — para o *layout* de configurações do Drafto |
| **Dark mode** | quais superfícies trocam de tom; o *editor* é o mesmo cinza? |
| **iPad** | *split view* (lista + editor), *sidebar* colapsável, *slide-over* |

Cada resposta = 1 screenshot + 1 linha em `tokens.json`/`layout/notes.md`. Sem os dois, está em
andamento.

### 3.3 Runtime (Tier C; a fonte exata)

```bash
# árvore de views com frames (o gold standard de medida)
frida -U -f <bundle_id> -l layout-dump.js     # nosso wrapper, ver §3.4
# ou, interativo (objection, maintenance-mode, mas útil):
objection -g <bundle_id> explore
#   android ui / ios ui ... ; ios info framework  ;  ios hooking ...
```

### 3.4 `layout-dump.js` (mini-script que **esta trilha escreve**; não vem do skill)

Objetivo: dumpar a hierarquia com `frame`, `font`, `textColor`, `backgroundColor`, `insets`, `cornerRadius`
— os números que viram `tokens.json`. É um *observador puro*: **não altera** comportamento (§1.2 do SPEC).

```js
// recursive snapshot; run with: frida -U -f <bundle> -l layout-dump.js
function pt(v){ return Math.round(v*100)/100 }
function desc(v, depth) {
  if (depth > 12) return null
  const o = { cls: v.className ? v.className.toString() : '?',
              frame: v.frame ? [pt(v.frame.origin.x), pt(v.frame.origin.y), pt(v.frame.size.width), pt(v.frame.size.height)] : null }
  if (v.text && v.text.length) o.text_len = v.text.length          // NUNCA o texto (PII)
  if (v.font)  o.font = { size: pt(v.font.pointSize()), name: v.font.fontName.toString() }
  if (v.layer) { o.radius = pt(v.layer.cornerRadius()); o.masksToBounds = !!v.layer.masksToBounds() }
  const kids = v.subviews ? v.subviews.toArray() : []
  o.children = kids.map(k => desc(k, depth+1)).filter(Boolean)
  return o
}
const root = ObjC.classes.UIWindow.lastObject().contentView()
console.log(JSON.stringify(desc(root, 0)))
```

O script real está versionado em [`tools/rev-ios/frida/layout-dump.js`](../../tools/rev-ios/frida/layout-dump.js)
— valida sintaticamente e contra um mock de runtime ObjC em 2026-11-11 ([F-0001](findings/0001-harness-e-toolchain.md));
**nunca executado contra o app-alvo** (não há device/simulador aqui). Contrato de saída: uma linha JSON por
dump, com `_meta` (pid/arch/locale/screen+scale/orientation/darkMode), `tree` recursiva com `frame`,
`windowPos`, `radius`, `bg`/`fg_color`, `font{pointSize,name,family,leading,weight}`, `text_len`
(**nunca** `text`), `safeArea` e `scroll{content,insets}`. Config por `CONFIG`/env:
`REV_IOS_TAG=light-M REV_IOS_WATCH=1 frida -U -f <bundle> -l tools/rev-ios/frida/layout-dump.js`.
Uso: `| tee "$RUN/runtime/layout.ndjson"`, um gesto por sessão. Pendências da fase: `layout/measure.py`
(pixel → pt/dp) e `layout-diff.py` (overlay Drafto × Drafts) — `TOOL-003`.

---

## 4. Conversão UIKit → Compose/Material 3 (a tabela de equivalências)

Não é "copiar": é escolher o análogo Android que preserva *ritmo* e *hierarquia*. Onde não há análogo, a
decisão vai para o ledger como `adapt` com justificativa.

| Drafts (iOS) | Drafto (Android/Compose) | Nota de paridade |
|---|---|---|
| `UINavigationController` bar (title + compose + organize) | `TopAppBar` (M3) | altura: 44pt → 56dp; **não** forçar igual, respeitar o padrão Material |
| Lista de drafts (`UITableView`, *self-sizing cells*) | `LazyColumn` + `ListItem` custom | alinhar **densidade**: mesmo nº de linhas de preview, mesma hierarquia de tipo |
| *Swipe actions* (archive/trash/delete) | `SwipeToDismissBox` + *actions* custom | gesture de 1 toque; manter *swipe right* = flag |
| *Long-press* no título → *context menu* | `DropdownMenu` | — |
| *Action bar* acima do teclado (ícones, scroll horizontal) | `Row(horizontalArrangement)` dentro de `imeNestedScroll`/custom keyboard row | **assinatura do app**: prioridade P1 de layout |
| *Format bar* do editor | `Row` de *chips* de formatação | — |
| *Search bar* + *scope* | `SearchBar` (M3) | — |
| *Pull-to-refresh* | `PullToRefresh` | — |
| Workspaces *picker* (menu) | `ModalBottomSheet` (M3) | *list* com seleção + "Edit" |
| Tags *filter* | `FilterChip` row | — |
| Multi-select *arrange mode* | *toolbar* inferior contextual (`BottomAppBar`) | seleção em lote |
| *Split view* iPad | `NavigationRail` + *pane* (Material 3 *window size classes*) | decidir por *compact/medium/expanded* |
| `UIRefreshControl`, *empty state* central | idem | texto próprio, não copiado |
| SF Symbols (ícones) | Material Symbols (mais próximo) | **jamais** importar o asset; escolher o *glyph* análogo |
| `SF Pro` / fontes empacotadas | `Roboto`/`Google Sans Flex` + *Dynamic Type* | **nunca** embutir fonte do app |
| `UIColor` dynamic (light/dark) | M3 *color scheme* + `Color.kt` | copiar o **valor**, não o nome interno |
| *Haptic feedback* | `LocalHapticFeedback` | paridade de sensação |
| iCloud sync (ausente no Android) | *deferred* | [00-MANDATE.md](../drafto/00-MANDATE.md) §4 |

### 4.1 Conversão de unidades

`pt` (iOS, 1/72" lógico) → `dp` (Android, 1/160" lógico) — **não** é 1:1:

```
px      = pt × scale            (scale: @2x=2, @3x=3)
dp      = px / (dpi/160)
exemplo: 44pt @3x = 132px; em densidade 420dpi (2.625×) → 132/2.625 ≈ 50.3dp
```

Decisão registrada no tema: para **ritmo vertical** usamos `dp = pt` arredondado ao *step* Material
(4dp), que preserva a proporção visual sem violar as convenções do platform. **Não** copiar 44pt
literal: o usuário Android espera 56dp no *app bar*. A nota de cada escolha vai em `layout/notes.md`.

Tipografia: `fontSizeSp = round(pt)` na *scale* 1.0, com *Dynamic Type* (`TextUnit.Em` nos estilos de
leitura do editor, `Sp` nos rótulos), de forma que o *AX* do Android corresponda ao *Dynamic Type* do iOS.

### 4.2 `layout/tokens.json` (contrato de saída)

```json
{
  "_meta": {"run":"20261111-getdrafts-53.0","source_device":"iPhone 15 Pro Max @3x",
            "dynamic_type":"M","theme":"light","measured_by":"layout/measure.py"},
  "color": {
    "surface":      {"hex":"#RRGGBB","light":"#…","dark":"#…","from":"assetutil:Name","evidence":"E2"},
    "textPrimary":  {"hex":"#…","from":"layout-dump.js>label.textColor","evidence":"E4"},
    "tagChip":      {"hex":"#…"}
  },
  "type": {
    "title":   {"size_pt":17,"weight":"regular","line_height_pt":22,"measured_px":66,"scale":3,"evidence":"E2"},
    "preview": {"size_pt":15,"line_count":2},
    "date":    {"size_pt":13,"opacity":0.6}
  },
  "list":  {"row_height_pt":74,"leading_pt":16,"trailing_pt":16,"separator":"none","content_top_pt":8},
  "editor":{"margins_pt":[16,20,16,20],"line_spacing":1.4,"font":"user-selectable"},
  "action_bar": {"height_pt":44,"icon_pt":28,"gap_pt":12,"scrollable":true},
  "navigation": {"title_mode":"workspace-name","actions":["compose","organize","search"]}
}
```

Consumo: `android/app/.../ui/theme/Color.kt` + `Theme.kt` recebem **valores**; `DraftListScreen`/
`EditorScreen` recebem **métricas**; cada valor tem comentário `// rev-ios <run-id> · <evidence>`.

---

## 5. Critério de aceite da paridade de layout

1. `tokens.json` cobre: cores (light+dark), escala tipográfica, lista (altura, *insets*, separador),
   editor (margens, *leading*), *action bar*, navegação. **Cada** item com `evidence` e `screenshot`.
2. *Overlay* de comparação: screenshot do Drafto renderizado no mesmo viewport (402×874 pt / 1080×2340
   px) sobre o do Drafts; desvio aceitável: **≤4dp** em posições de *inset*/altura de linha, **≤1sp** em
   tamanho de fonte, cor **ΔE ≤ 3**. O script de comparação é `tools/rev-ios/layout-diff.py` *(a
   escrever em C5)*.
3 *Empty state*, *loading* e *swipe actions* têm comportamento análogo documentado (não só *pixel*).
4. Zero asset/fonte/string copiados (checagem §7.5 do SPEC + `git grep` de nomes internos do target).
5. O que **não** couber no Android é decidido e anotado como `adapt`/`reject` (ex.: *split view* →
   *window size class*), nunca silenciosamente ignorado.

---

## 6. Riscos específicos de layout

| Risco | Mitigação |
|---|---|
| App usa *private* layout (sem XIB) e não há runtime disponível | *tokens* de `Assets.car` + screenshots medidos bastam para **80%**; o resto é `deferred` com nota |
| Snapshot do app-switcher borrado por *privacy overlay* | confirmar com `snapshot-overlay-check.js`; se borrar, simulador (Tier B) é obrigatório |
| *Dynamic Type* do iOS ≠ escala Android | medir 3 tamanhos e ajustar a curva, não só o default |
| Copiar *trade dress* sem querer | revisão de *design* contra §7.6 do SPEC: estrutura sim, *branding* não |
| iPad-first features sem equivalente | decidir cedo: `NavigationRail` ou *fallback* só-celular; registrar como decisão de produto (ADR no `docs/drafto/adr/`) |
