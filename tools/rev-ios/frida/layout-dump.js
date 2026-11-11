/*
 * layout-dump.js — snapshot read-only da hierarquia de views (trilha rev-ios, C5)
 *
 * Para quê: extrair os NÚMEROS de layout do Drafts (frames, insets, font, cores, cornerRadius)
 *   para alimentar `layout/tokens.json` — ver docs/rev-ios/04-LAYOUT-PARITY.md §3.4.
 *
 * Uso:
 *   frida -U -f com.agiletortoise.Drafts5 -l tools/rev-ios/frida/layout-dump.js | tee runtime/layout.ndjson
 *   # simulador com gadget: frida -H 127.0.0.1:27042 -n Drafts -l …/layout-dump.js
 *   # capture tagged: exportar REV_IOS_TAG=light-M antes (vai para o JSON)
 *   # disparar depois de cada mudança de tela; uma linha JSON por dump.
 *
 * Contratos desta trilha (não relaxar):
 *   1. READ-ONLY. Nenhum setter, nenhum swizzle, nenhum patch — observar basta (00-SPEC §1.2).
 *   2. SEM PII. Texto é medido (comprimento, fonte, cor), nunca copiado. `text_len`, não `text`.
 *   3. Toda linha de saída carrega `_meta` com processo/idioma/tipo de tela p/ o cartão de evidência.
 *   4. Se um campo não pôde ser lido, sale `null` — nunca 0 (0 é um valor, null é "não sei").
 *
 * Notas de runtime:
 *   - UIKit só pode ser tocado na main thread: tudo roda via ObjC.schedule(ObjC.mainQueue, …).
 *   - `-recursiveDescription` é a âncora (string com frames, formato do próprio UIKit); a árvore
 *     estruturada é o que vira token. Guardamos as duas: a primeira para auditoria, a segunda para uso.
 *   - Em apps SwiftUI a árvore UIKit é hostil (AGListView/HostingView); nesse caso `depth` cresce e a
 *     leitura útil vem de `text`/`font` dos leafs — por isso `CONFIG.maxDepth` é alto e o filtro por
 *     prefixo é opt-in.
 */
'use strict';

var CONFIG = {
  maxDepth: 24,
  // Só estas classes entram na árvore estruturada (vazio = todas). Reduz ruído de framework.
  classPrefixes: [],            // ex.: ["Draft", "DT", "Workspace", "Action"]
  // Views cujo frame é descartável (layout interno de sistema).
  skipClasses: ["UINavigationBar", "UIStatusBar", "_UIVisualEffectView"],
  includeLayer: true,
  includeTextMetrics: true,
  tag: (typeof env !== "undefined" && env.REV_IOS_TAG) ? env.REV_IOS_TAG : null
};

function round(n) { return (typeof n === "number" && isFinite(n)) ? Math.round(n * 1000) / 1000 : null; }

function clsName(o) {
  try { return o === null ? null : o.className().toString(); } catch (e) { return null; }
}

function wanted(name) {
  if (!name) return false;
  if (CONFIG.skipClasses.indexOf(name) !== -1) return false;
  if (CONFIG.classPrefixes.length === 0) return true;
  for (var i = 0; i < CONFIG.classPrefixes.length; i++) {
    if (name.indexOf(CONFIG.classPrefixes[i]) === 0) return true;
  }
  return false;
}

function cgColorHex(colorRef) {
  // UIColor -> #RRGGBBAA. NSUIColor em iOS; precisa de espaço sRGB p/ valores estáveis.
  try {
    var c = ObjC.classes.NSUIColor.colorWithCGColor_(colorRef);
    var r = Memory.alloc(8), g = Memory.alloc(8), b = Memory.alloc(8), a = Memory.alloc(8);
    if (!c.getRed_white_alpha_error_ || !c.getRed_white_alpha_error_(r, g, b, a)) {
      c.getRed_green_blue_alpha_(r, g, b, a);
    }
    function byte(p) { return Math.round(Math.min(1, Math.max(0, p.readDouble())) * 255); }
    function hex(v) { return ("0" + v.toString(16)).slice(-2).toUpperCase(); }
    return "#" + hex(byte(r)) + hex(byte(g)) + hex(byte(b)) + (byte(a) < 255 ? hex(byte(a)) : "");
  } catch (e) { return null; }
}

function colorOf(view, sel) {
  try {
    var c = view[sel]();
    if (c === null) return null;
    return cgColorHex(c.CGColor());
  } catch (e) { return null; }
}

function fontOf(view) {
  if (!CONFIG.includeTextMetrics) return null;
  try {
    var f = view.font ? view.font() : null;
    if (f === null || f === undefined) return null;
    var out = { pointSize: round(f.pointSize()), name: f.fontName().toString() };
    try { out.family = f.familyName().toString(); } catch (e) {}
    try { out.leading = round(f.leading()); } catch (e) {}        // espaço de linha do próprio font
    try {                                                    // weight via descriptor (estável)
      var d = f.fontDescriptor();
      var t = d.objectForKeyedSubscript_("NSFontWeightAttribute");
      if (t !== null && t !== undefined) out.weight = round(t.doubleValue());
    } catch (e) {}
    return out;
  } catch (e) { return null; }
}

function textTraits(view) {
  if (!CONFIG.includeTextMetrics) return {};
  var out = {};
  try {
    var t = view.text ? view.text() : null;
    if (t !== null && t !== undefined) out.text_len = t.length();
    if (view.textAlignment) out.align = Number(view.textAlignment());
    if (view.numberOfLines) out.maxLines = Number(view.numberOfLines());
    if (view.font && view.minimumScaleFactor) out.minScale = round(view.minimumScaleFactor());
  } catch (e) {}
  return out;
}

function node(view, depth) {
  var name = clsName(view);
  var n = { cls: name };
  try {
    var f = view.frame(), o = view.bounds().origin;
    n.frame = [round(f.origin.x), round(f.origin.y), round(f.size.width), round(f.size.height)];
    n.windowPos = [round(view.convertPoint_toView_(view.bounds().origin, null).x),
                   round(view.convertPoint_toView_(view.bounds().origin, null).y)];
  } catch (e) { n.frame = null; }
  try { n.hidden = !!view.isHidden(); } catch (e) {}
  try { n.alpha = round(view.alpha()); } catch (e) {}
  try { n.opaque = !!view.isOpaque(); } catch (e) {}
  try { n.firstResponder = !!view.isFirstResponder(); } catch (e) {}
  if (CONFIG.includeLayer) {
    try {
      var L = view.layer();
      n.radius = round(L.cornerRadius());
      n.borderWidth = round(L.borderWidth());
      n.masksToBounds = !!L.masksToBounds();
      n.bg = cgColorHex(L.backgroundColor());
    } catch (e) {}
  }
  n.bg_color = colorOf(view, "backgroundColor");
  n.fg_color = colorOf(view, "textColor");
  var font = fontOf(view);
  if (font) n.font = font;
  var tr = textTraits(view);
  for (var k in tr) if (Object.prototype.hasOwnProperty.call(tr, k)) n[k] = tr[k];
  try {
    var iv = view.safeAreaInsets ? view.safeAreaInsets() : null;
    if (iv) n.safeArea = [round(iv.top), round(iv.left), round(iv.bottom), round(iv.right)];
  } catch (e) {}
  try {
    var sc = view.scrollView ? view.scrollView() : null;
    if (sc) n.scroll = { content: [round(sc.contentSize().width), round(sc.contentSize().height)],
                          insets: [round(sc.contentInset().top), round(sc.contentInset().left)] };
  } catch (e) {}

  if (depth < CONFIG.maxDepth) {
    var kids = [];
    try { kids = view.subviews().toArray(); } catch (e) {}
    var keep = [];
    for (var i = 0; i < kids.length; i++) {
      var child = node(kids[i], depth + 1);
      if (child !== null) keep.push(child);
    }
    if (keep.length) n.children = keep;
  }
  // folha sem interesse e sem herdeiros úteis -> podada
  if (!wanted(name) && !(n.children && n.children.length)) return null;
  return n;
}

function dump() {
  var App = ObjC.classes.UIApplication;
  if (!App) { send({ error: "UIApplication indisponível (processo alvo errado?)" }); return; }
  var windows = App.sharedApplication().windows().toArray();
  var info = ObjC.classes.NSLocale.currentLocale().localeIdentifier().toString();
  var dims = App.sharedApplication().keyWindow().screen().bounds();
  send({
    _meta: {
      tool: "rev-ios/layout-dump.js",
      tag: CONFIG.tag,
      pid: Process.id,
      arch: Process.arch,
      locale: info,
      screen: { w: round(dims.size.width), h: round(dims.size.height), scale: round(App.sharedApplication().keyWindow().screen().scale()) },
      orientation: (function () {
        try { return Number(ObjC.classes.UIDevice.currentDevice().orientation()); } catch (e) { return null; }
      })(),
      darkMode: (function () {
        try { return Number(App.sharedApplication().keyWindow().overrideUserInterfaceStyle()); } catch (e) { return null; }
      })(),
      evidence: "E4"
    },
    recursiveDescription: (function () {   // âncora de auditoria (formato do próprio UIKit)
      try {
        var s = windows[0].performSelector_("recursiveDescription");
        if (s === null || s === undefined) return null;
        var t = s.toString();
        return t.length > 40000 ? t.slice(0, 40000) + "\n…[truncado]" : t;
      } catch (e) { return null; }
    })(),
    tree: node(windows[0], 0)
  });
}

if (!ObjC.available) {
  throw new Error("runtime ObjC indisponível — este script é para o processo de um app UIKit");
}

// main thread only (UIKit)
ObjC.schedule(ObjC.mainQueue, function () {
  try { dump(); } catch (e) { send({ error: "dump falhou: " + e.message }); }
});

// modo contínuo: exportar REV_IOS_WATCH=1 para re-dumpar a cada 2s (durante gestos manuais)
if (typeof env !== "undefined" && env.REV_IOS_WATCH) {
  setInterval(function () { ObjC.schedule(ObjC.mainQueue, function () { try { dump(); } catch (e) {} }); }, 2000);
}
