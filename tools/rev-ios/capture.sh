#!/usr/bin/env bash
# capture.sh — harness da trilha rev-ios (captura & extração do Get Drafts iOS)
#
# Spec .......... docs/rev-ios/00-SPEC.md
# Plano ......... docs/rev-ios/01-CAPTURE-PLAN.md   (o que coletar, como, com que prova)
# Mapa .......... docs/rev-ios/02-EXTRACTION-MAP.md (o que extrair, para onde vai)
#
# Princípios (não negociáveis):
#   1. Artefatos NUNCA dentro do repositório. Raiz = $REV_IOS_ARTIFACTS_DIR
#      (padrão $HOME/.rev-ios/artifacts).
#   2. Credenciais NUNCA tocam este script: auth é do ipatool, no keychain do host.
#   3. Ferramenta ausente => "skip" registrado, não falha (o host é Tier A).
#   4. Observação pura: extrai e resume. Não patcheia, não re-assina, não injeta, não bypassa.
#   5. Texto de usuário é PII: só nomes de coluna/chave/enum curto saem dos dados.
#
# Subcomandos: preflight · new-run · acquire · triage · surface · hash · help
set -uo pipefail

# ---------------------------------------------------------------- caminhos ----
script_path() { printf '%s' "${BASH_SOURCE[0]}"; }
REPO_ROOT="$(git -C "$(dirname "$(script_path)")" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "${REPO_ROOT:-}" ] || REPO_ROOT="$(cd "$(dirname "$(script_path)")/../.." && pwd)"

ART_ROOT="${REV_IOS_ARTIFACTS_DIR:-$HOME/.rev-ios/artifacts}"
RUN_POINTER="$ART_ROOT/.current"
SKILL_DIR="${REV_IOS_SKILL_DIR:-$REPO_ROOT/skills/ios-app-security-audit}"
[ -d "$SKILL_DIR" ] || SKILL_DIR="$HOME/.agents/skills/ios-app-security-audit"

RUN="${REV_IOS_RUN:-}"
RUN_DIR=""
KIND=""
OPT_TARGET="${REV_IOS_TARGET:-getdrafts}"
OPT_BUILD=""
OPT_BUNDLE="com.agiletortoise.Drafts5"
OPT_SRC=""
FROM_BUNDLE=""
FROM_DB=""
DRY=0
STRICT=0
ASSUME_YES=0
JSON_OUT=0

# ------------------------------------------------------------------ utils ----
say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
skip() { printf '  skip  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
now()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
today() { date -u +%Y%m%d; }
sha() {
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif have shasum;   then shasum -a 256 "$1" | cut -d' ' -f1
  else printf 'no-sha-tool'; fi
}
size() { wc -c < "$1" 2>/dev/null | tr -d ' '; }
tool_ver() { "$@" 2>/dev/null | head -1 | cut -c1-40; }
rel() { printf '%s' "${1#"$RUN_DIR"/}"; }

usage() {
  cat <<'EOF'
capture.sh — harness da trilha rev-ios (captura & extração do Get Drafts iOS)

Uso: capture.sh <comando> [opções]

  preflight [--json] [--strict]
      Matriz de capacidades -> quais fases (C0..C5) este host habilita.

  new-run [--target <nome>] [--build <v>] [--dry-run]
      Cria $REV_IOS_ARTIFACTS_DIR/<yyyymmdd>-<alvo>[-<build>] + provenance.json.

  acquire [--bundle <id>] [--yes]            # sem --yes: só imprime o plano
      Aquisição do IPA via ipatool (Tier A/B). Credenciais: só no host, nunca aqui.

  triage <arquivo> [--kind ipa|user-backup|db] [--run <id>]
      C1: cópia p/ raw/ + unzip + triagem (Info.plist, schemes, extensões, frameworks,
      cryptid, strings de interesse) + triage.md + SHA256SUMS + artifacts.jsonl.

  surface --from-bundle <dir.app> | --from-db <arquivo.sqlite> [--run <id>]
      C2/C3: surface/*.json (com _meta) e db/{schema.sql,tables.json,enums.json}.

  hash <arquivo>
      {"sha256":…,"bytes":…} pronto para colar em provenance.json.

  purge [raw|bundle|import|db|runtime|layout|all]
      Destrói material sensível do run, preservando os hashes em purge.log.
      (a custódia continua auditável sem os bytes; use após C3/C4)

Opções comuns: --run <id> --target <nome> --build <v> --dry-run

Ambiente: REV_IOS_ARTIFACTS_DIR · REV_IOS_RUN · REV_IOS_SKILL_DIR
Artefatos binários jamais entram no git (docs/rev-ios/00-SPEC.md §7.3).
EOF
}

# ------------------------------------------------------------ run / run dir ---
create_run() {
  local id="${1:-}"
  [ -n "$id" ] || id="$(today)-${OPT_TARGET}${OPT_BUILD:+-$OPT_BUILD}"
  RUN="$id"; RUN_DIR="$ART_ROOT/$RUN"
  mkdir -p "$RUN_DIR" || { bad "sem permissão em $ART_ROOT"; exit 1; }
  mkdir -p "$RUN_DIR"/{raw,bundle,surface,db,import,runtime,layout/screens,findings}
  printf '%s' "$RUN" > "$RUN_POINTER"
  provenance_skeleton
  say "run: $RUN_DIR"
}

ensure_run() {
  if [ -z "$RUN" ] && [ -f "$RUN_POINTER" ]; then RUN="$(cat "$RUN_POINTER")"; fi
  if [ -n "$RUN" ] && [ -d "$ART_ROOT/$RUN" ]; then
    RUN_DIR="$ART_ROOT/$RUN"
  else
    create_run "$RUN"
    return 0
  fi
  mkdir -p "$RUN_DIR"/{raw,bundle,surface,db,import,runtime,layout/screens,findings}
}

triage_file() { printf '%s' "$RUN_DIR/triage.md"; }
log_triage()  { printf '%s\n' "$*" >> "$(triage_file)"; }

provenance_skeleton() {
  local pin="none"
  [ -f "$SKILL_DIR/.rev-ios-pin" ] && pin="$(sed -n 's/^upstream_commit=//p' "$SKILL_DIR/.rev-ios-pin")"
  cat > "$RUN_DIR/provenance.json" <<EOF
{
  "run_id": "$RUN",
  "target": {
    "app": "Drafts (Agile Tortoise)",
    "bundle_id_claimed": "$OPT_BUNDLE",
    "build": "${OPT_BUILD:-unknown}",
    "source": "pending",
    "note": "bundle/build precisam confirmacao E2 (ipatool search / Info.plist) - docs/rev-ios/01-CAPTURE-PLAN.md sec.1"
  },
  "acquired_at": "$(now)",
  "actor": "${USER:-unknown}",
  "host": {
    "os": "$(uname -s | tr 'A-Z' 'a-z')",
    "arch": "$(uname -m)",
    "tools": {
      "ipatool": "$(have ipatool && tool_ver ipatool --version || echo absent)",
      "frida": "$(have frida && tool_ver frida --version || echo absent)",
      "sqlite3": "$(have sqlite3 && tool_ver sqlite3 --version || echo absent)",
      "idevice_id": "$(have idevice_id && tool_ver idevice_id -v || echo absent)",
      "xcrun": "$(have xcrun && tool_ver xcrun --version || echo absent)"
    }
  },
  "skill": { "dir": "$SKILL_DIR", "upstream_commit": "${pin:0:7}" },
  "artifacts": [],
  "consent": { "licensed_copy": false, "synthetic_corpus": false, "no_redistribution": true },
  "notes": "preencher consent.* antes de usar o run como evidencia (00-SPEC.md sec.7)"
}
EOF
}

record_artifact() { # <caminho-relativo-no-run> [k=v ...]
  local relp="$1"; shift
  local f="$RUN_DIR/$relp"
  [ -f "$f" ] || return 0
  local extra="" kv
  for kv in "$@"; do
    local k="${kv%%=*}" v="${kv#*=}"
    extra="$extra,\"$k\":\"$v\""
  done
  printf '{"path":"%s","sha256":"%s","bytes":%s,"at":"%s"%s}\n' \
    "$relp" "$(sha "$f")" "$(size "$f")" "$(now)" "$extra" >> "$RUN_DIR/artifacts.jsonl"
  printf '%s  %s\n' "$(sha "$f")" "$relp" >> "$RUN_DIR/SHA256SUMS.tmp"
}

finalize_run() {
  # SHA256SUMS deduplicado + contagem de artefatos + resumo legível
  local T="$(triage_file)"
  if [ -f "$RUN_DIR/SHA256SUMS.tmp" ]; then
    sort -u -k2 "$RUN_DIR/SHA256SUMS.tmp" > "$RUN_DIR/SHA256SUMS"
    rm -f "$RUN_DIR/SHA256SUMS.tmp"
  fi
  local n=0
  [ -f "$RUN_DIR/artifacts.jsonl" ] && n="$(sort -u "$RUN_DIR/artifacts.jsonl" | grep -c . )"
  [ "$n" -gt 0 ] && tail -n "$n" "$RUN_DIR/artifacts.jsonl" > "$RUN_DIR/artifacts.jsonl.u" && mv "$RUN_DIR/artifacts.jsonl.u" "$RUN_DIR/artifacts.jsonl"
  log_triage ""
  log_triage "## Manifesto"
  log_triage "- artefatos com hash: $n"
  log_triage "- SHA256SUMS: \`SHA256SUMS\` · proveniência: \`provenance.json\`"
  log_triage "- gerado por: \`tools/rev-ios/capture.sh\` em $(now)"
  log_triage ""
  log_triage "## Checklist de saída (01-CAPTURE-PLAN.md §6)"
  log_triage "- [ ] bundle/build confirmados em E2"
  log_triage "- [ ] encrypted: true|false registrado"
  log_triage "- [ ] provenance.json.consent preenchido"
  log_triage "- [ ] instância sintética usada (nunca dados reais)"
  log_triage "- [ ] \`git status --porcelain\` sem artefatos"
  log_triage "- [ ] LEDGER.md atualizado + cartões em docs/rev-ios/findings/"
  say "manifesto: $n artefato(s) · $RUN_DIR/SHA256SUMS"
}

# ---------------------------------------------------------------- preflight --
check() { # <var> <label> <cmd...>  -> grava 1/0 em <var> e imprime ok/skip
  local __v="$1" __label="$2"; shift 2
  if have "${1:-}"; then
    printf -v "$__v" '%s' 1
    ok "$__label ($(tool_ver "$@"))"
  else
    printf -v "$__v" '%s' 0
    skip "$__label"
  fi
}

cmd_preflight() {
  say "rev-ios · preflight · $(uname -s) $(uname -m) · $(now)"
  say "  artefatos : $ART_ROOT"
  say "  skill     : $SKILL_DIR"
  say ""
  say "[skill vendored]"
  local skill=0
  if [ -f "$SKILL_DIR/SKILL.md" ] && [ -d "$SKILL_DIR/references" ]; then
    skill=1
    ok "$(find "$SKILL_DIR" -type f | wc -l | tr -d ' ') arquivos · pin $(sed -n 's/^upstream_commit=//p' "$SKILL_DIR/.rev-ios-pin" 2>/dev/null | cut -c1-7)"
    ok "uso/instalação: $SKILL_DIR/README.md · limitações: §Limitations"
  else
    bad "skill ausente — rode: $REPO_ROOT/tools/rev-ios/install-skill.sh"
  fi
  say ""
  say "[tier A · estática em qualquer host]"
  check unzip "unzip" unzip -v
  check zip   "zip"   zip -v
  check rg    "rg"    rg --version
  check strings "strings (binutils)" strings --version
  check python3 "python3" python3 --version
  local static=$((unzip + rg + strings + python3))
  say ""
  say "[plist / mach-o / assets]"
  local plist=0
  if have plutil || have plistutil; then ok "plist (plutil|plistutil)"; plist=1; else skip "plist (plutil|plistutil) — apt install libplist-utils"; fi
  local macho=0
  if have otool || have llvm-objdump || have jtool2; then ok "macho (otool|llvm-objdump|jtool2)"; macho=1; else skip "macho (otool|llvm-objdump|jtool2)"; fi
  local car=0
  if have assetutil || have carthief; then ok "Assets.car (assetutil|carthief)"; car=1; else skip "Assets.car (assetutil[macOS]|carthief)"; fi
  say ""
  say "[dados locais]"
  local db=0
  if have sqlite3; then ok "sqlite3"; db=1
  elif python3 -c 'import sqlite3' >/dev/null 2>&1; then ok "python3 sqlite3 (basta para C3)"; db=1
  else skip "sqlite (sqlite3 ou python3-sqlite3)"; fi
  say ""
  say "[aquisição / dinâmica]"
  check ipatool "ipatool (aquisição)" ipatool --version
  check frida   "frida (Fase 4)" frida --version
  check idev    "libimobiledevice (idevice_id)" idevice_id -h
  local sim=0
  if have xcrun; then ok "xcrun/simctl (macOS)"; sim=1; else skip "xcrun/simctl (só macOS — simulador/SimForge)"; fi
  say ""
  say "[fases habilitadas neste host]"
  say "  C0 preflight ....... $([ $skill -eq 1 ] && echo yes || echo NO)"
  say "  C1 captura/triage .. $([ $unzip -eq 1 ] && [ $python3 -eq 1 ] && echo 'yes (unzip+strings+python)' || echo 'no — falta unzip/python3')"
  say "  C2 surface ......... $([ $plist -eq 1 ] && echo 'yes (plist completo)' || echo 'parcial (rg/strings; plist ilegível)')"
  say "  C3 modelo (sqlite) . $([ $db -eq 1 ] && echo yes || echo NO)"
  say "  C4 semântica ....... docs+backup aqui; runtime só com Tier C"
  say "  C5 layout .......... $([ $sim -eq 1 ] && echo 'simulator ok' || echo 'device/sim remoto') · assets.car: $([ $car -eq 1 ] && echo ok || echo 'Tier B (macOS)')"
  say "  binário decifrado .. $([ $frida -eq 1 ] && [ $idev -eq 1 ] && echo 'possível (Tier C)' || echo 'não neste host')"
  say "  mach-o ............. $([ $macho -eq 1 ] && echo ok || echo 'sem loader: cryptid = unknown (não ler como ausente)')"
  say ""
  say "  lembrete: nunca contornar DRM para obter o app — ver 00-SPEC.md §7.1"
  say "leitura obrigatória p/ Linux: $SKILL_DIR/references/linux-ios-analysis-workarounds.md"
  if [ "$STRICT" -eq 1 ] && [ "$static" -lt 2 ]; then
    bad "nenhuma capacidade mínima disponível (unzip/rg/strings/python3)"; return 1
  fi
  return 0
}

cmd_preflight_json() {
  local c
  printf '{"at":"%s","os":"%s","arch":"%s","artifacts_dir":"%s","skill_dir":"%s","skill_present":%s,"tools":{' \
    "$(now)" "$(uname -s)" "$(uname -m)" "$ART_ROOT" "$SKILL_DIR" \
    "$([ -f "$SKILL_DIR/SKILL.md" ] && echo true || echo false)"
  local first=1
  for c in unzip zip rg strings python3 plutil plistutil llvm-objdump otool jtool2 assetutil \
           sqlite3 ipatool frida objection idevice_id ideviceinstaller dsdump xcrun docker; do
    [ $first -eq 1 ] || printf ','
    first=0
    printf '"%s":%s' "$c" "$(have "$c" && echo true || echo false)"
  done
  printf '}}\n'
}

# ------------------------------------------------------------------ acquire --
cmd_acquire() {
  say "plano de aquisição (ipatool) — nada é baixado sem --yes"
  say "  bundle alvo : $OPT_BUNDLE"
  say "  host        : máquina do cliente + conta DESCARTÁVEL (01-CAPTURE-PLAN.md §3.1)"
  say "  destino     : \$REV_IOS_ARTIFACTS_DIR/raw/"
  say ""
  say "  ipatool auth login -e <apple-id-descartavel>     # credencial só no keychain do host"
  say "  ipatool auth info"
  say "  ipatool search \"Drafts\" --format json | tee raw/search.json"
  say "  ipatool list-versions -b $OPT_BUNDLE              # para fixar um build (R3)"
  say "  ipatool download -b $OPT_BUNDLE --purchase --output raw/Drafts.ipa"
  say ""
  say "  esperado: IPA com cryptid=1 (FairPlay). triage grava encrypted:true e segue"
  say "  para o que é legível sem decifração (plist, Assets, extensões, plists embutidos)."
  [ "$DRY" -eq 1 ] && { say ""; say "[dry-run] nada executado."; return 0; }
  if ! have ipatool; then
    bad "ipatool ausente neste host. Opções: (a) rodar em Tier B; (b) trazer o IPA e usar 'triage <arquivo>'."
    return 3
  fi
  if [ "$ASSUME_YES" -ne 1 ]; then
    bad "requisição de rede/loja exige intenção explícita: adicione --yes"
    return 3
  fi
  mkdir -p "$ART_ROOT/raw"
  if ! ipatool download -b "$OPT_BUNDLE" --purchase --output "$ART_ROOT/raw/Drafts-${OPT_BUILD:-latest}.ipa"; then
    bad "ipatool falhou (auth? rede?); nada gravado"
    return 3
  fi
  ensure_run
  local f="$ART_ROOT/raw/Drafts-${OPT_BUILD:-latest}.ipa"
  mv -n "$f" "$RUN_DIR/raw/" 2>/dev/null || true
  record_artifact "raw/$(basename "$f")"
  log_triage "- aquisição: ipatool download -b $OPT_BUNDLE ($(basename "$f"))"
  finalize_run
  say "ok: $RUN_DIR/raw — próximo: capture.sh triage '$RUN_DIR/raw/$(basename "$f")'"
}

# ------------------------------------------------------------------- triage ---
detect_kind() {
  case "$1" in
    *.ipa|*.app) echo ipa ;;
    *.sqlite|*.sqlite3|*.db) echo db ;;
    *.zip)
      if unzip -l "$1" 2>/dev/null | grep -q 'Payload/.*\.app/'; then echo ipa; else echo user-backup; fi ;;
    *)
      if unzip -l "$1" >/dev/null 2>&1; then
        if unzip -l "$1" 2>/dev/null | grep -q 'Payload/.*\.app/'; then echo ipa; else echo user-backup; fi
      else echo unknown; fi ;;
  esac
}

cmd_triage() {
  local src="${1:-}"
  [ -n "$src" ] || { bad "uso: capture.sh triage <arquivo> [--kind ipa|user-backup|db] [--run <id>]"; return 2; }
  [ -f "$src" ] || { bad "não existe: $src"; return 2; }
  local kind="${KIND:-$(detect_kind "$src")}"

  ensure_run
  say "run  : $RUN_DIR"
  say "alvo : $(basename "$src") [$kind]"
  : > "$(triage_file)"
  log_triage "# Triage — $RUN"
  log_triage ""
  log_triage "- gerado: $(now)"
  log_triage "- host: $(uname -s) $(uname -m)"
  log_triage "- entrada: \`$(basename "$src")\` (kind: \`$kind\`)"

  cp -f "$src" "$RUN_DIR/raw/" 2>/dev/null || { bad "não consegui copiar para raw/"; return 1; }
  record_artifact "raw/$(basename "$src")" "kind=$kind"
  ok "cópia em raw/ + hash"

  case "$kind" in
    ipa)        triage_ipa "$src" ;;
    user-backup) triage_backup "$src" ;;
    db)         cp -f "$RUN_DIR/raw/$(basename "$src")" "$RUN_DIR/db/copy.sqlite"
                cmd_surface_db "$RUN_DIR/db/copy.sqlite" ;;
    *)          skip "kind desconhecido — só hash + cópia (especifique --kind)"; log_triage "- kind desconhecido: nada extraído" ;;
  esac

  finalize_run
  say ""
  say "resumo : $RUN_DIR/triage.md"
  say "próximo: cartões em docs/rev-ios/findings/NNNN-*.md + status em LEDGER.md"
}

triage_ipa() {
  local src="$1"
  rm -rf "$RUN_DIR/bundle/Payload"
  if unzip -oq "$src" -d "$RUN_DIR/bundle" 2>/dev/null; then ok "unzip -> bundle/"
  else bad "unzip falhou (arquivo truncado?)"; log_triage "- unzip: **falhou**"; return 1; fi
  local app
  app="$(find "$RUN_DIR/bundle" -maxdepth 4 -type d -name '*.app' | head -1)"
  if [ -z "$app" ]; then
    skip "nenhum *.app em bundle/ (IPA parcial?)"
    log_triage "- bundle: **nenhum .app encontrado**"
    return 0
  fi
  log_triage "- bundle: \`$(rel "$app")\`"
  surface_bundle "$app"
  triage_strings "$app"
}

triage_backup() {
  local src="$1"
  rm -rf "$RUN_DIR/import/backup"
  if unzip -oq "$src" -d "$RUN_DIR/import/backup" 2>/dev/null; then ok "unzip -> import/backup/"
  else bad "unzip falhou"; return 1; fi
  ( cd "$RUN_DIR/import" && find backup -type f | sort > files.txt ) 2>/dev/null
  log_triage "- **aviso**: \`import/backup/\` contém o material original (dados de usuário). Mantenha fora do repo e purge depois: \`capture.sh purge --import\`"
  local n; n=$(wc -l < "$RUN_DIR/import/files.txt" 2>/dev/null | tr -d ' ')
  log_triage "- backup: $n arquivos (\`import/files.txt\`)"
  shape_backup
}

# Extrai só o ESQUELETO (chaves+tipos) dos JSON/plists do backup — sem valores (PII).
shape_backup() {
  python3 - "$RUN_DIR/import/backup" "$RUN_DIR/import/shape.json" <<'PY' || skip "shape-only falhou"
import json, os, sys
root, out = sys.argv[1], sys.argv[2]
def shape(v):
    if isinstance(v, dict):  return {k: shape(x) for k, x in sorted(v.items())}
    if isinstance(v, list):   return [shape(v[0])] if v else []
    if isinstance(v, bool):   return "bool"
    if isinstance(v, str):    return "string"
    if isinstance(v, (int, float)): return "number"
    if v is None:             return "null"
    return type(v).__name__
shapes, n = {}, 0
for dp, _, fns in os.walk(root):
    for fn in sorted(fns):
        if n >= 80: break
        low = fn.lower()
        if not low.endswith((".json", ".plist")): continue
        p = os.path.join(dp, fn)
        data = None
        try:
            with open(p, encoding="utf-8") as fh: data = json.load(fh)
        except Exception:
            try:
                import plistlib
                with open(p, "rb") as fh: data = plistlib.load(fh)
            except Exception:
                continue
        shapes[os.path.relpath(p, root)] = shape(data); n += 1
json.dump({"_meta": {"mode": "shape-only (chaves e tipos; valores de texto descartados)",
                     "files": n, "evidence": "E2"},
           "shapes": shapes}, open(out, "w"), indent=1, sort_keys=True, default=str)
print("  ok    import/shape.json (%d arquivos analisados)" % n)
PY
  record_artifact "import/shape.json"
}

# nomes de campos/URLs/template tags no binário — NÃO valores de usuário
triage_strings() {
  local app="$1" bin
  bin="$(app_binary "$app")"
  [ -n "$bin" ] || { skip "binário principal não identificado"; return 0; }
  have strings || { skip "strings ausente"; return 0; }
  local sfile="$RUN_DIR/surface/strings.txt"
  mkdir -p "$RUN_DIR/surface"
  strings -a "$bin" 2>/dev/null | head -c 4000000 > "$sfile" || true
  local lines; lines=$(wc -l < "$sfile" | tr -d ' ')
  if have rg; then
    rg -o --no-filename '\[\[[a-z_][a-z0-9_]*\]\]' "$sfile" 2>/dev/null | sort -u > "$RUN_DIR/surface/template-tags.txt" || true
    rg -o --no-filename 'drafts://[A-Za-z0-9/?=&._%:-]+' "$sfile" 2>/dev/null | sort -u > "$RUN_DIR/surface/drafts-urls.txt" || true
  else
    grep -oE '\[\[[a-z_][a-z0-9_]*\]\]' "$sfile" | sort -u > "$RUN_DIR/surface/template-tags.txt" || true
    grep -oE 'drafts://[A-Za-z0-9/?=&._%:-]+' "$sfile" | sort -u > "$RUN_DIR/surface/drafts-urls.txt" || true
  fi
  record_artifact "surface/template-tags.txt"
  record_artifact "surface/drafts-urls.txt"
  log_triage "- strings: \`surface/strings.txt\` ($lines linhas, cap 4 MB)"
  log_triage "- template tags candidatas: \`surface/template-tags.txt\` ($(wc -l < "$RUN_DIR/surface/template-tags.txt" | tr -d ' '))"
  log_triage "- rascunhos de drafts://: \`surface/drafts-urls.txt\` ($(wc -l < "$RUN_DIR/surface/drafts-urls.txt" | tr -d ' '))"
  log_triage "- **atenção**: string presente ≠ comportamento. Nada daqui vira modelo sem E3/E4 (02-EXTRACTION-MAP.md §4)."
  ok "strings de interesse extraídas"
}

app_binary() { # <app-dir> -> caminho do executável principal (via CFBundleExecutable se legível)
  local app="$1" name=""
  if [ -f "$app/Info.plist" ] && (have plutil || have plistutil); then
    name="$(plist_to_json "$app/Info.plist" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("CFBundleExecutable",""))' 2>/dev/null || true)"
  fi
  [ -n "$name" ] && [ -f "$app/$name" ] && { printf '%s' "$app/$name"; return 0; }
  find "$app" -maxdepth 1 -type f -perm -u+x | head -1
}

plist_to_json() { # <plist> -> JSON na stdout (usa o que existir)
  local p="$1"
  if have plutil; then plutil -convert json -o - "$p" 2>/dev/null && return 0; fi
  if have plistutil; then
    local tmp; tmp="$(mktemp)"
    plistutil -i "$p" -o "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    python3 -c 'import plistlib,sys,json; print(json.dumps(plistlib.load(open(sys.argv[1],"rb")), indent=1, default=str))' "$tmp"
    local rc=$?; rm -f "$tmp"; return $rc
  fi
  python3 -c 'import plistlib,sys,json; print(json.dumps(plistlib.load(open(sys.argv[1],"rb")), indent=1, default=str))' "$p"
}

# Confirma identidade do alvo a partir do Info.plist: fecha CAP-001 (evidence E2) e
# grava version/build/bundle/schemes em provenance.json. Nunca reescreve o resto.
confirm_identity() { # <plist.json> <plist-orig>
  local pj="$1"
  [ -f "$pj" ] || { skip "sem plist.json — identidade não confirmada"; return 0; }
  python3 - "$pj" "$RUN_DIR/provenance.json" "$OPT_BUNDLE" <<'PY' || skip "identidade não confirmada (plist ilegível)"
import json, sys, datetime
p, prov, claim = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(p))
except Exception:
    sys.exit(1)
schemes = []
for t in (d.get("CFBundleURLTypes") or []):
    schemes += list(t.get("CFBundleURLSchemes") or [])
bid = d.get("CFBundleIdentifier")
try:
    j = json.load(open(prov))
except Exception:
    j = {}
t = j.setdefault("target", {})
t["bundle_id"] = bid
t["build"] = d.get("CFBundleVersion")
t["version"] = d.get("CFBundleShortVersionString")
t["min_os"] = d.get("MinimumOSVersion")
t["schemes_declared"] = schemes
t["source"] = "bundle-extracted"
j["identity"] = {
    "evidence": "E2:Info.plist",
    "confirmed_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "bundle_matches_claim": bool(bid) and bid == claim,
    "ledger_ref": "CAP-001",
}
json.dump(j, open(prov, "w"), indent=1, sort_keys=True, default=str)
print("  ok    identidade E2: %s v%s (%s) · schemes=%s%s" % (
    bid, d.get("CFBundleShortVersionString"), d.get("CFBundleVersion"),
    ",".join(schemes) or "nenhum",
    "" if bid == claim else "  [AVISO: difere do claim %s — atualizar 01-CAPTURE-PLAN.md §1]" % claim))
PY
}

# ------------------------------------------------------------------ surface ---
surface_bundle() { # <app-dir>
  local app="$1" out="$RUN_DIR/surface"; mkdir -p "$out"
  local plist="$app/Info.plist"
  if [ -f "$plist" ]; then
    if plist_to_json "$plist" > "$out/plist.json" 2>/dev/null && [ -s "$out/plist.json" ]; then
      ok "Info.plist -> surface/plist.json"
      record_artifact "surface/plist.json" "role=info_plist"
      confirm_identity "$out/plist.json" "$app/Info.plist"
      python3 - "$out/plist.json" "$out" <<'PY' || skip "resumo de plist pulado"
import json, os, sys
p, out = sys.argv[1], sys.argv[2]
meta = {"_meta": {"source": "Info.plist", "cmd": "capture.sh surface --from-bundle", "evidence": "E2"}}
try:
    d = json.load(open(p))
except Exception:
    sys.exit(1)
keep = ["CFBundleIdentifier","CFBundleShortVersionString","CFBundleVersion","MinimumOSVersion",
        "UILaunchStoryboardName","UIMainStoryboardFile","UIUserInterfaceStyle","UIAppFonts",
        "UIApplicationSceneManifest","LSApplicationQueriesSchemes","NSLocationWhenInUseUsageDescription",
        "NSMicrophoneUsageDescription","NSFaceIDUsageDescription","CFBundleIconName","CFBundleDisplayName"]
json.dump({**meta, "summary": {k: d.get(k, "ABSENT") for k in keep}}, open(os.path.join(out, "plist-summary.json"), "w"), indent=1, default=str)
json.dump({**meta, "CFBundleURLTypes": d.get("CFBundleURLTypes", "ABSENT")}, open(os.path.join(out, "url-schemes.json"), "w"), indent=1, default=str)
print("  ok    surface/plist-summary.json + surface/url-schemes.json")
PY
      record_artifact "surface/url-schemes.json"
      record_artifact "surface/plist-summary.json"
      log_triage "- URL schemes: \`surface/url-schemes.json\` (se \`ABSENT\`, o app usa outro mecanismo de deep link — confirmar)"
    else
      skip "Info.plist presente mas não decodificado (sem plutil/plistutil?)"
      log_triage "- Info.plist: **unreadable** — NÃO interpretar como ausente (R2 do 00-SPEC.md §8)"
    fi
  else
    skip "sem Info.plist em $app"
  fi
  find "$app" -maxdepth 4 -name '*.appex' 2>/dev/null | sed "s#$RUN_DIR/##" > "$out/extensions.txt" || true
  ls "$app/Frameworks" 2>/dev/null | sort > "$out/frameworks.txt" || true
  find "$app" -maxdepth 1 \( -name '*.car' -o -name '*.storyboardc' -o -name '*.nib' -o -name '*.bundle' \) 2>/dev/null | sed "s#$RUN_DIR/##" > "$out/layout-artifacts.txt" || true
  record_artifact "surface/extensions.txt"; record_artifact "surface/frameworks.txt"; record_artifact "surface/layout-artifacts.txt"
  local nx; nx=$(wc -l < "$out/extensions.txt" | tr -d ' ')
  log_triage "- extensões: $nx ($(sed 's#.*/##' "$out/extensions.txt" | paste -sd, - 2>/dev/null || echo -))"
  log_triage "- frameworks: $(wc -l < "$out/frameworks.txt" | tr -d ' ') (\`surface/frameworks.txt\`)"
  log_triage "- assets/xibs: \`surface/layout-artifacts.txt\` ($(wc -l < "$out/layout-artifacts.txt" | tr -d ' '))"
  say "- extensões: $nx · frameworks: $(wc -l < "$out/frameworks.txt" | tr -d ' ') linhas"

  local bin enc="unknown"
  bin="$(app_binary "$app")"
  if [ -n "$bin" ] && [ -f "$bin" ]; then
    log_triage "- binário: \`$(rel "$bin")\` · sha256 \`$(sha "$bin")\` · $(size "$bin") bytes"
    if have otool; then
      enc="$(otool -l "$bin" 2>/dev/null | awk '/LC_ENCRYPTION_INFO/{f=1} f && /cryptid/{print $2; exit}')"
    elif have jtool2; then
      enc="$(jtool2 -l "$bin" 2>/dev/null | awk '/cryptid/{print $2; exit}')"
    elif have llvm-objdump; then
      enc="$(llvm-objdump -p "$bin" 2>/dev/null | awk '/LC_ENCRYPTION_INFO/{f=1} f && /cryptid/{print $2; exit}')"
    fi
    [ -n "$enc" ] || enc="unknown (sem otool/jtool2/llvm-objdump)"
    log_triage "- encrypted (cryptid): \`$enc\`"
    [ "$enc" = "1" ] && log_triage "- esperado para IPA da App Store: símbolos só em Tier C (01-CAPTURE-PLAN.md §3.2)"
    ok "cryptid=$enc"
  fi
}

cmd_surface_db() { # <sqlite>
  local db="$1" out="$RUN_DIR/db"; mkdir -p "$out"
  [ -f "$db" ] || { bad "banco não encontrado: $db"; return 1; }
  python3 - "$db" "$out" <<'PY' || { skip "sqlite ilegível (formato? criptografado?)"; return 1; }
import json, os, re, sqlite3, sys
db, out = sys.argv[1], sys.argv[2]
con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db), uri=True)
cur = con.cursor()
rows = list(cur.execute("SELECT name, type, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC, name"))
if not rows:
    print("  FAIL  sqlite_master vazio — não é um banco SQLite legível"); sys.exit(1)
open(os.path.join(out, "schema.sql"), "w").write("\n".join(r[2] + ";" for r in rows if r[2]) + "\n")
tables = [r[0] for r in rows if r[1] == "table" and not r[0].startswith("sqlite_")]
enumish = re.compile(r"(folder|flag|stat|type|kind|mode|syntax|scope|group|order|sort|version|state)", re.I)
info, enums = {}, {}
for t in tables:
    cols = [{"cid": r[0], "name": r[1], "type": r[2], "notnull": r[3], "default": r[4], "pk": r[5]}
            for r in cur.execute('PRAGMA table_info("%s")' % t)]
    try:
        cnt = cur.execute('SELECT count(*) FROM "%s"' % t).fetchone()[0]
    except Exception:
        cnt = -1
    info[t] = {"columns": cols, "rows": cnt}
    for c in cols:
        if not c["name"] or not enumish.search(c["name"]):
            continue
        try:
            vals = [v[0] for v in cur.execute('SELECT DISTINCT "%s" FROM "%s" LIMIT 40' % (c["name"], t))]
        except Exception:
            continue
        keep = [v for v in vals if v is None or (isinstance(v, str) and len(v) <= 40) or isinstance(v, (int, float, bytes)) and not isinstance(v, bytes)]
        if keep:
            enums.setdefault(t, {})[c["name"]] = keep
idx = [{"name": r[0], "table": r[1], "sql": r[2]} for r in cur.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' ORDER BY name")]
meta = {}
for k in ("user_version", "journal_mode", "page_size", "encoding"):
    try: meta[k] = cur.execute("PRAGMA %s" % k).fetchone()[0]
    except Exception: meta[k] = None
M = {"_meta": {"cmd": "capture.sh surface --from-db", "evidence": "E3", "read_only": True, "source": os.path.basename(db)}}
json.dump({**M, "tables": info, "indexes": idx, "pragmas": meta}, open(os.path.join(out, "tables.json"), "w"), indent=1, default=str)
json.dump({**M, "redaction": "só colunas de nome enum-like, valores <=40 chars, LIMIT 40", "values": enums},
          open(os.path.join(out, "enums.json"), "w"), indent=1, default=str)
print("  ok    db/schema.sql (%d tabelas) · db/tables.json · db/enums.json" % len(tables))
print("        user_version=%s · texto de usuário NÃO copiado (PII)" % meta.get("user_version"))
PY
  record_artifact "db/schema.sql"; record_artifact "db/tables.json"; record_artifact "db/enums.json"
  log_triage ""
  log_triage "## Modelo de dados (C3)"
  log_triage "- \`db/schema.sql\` · \`db/tables.json\` · \`db/enums.json\`"
  log_triage "- evidência E3 (cópia read-only; original intocado)"
  log_triage "- abrir cartões: OB-MODEL-001/002/006/010/011/012 + OB-SEARCH-001 (02-EXTRACTION-MAP.md §2)"
  say "ok: $out"
}

cmd_surface() {
  [ -n "$FROM_BUNDLE" ] || [ -n "$FROM_DB" ] || { bad "uso: surface --from-bundle <dir.app> | --from-db <sqlite>"; return 2; }
  [ -d "$FROM_BUNDLE" ] || { [ -z "$FROM_BUNDLE" ] || { bad "não é diretório: $FROM_BUNDLE"; return 2; }; }
  ensure_run
  if [ -n "$FROM_DB" ]; then cmd_surface_db "$FROM_DB"; else surface_bundle "$FROM_BUNDLE"; fi
  finalize_run
}

# purge -- [--import] [--raw] [--bundle] [--all]
# Destrói o material sensível do run, preservando os hashes em purge.log.
# A custódia continua verificável (provenance/SHA256SUMS), mas os bytes somem.
cmd_purge() {
  # alvos aceitos (com ou sem --): raw bundle import db runtime layout all
  local -a valid=(raw bundle import db runtime layout)
  local what="" t
  for t in "$@"; do
    t="${t#--}"
    case "$t" in
      all) what="$what raw bundle import db runtime layout" ;;
      "") ;;
      *) for v in "${valid[@]}"; do [ "$t" = "$v" ] && what="$what $t"; done ;;
    esac
  done
  what="${what# }"
  # dedupe sem depender de sort -u em strings
  local seen=" " list="" x
  for x in $what; do case "$seen" in *" $x "*) ;; *) seen="$seen$x "; list="$list $x";; esac; done
  list="${list# }"
  [ -n "$list" ] || { bad "uso: capture.sh purge [raw|bundle|import|db|runtime|layout|all]"; return 2; }
  ensure_run
  local d n=0
  for d in $list; do
    [ -d "$RUN_DIR/$d" ] || continue
    : > "$RUN_DIR/.purge.tmp"
    ( cd "$RUN_DIR" && find "$d" -type f -print0 2>/dev/null | xargs -0 -r sha256sum ) >> "$RUN_DIR/.purge.tmp" 2>/dev/null || true
    if [ -s "$RUN_DIR/.purge.tmp" ]; then
      printf '# purgado em %s: %s/\n' "$(now)" "$d" >> "$RUN_DIR/purge.log"
      cat "$RUN_DIR/.purge.tmp" >> "$RUN_DIR/purge.log"
    fi
    rm -f "$RUN_DIR/.purge.tmp"
    rm -rf "${RUN_DIR:?}/$d" && mkdir -p "$RUN_DIR/$d" && n=$((n+1))
    say "  purgado  $d/ (hashes em purge.log)"
  done
  say "purge: $n diretório(s) limpos em $RUN_DIR"
  say "os hashes continuam em SHA256SUMS/purge.log — a evidência documentada permanece auditável"
}

# -------------------------------------------------------------------- hash ----
cmd_hash() {
  local f="${1:-}"
  [ -n "$f" ] && [ -f "$f" ] || { bad "uso: capture.sh hash <arquivo>"; return 2; }
  printf '{"path":"%s","sha256":"%s","bytes":%s,"at":"%s"}\n' "$f" "$(sha "$f")" "$(size "$f")" "$(now)"
}

# --------------------------------------------------------------- argv (flat) --
CMD="${1:-help}"
[ $# -gt 0 ] && shift
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)  DRY=1 ;;
    --yes|-y)   ASSUME_YES=1 ;;
    --strict)   STRICT=1 ;;
    --json|-j)  JSON_OUT=1 ;;
    --kind)     shift; KIND="${1:-}" ;;
    --run)      shift; RUN="${1:-}" ;;
    --target)   shift; OPT_TARGET="${1:-getdrafts}" ;;
    --build)    shift; OPT_BUILD="${1:-}" ;;
    --bundle)   shift; OPT_BUNDLE="${1:-$OPT_BUNDLE}" ;;
    --from-bundle) shift; FROM_BUNDLE="${1:-}" ;;
    --from-db)     shift; FROM_DB="${1:-}" ;;
    -h|--help)  CMD="help" ;;
    *) POS+=("$1") ;;
  esac
  shift
done

case "$CMD" in
  preflight) if [ "$JSON_OUT" -eq 1 ]; then cmd_preflight_json; else cmd_preflight; fi ;;
  new-run)
    if [ "$DRY" -eq 1 ]; then
      say "[dry-run] criaria: $ART_ROOT/$(today)-${OPT_TARGET}${OPT_BUILD:+-$OPT_BUILD}"
    else
      RUN=""; create_run
    fi ;;
  acquire) cmd_acquire ;;
  triage)  cmd_triage ${POS+"${POS[@]}"} ;;
  surface) cmd_surface ;;
  hash)    cmd_hash ${POS+"${POS[@]}"} ;;
  purge)   cmd_purge ${POS+"${POS[@]}"} ;;
  help|-h|--help) usage ;;
  *) bad "comando desconhecido: $CMD"; usage; exit 2 ;;
esac
