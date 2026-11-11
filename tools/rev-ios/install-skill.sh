#!/usr/bin/env bash
# install-skill.sh — instala/valida o skill iOS vendored para a trilha rev-ios
#
# O README upstream manda:  cd ~/.agents/skills/ && git clone https://github.com/DragonJAR/iOS-Pentesting-Skill ios-app-security-audit
# Nós substituímos o clone por um link para a cópia **deste branch** (pinned em .rev-ios-pin),
# porque a trilha exige que o ramo seja a fonte da knowledge (isolamento rev-ios).
#
# Uso:
#   install-skill.sh              # instala (symlink) em ~/.agents/skills/
#   install-skill.sh --copy       # copia em vez de linkar (para containers que não seguem symlink)
#   install-skill.sh --check      # valida pin + hashes + arquivos exigidos pela spec
#   install-skill.sh --update     # traz upstream p/ um tmp e mostra o delta (não aplica)
#   install-skill.sh --update --force   # aplica a atualização + re-escreve VENDOR.md/pin
#   install-skill.sh --uninstall  # remove o link instalado
#
# Saída: 0 ok · 1 checagem falhou · 3 ambiente (sem git/rede/permissão)
set -uo pipefail

REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "${REPO_ROOT:-}" ] || REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/skills/ios-app-security-audit"
SKILLS_HOME="${AGENT_SKILLS_DIR:-$HOME/.agents/skills}"
DEST="$SKILLS_HOME/ios-app-security-audit"
MODE=link; DO=""

# arquivos que a spec desta trilha cita nominalmente — precisam existir
REQUIRED=(
  SKILL.md README.md LICENSE VENDOR.md .rev-ios-pin
  references/linux-ios-analysis-workarounds.md
  references/ipa-extraction-guide.md
  references/tool-versions.md
  references/tool-installation-ios.md
  references/frida-scripts-index.md
  references/getting-started-ios.md
  references/troubleshooting-ios.md
  references/ios-pentesting-decision-tree.md
  references/libimobiledevice-guide.md
  references/simforge-ios-testing.md
  scripts/preflight_check.py
  scripts/screenshot-extractor.sh
  scripts/auto-audit-static-ios.sh
  scripts/quick-static-analysis.sh
  assets/frida-scripts/sqlite-query-logger-ios.js
  assets/frida-scripts/coredata-interceptor.js
  assets/frida-scripts/nsuserdefaults-dumper.js
  assets/frida-scripts/binary-class-dump.js
  assets/frida-scripts/class-explorer-ios.js
  assets/frida-scripts/objc-method-tracer.js
  assets/frida-scripts/url-scheme-monitor.js
  assets/frida-scripts/pasteboard-monitor.js
  assets/frida-scripts/snapshot-overlay-check.js
)

say() { printf '%s\n' "$*"; }
ok()  { printf '  ok    %s\n' "$*"; }
ko()  { printf '  FAIL  %s\n' "$*" >&2; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

check() {
  local rc=0 f
  say "skill: $SRC"
  [ -d "$SRC" ] || { ko "diretório não encontrado — o branch está checado?"; return 1; }
  for f in "${REQUIRED[@]}"; do
    if [ -f "$SRC/$f" ]; then :; else ko "faltando: $f"; rc=1; fi
  done
  [ $rc -eq 0 ] && ok "arquivos exigidos pela spec: ${#REQUIRED[@]}/${#REQUIRED[@]}"

  local pin_c=""
  [ -f "$SRC/.rev-ios-pin" ] && pin_c="$(sed -n 's/^upstream_commit=//p' "$SRC/.rev-ios-pin")"
  if [ -n "$pin_c" ]; then ok "pin: ${pin_c:0:12}"; else ko "sem .rev-ios-pin"; rc=1; fi
  if grep -q -- "$pin_c" "$SRC/VENDOR.md" 2>/dev/null; then
    ok "VENDOR.md coerente com o pin"
  else
    ko "VENDOR.md não menciona o commit do pin (desincronizado)"; rc=1
  fi

  # hashes publicados em VENDOR.md
  local line want got
  for line in "SKILL.md" "README.md"; do
    want="$(grep -F "  $line" "$SRC/VENDOR.md" | awk '{print $1}' | head -1)"
    got="$(sha "$SRC/$line")"
    if [ -n "$want" ] && [ "$want" = "$got" ]; then ok "sha256 $line confere"
    elif [ -z "$want" ]; then say "  skip  $line: sem hash publicado em VENDOR.md"
    else ko "sha256 $line DIFERE (want ${want:0:12}… got ${got:0:12}…)"; rc=1; fi
  done

  # PATCHES.md: cada patch declarado tem de bater com o hash registrado
  if [ -f "$SRC/PATCHES.md" ]; then
    local nrows=0 pfile want got line
    while IFS= read -r line; do
      pfile="$(printf '%s\n' "$line" | awk -F'|' '{gsub(/[` ]/,"",$3); print $3}')"
      want="$(printf '%s\n' "$line" | awk -F'|' '{gsub(/[` ]/,"",$8); print $8}')"
      case "$want" in *[!0-9a-f]*|"") continue ;; esac
      [ ${#want} -eq 64 ] || continue
      nrows=$((nrows+1))
      if [ -f "$SRC/$pfile" ] && [ "$(sha "$SRC/$pfile")" = "$want" ]; then
        ok "patch P$nrows confere: $pfile"
      else
        ko "patch NÃO confere: $pfile (arquivo ausente ou hash difere de PATCHES.md)"; rc=1
      fi
    done < <(grep -E '^\| P[0-9]+' "$SRC/PATCHES.md")
    say "  ok    PATCHES.md: $nrows patch(es) verificado(s)"
  fi

  # gate de credencial: a cópia vendored não pode conter segredo em formato real
  if command -v rg >/dev/null 2>&1; then
    local hits
    hits="$(rg -n --no-heading -o \
'(sk_live|sk_test|pk_live|pk_test)_[0-9A-Za-z]{12,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{36,}|xox[baprs]-[0-9A-Za-z-]{12,}|AIza[0-9A-Za-z_-]{35,}' "$SRC" 2>/dev/null \
      | rg -v 'EXAMPLE|REDACTED|XXXX|placeholder' | head -5)"
    if [ -z "$hits" ]; then ok "varredura de credenciais: limpa (compatível com push protection)"
    else ko "credencial em formato REAL na cópia vendored — neutralize e registre em PATCHES.md:"
         printf '%s\n' "$hits" >&2; rc=1; fi
  else
    say "  skip  varredura de credenciais (rg ausente)"
  fi

  # integridade do resto: nada deve ter sido editado localmente
  if command -v git >/dev/null 2>&1; then
    local dirty
    local allow='VENDOR\.md|\.rev-ios-pin|PATCHES\.md'
    if [ -f "$SRC/PATCHES.md" ]; then
      local pf
      while IFS= read -r pf; do
        [ -n "$pf" ] && allow="$allow|$(printf '%s' "$pf" | sed 's/[.\/^$*]/\\&/g')"
      done < <(awk -F'|' '/^\| P[0-9]+/{gsub(/[` ]/,"",$3); print $3}' "$SRC/PATCHES.md")
    fi
    dirty="$(git -C "$REPO_ROOT" status --porcelain -- "$SRC" 2>/dev/null | grep -v '^??' \
             | grep -Ev "skills/ios-app-security-audit/($allow)$" | wc -l | tr -d ' ')"
    if [ "${dirty:-0}" = "0" ]; then ok "cópia vendored sem edição local (obrigatório)"; else
      ko "$dirty arquivo(s) vendored modificado(s) — restaure; deltas vão em skills/getdrafts-ios-rev/ e docs/rev-ios/"; rc=1
    fi
  fi

  # instalado onde o agente procura?
  if [ -e "$DEST" ]; then
    ok "instalado em $DEST"
    [ "$(cd "$DEST" && pwd -P)" = "$(cd "$SRC" && pwd -P)" ] || say "  skip  o caminho instalado difere do vendored (link antigo? rode de novo)"
  else
    say "  skip  não instalado em $DEST (rode: install-skill.sh)"
  fi
  return $rc
}

install() {
  [ -d "$SRC" ] || { ko "cópia vendored ausente em $SRC"; exit 1; }
  mkdir -p "$SKILLS_HOME" || { ko "sem permissão em $SKILLS_HOME"; exit 3; }
  if [ -e "$DEST" ] || [ -L "$DEST" ]; then
    if [ -L "$DEST" ]; then rm -f "$DEST"; else say "  aviso : $DEST já existe e não é link — preservado como $DEST.bak"; mv "$DEST" "$DEST.bak"; fi
  fi
  if [ "$MODE" = copy ]; then
    cp -R "$SRC" "$DEST"
  else
    ln -s "$SRC" "$DEST"
  fi
  chmod +x "$DEST"/scripts/*.sh 2>/dev/null || true
  ok "instalado ($MODE): $DEST -> $SRC"
  say ""
  say "uso no agente: o SKILL.md descreve as 6 fases; comece por"
  say "  $DEST/references/getting-started-ios.md   (15 min de orientação)"
  say "  $DEST/references/linux-ios-analysis-workarounds.md   (se o host é Linux)"
  say "e o procedimento específico do alvo está em skills/getdrafts-ios-rev/SKILL.md"
}

uninstall() {
  if [ -L "$DEST" ]; then rm -f "$DEST"; ok "link removido de $DEST"; else say "  skip  $DEST não é um link nosso (nada removido)"; fi
}

update_upstream() {
  command -v git >/dev/null 2>&1 || { ko "git ausente"; exit 3; }
  local tmp; tmp="$(mktemp -d)"
  say "clonando upstream para $tmp (rede necessária)"
  if ! git clone --quiet --depth 1 https://github.com/DragonJAR/iOS-Pentesting-Skill "$tmp/ios-skill"; then
    ko "clone falhou (rede/perm); nada alterado"; rm -rf "$tmp"; exit 3
  fi
  local newc; newc="$(git -C "$tmp/ios-skill" rev-parse HEAD)"
  local oldc; oldc="$(sed -n 's/^upstream_commit=//p' "$SRC/.rev-ios-pin" 2>/dev/null)"
  say "upstream HEAD : $newc"
  say "pino atual    : $oldc"
  if [ "$newc" = "$oldc" ]; then ok "já no commit mais recente"; rm -rf "$tmp"; return 0; fi
  say ""
  say "delta (arquivos diferem):"
  diff -rq "$SRC" "$tmp/ios-skill" --exclude=.git --exclude=.github --exclude=VENDOR.md --exclude=.rev-ios-pin 2>/dev/null | head -40
  if [ "${FORCE:-0}" != 1 ]; then
    say ""
    say "[dry-run] nada aplicado. Para aplicar: $0 --update --force  (e depois revisar VENDOR.md + reler o README)"
    rm -rf "$tmp"; return 0
  fi
  say ""
  say "aplicando atualização…"
  ( cd "$SRC" && find . -mindepth 1 -maxdepth 1 ! -name VENDOR.md ! -name .rev-ios-pin -exec rm -rf {} + )
  ( cd "$tmp/ios-skill" && tar --exclude='./.git' --exclude='./.github' --exclude='./.gitignore' --exclude='./.gitattributes' -cf - . ) | ( cd "$SRC" && tar -xf - )
  local n; n="$(find "$SRC" -type f | wc -l | tr -d ' ')"
  cat > "$SRC/.rev-ios-pin" <<EOF
upstream_url=https://github.com/DragonJAR/iOS-Pentesting-Skill
upstream_ref=main
upstream_commit=$newc
upstream_date=$(git -C "$tmp/ios-skill" log -1 --format=%cI)
skill_version=$(sed -n 's/^  version: "\{0,1\}\([0-9.]*\)"\{0,1\}$/\1/p' "$SRC/SKILL.md" | head -1)
license=Apache-2.0
snapshotted_at=$(date -u +%Y-%m-%d)
snapshotted_by=${USER:-unknown}
files=$n
excluded=.git,.github,.gitignore,.gitattributes
EOF
  say "pin atualizado → $newc ($n arquivos)"
  say "AÇÃO MANUAL OBRIGATÓRIA: atualizar VENDOR.md (commit, data, hashes de SKILL.md/README.md, contagem)"
  say "  e reler o README (mudanças de pré-requisitos/limitações afetam docs/rev-ios/01-CAPTURE-PLAN.md §4)"
  say "  hashes: $(sha "$SRC/SKILL.md")  SKILL.md"
  say "          $(sha "$SRC/README.md")  README.md"
  say "e rodar: $0 --check"
  rm -rf "$tmp"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --copy) MODE=copy ;;
    --check) DO=check ;;
    --update) DO=update ;;
    --force) FORCE=1 ;;
    --uninstall) DO=uninstall ;;
    -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'opção desconhecida: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

case "$DO" in
  check)     check ;;
  update)    update_upstream ;;
  uninstall) uninstall ;;
  "")        install; say ""; check ;;
esac
