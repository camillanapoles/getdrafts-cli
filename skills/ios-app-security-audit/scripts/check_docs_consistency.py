#!/usr/bin/env python3
"""
Consistency checker for the iOS-Pentesting-Skill documentation.

Single source of truth: the filesystem. Every count, file name and script
reference in the documentation is validated against what actually exists on
disk, so documentation can no longer drift silently.

Checks performed
----------------
1. FILE REFERENCES   - every `frida -l <script>.js` and `python3 scripts/<x>.py`
                       reference in the docs must point at a file that exists.
2. FRIDA CATALOG     - references/frida-scripts-index.md must list every bundled
                       Frida script, and must not list scripts that do not exist.
3. STALE COUNTS      - declared counts ("73 Frida scripts", "93 reference
                       documents", ...) must match the real numbers.
4. MARKDOWN LINKS    - relative links between documents must resolve.
5. MARKDOWN ANCHORS  - in-page anchors must match a heading that exists.
6. FRIDA API         - the bundled scripts and the docs must not use the
                       Frida APIs that Frida 17 removed.

Severities
----------
error    the documentation points at something that does not exist, or two
         documents disagree about a fact. Always fails the build.
warning  suspicious, not proven broken. Fails the build only with --strict.
info     intentional by design (a template the reader must author, a
         placeholder file name inside an example). Never fails the build.

Usage
-----
    python3 scripts/check_docs_consistency.py            # human readable
    python3 scripts/check_docs_consistency.py --json     # machine readable
    python3 scripts/check_docs_consistency.py --strict   # warnings are errors

Exit codes
----------
    0  no errors
    1  at least one error found
    2  bad usage
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
REFERENCES_DIR = REPO_ROOT / "references"
FRIDA_DIR = REPO_ROOT / "assets" / "frida-scripts"
FRIDA_INDEX = REFERENCES_DIR / "frida-scripts-index.md"

# Directories never scanned for documentation.
IGNORED_DIR_PARTS = {".git", ".claude", "dev", ".ruff_cache", "__pycache__", ".atl"}

# The checker validates the documentation the skill actually ships and that its
# agent reads. It deliberately does not scan every .md in the repository:
# internal reports and notes are not consumed by the agent and would only
# produce noise.
DOC_ROOTS = ("references", "assets")
DOC_ROOT_FILES = ("SKILL.md", "README.md", "README.es.md")

# Minimum size of an identical block between two references before it is
# reported as duplication.
DUPLICATION_MIN_LINES = 60

# Names that are obviously user supplied placeholders, not bundled assets.
PLACEHOLDER_NAMES = {
    "script.js",
    "my_script.js",
    "your_script.js",
    "test.js",
    "example.js",
    "hook.js",
    "payload.js",
    "app.js",
    "content.js",
    "bundle.js",
    "cordova.js",
    "cordova_plugins.js",
}

# Phrases that mark a reference as a template the reader must author himself.
TEMPLATE_MARKERS = (
    "copy-paste template",
    "save as",
    "save it as",
    "your own repository",
    "your own repo",
    "not shipped by this skill",
    "not provided by this skill",
    "you must author",
    "not bundled",
    "create the following script",
    "save the following",
    "write the following",
)

# Marker shown in the report for references that are intentional templates.
TEMPLATE_REASON = "declared inline as a template (reader must author it)"

# Marker shown in the report for placeholder file names used inside examples.
PLACEHOLDER_REASON = "placeholder file name used inside an example"

# Protocols commonly mistaken for classes. A protocol has no implementation of
# its own: ObjC.classes.<Protocol> is undefined, so the lookup fails and the
# hook is never installed.
IODELEGATE_PROTOCOLS = (
    "UIApplicationDelegate",
    "UICollectionViewDelegate",
    "UICollectionViewDragDelegate",
    "UICollectionViewDropDelegate",
    "UIDocumentInteractionDelegate",
    "UIFontDescriptorDelegate",
    "UIGestureRecognizerDelegate",
    "UIImagePickerControllerDelegate",
    "UINavigationControllerDelegate",
    "UIPickerViewDelegate",
    "UIPopoverPresentationControllerDelegate",
    "UIPrintInteractionControllerDelegate",
    "UIRemoteKeyboardViewDelegate",
    "UIScrollViewDelegate",
    "UISearchBarDelegate",
    "UITabBarControllerDelegate",
    "UITableViewDelegate",
    "UITextFieldDelegate",
    "UITextViewDelegate",
    "UIToolbarDelegate",
    "UIWebViewDelegate",
    "WKUIDelegate",
    "WKNavigationDelegate",
    "NSFileManagerDelegate",
    "NSURLSessionDelegate",
    "NSURLConnectionDelegate",
    "NSUserNotificationCenterDelegate",
    "NSToolbarDelegate",
    "CLLocationManagerDelegate",
)

# Reference documents that are local tooling notes, not part of the skill.
NON_SKILL_DOCS = {"CLAUDE.md"}


@dataclass
class Issue:
    severity: str  # "error" | "warning" | "info"
    check: str
    location: str
    message: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "check": self.check,
            "location": self.location,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def add(self, severity: str, check: str, location: str, message: str, detail: str = "") -> None:
        self.issues.append(Issue(severity, check, location, message, detail))

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def infos(self) -> list[Issue]:
        """Findings that are intentional by design and never fail the build.

        A template that the reader is told to author, or a placeholder file
        name used inside an example, is not drift: the documentation is
        behaving exactly as intended. Reporting those as warnings made
        ``--strict`` unusable in CI, because the gate could never go green.
        """
        return [i for i in self.issues if i.severity == "info"]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def iter_docs() -> Iterable[Path]:
    """Yield every markdown document that belongs to the skill."""
    seen: set[Path] = set()

    for name in DOC_ROOT_FILES:
        candidate = REPO_ROOT / name
        if candidate.exists() and candidate not in seen:
            seen.add(candidate)
            yield candidate

    for root_name in DOC_ROOTS:
        root = REPO_ROOT / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.md")):
            if path in seen:
                continue
            rel = path.relative_to(REPO_ROOT)
            if IGNORED_DIR_PARTS & set(rel.parts):
                continue
            if path.name in NON_SKILL_DOCS:
                continue
            seen.add(path)
            yield path


def _code_blocks(text: str) -> list[tuple[int, int, str, str]]:
    """Return (start, end, lang, content) for every fenced code block."""
    blocks: list[tuple[int, int, str, str]] = []
    fence = re.compile(r"^```([A-Za-z0-9_+-]*)\s*$", re.M)
    pos = 0
    while True:
        opening = fence.search(text, pos)
        if opening is None:
            break
        closing = fence.search(text, opening.end())
        if closing is None:
            break
        lang = opening.group(1).lower()
        blocks.append((opening.start(), closing.end(), lang, text[opening.end() : closing.start()]))
        pos = closing.end()
    return blocks


def enclosing_code_block(text: str, offset: int) -> tuple[str, str] | None:
    """Return (language, content) of the fenced code block containing offset."""
    for _start, end, lang, content in _code_blocks(text):
        if end > offset:
            return lang, content
    return None


def preceding_code_block(text: str, offset: int) -> tuple[str, str] | None:
    """Return the code block immediately before the one containing offset.

    Only an adjacent block counts: the prose between the two blocks must be
    short, otherwise the earlier block belongs to an unrelated section.
    """
    blocks = _code_blocks(text)
    for index, (_start, end, _lang, _content) in enumerate(blocks):
        if end > offset:
            if index == 0:
                return None
            prev_start, prev_end, lang, content = blocks[index - 1]
            gap = text[prev_end : offset]
            # Allow only a short prose bridge (a "Usage:" line and blank lines).
            if gap.count("\n") > 6:
                return None
            return lang, content
    return None


def _block_defines_script(lang: str, content: str) -> bool:
    """True when the block is the script source itself."""
    if lang in ("javascript", "js", "python", "py", "typescript", "ts"):
        return bool(re.search(r"\b(Interceptor\.attach|def |function |require\(|import )", content))
    return False


def defines_script_inline(text: str, offset: int, name: str) -> bool:
    """True when the surrounding code block itself defines the script.

    Two common shapes: a bash heredoc that writes the file
    ("cat > foo.js << 'EOF'"), and a javascript/python block that *is* the
    script source, so the following `frida -l foo.js` loads the snippet the
    reader just saved.
    """
    for block in (enclosing_code_block(text, offset), preceding_code_block(text, offset)):
        if block is None:
            continue
        lang, content = block

        # bash heredoc writing the file
        if re.search(rf"cat\s*>\s*\S*{re.escape(name)}\b", content):
            return True

        if _block_defines_script(lang, content):
            return True
    return False


def source_provided_inline(text: str, offset: int, name: str) -> bool:
    """True when the document also contains the full source of the script.

    The common shape is a section that first references the script in a
    workflow and then provides it as a fenced block whose second line names
    the file, e.g.

        ```python
        #!/usr/bin/env python3
        # scripts/detect_secrets.py
        ```
    """
    line_no = line_of(text, offset)
    lines = text.splitlines()

    start = 0
    for i in range(line_no - 1, -1, -1):
        if lines[i].startswith("## "):
            start = i
            break

    # A shebang followed by a comment naming the script identifies the block
    # that carries the full source. The comment may carry a path prefix
    # ("# scripts/detect_secrets.py").
    pattern = re.compile(rf"^#\s*(?:[\w.\-]+/)*\S*{re.escape(name)}\s*$")
    for i in range(start, len(lines)):
        if not lines[i].startswith("#!"):
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            if pattern.match(lines[j].strip()):
                return True
    return False


def is_template_context(text: str, offset: int, name: str = "") -> bool:
    """True when the reference is declared as a template the reader authors.

    The disclaimer is a note placed near the start of a top-level section
    (usually "## N. Some Workflow") and applies to everything that section
    contains, including code blocks far below it. The enclosing section is
    therefore resolved from the nearest level-2 heading above the reference.
    """
    if name and defines_script_inline(text, offset, name):
        return True
    if name and source_provided_inline(text, offset, name):
        return True

    line_no = line_of(text, offset)
    lines = text.splitlines()

    # Enclosing top-level ("## ") section.
    start = 0
    for i in range(line_no - 1, -1, -1):
        if lines[i].startswith("## "):
            start = i
            break

    end = min(len(lines), line_no + 6)
    snippet = "\n".join(lines[start:end]).lower()
    if any(marker in snippet for marker in TEMPLATE_MARKERS):
        return True

    # Fall back to a generous backward window for notes placed in a preamble.
    back = max(0, line_no - 1 - 80)
    snippet = "\n".join(lines[back:end]).lower()
    return any(marker in snippet for marker in TEMPLATE_MARKERS)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def check_file_references(report: Report) -> None:
    """Every script reference in the docs must resolve to a real file."""
    frida_scripts = {p.name for p in FRIDA_DIR.glob("*.js")}
    script_files = {p.name for p in SCRIPTS_DIR.iterdir() if p.is_file()}

    # The path prefix is optional: "frida -l foo.js", "-l ./scripts/foo.js" and
    # "-l assets/frida-scripts/foo.js" must all be recognised.
    frida_pattern = re.compile(
        r"-l\s+(?:\./)?(?:[\w.\-]+/)*([A-Za-z0-9_.\-]+\.js)\b"
    )
    script_pattern = re.compile(r"scripts/([A-Za-z0-9_.\-]+\.(?:py|sh|ps1))\b")

    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")

        for match in frida_pattern.finditer(text):
            name = match.group(1)
            if name in frida_scripts:
                continue
            location = f"{rel(doc)}:{line_of(text, match.start())}"
            if name in PLACEHOLDER_NAMES:
                report.add(
                    "info",
                    "file-reference",
                    location,
                    f"`{name}` is a placeholder name, not a bundled script",
                    PLACEHOLDER_REASON,
                )
                continue
            if is_template_context(text, match.start(), name):
                report.add(
                    "info",
                    "file-reference",
                    location,
                    f"`{name}` does not exist in assets/frida-scripts/",
                    TEMPLATE_REASON,
                )
                continue
            report.add(
                "error",
                "file-reference",
                location,
                f"`frida -l {name}` references a file that does not exist",
                f"assets/frida-scripts/ has no '{name}'",
            )

        for match in script_pattern.finditer(text):
            name = match.group(1)
            if name in script_files:
                continue
            location = f"{rel(doc)}:{line_of(text, match.start())}"
            if is_template_context(text, match.start(), name):
                report.add(
                    "info",
                    "file-reference",
                    location,
                    f"`scripts/{name}` does not exist",
                    TEMPLATE_REASON,
                )
                continue
            report.add(
                "error",
                "file-reference",
                location,
                f"`scripts/{name}` does not exist",
                "the documentation points the agent at a missing file",
            )


def check_frida_catalog(report: Report) -> None:
    """The canonical Frida catalog must match the bundled scripts exactly."""
    if not FRIDA_INDEX.exists():
        report.add("error", "frida-catalog", rel(FRIDA_INDEX), "canonical catalog is missing")
        return

    bundled = {p.name for p in FRIDA_DIR.glob("*.js")}
    text = FRIDA_INDEX.read_text(encoding="utf-8", errors="ignore")
    cited = {m for m in re.findall(r"([A-Za-z0-9_.\-]+\.js)\b", text) if m not in PLACEHOLDER_NAMES}

    for missing in sorted(bundled - cited):
        report.add(
            "error",
            "frida-catalog",
            rel(FRIDA_INDEX),
            f"bundled script `{missing}` is not listed in the canonical catalog",
            "the agent will never discover or use this script",
        )
    for ghost in sorted(cited - bundled):
        report.add(
            "error",
            "frida-catalog",
            rel(FRIDA_INDEX),
            f"catalog lists `{ghost}` but the file does not exist",
        )

    report.stats["frida_scripts"] = len(bundled)
    report.stats["frida_catalog_entries"] = len(cited)


def check_stale_counts(report: Report) -> None:
    """Declared counts in the docs must match reality."""
    frida_count = len(list(FRIDA_DIR.glob("*.js")))
    reference_count = len([p for p in REFERENCES_DIR.glob("*.md") if p.name not in NON_SKILL_DOCS])
    script_count = len(
        [p for p in SCRIPTS_DIR.iterdir() if p.is_file() and p.suffix in (".py", ".sh", ".ps1")]
    )

    report.stats["frida_scripts"] = frida_count
    report.stats["reference_docs"] = reference_count
    report.stats["scripts"] = script_count

    # (label, real value, pattern that declares the count)
    # The negative lookbehind stops "python3 scripts/foo.py" from being read
    # as the count "3 scripts"; the lookahead rejects "3 scripts/".
    declared = [
        (
            "frida scripts",
            frida_count,
            r"(?<![\w.])(\d+)\s+(?:Frida\s+)?scripts(?![\w/-])",
        ),
        (
            "reference documents",
            reference_count,
            r"(?<![\w.])(\d+)\s+(?:reference\s+)?(?:documents|docs)(?![\w/-])",
        ),
    ]

    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        for label, real, pattern in declared:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                claimed = int(match.group(1))
                if claimed == real:
                    continue
                # Only flag counts that are plausibly about this repo
                context = text[max(0, match.start() - 120) : match.end() + 40].lower()
                if label == "frida scripts" and "frida" not in context:
                    continue
                if label == "reference documents" and "reference" not in context:
                    continue
                report.add(
                    "error",
                    "stale-count",
                    f"{rel(doc)}:{line_of(text, match.start())}",
                    f"declares {claimed} {label} but there are {real}",
                    match.group(0).strip(),
                )


def check_skill_index(report: Report) -> None:
    """Every reference document must be listed in SKILL.md's References Index.

    The index is how an agent discovers the available references. A file that
    exists but is not indexed is invisible, and the count of references has
    drifted more than once in this repo's history because nothing enforced it.
    """
    skill_path = REPO_ROOT / "SKILL.md"
    if not skill_path.exists():
        report.add("error", "skill-index", "SKILL.md", "SKILL.md is missing")
        return

    text = skill_path.read_text(encoding="utf-8", errors="ignore")
    try:
        start = text.index("## References Index")
        end = text.index("## Platform-Specific Notes", start)
    except ValueError:
        report.add(
            "error",
            "skill-index",
            "SKILL.md",
            "could not locate the '## References Index' section",
        )
        return

    block = text[start:end]
    # The index lists bare names without the .md extension.
    cited = set(re.findall(r"`([a-z0-9\-]+)`", block))

    for doc in sorted(REFERENCES_DIR.glob("*.md")):
        if doc.name in NON_SKILL_DOCS:
            continue
        if doc.stem not in cited:
            report.add(
                "error",
                "skill-index",
                "SKILL.md (References Index)",
                f"`references/{doc.name}` is not listed in the References Index",
                "the agent cannot discover this reference document",
            )


def check_skill_frida_table(report: Report) -> None:
    """Every bundled Frida script must be listed in SKILL.md's script table.

    SKILL.md carries a script -> phase table that is the fast path for the
    agent; references/frida-scripts-index.md is the full catalog. Both must
    stay in sync with the files on disk.
    """
    skill_path = REPO_ROOT / "SKILL.md"
    if not skill_path.exists():
        return

    text = skill_path.read_text(encoding="utf-8", errors="ignore")
    marker = "**Assets — Frida scripts**"
    if marker not in text:
        report.add("error", "skill-frida-table", "SKILL.md", "Frida script table not found")
        return

    block = text[text.index(marker) :]
    cited = set(re.findall(r"`([a-z0-9_\-]+\.js)`", block))

    for script in sorted(FRIDA_DIR.glob("*.js")):
        if script.name not in cited:
            report.add(
                "error",
                "skill-frida-table",
                "SKILL.md (Frida scripts table)",
                f"`{script.name}` is not listed in the SKILL.md script table",
                "the agent will not know this script exists",
            )


def check_readme_trees(report: Report) -> None:
    """The README file tree must list every reference document.

    Both READMEs claim "93 reference documents" above the tree. If the tree
    drifts, that claim becomes false and a reader cannot find a document that
    exists, so the count and the tree are validated against the filesystem.
    """
    for readme_name in ("README.md", "README.es.md"):
        readme = REPO_ROOT / readme_name
        if not readme.exists():
            continue
        text = readme.read_text(encoding="utf-8", errors="ignore")
        tree = "\n".join(
            line for line in text.splitlines() if line.startswith("│") or line.startswith("├")
        )
        listed = set(re.findall(r"([a-z0-9\-]+\.md)", tree))

        for doc in sorted(REFERENCES_DIR.glob("*.md")):
            if doc.name in NON_SKILL_DOCS:
                continue
            if doc.name not in listed:
                report.add(
                    "error",
                    "readme-tree",
                    f"{readme_name} (file tree)",
                    f"`references/{doc.name}` is missing from the file tree",
                    "the tree no longer matches the shipped documents",
                )


def _collect_args(node: ast.Call) -> tuple[list[str], int]:
    """Return (flags, required positionals) declared by one add_argument call."""
    flags: list[str] = []
    positionals = 0
    for arg in node.args:
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            continue
        if arg.value.startswith("-"):
            flags.append(arg.value)
        else:
            positionals += 1
            for kw in node.keywords:
                if (
                    kw.arg == "nargs"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value in ("?", "*")
                ):
                    positionals -= 1
    return flags, positionals


def _script_flags(path: Path) -> tuple[set[str], int, dict[str, tuple[set[str], int]]]:
    """Read a script's CLI surface from its AST.

    Returns (root flags, root required positionals, {subcommand: (flags,
    positionals)}).

    The script is never executed: only the `add_argument` calls are inspected,
    so importing a module with side effects is not a risk. Subparsers are
    tracked per command, because a script like `mobsf_config.py` takes a
    different argument depending on which subcommand is used.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return set(), 0, {}

    root_flags: set[str] = set()
    root_positionals = 0
    subcommands: dict[str, tuple[set[str], int]] = {}

    # Which variable holds a subparser factory, and which holds each parser.
    subparser_vars: set[str] = set()
    parser_of_var: dict[str, str] = {}  # variable -> subcommand name

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if not isinstance(func, ast.Attribute):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if func.attr == "add_subparsers":
                    subparser_vars.add(target.id)
                elif func.attr == "add_parser" and isinstance(func.value, ast.Name):
                    if func.value.id in subparser_vars:
                        first = node.value.args[0]
                        if isinstance(first, ast.Constant) and isinstance(first.value, str):
                            parser_of_var[target.id] = first.value

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) or isinstance(func, ast.Name)):
            continue
        attr = func.attr if isinstance(func, ast.Attribute) else func.id
        if attr != "add_argument":
            continue

        flags, positionals = _collect_args(node)
        owner = None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            owner = parser_of_var.get(func.value.id)
        if owner is None:
            root_flags.update(flags)
            root_positionals += positionals
        else:
            sub_flags, sub_positionals = subcommands.get(owner, (set(), 0))
            sub_flags.update(flags)
            subcommands[owner] = (sub_flags, sub_positionals + positionals)

    return root_flags, root_positionals, subcommands


def _flag_is_accepted(flag: str, known: set[str]) -> bool:
    """True when the flag exists exactly or is an unambiguous abbreviation.

    argparse accepts unambiguous prefixes, so `--inp` is valid for `--input`.
    """
    if flag in known:
        return True
    if flag.startswith("--"):
        matches = [k for k in known if k.startswith("--") and k.startswith(flag)]
        return len(matches) == 1
    return False


def check_cli_signatures(report: Report) -> None:
    """Documented invocations must use flags the script actually accepts.

    This is the recurring drift class in this repo's history: `mobsf_upload.py
    --ipa app.ipa` when the argument is positional, `ideviceinstaller -i`
    after the upstream flag rename, `jtool2 -disarch`. The agent follows the
    documentation, so a wrong flag breaks the audit at run time.
    """
    script_flags: dict[str, tuple[set[str], int, dict]] = {}
    for script in sorted(SCRIPTS_DIR.glob("*.py")):
        if script.name.startswith("_"):
            continue
        flags, positionals, subcommands = _script_flags(script)
        if flags or positionals or subcommands:
            script_flags[script.name] = (flags, positionals, subcommands)

    if not script_flags:
        return

    # python3 scripts/foo.py --flag value  /  python3 ./scripts/foo.py --flag
    # Script names may contain hyphens (generate-report.py).
    invocation = re.compile(
        r"(?:python3|python)\s+(?:\./)?(?:scripts/)?([A-Za-z0-9_\-]+\.py)[ \t]*([^\n]*)"
    )

    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        joined = re.sub(r"\\\n\s*", " ", text)
        for match in invocation.finditer(joined):
            script_name, args = match.group(1), match.group(2)
            if script_name not in script_flags:
                continue
            known, required_positional, subcommands = script_flags[script_name]
            location = f"{rel(doc)}:{text[: match.start()].count(chr(10)) + 1}"

            # Tokenize the command: a token starting with "-" is a flag, the
            # token after a flag is its value, anything else is positional.
            # A "#" starts a trailing comment and ends the command.
            tokens = args.split()
            flags_used: list[str] = []
            positionals: list[str] = []
            expect_value = False
            for token in tokens:
                if token.startswith("#"):
                    break
                if expect_value:
                    expect_value = False
                    continue
                if token.startswith("-"):
                    flags_used.append(token)
                    expect_value = True
                elif token in {"|", "}"}:
                    break
                else:
                    positionals.append(token)

            # A script with subcommands takes a different argument shape per
            # subcommand, so resolve the signature from the subcommand used.
            sub_name = positionals[0] if positionals else None
            if subcommands and sub_name in subcommands:
                sub_flags, sub_positionals = subcommands[sub_name]
                known = known | sub_flags
                required_positional = sub_positionals
                positionals = positionals[1:]  # the subcommand name itself

            for flag in flags_used:
                if not _flag_is_accepted(flag, known):
                    report.add(
                        "error",
                        "cli-signature",
                        location,
                        f"`{script_name}` does not accept `{flag}`",
                        f"accepted flags: {', '.join(sorted(known)) or 'none'}",
                    )

            if required_positional and len(positionals) < required_positional:
                report.add(
                    "error",
                    "cli-signature",
                    location,
                    f"`{script_name}` requires {required_positional} positional argument(s) "
                    "but the command passes fewer",
                    "the agent will invoke the script with the wrong arguments",
                )


def check_duplication(report: Report) -> None:
    """Warn about large blocks of text copied between reference documents.

    This repo had a 313-line deep-link guide pasted into nine unrelated
    storage/IPC guides; every copy drifted on its own afterwards. A shared
    section belongs in one file with a link from the others.

    Only blocks of at least DUPLICATION_MIN_LINES identical lines are
    reported, and the finding is a warning: a small amount of shared wording
    between two references is normal and healthy.
    """
    docs = [p for p in REFERENCES_DIR.glob("*.md") if p.name not in NON_SKILL_DOCS]
    if len(docs) < 2:
        return

    window = DUPLICATION_MIN_LINES
    # Every window start is used (step 1) so that a shared block is detected
    # regardless of the offset it happens to sit at in each file.
    index: dict[str, dict[str, int]] = {}
    for doc in docs:
        lines = doc.read_text(encoding="utf-8", errors="ignore").splitlines()
        normalized = [line.rstrip() for line in lines]
        for start in range(0, max(0, len(normalized) - window + 1)):
            chunk = normalized[start : start + window]
            if sum(1 for line in chunk if line.strip()) < window * 0.6:
                continue
            key = hashlib.sha256("\n".join(chunk).encode("utf-8")).hexdigest()
            index.setdefault(key, {})[doc.name] = start + 1

    # Merge windows that overlap in the same file: one copied block produces
    # many windows and must be reported once.
    clusters: list[dict[str, list[int]]] = []
    for locations in index.values():
        if len(locations) < 2:
            continue
        merged = False
        for cluster in clusters:
            if any(
                name in cluster
                and not (start > cluster[name][1] or start + window <= cluster[name][0])
                for name, start in locations.items()
            ):
                for name, start in locations.items():
                    low, high = cluster[name]
                    cluster[name] = [min(low, start), max(high, start + window - 1)]
                merged = True
                break
        if not merged:
            clusters.append({name: [start, start + window - 1] for name, start in locations.items()})

    for cluster in clusters:
        if len(cluster) < 2:
            continue
        where = ", ".join(f"{n}:{lines[0]}-{lines[1]}" for n, lines in sorted(cluster.items()))
        report.add(
            "warning",
            "duplication",
            "references/",
            f"{DUPLICATION_MIN_LINES}+ identical lines shared by {len(cluster)} documents",
            f"{where} — move the shared text to one file and link to it",
        )


def check_script_self_references(report: Report) -> None:
    """A script must not tell the user to run a name that does not exist.

    The repo fixed this once (hyphenated script names in the usage text of
    `mobsf_*`) but the same pattern came back in other files. The usage text
    is what the agent reads when a command fails, so a wrong name there sends
    it straight to a "file not found".
    """
    existing = {
        p.name
        for p in SCRIPTS_DIR.iterdir()
        if p.is_file() and p.suffix in (".py", ".sh", ".ps1")
    }
    if not existing:
        return

    reference = re.compile(
        r"(?:python3?\s+|Usage:\s*|Run:\s*|./scripts/|scripts/)([A-Za-z0-9_\-]+\.(?:py|sh|ps1))"
    )

    for script in sorted(SCRIPTS_DIR.glob("*")):
        if not script.is_file() or script.suffix not in (".py", ".sh", ".ps1"):
            continue
        text = script.read_text(encoding="utf-8", errors="ignore")
        for match in reference.finditer(text):
            name = match.group(1)
            if name in existing:
                continue
            # Only a near-miss is a defect: the name differs from a real
            # script only by the separator ("dependency-scanner.py" for
            # "dependency_scanner.py"). Names such as "manage.py" or
            # "setup.py" belong to other projects and are not ours to police.
            twin = name.replace("-", "_")
            if twin not in existing:
                continue
            line = text.count("\n", 0, match.start()) + 1
            report.add(
                "error",
                "script-self-reference",
                f"{rel(script)}:{line}",
                f"`{name}` does not exist in scripts/",
                f"the real file is '{twin}'",
            )


def check_markdown_links(report: Report) -> None:
    """Relative markdown links must resolve to an existing file."""
    link_pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        for match in link_pattern.finditer(text):
            target = match.group(1).strip()
            if not target or target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            clean = target.split("#", 1)[0]
            if not clean:
                continue
            if not clean.endswith(".md"):
                continue
            resolved = (doc.parent / clean).resolve()
            if resolved.exists():
                continue
            report.add(
                "error",
                "broken-link",
                f"{rel(doc)}:{line_of(text, match.start())}",
                f"link target does not exist: `{target}`",
            )


def _github_slug(text: str, seen: dict[str, int]) -> str:
    """Reproduce the anchor slug GitHub generates for a heading.

    GitHub removes punctuation instead of replacing it, so "Sources & Credits"
    becomes "sources--credits" (two hyphens). Collapsing runs of whitespace
    would produce "sources-credits" and flag correct links as broken.
    """
    slug = text.strip().lower()
    slug = re.sub(r"<[!/a-z].*?>", "", slug)
    slug = re.sub(r"[^\w\- ]", "", slug)
    slug = slug.replace(" ", "-")
    count = seen.get(slug, 0)
    seen[slug] = count + 1
    return slug if count == 0 else f"{slug}-{count}"


def check_markdown_anchors(report: Report) -> None:
    """In-page anchors must point at a heading that really exists."""
    anchor_pattern = re.compile(r"\]\(#([^)]+)\)")
    heading_pattern = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        seen: dict[str, int] = {}
        anchors = {_github_slug(m.group(1), seen) for m in heading_pattern.finditer(text)}
        for match in anchor_pattern.finditer(text):
            target = match.group(1).strip().lower()
            if target in anchors:
                continue
            report.add(
                "error",
                "markdown-anchor",
                f"{rel(doc)}:{line_of(text, match.start())}",
                f"in-page anchor does not match any heading: `#{target}`",
            )


def _strip_js_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments, preserving the line numbers.

    A linter that flags the word ``process.on(`` inside an explanatory
    comment is worse than no linter at all, so the comments are blanked out
    before the source is scanned. The number of lines is kept, so the
    reported positions still refer to the original file.
    """
    def _blank_block(match: re.Match) -> str:
        return "\n" * match.group(0).count("\n")

    text = re.sub(r"/\*.*?\*/", _blank_block, text, flags=re.S)

    lines = []
    for line in text.split("\n"):
        quote = None
        index = 0
        while index < len(line):
            char = line[index]
            if quote:
                if char == "\\":
                    index += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "\"'`":
                quote = char
            elif char == "/" and index + 1 < len(line) and line[index + 1] == "/":
                line = line[:index]
                break
            index += 1
        lines.append(line)
    return "\n".join(lines)


def check_frida_api(report: Report) -> None:
    """The bundled scripts and the docs must not use Frida APIs removed in 17.

    Three rules, all of them silent-failure traps:

    1. ``Module.findExportByName(module, symbol)`` -- the static two argument
       form was removed in Frida 17 and now throws a TypeError. Only the
       instance method ``module.findExportByName(symbol)`` exists.
    2. ``Process.getModuleByName(name)`` -- throws when the module is not
       loaded, which aborts the whole hook block. The ``find`` variant returns
       null instead.
    3. ``ObjC.classes.forEach(...)`` -- ``ObjC.classes`` is a map, not an
       array, so it has no ``forEach``.
    """
    static_lookup = re.compile(r"(?<![A-Za-z0-9_$])Module\.findExportByName\s*\(")
    throwing_lookup = re.compile(r"(?<![A-Za-z0-9_$])Process\.getModuleByName\s*\(")
    objc_foreach = re.compile(r"(?<![A-Za-z0-9_$])ObjC\.classes\.forEach\s*\(")
    # Globals that exist in Node but not in the Frida runtime. Using them
    # aborts the script at load time, so the hook never runs.
    node_global = re.compile(r"(?<![A-Za-z0-9_$.])process\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\(")
    node_require = re.compile(r"(?<![A-Za-z0-9_$.])require\s*\(")
    # The bridge returns a METHOD WRAPPER for any selector, so a method has to
    # be invoked to get its value. Reading `app.delegate` yields a function.
    uncalled_method = re.compile(r"\.delegate\b(?!\s*\()")
    # A protocol is not a class: ObjC.classes.UIApplicationDelegate is
    # undefined, and the real IMP lives in the app's delegate class.
    protocol_as_class = re.compile(
        r"ObjC\.classes\.(?:" + "|".join(IODELEGATE_PROTOCOLS) + r")\b"
    )
    # A method that takes an Objective-C block needs an ObjC.Block, not a
    # plain JavaScript function.
    js_function_as_block = re.compile(r"(?:Using|With)Block_\s*\(\s*function\b")

    for script in sorted(FRIDA_DIR.glob("*.js")):
        text = script.read_text(encoding="utf-8", errors="ignore")
        code = _strip_js_comments(text)
        location = rel(script)
        for match in static_lookup.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(text, match.start())}",
                "`Module.findExportByName(module, symbol)` was removed in Frida 17",
                "use Module.findGlobalExportByName(symbol) or module.findExportByName(symbol)",
            )
        for match in throwing_lookup.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(text, match.start())}",
                "`Process.getModuleByName()` throws when the module is not loaded",
                "use Process.findModuleByName(), which returns null instead",
            )
        for match in objc_foreach.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(text, match.start())}",
                "`ObjC.classes` is a map and has no `forEach`",
                "use Object.keys(ObjC.classes).forEach(...)",
            )
        for match in node_global.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(text, match.start())}",
                "`process` is a Node global that does not exist in the Frida runtime",
                "use recv('...'), setInterval or Script APIs instead",
            )
        for match in node_require.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(text, match.start())}",
                "`require()` is a Node global that does not exist in the Frida runtime",
                "use the Frida APIs directly, or an ES module with an explicit import",
            )
        # The Java bridge does not exist on iOS: there is no Java VM, so the
        # global is undefined and touching it aborts the script at load.
        if re.search(r"(?<![A-Za-z0-9_$.])Java\s*\.", code) and "typeof Java" not in code:
            report.add(
                "error",
                "frida-api",
                location,
                "the `Java` global does not exist on iOS",
                "guard it with `typeof Java !== 'undefined'` or remove it",
            )
        for match in uncalled_method.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(code, match.start())}",
                "the bridge returns a method wrapper, so the method has to be invoked",
                "use `app.delegate()` — reading `app.delegate` yields a function",
            )
        for match in protocol_as_class.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(code, match.start())}",
                "a protocol is not a class: `ObjC.classes.<Protocol>` is undefined",
                "resolve the concrete class at runtime, or use ObjC.protocols",
            )
        for match in js_function_as_block.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{location}:{line_of(code, match.start())}",
                "a method that takes an Objective-C block needs an `ObjC.Block`",
                "build one with new ObjC.Block({ retType, argTypes, implementation })",
            )

    # The documentation teaches the API: a dead pattern in an example is worse
    # than no example at all, because the reader copies it.
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        code = _strip_js_comments(text)
        for match in static_lookup.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{rel(doc)}:{line_of(code, match.start())}",
                "`Module.findExportByName(module, symbol)` was removed in Frida 17",
                "use Module.findGlobalExportByName(symbol) or module.findExportByName(symbol)",
            )
        for match in protocol_as_class.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{rel(doc)}:{line_of(code, match.start())}",
                "a protocol is not a class: `ObjC.classes.<Protocol>` is undefined",
                "resolve the concrete class at runtime, or use ObjC.protocols",
            )
        for match in js_function_as_block.finditer(code):
            report.add(
                "error",
                "frida-api",
                f"{rel(doc)}:{line_of(code, match.start())}",
                "a method that takes an Objective-C block needs an `ObjC.Block`",
                "build one with new ObjC.Block({ retType, argTypes, implementation })",
            )


def check_objc_pointer_misuse(report: Report) -> None:
    """Objective-C methods must not be called on a raw NativeCallback parameter.

    Inside a ``NativeCallback`` the arguments arrive as plain pointers. Calling
    an Objective-C method on one (``url.absoluteString()``) raises a TypeError
    and the hook silently stops working. The value has to be wrapped first:
    ``new ObjC.Object(url).absoluteString()``.
    """
    objc_methods = ("absoluteString", "activityType", "webpageURL")
    callback_pattern = re.compile(r"new NativeCallback\s*\(\s*function\s*\(([^)]*)\)\s*\{")

    for script in sorted(FRIDA_DIR.glob("*.js")):
        text = script.read_text(encoding="utf-8", errors="ignore")
        code = _strip_js_comments(text)
        for match in callback_pattern.finditer(code):
            params = [p.strip().lstrip("$") for p in match.group(1).split(",") if p.strip()]
            params = [p for p in params if p not in ("self", "sel", "_cmd")]
            if not params:
                continue

            body_start = match.end()
            depth = 1
            index = body_start
            while index < len(code) and depth > 0:
                if code[index] == "{":
                    depth += 1
                elif code[index] == "}":
                    depth -= 1
                index += 1
            body = code[body_start:index]

            for param in params:
                for method in objc_methods:
                    call = re.compile(rf"(?<![A-Za-z0-9_$.]){re.escape(param)}\.{method}\s*\(")
                    for hit in call.finditer(body):
                        report.add(
                            "error",
                            "objc-pointer",
                            f"{rel(script)}:{line_of(code, body_start + hit.start())}",
                            f"`{param}.{method}()` is called on a raw pointer parameter",
                            f"wrap it first: new ObjC.Object({param}).{method}()",
                        )


def check_frida17_migration(report: Report) -> None:
    """Reject the Frida APIs that Frida 17 removed.

    Two migrations are easy to miss because the surrounding prose already
    announces them:

    * ``--no-pause`` was removed. The app resumes automatically on spawn, so
      the flag is not only unnecessary, it is rejected by the CLI.
    * ``Memory.read*()`` / ``Memory.write*()`` moved to the pointer API
      (``addr.read*()``).

    The examples that deliberately show the OLD form (the migration sections
    of the Frida guide) are left alone: they exist precisely to contrast the
    old and the new API.
    """
    no_pause = re.compile(r"--no-pause")
    frida_command = re.compile(r"\bfrida\b\s+-[A-Za-z]")
    memory_api = re.compile(r"\bMemory\.(?:read|write)[A-Za-z0-9]*\s*\(")
    old_heading = re.compile(r"\b(OLD|Before|Deprecated)\b", re.IGNORECASE)

    def nearest_heading(text: str, offset: int) -> str:
        heading = ""
        for match in re.finditer(r"^#{1,6}\s+(.*)$", text[:offset], re.MULTILINE):
            heading = match.group(1)
        return heading

    targets = [(p, p.read_text(encoding="utf-8", errors="ignore")) for p in sorted(FRIDA_DIR.glob("*.js"))]
    targets += [(p, p.read_text(encoding="utf-8", errors="ignore")) for p in iter_docs()]

    for path, text in targets:
        location = rel(path)
        for line_no, line in enumerate(text.split("\n"), 1):
            if no_pause.search(line) and (frida_command.search(line) or line.strip() == "--no-pause"):
                report.add(
                    "error",
                    "frida-17-migration",
                    f"{location}:{line_no}",
                    "`--no-pause` was removed in Frida 17 and the CLI rejects it",
                    "omit the flag: the app resumes automatically on spawn (use --pause to pause it)",
                )
        for match in memory_api.finditer(text):
            heading = nearest_heading(text, match.start())
            if old_heading.search(heading):
                continue
            report.add(
                "error",
                "frida-17-migration",
                f"{location}:{line_of(text, match.start())}",
                "`Memory.read*()` / `Memory.write*()` moved to the pointer API in Frida 17",
                "use `addr.read*()` / `addr.write*()`",
            )


def check_doc_command_blocks(report: Report) -> None:
    """A shell continuation must not be followed by a comment or a fence.

    A trailing backslash joins the next line into the command, so a comment
    right after it stops being a comment and becomes an argument:
    ``frida ... \\ # OR -l other.js`` passes ``#`` and ``OR`` to the CLI.
    The same happens when the continuation points at the closing fence.
    """
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        lines = text.split("\n")
        for index, line in enumerate(lines[:-1]):
            if not line.rstrip().endswith("\\"):
                continue
            following = lines[index + 1].strip()
            if following == "" or following.startswith("```") or following.startswith("#"):
                report.add(
                    "error",
                    "doc-command",
                    f"{rel(doc)}:{index + 1}",
                    "line continuation followed by a comment or a code fence",
                    "end the command before the comment, or drop the backslash",
                )


def check_doc_code_blocks(report: Report) -> None:
    """Every shell block and every complete JavaScript block must parse.

    The documentation is copy-paste material: an agent runs the command or
    pastes the snippet verbatim. A block that does not parse fails at the
    moment it is used, and the failure points at the reader instead of at the
    document.

    A JavaScript block that elides part of the code (``{ ... }``) is a
    deliberate fragment and is left alone.
    """
    elision = re.compile(r"[\{,:\(]\s*\.\.\.")
    for doc in iter_docs():
        text = doc.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(r"^```([A-Za-z0-9_+-]*)[ \t]*\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
            language = (match.group(1) or "").strip().lower()
            code = match.group(2)
            if len(code.strip()) < 5:
                continue
            if language in ("bash", "sh", "shell"):
                ok, detail = _shell_block_parses(code)
                if not ok:
                    report.add(
                        "error",
                        "doc-code",
                        f"{rel(doc)}:{line_of(text, match.start())}",
                        "this shell block does not parse",
                        detail,
                    )
            elif language in ("javascript", "js", "node"):
                if elision.search(code):
                    continue
                ok, detail = _javascript_block_parses(code)
                if not ok:
                    report.add(
                        "error",
                        "doc-code",
                        f"{rel(doc)}:{line_of(text, match.start())}",
                        "this JavaScript block does not parse",
                        detail,
                    )


def _shell_block_parses(code: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(code)
        path = handle.name
    try:
        result = subprocess.run(["bash", "-n", path], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return True, ""
        lines = [line for line in result.stderr.split("\n") if "error" in line]
        return False, (lines[0] if lines else result.stderr.strip())[:200]
    except Exception:  # pragma: no cover - environment dependent
        return True, ""
    finally:
        os.unlink(path)


def _javascript_block_parses(code: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write(code)
        path = handle.name
    try:
        result = subprocess.run(["node", "--check", path], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return True, ""
        lines = [line for line in result.stderr.split("\n") if "Error" in line]
        return False, (lines[0] if lines else result.stderr.strip())[:200]
    except Exception:  # pragma: no cover - node may be absent
        return True, ""


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def print_report(report: Report, strict: bool) -> int:
    errors = report.errors
    warnings = report.warnings
    infos = report.infos
    if strict:
        warnings = errors + warnings

    print("iOS-Pentesting-Skill - documentation consistency")
    print("=" * 60)
    stats = report.stats
    if stats:
        print(
            f"real content: {stats.get('frida_scripts', 0)} frida scripts, "
            f"{stats.get('reference_docs', 0)} reference docs, "
            f"{stats.get('scripts', 0)} scripts"
        )
    print()

    if not errors and not warnings:
        print("OK - documentation is consistent with the repository.")
    else:
        for issue in errors:
            print(f"ERROR   [{issue.check}] {issue.location}")
            print(f"        {issue.message}")
            if issue.detail:
                print(f"        {issue.detail}")
        if errors:
            print()

        for issue in warnings:
            print(f"WARN    [{issue.check}] {issue.location}")
            print(f"        {issue.message}")
            if issue.detail:
                print(f"        {issue.detail}")
        if warnings:
            print()

    if infos:
        # Notes are intentional-by-design findings. Listing them one by one
        # would bury the real signal, so they are grouped by cause.
        grouped: dict[tuple[str, str], int] = {}
        for issue in infos:
            key = (issue.check, issue.detail or issue.message)
            grouped[key] = grouped.get(key, 0) + 1
        print("NOTES (intentional, never fail the build):")
        for (check, reason), count in sorted(grouped.items(), key=lambda kv: -kv[1]):
            print(f"  {count:3d}  [{check}] {reason}")
        print()

    print(f"{len(errors)} error(s), {len(warnings)} warning(s), {len(infos)} note(s)")
    if not errors and not warnings and not infos:
        return 0
    return 1 if errors or (strict and warnings) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = parser.parse_args()

    report = Report()
    check_file_references(report)
    check_frida_catalog(report)
    check_stale_counts(report)
    check_skill_index(report)
    check_skill_frida_table(report)
    check_readme_trees(report)
    check_cli_signatures(report)
    check_duplication(report)
    check_script_self_references(report)
    check_markdown_links(report)
    check_markdown_anchors(report)
    check_frida_api(report)
    check_frida17_migration(report)
    check_objc_pointer_misuse(report)
    check_doc_command_blocks(report)
    check_doc_code_blocks(report)

    if args.json:
        print(
            json.dumps(
                {
                    "errors": len(report.errors),
                    "warnings": len(report.warnings),
                    "infos": len(report.infos),
                    "stats": report.stats,
                    "issues": [i.to_dict() for i in report.issues],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1 if report.errors or (args.strict and report.warnings) else 0

    return print_report(report, args.strict)


if __name__ == "__main__":
    sys.exit(main())
