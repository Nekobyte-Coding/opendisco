"""Checks the app's translations (src/opendisco/resources/locale/*.json) against the code.

Lists every text the code wraps for translation (_(), tr() and N_() with a literal English text)
and reports, for each catalog, the texts it lacks, the ones the code no longer has, and
translations whose {placeholders} differ from the English. Also catches wrapped f-strings and
functions where a local _ (a throwaway variable) would hide the translation function.

  python3 packaging/i18n_check.py                 check every catalog (exit status 1 on a problem)
  python3 packaging/i18n_check.py --list          every wrapped text, with where it's used
  python3 packaging/i18n_check.py --missing ja    the texts ja.json lacks, as JSON (for translating)
  python3 packaging/i18n_check.py --prune         drop the texts the code no longer has
"""
from __future__ import annotations

import argparse
import ast
import json
import string
import symtable
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "opendisco"
LOCALE = PACKAGE / "resources" / "locale"
WRAPPERS = ("_", "tr", "N_")
LANGUAGES = ("es", "pt-BR", "ja")


def _name(func) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "i18n":
        return func.attr
    return None


def wrapped() -> tuple[dict, list]:
    """Every wrapped text -> where it's used, and the problems found in the code."""
    texts, problems = {}, []
    for path in sorted(PACKAGE.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, str(path))
        where = path.relative_to(ROOT)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _name(node.func) in WRAPPERS and node.args):
                continue
            first = node.args[0]
            if isinstance(first, ast.JoinedStr):
                problems.append(f"{where}:{node.lineno}: an f-string in {_name(node.func)}(): use tr() with "
                                "named values")
            elif isinstance(first, ast.Constant) and isinstance(first.value, str):
                texts.setdefault(first.value, []).append(f"{where}:{node.lineno}")
                if _name(node.func) == "_" and len(node.args) > 1:
                    problems.append(f"{where}:{node.lineno}: _() takes one text")
            elif _name(node.func) == "tr":
                problems.append(f"{where}:{node.lineno}: tr() with a template that isn't a literal text")
        if path.name != "i18n.py":  # (where they're defined)
            problems += _shadowed(source, where)
    return texts, problems


def _shadowed(source: str, where) -> list:
    """Scopes that assign _, tr or N_ (a throwaway, a loop variable) and also call it for a
    translation, and a module that rebinds one of them for every function in it."""
    found = []
    tree = ast.parse(source)
    calls = {}  # (scope's first line, name) for each scope's own calls
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id in WRAPPERS:
                    calls.setdefault((node.lineno, inner.func.id), []).append(inner.lineno)

    def visit(table):
        for name in WRAPPERS:
            try:
                symbol = table.lookup(name)
            except KeyError:
                continue
            if table.get_type() == "module" and symbol.is_assigned() and not symbol.is_imported():
                found.append(f"{where}: the module assigns {name}, hiding the translation function")
            elif table.get_type() == "function" and (table.get_lineno(), name) in calls and symbol.is_assigned():
                found.append(f"{where}:{table.get_lineno()}: {table.get_name()}() assigns {name} and calls {name}(): "
                             "rename the variable")
        for child in table.get_children():
            visit(child)

    visit(symtable.symtable(source, str(where), "exec"))
    return found


def fields(text: str) -> set:
    """A template's placeholders, with their format specs."""
    try:
        return {(name, spec) for _, name, spec, _ in string.Formatter().parse(text) if name is not None}
    except ValueError:
        return {("<not a valid template>", "")}


def load(code: str) -> dict:
    path = LOCALE / f"{code}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save(code: str, catalog: dict) -> None:
    (LOCALE / f"{code}.json").write_text(json.dumps(catalog, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def check(texts: dict, code: str) -> list:
    catalog = load(code)
    problems = []
    for text in texts:
        if not catalog.get(text):
            problems.append(f"{code}: missing: {text!r} ({texts[text][0]})")
        elif fields(catalog[text]) != fields(text):
            problems.append(f"{code}: placeholders differ: {text!r} -> {catalog[text]!r}")
    problems += [f"{code}: no longer in the code: {text!r}" for text in catalog
                 if text not in texts and not text.startswith("@")]
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the app's translations against the code.")
    parser.add_argument("--list", action="store_true", help="print every wrapped text and where it's used")
    parser.add_argument("--missing", metavar="LANG", help="print the texts LANG's catalog lacks, as JSON")
    parser.add_argument("--prune", action="store_true", help="drop the texts the code no longer has")
    args = parser.parse_args()
    texts, problems = wrapped()
    if args.list:
        for text, where in sorted(texts.items(), key=lambda item: item[1][0]):
            print(f"{', '.join(where)}\n  {text!r}")
        print(f"{len(texts)} texts")
        return 0
    if args.missing:
        catalog = load(args.missing)
        missing = {text: where for text, where in texts.items() if not catalog.get(text)}
        json.dump(missing, sys.stdout, ensure_ascii=False, indent=1)
        print()
        return 0
    if args.prune:
        for code in LANGUAGES:
            catalog = load(code)
            save(code, {k: v for k, v in catalog.items() if k in texts or k.startswith("@")})
    for code in LANGUAGES:
        problems += check(texts, code)
    for problem in problems:
        print(problem)
    print(f"{len(texts)} texts; " + ("all catalogs complete" if not problems else f"{len(problems)} problems"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
