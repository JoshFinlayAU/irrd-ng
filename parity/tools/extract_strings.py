"""Catalogue the user-facing strings in the pinned IRRd v4 source.

Walks every non-test, non-web-UI module under vendor/irrd-v4/irrd and writes
one TSV row per string literal or f-string that reaches a user, an operator or
a mail: anything raised, logged, appended to an error list, returned, or
assigned to a message-like name. f-strings keep their placeholders as {expr}.

Usage: python3 -I parity/tools/extract_strings.py vendor/irrd-v4 > parity/reference/v4-strings.tsv
"""

import ast
import sys
from pathlib import Path

SINKS = {"append", "error", "warning", "info", "debug", "critical", "exception", "add_error", "add_info", "add_warning"}


def render(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(v.value)
            else:
                parts.append("{" + ast.unparse(v.value) + "}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = render(node.left), render(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def kind_of(parent):
    if isinstance(parent, ast.Raise):
        return "raise"
    if isinstance(parent, ast.Return):
        return "return"
    if isinstance(parent, ast.Call):
        f = parent.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        if name in SINKS:
            return name
        if name.endswith(("Exception", "Error")):
            return "raise"
    return None


def main(root):
    base = Path(root)
    for path in sorted((base / "irrd").rglob("*.py")):
        rel = path.relative_to(base)
        if "tests" in rel.parts or rel.parts[1] in {"webui", "vendor", "integration_tests"} or "alembic" in rel.parts:
            continue
        tree = ast.parse(path.read_text(), str(rel))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        seen = set()
        for node in ast.walk(tree):
            text = render(node)
            if text is None or len(text.strip()) < 4 or id(node) in seen:
                continue
            if isinstance(parents.get(node), (ast.BinOp, ast.JoinedStr)):
                continue
            p = parents.get(node)
            kind = kind_of(p)
            if kind is None and isinstance(p, ast.Call):
                kind = kind_of(parents.get(p))
            if kind is None:
                continue
            seen.add(id(node))
            esc = text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
            print(f"{rel}\t{node.lineno}\t{kind}\t{esc}")


if __name__ == "__main__":
    print("file\tline\tkind\ttext")
    main(sys.argv[1])
