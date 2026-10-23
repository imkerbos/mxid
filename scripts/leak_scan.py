#!/usr/bin/env python3
"""Refuse content that must not be published from this repository.

One implementation for three callers, because three implementations means three
different answers to the same question:

    leak_scan.py tree [<range>]      working tree, plus what a push adds
    leak_scan.py remote <url>...     what a stranger can actually clone

Rules come from hack/internal-data-patterns.txt (ships here; shapes only) and
hack/internal-data-patterns.local.txt (this machine's actual strings, kept out
by .gitignore — publishing the list would publish what it protects).

Python's `re` rather than grep, deliberately. The rules use lookbehind, which
`grep -E` rejects outright: an earlier shell version printed "OK" while every
one of those rules was erroring out unseen. A check that cannot fail is not a
check. For the same reason an empty rule set is an error here, not a pass — the
2026-10 disclosure happened with the hooks running and reporting success,
against a repository that had no rule file at all.

Findings report where, never what: an audit report quoting the string is one
more copy of it.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

RULE_FILES = ("hack/internal-data-patterns.txt",
              "hack/internal-data-patterns.local.txt")
RED, DIM, OFF = "\033[31m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    RED = DIM = OFF = ""


def repo_root():
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    return Path(out.stdout.strip() or ".")


def load_rules(root):
    rules = []
    for name in RULE_FILES:
        p = root / name
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            rule_name, rest = line.split("|", 1)
            skip = None
            if "|skip=" in rest:
                rest, _, skip_src = rest.rpartition("|skip=")
                skip = re.compile(skip_src)
            try:
                rules.append((rule_name, re.compile(rest, re.I), skip))
            except re.error as e:
                print(f"{RED}规则无法编译{OFF} {rule_name}: {e}", file=sys.stderr)
                sys.exit(2)
    if not rules:
        print(f"{RED}没有任何规则，拒绝以空检查冒充通过{OFF}", file=sys.stderr)
        sys.exit(2)
    return rules


def git(*args, cwd=None):
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          errors="replace", cwd=cwd).stdout


def report(found, rule, where, extra=""):
    print(f"    {RED}✗ {rule}{OFF}  {where}{extra}")
    found.append(rule)


def scan_tree(root, rules, rng):
    found = []
    for rel in git("ls-files", cwd=root).splitlines():
        p = root / rel
        if not p.is_file():
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:8192]:          # binary: a Go binary carries key headers
            continue
        text = raw.decode("utf-8", "replace")
        for name, pat, skip in rules:
            if skip and skip.search(rel):
                continue
            m = pat.search(text)
            if m:
                line = text[:m.start()].count("\n") + 1
                report(found, name, rel, f" 第 {line} 行")

    if rng:
        # Walk each commit rather than diffing the endpoints: a name added and
        # then removed leaves nothing in the net diff but stays in the history.
        diff = git("log", "-p", "--unified=0", "--no-color", "--format=%n@@C %H", rng, cwd=root)
        added, path = [], "(待推送)"
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                path = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                added.append((path, line[1:]))
        for name, pat, skip in rules:
            for path, text in added:
                if skip and skip.search(path):
                    continue
                if pat.search(text):
                    report(found, name, f"{path}（待推送的新增行）")
                    break
        msgs = git("log", "--format=%B", rng, cwd=root)
        for name, pat, skip in rules:
            if pat.search(msgs):
                report(found, name, "待推送的提交信息")
    return found


def scan_remote(rules, urls):
    found = []
    with tempfile.TemporaryDirectory() as work:
        for url in urls:
            print(f"--- {url}")
            dest = Path(work) / re.sub(r"\W+", "_", url)
            # --mirror brings every ref the server advertises, refs/pull/*
            # included. Those are what a force-push cannot reach.
            if subprocess.run(["git", "clone", "--mirror", "-q", url, str(dest)],
                              capture_output=True).returncode != 0:
                print("    跳过：克隆不下来（私有或不存在）")
                continue
            refs = [r for r in git("for-each-ref", "--format=%(refname)", cwd=dest).splitlines() if r]
            n_pull = sum(1 for r in refs if r.startswith("refs/pull/"))
            print(f"    {len(refs)} 个 ref（PR ref {n_pull} 个）")

            for name, pat, skip in rules:
                for ref in refs:
                    out = subprocess.run(
                        ["git", "-C", str(dest), "grep", "-I", "-l", "-P", "-i", pat.pattern, ref],
                        capture_output=True, text=True, errors="replace")
                    for line in out.stdout.splitlines():
                        if ":" not in line:
                            continue
                        path = line.split(":", 1)[1]
                        if skip and skip.search(path):
                            continue
                        mark = "  ← PR ref（强推清不掉）" if ref.startswith("refs/pull/") else ""
                        report(found, name, f"{path}  {ref}", mark)
            msgs = git("log", "--all", "--format=%H %s %b", cwd=dest)
            for name, pat, skip in rules:
                if pat.search(msgs):
                    report(found, name, "提交信息")
    return found


def main():
    root = repo_root()
    rules = load_rules(root)
    mode = sys.argv[1] if len(sys.argv) > 1 else "tree"

    if mode == "remote":
        urls = sys.argv[2:]
        if not urls:
            urls = sorted({
                re.sub(r"^git@github\.com:", "https://github.com/", l.split()[1])
                for l in git("remote", "-v", cwd=root).splitlines() if "(fetch)" in l
            })
        print(f"==> remote-audit: {len(rules)} 条规则，{len(urls)} 个远端")
        found = scan_remote(rules, urls)
        if found:
            print(f"\n远端仍可取到上述内容。PR ref 用强推清不掉，只有删库重建能去掉。")
            return 1
        print("✓ remote-audit OK")
        return 0

    rng = sys.argv[2] if len(sys.argv) > 2 else ""
    print(f"==> leak-scan: {len(rules)} 条规则")
    found = scan_tree(root, rules, rng)
    if found:
        print(f"{DIM}修掉它，不要绕过检查。{OFF}")
        return 1
    print("✓ leak-scan OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
