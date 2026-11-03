#!/usr/bin/env python3
"""Fails if a dependency of the shipped binary uses a licence the project does not accept.

Reads `cargo metadata`, looks at every package that is not a workspace member and checks each
SPDX expression: an OR expression passes if at least one alternative is accepted, an AND
expression needs every part accepted. Accepted: permissive licences plus MPL-2.0 (file-level
copyleft, fine for linking). Rejected: GPL/AGPL/LGPL families, SSPL, unknown or missing licences.

    python scripts/check-licenses.py            # prints a table, exit 1 on a problem
"""
import json
import re
import subprocess
import sys

ACCEPT = {
    "MIT", "MIT-0", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unicode-3.0", "Unicode-DFS-2016", "Zlib", "0BSD", "CC0-1.0", "Unlicense", "MPL-2.0",
    "BSL-1.0", "OpenSSL", "NCSA", "CDLA-Permissive-2.0",
}


def ok(expr):
    expr = expr.replace("/", " OR ")
    # split on OR at the top level (parentheses are rare in crates.io licences; handle simply)
    def eval_and(part):
        part = part.strip().strip("()")
        terms = [t.strip().strip("()") for t in re.split(r"\s+AND\s+", part)]
        return all(t in ACCEPT or t.replace(" WITH LLVM-exception", "") in ACCEPT for t in terms)
    alternatives = re.split(r"\s+OR\s+", expr)
    return any(eval_and(a) for a in alternatives)


def main():
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked"]))
    members = set(meta["workspace_members"])
    bad, seen = [], {}
    for p in meta["packages"]:
        if p["id"] in members:
            continue
        lic = p.get("license") or ""
        seen.setdefault(lic or "(none)", []).append(p["name"])
        if not lic or not ok(lic):
            bad.append((p["name"], p["version"], lic or "(none)"))
    for lic, names in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        print(f"{len(names):4}  {lic}")
    if bad:
        print("\nNOT ACCEPTED:")
        for b in bad:
            print("  %s %s: %s" % b)
        sys.exit(1)
    print(f"\n{sum(len(v) for v in seen.values())} dependencies, all licences accepted")


if __name__ == "__main__":
    main()
