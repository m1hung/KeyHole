#!/usr/bin/env python3
"""Patch XcodeGen output: link local SPM product deps to their package reference.

XcodeGen omits `package = ...` on XCSwiftPackageProductDependency entries for
XCLocalSwiftPackageReference, which makes Xcode report "Missing package product".
See https://github.com/yonaskolb/XcodeGen/issues/1549
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fix_pbxproj(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")

    local_ref_match = re.search(
        r"(\w+) /\* XCLocalSwiftPackageReference \"[^\"]*\" \*/ = \{\s*\n"
        r"\s*isa = XCLocalSwiftPackageReference;",
        text,
    )
    if not local_ref_match:
        return False

    package_ref = local_ref_match.group(1)
    changed = False

    def patch_dependency(match: re.Match[str]) -> str:
        nonlocal changed
        block = match.group(0)
        if "package =" in block:
            return block
        changed = True
        header, product_line, footer = match.groups()
        return (
            f"{header}"
            f"\t\t\tpackage = {package_ref} /* XCLocalSwiftPackageReference */;\n"
            f"{product_line}{footer}"
        )

    pattern = re.compile(
        r"(\t\t\w+ /\* \w+ \*/ = \{\n"
        r"\t\t\tisa = XCSwiftPackageProductDependency;\n)"
        r"(\t\t\tproductName = [^;]+;\n)"
        r"(\t\t\};)",
        re.MULTILINE,
    )

    new_text = pattern.sub(patch_dependency, text)
    if changed:
        path.write_text(new_text, encoding="utf-8")
    return changed


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    pbxproj = script_dir.parent / "Keyhole.xcodeproj" / "project.pbxproj"
    if not pbxproj.is_file():
        print(f"fix-local-package-backlinks: {pbxproj} not found", file=sys.stderr)
        return 1
    if fix_pbxproj(pbxproj):
        print("fix-local-package-backlinks: patched local package product backlinks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
