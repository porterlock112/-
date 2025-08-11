"""Simple file organizer.

This script moves documents into a ``Filed/`` directory based on extension.
It also detects keywords related to U.S. federal civil-rights filings and
places those documents into a special ``federal_us_civil_rights`` folder.
"""

import argparse
import os
import shutil
from typing import Iterable


EXTENSIONS = [
    "pdf",
    "tiff",
    "jpg",
    "png",
    "csv",
    "zip",
    "tax2021",
    "txt",
]

# Keywords that indicate a federal civil-rights filing
CIVIL_RIGHTS_KEYWORDS = [
    "42 usc 1983",
    "civil_rights",
    "civil-rights",
    "federal binder",
]


def detect_civil_rights(name: str, keywords: Iterable[str]) -> bool:
    """Return True if any keyword appears in ``name`` (case-insensitive)."""

    low = name.lower()
    return any(k.lower() in low for k in keywords)


def organize(root: str, dest: str, dry_run: bool = False) -> None:
    """Organize files under ``root`` into ``dest``.

    Files are grouped by extension, with a special folder for items that
    appear to be U.S. federal civil-rights filings.
    """

    os.makedirs(dest, exist_ok=True)
    skip = {".git", ".github", os.path.basename(__file__), os.path.basename(dest)}

    for name in os.listdir(root):
        if name in skip:
            continue
        src_path = os.path.join(root, name)
        if not os.path.isfile(src_path):
            continue

        ext = os.path.splitext(name)[1].lower().lstrip(".")
        if not ext:
            continue

        if detect_civil_rights(name, CIVIL_RIGHTS_KEYWORDS):
            dest_dir = os.path.join(dest, "federal_us_civil_rights")
        elif ext in EXTENSIONS:
            dest_dir = os.path.join(dest, ext)
        else:
            dest_dir = os.path.join(dest, "other")

        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, name)

        if dry_run:
            print(f"[dry-run] Move {name} -> {dest_dir}")
        else:
            if not os.path.exists(dest_path):
                shutil.move(src_path, dest_path)
                print(f"Moved {name} -> {dest_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Organize files by extension")
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="directory containing files to organize",
    )
    parser.add_argument(
        "--dest",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "Filed"),
        help="destination directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show moves without modifying the filesystem",
    )
    args = parser.parse_args()

    organize(args.root, args.dest, args.dry_run)


if __name__ == "__main__":  # pragma: no cover - simple CLI entry point
    main()

