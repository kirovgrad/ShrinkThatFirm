from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from .models import CollectedFile, FileGroup


def find_duplicate_files(files: Sequence[CollectedFile]) -> list[FileGroup]:
    by_hash: dict[str, list[CollectedFile]] = defaultdict(list)
    for f in files:
        by_hash[f.md5].append(f)

    groups: list[FileGroup] = []
    for digest, members in by_hash.items():
        if len(members) < 2:
            continue
        # Identical hashes imply identical content and size.
        groups.append(
            FileGroup(
                md5=digest,
                file_size=members[0].size,
                paths=tuple(f.path for f in members),
            )
        )

    return sorted(groups, key=lambda g: g.wasted, reverse=True)
