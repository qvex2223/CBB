#!/usr/bin/env python3
"""
funnel.py — one definition of "an item in a funnel tier".

`leads/`, `primitives/` and `findings/` hold two layouts at once: a flat `<slug>.md`, and
a folder per item holding its write-up next to its evidence. Every counter and every queue
in this workspace had to decide what counts, and they decided differently:

  * `lead_queue.scan` globbed `*.md` only, so no folder-form item ever entered the queue
    the lanes are picked from — 9 of them on disk, 10 of yukki-lk's 22 primitives;
  * `stop_gate._tier_item_files` looked for `<slug>/README.md`, which is 4 of those 9;
  * both counted a tier's own `README.md` — the tier's instructions — as an item, and on
    rowi one of three lanes was briefed to hunt `primitives/README.md`.

Measured 2026-11-13. A count is only as good as where it looked, so the rule lives here
and both read it from here.

The write-up of a folder-form item, in order: `README.md`, else `<folder-name>.md`, else
the single `.md` in the folder. A folder with several and none of those names is not an
item — `leads/refuted/` holds two closed write-ups — and is skipped rather than guessed
at, because guessing would brief a worker to attack an archive.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, List

TIERS = ("findings", "primitives", "leads")


def item_write_up(folder: Path) -> Path | None:
    """The one file that IS this folder-form item, or None when the folder is not one."""
    readme = folder / "README.md"
    if readme.is_file():
        return readme
    named = folder / f"{folder.name}.md"
    if named.is_file():
        return named
    mds = [p for p in sorted(folder.glob("*.md")) if p.is_file()]
    return mds[0] if len(mds) == 1 else None


def tier_items(tier_dir: Path) -> Iterator[Path]:
    """Every item in one tier, flat and folder-form, in a stable order.

    A tier's own `README.md` is its instructions and is never an item. A folder-form
    item's own `README.md` is its write-up and always is.
    """
    if not tier_dir.is_dir():
        return
    for f in sorted(tier_dir.glob("*.md")):
        if f.name.lower() != "readme.md":
            yield f
    try:
        subs = sorted(p for p in tier_dir.iterdir() if p.is_dir())
    except OSError:
        return
    for sub in subs:
        got = item_write_up(sub)
        if got is not None:
            yield got


def items(project_dir: Path, tiers: tuple[str, ...] = TIERS) -> List[Path]:
    out: List[Path] = []
    for t in tiers:
        out += list(tier_items(project_dir / t))
    return out


# Markdown names that describe the FILE's role rather than naming the item. In the
# folder-per-item layout the folder carries the slug and the markdown inside is called
# something like this, so none of these may become an item's name.
#
# A structural rule — "parent is not a tier directory, so the parent is the slug" — was
# tried first and is wrong: a flat item does not always sit in a directory this module
# recognises (a test fixture writes `<tmpdir>/some-finding-slug.md`, and a new tier would
# behave the same), and it was then named after its directory. The file's own name is the
# only thing that says which of the two layouts it is in.
GENERIC_ITEM_NAMES = frozenset({
    "readme", "finding", "findings", "lead", "leads", "primitive", "primitives",
    "index", "notes", "note", "writeup", "write-up", "report", "summary",
})


def item_name(path) -> str:
    """The slug that names an item, for a flat file and for a folder-form one alike.

    `Path(f).stem` is the slug for `leads/host-reflects-origin.md` and the literal word
    `README` for `leads/host-reflects-origin/README.md`. That word was then fed to the
    class guesser, the skill picker and every brief line, so three yukki-lk primitives
    ranked and briefed as "README" with the class guessed from the word. The folder is
    what carries the slug in that layout, so read the name from there. Measured
    2026-11-13.

    Forgiving only `readme` was not enough, because the layout's fourth form is "the single
    `.md` in the folder" and it may be called anything — `finding.md` is what the
    one-folder-per-finding habit produces. Measured 2026-11-14 on a six-lane wave:
    `findings/www-android-deeplink-callback-javascript-scheme-xss/finding.md` and
    `primitives/chat-prod-unauth-support-chat-readable-by-client-chosen-basketuid/finding.md`
    were BOTH named `finding`, so two distinct refuter lanes printed as one repeated record
    and a reader could not tell three lanes from two. Same on mail_vk. Hence
    `GENERIC_ITEM_NAMES` rather than one word.
    """
    p = Path(str(path))
    if p.stem.lower() in GENERIC_ITEM_NAMES and p.parent.name:
        return p.parent.name
    return p.stem
