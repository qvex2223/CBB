#!/usr/bin/env python3
"""doctrine.py — the crit/high doctrine every skilled worker brief carries.

Why this exists: the lessons in docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md
reach a worker only if the worker happens to load `bb-methodology`. Workers do the
hunting, so the doctrine travels in their launch text instead:
  * engine/engine.py::_hunt_agent appends it after the rules of engagement;
  * the worker launcher adds it to every role except freeroam;
  * scripts/hunt-arm.py tells the orchestrator to paste it into every Agent brief.

Freeroam never gets it: its value is that it carries NO methodology
(tests/test_freeroam_stays_naive.py).

`cbh doctrine` prints it. Keep it short; it is paid for in every worker's context.
"""
from __future__ import annotations

import sys

DOCTRINE = """\
CRIT/HIGH DOCTRINE (learned from 117 disclosed crit/high reports — follow it, it is how they were found):
1. COMPOSE BEFORE YOU CLOSE. A Low is a component. Before writing any primitive off, ask who
   consumes it: `python3 engine/vectors.py consumers <class>` (self-XSS+unkeyed cache, XSS+OAuth
   prompt=none, open redirect+redirect_uri, DNS-only SSRF+redirect loop, leaked key+scope map).
2. READ BODIES, NOT STATUS CODES. A 3xx carrying a page (execution-after-redirect), a 4xx whose
   JSON still holds data, a secret in any body — bbcurl prints `SIGNAL ...` for these; act on it.
3. SAME OPERATION, SECOND INTERFACE. Every privileged action through REST, GraphQL, Next.js
   Server Action (`Next-Action`), mobile/partner API, export/import, GET vs POST. The check
   usually lives on only one of them. Prove by reading the state back.
4. IDENTITIES FIRST for any authz surface: owner + member + outsider (+ a 2nd tenant) before
   the first payload. Ids come from share URLs, denial bodies, exports.
5. SERVER-SIDE FETCHERS (PDF/screenshot render, import-from-URL, webhook test, avatar URL)
   are SSRF; the payout depends on reaching a credentials READ, not on a callback.
6. BUILD THE ORACLE before calling anything blind: boolean error, length, count, order,
   redirect loop, timing pairs. A vector is not dead while no oracle was tried.
7. DEFENDER'S ARTEFACTS ARE FREE: patch diffs, advisories, the programme's disclosed reports,
   your own rejected ones — look for the other spot and the fix bypass. Seen something odd?
   `cbh report-intel docs/disclosed-reports "<what you observe>"` returns the closest paid
   crit/high reports with their mechanic and proof.
8. PROVE, THEN TRY TO KILL IT: a control that could prove you wrong (`cbh refute`), minimal
   bounded impact (a hash or a count, never the data). Severity follows data at risk, never
   the elegance of the chain — a Low stays a Low.
"""


def text() -> str:
    return DOCTRINE


def main(argv=None) -> int:
    sys.stdout.write(DOCTRINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
