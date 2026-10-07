---
name: debrief
description: Close the session on facts — append a full-prose debrief to the engagement's notes.md (requests fired, findings, rejections, open vectors). Usage: /debrief [project] [--since-minutes N] [--print]
---

# /debrief

The other half of `session-brief`. It opens the next session on facts; this
closes the current one on facts, so the next brief is not opening on a fiction.

## When to Use

- ending a hunting session, or switching engagements
- before handing the target back to the operator
- when the session ran long and `notes.md` has drifted from what happened

## What It Writes

Into `Targets/<name>/notes.md`, in **full prose** (not a scoreboard — the notes
are read back by `/pickup`, `cbh view` and `session-brief`, and a compressed
note is a direct loss to cross-session memory):

- requests actually fired (`audit.jsonl`) — the only thing that counts as work
- findings logged and rejections logged (rejections are results too)
- hosts touched
- every open vector with its **next mutation**
- what was not done, stated plainly

## Usage

```
/debrief
/debrief Targets/kcell
/debrief --since-minutes 240
/debrief --print          # show it, write nothing
```

## Rules

- this records what the artefacts say, not what the session remembers
- an untried vector stays open in the debrief; only `vectors.py mark` with real
  fired requests (or an explicit operator decision) closes it
- nothing here is a severity judgement — the debrief does not decide what a
  finding was worth

## After the debrief

If the session produced a Medium-or-higher with a PASSing PoC, it is already
banked in `findings/` and the sweep continues — continuous mode is on. The
debrief is the record, not the exit.
