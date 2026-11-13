---
name: refute
description: Try to KILL a finding before a triager does — fire the controls whose PASS means the finding is wrong, then judge them. Usage: /refute findings/<finding>.md [--plan]
---

# /refute

Every other gate in this workspace rewards a yes. `poc_runtime` asks "did the
exploit work", `cbh evidence` asks "is there a PASS behind this", `/validate` asks
the seven questions — and the model that wrote the finding is the one answering.
The hunters who measured this only moved their false-positive rate (80% -> 60%)
once a separate pass was rewarded for **disproving** instead.

So this fires the controls.

## Run it

```
/refute findings/idor-orders.md --plan     # build the controls, send nothing
/refute findings/idor-orders.md            # fire them, judge, write .refute.json
```

It works off the **spec that was actually fired**, not the write-up: a sibling
`<finding>.poc.json`, or whatever the `.result.json` names. No spec, no refutation
— `cbh spec <url-substring> --out <stem>.poc.json` rebuilds one from a request that
already flew.

## The controls

| Control | A PASS means | Verdict |
|---|---|---|
| `credentials-removed` | the same request works with every credential header stripped | **MIS-FRAMED** — unauthenticated exposure may still be a bug, but not the one written |
| `control-value` | the attack value swapped for your own still satisfies the **original** `expect` | **KILLED** — the response does not react to the input; the oracle is a stub |
| `exploit-removed` | a `steps` chain still verifies with the exploit step deleted | **KILLED** — the state was already there |
| `answer-never-moved` | no request at all: the corpus says the decisive field never changed across >=6 captures | **KILLED** |

The value controls need the spec to say what the attack value is:

```json
"refute": {"attack": "124", "control": "123"}
```

Without it they come back SKIPPED with that line printed. Guessing which token in a
URL is the payload is exactly the inference that produces a confident wrong answer,
so the tool does not do it. The program's mandatory headers are never stripped.

**`expect` is not substituted in the control-value run, on purpose.** Substitute it
and the control degenerates into "does my own object return my own data", which
proves nothing. Left alone, it asks the question that matters: does the original
expectation still hold once the attack is gone?

## After a verdict

- **KILLED / MIS-FRAMED** — `cbh evidence` now reports **REFUTED**, which outranks
  the exploit's own PASS. Do not report it as written. `cbh triage <finding>
  --demote` moves the file to `leads/` or `primitives/` with the reason attached,
  then `/remember --result rejected` so the next session does not repeat the move.
  The file is never deleted: the observation was usually real even when the claim
  was not.
- **SURVIVED** — the controls fired and failed as they should. That is not proof of
  impact: `cbh evidence <finding>` still has to say DEMONSTRATED, and `/validate`
  still runs.
- **INCOMPLETE** — nothing could be built from this spec. Declare the attack value,
  or turn the PoC into a `steps` chain, and run it again.

## Where it sits

```
poc_runtime  ->  cbh refute  ->  cbh dedup  ->  /validate  ->  /report
(does it work) (is it wrong) (is it mine twice) (7 questions)
```

Controls leave through `poc_runtime`, so scope, pacing, mandatory headers, the audit
log and the response corpus all apply. Their artifacts land in
`refutations/<finding>/`, which `engine/evidence.py` excludes from the evidence pool
— a request built to pass when the finding is wrong must never read as proof that it
is right.
