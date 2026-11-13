# Corpus gap report — would the toolkit have found these?

Corpus: `docs/disclosed-reports/corpus-2026-11-13/corpus.json` · toolkit: `/home/qvex/security-research/BugHunter` · 10 reports

- skill exists for the class: **100.0%**
- technique keywords present where the agent is routed: **100.0%**
- misrouted (technique exists, but in a skill the class does not route to): 0
- still in the file the record names (`landed_in`): **100.0%** of 10 record(s) that name one; 0 name none

| lesson | n | technique coverage |
|---|---|---|
| a parse surface the client never calls is still reachable | 1 | 100.0% |
| one request can split a WAF from its backend | 1 | 100.0% |
| the sanitiser's allowlist is not the document's full grammar | 1 | 100.0% |
| a CSP that stops every script can still leave the form boundary open | 1 | 100.0% |
| an exfil that runs out of rounds is a reassembly problem, not a bandwidth problem | 1 | 100.0% |
| the source census is cheaper than the payload | 1 | 100.0% |
| the cached object can be a credential, not a page | 1 | 100.0% |
| the rung you stop on is the severity | 1 | 100.0% |
| a detector tuned for malformed requests misses the well-formed one | 1 | 100.0% |
| a fingerprint row costs one read and decides the lane | 1 | 100.0% |

## Gaps — each is a backlog item (mutation, signal row or consumer entry)

