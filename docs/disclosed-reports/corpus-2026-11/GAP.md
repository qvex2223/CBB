# Corpus gap report — would the toolkit have found these?

Corpus: `docs/disclosed-reports/corpus-2026-11/corpus.json` · toolkit: `/home/qvex/security-research/BugHunter` · 120 reports

- skill exists for the class: **99.2%**
- technique keywords present where the agent is routed: **99.2%**
- misrouted (technique exists, but in a skill the class does not route to): 1

| lesson | n | technique coverage |
|---|---|---|
| parser-differential | 21 | 100.0% |
| composition | 18 | 100.0% |
| other | 16 | 100.0% |
| oracle | 13 | 100.0% |
| sibling-interface | 11 | 100.0% |
| client-supplied-field | 9 | 100.0% |
| framework-internals | 7 | 85.7% |
| body-not-status | 7 | 100.0% |
| server-side-fetcher | 5 | 100.0% |
| secret-validation | 5 | 100.0% |
| filter-operator | 3 | 100.0% |
| multi-identity | 3 | 100.0% |
| patch-bypass | 2 | 100.0% |

## Gaps — each is a backlog item (mutation, signal row or consumer entry)

- `h1-10` [framework-internals] classes=ssrf missing: remote_attachment_url=, attributecleaner allowlist, project.json import — https://hackerone.com/reports/826361
