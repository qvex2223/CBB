# Corpus gap report — would the toolkit have found these?

Corpus: `docs/disclosed-reports/corpus-2026-11-02/corpus.json` · toolkit: `/home/qvex/security-research/BugHunter` · 41 reports

- skill exists for the class: **100.0%**
- technique keywords present where the agent is routed: **92.7%**
- misrouted (technique exists, but in a skill the class does not route to): 2

| lesson | n | technique coverage |
|---|---|---|
| parser-differential | 11 | 100.0% |
| composition | 5 | 60.0% |
| framework-internals | 5 | 100.0% |
| oracle | 4 | 75.0% |
| server-side-fetcher | 4 | 100.0% |
| secret-validation | 3 | 100.0% |
| client-supplied-field | 3 | 100.0% |
| patch-bypass | 2 | 100.0% |
| sibling-interface | 2 | 100.0% |
| filter-operator | 1 | 100.0% |
| body-not-status | 1 | 100.0% |

## Gaps — each is a backlog item (mutation, signal row or consumer entry)

- `r-002` [composition] classes=rce,race-condition,parser-differential,other missing: maglev deoptimization, heapnumber deduplication, partitionalloc overflow, wasm code pointer table, crashpad race, bypass_process_freeze — https://xbow.com/labs/research/zero-to-calc-in-six-days-inside-xbow-chrome-full-chain
- `r-005` [composition] classes=rce,parser-differential,race-condition,other missing: v8 regexp uaf, electron ipc — https://bugcrowd.com/disclosures/63864b55-10d6-4e82-a619-192b8c0c99ad/1-click-remote-code-execution-via-twitch-embed
- `r-022` [oracle] classes=info-leak,other missing: crx auto-install — https://zhero-web-sec.github.io/research-and-things/one-trigram-at-a-time-xsleak-via-universal-css-injection-and-dos-in-opera-(gx)
