---
title: Home
nav_order: 1
description: A Claude skill bundle for web application bug hunting.
permalink: /
---

# claude-bughunter (web edition)
{: .fs-9 }

A drop-in [Claude Code skill](https://docs.claude.com/en/docs/claude-code/skills)
bundle that makes Claude behave like a senior web-app bug-hunting researcher — it
knows the techniques, the chain templates, the VRT mappings, and the hygiene, and
it stays in scope.
{: .fs-6 .fw-300 }

[Get started](#quickstart){: .btn .btn-primary .mr-2 }
[Browse the skill catalog](./skills.html){: .btn }
[View on GitHub](https://github.com/elementalsouls/Claude-BugHunter){: .btn }

---

## What you get

- **66 skills** across web recon, 45 web-app vuln-class + framework skills, and
  reporting — all **auto-loading by topic**, no invocation by name.
- **681 disclosed-report patterns** curated from public HackerOne reports.
- **Full OWASP-mapped coverage** — XSS, SQLi, SSRF, IDOR, RCE, SSTI, XXE, OAuth,
  SAML, GraphQL, deserialization, HTTP smuggling, cache poisoning, and more.
- **Reporting + validation** — 7-Question Gate, VRT mapping, evidence hygiene.
- **Burp MCP integration** and an engagement-folder scaffold.

## Quickstart

```bash
# Clone and install into ~/.claude/
git clone https://github.com/elementalsouls/Claude-BugHunter.git
cd Claude-BugHunter
bash scripts/install.sh
```

Then open Claude Code and describe what you're testing in plain English —
the relevant skill loads automatically:

```
> I'm testing acme.com, an in-scope HackerOne target. Start recon and
  rank the attack surface.
```

See the full [Installation guide](https://github.com/elementalsouls/Claude-BugHunter/blob/main/INSTALL.md)
and [Usage guide](https://github.com/elementalsouls/Claude-BugHunter/blob/main/USAGE.md).

## Stay in scope

This bundle is for assets you **own** or are **authorized to assess** (in-scope
bug-bounty programs, signed-RoE pentests, CTFs, your own lab). It ships
validation gates that auto-trigger on ambiguity. See the
[Security policy](https://github.com/elementalsouls/Claude-BugHunter/blob/main/SECURITY.md).

---

## Sponsored by

[Atlas Cloud](https://www.atlascloud.ai/console/coding-plan) — a full-modal AI
inference platform: one API for video, image, and LLM models (300+ curated).
Check out their [coding-plan promotion](https://www.atlascloud.ai/console/coding-plan)
for budget-friendly API access.
