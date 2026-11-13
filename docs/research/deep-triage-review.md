# Final independent re-review: deep triage research

Reviewed on 2026-11-12 against unchanged HEAD `d0b82b4e387894c2454a328d89cb7a8c7aff1fa6` in `/home/pejoy/code/netops-mw-skill`.

Verdict: **approved for the research-only delivery; no remaining findings within the focused re-review scope.** All three findings in `/tmp/netops-deep-research-sol-review.md` are resolved. This review covers the completed corrections described in `/tmp/netops-deep-research-fixes.md`, plus Markdown/JSON correspondence. The prior primary-source audit remains applicable; no new broad audit or runtime suite was needed.

1. **Existing v0.1 baseline — resolved.** The research note and both case catalogs now acknowledge existing normal/pinned replay matching while distinguishing the missing live pinned collection/comparison. DEEP-10 acknowledges negotiated `http_version` metadata. Ranked recommendation 3 and DEEP-12 acknowledge field discovery, input/raw-event hashes, frame numbers, timestamps, streams, available expert flags, summaries and coverage. They identify the proposed additions as structured per-stream timelines, finding-to-frame references, richer capture-origin/drop/visibility information and optional opposite-end correlation. DEEP-13 acknowledges existing zero-window flags/counts and distinguishes detailed window/socket correlation. These statements agree with the baseline code examined in the initial review.

2. **DEEP-16 state semantics — resolved.** Its allowed conclusion and proposed local test explicitly cover all three requested cases: valid short target success supports `not_reproduced`; the same success with optional DNS, ping or control absent remains `not_reproduced` with limitations; absent required target observations or evidence essential to a specifically requested comparison supports `insufficient_evidence` for that conclusion. The top-level contract in both catalogs preserves valid target observations when optional evidence is missing. Permanent health, denial of historical failure and unsupported root-cause claims remain prohibited.

3. **tracepath source — resolved.** The research note now links to `https://github.com/iputils/iputils/blob/master/doc/tracepath.xml`, the owner manual verified during the initial review. The broken `tracepath.8.adoc` link is absent.

Fresh verification parsed the JSON and checked all 16 unique sequential case IDs, top-level and per-case `designed_not_executed` status, nonempty fields, registered source IDs, every substantive Markdown/JSON case field, ordered case source references, source-registry equality and exact top-level contract correspondence. All checks passed. The files continue to identify the scenarios as designs, not executed tests, incident records or directly runtime-compatible v0.1 fixtures.

Working-tree inspection showed only the three intended untracked research files. Tracked and staged diffs are empty. HEAD is unchanged. This re-review edited only this temporary review record; no project runtime, tests, package, branch, index or remote changed.

Reviewed artifact SHA-256 values:

| Artifact under `docs/research/` | SHA-256 |
| --- | --- |
| `deep-triage-tools-and-cases.md` | `c21efde4ca48a29d72a736ac6d09c0d80bb1becdc417e5a1ce5bd224ddec15ec` |
| `deep-triage-cases.md` | `e02d19e42d3805393bd62dd071955aa73b9714ab257a7334319c4bf620c0b29c` |
| `deep-triage-case-catalog.json` | `ab94a2a5a8d85beaf360963a55d320c600b61d88e86a91aabc966463c0a5c6a7` |

I explicitly approve mechanically adding a faithful final review record and committing these reviewed research documents without another review. This approval covers documentation only. Runtime extension implementation and architecture design approval remain separate future work; the 16 designed cases have not been executed.
