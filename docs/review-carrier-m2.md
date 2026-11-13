# Carrier M2 final review

Two independent Sol reviewers assessed frozen source `f78c8972fffdb44619954afd4eb0b96f4652ca5b`
against merged M1 `b2e7ee524d83ebb9dee3e51dd471c053c48b6974`. Terra/Luna completed corrections,
then final verification ran before these re-reviews. The parent finalized nonpackaged status documents
afterward. M2 was merged through [PR #13](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/pull/13)
at `147c2af0fb244cf913af105d148051bee316a679`. See the [validation record](validation-carrier-m2.md)
for commands, hashes and platform limits. Initial reports remain retained separately.

## Standards

# M2 final Standards re-review

Reviewed frozen `f78c8972fffdb44619954afd4eb0b96f4652ca5b` against merged M1 `b2e7ee524d83ebb9dee3e51dd471c053c48b6974`, focusing on `4be2029..f78c897`. The reviewed history contains the implementation and correction commits. The first review remains unchanged.

Applied the same standards sources: `AGENTS.md`, three agent guides, root glossary and ADR, merged roadmap, issue #6, M2 plan, ingestion and case contracts, five Skill contracts and explicit release allowlists. Repository requirements override the Fowler smell baseline; current user authorization governs milestone integration.

**Documented-standard violations: none. Required corrections: none. Baseline smells: no material findings.**

The previous integral-count clarification is closed. JSON and CSV now accept finite, non-negative integral numbers, preserve integer versus floating representation, and reject boolean, fractional, negative and nonfinite counts. The bundled contract states the accepted forms.

Collection-age evaluation now resides in one shared helper used by successful parsing and failure paths. Old collection snapshots are marked stale across topology, eventless, unsupported, error and timeout outcomes. Event-age checks remain independent. The new stale-topology fixture retains declared historical verified links while explicitly marking the snapshot stale; it invents neither current topology nor an event timestamp.

Independently reran all 21 ingestion tests: passed in 9.422 seconds. Reviewed final logs record 162 full tests in 71.240 seconds and 83 extracted tests in 38.321 seconds, with no skips. Changed Python parses with Python 3.10 grammar and remains standard-library code. All 13 synthetic fixture provenance hash sets match.

Independently verified both archive/manifest pairs reproduce exactly and every packaged byte matches the frozen source and manifest. Suite: 42 files, SHA-256 `6d471218b6cc6085c88f6297bc8e0f62458581e33d0c786ad8b773c0666638b4`. Standalone: unchanged 16 files, SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. Existing entries, collector, standalone builder, 25-second budget and four diagnosis states remain unchanged. No fixtures, private maps, raw originals, hidden answers or development dependencies are packaged.

**Verdict: Standards pass, zero open findings.** No maintained source edits or external actions performed. The parent owns authorized integration; actual-client, native Windows and external-security validation remain user-deferred and unclaimed.

## Spec

# Spec re-review — M2 / issue #6

Reviewed frozen `f78c8972fffdb44619954afd4eb0b96f4652ca5b` against M1 `b2e7ee524d83ebb9dee3e51dd471c053c48b6974`, focusing on corrections since `4be202988c342ad6602fea3c7400d262839c2778`. The prior report is preserved.

**Verdict: pass. Both prior P2 findings are resolved; no new material specification regression identified.**

- **Integral counts:** repeating the public CLI reproduction with JSON `sample_count: 1.0` now produces `complete`, retains the observation and preserves its float representation in visible output and carrier metadata. A public CSV check using `1.0` also succeeds and preserves the parsed representation. Public fractional and boolean inputs produce `parse_error`; runtime finite-number checks continue rejecting negative and nonfinite values. The reference now describes the accepted integral numeric forms.
- **Stale collection snapshots:** repeating the day-old topology reproduction with a 60-second maximum age now produces `complete` plus `quality: ["stale"]`. The declared verified link remains present without being represented as fresh evidence. A shared collection-age check covers all formats and failure outcomes, alongside existing per-event checks. A controlled timeout-result check also retains `stale`. The documented strict age boundary matches the implementation.

The correction diff changes neither the privacy/publication boundary nor the existing controller and standalone collector contracts. Raw and reversible mapping storage remain separate from visible derivatives. No network/device actions or additional diagnostic behavior were introduced.

Reviewed final evidence records 162 full tests and 83 extracted tests passing, with two identical 42-file builds and manifests. Suite SHA-256 is `6d471218b6cc6085c88f6297bc8e0f62458581e33d0c786ad8b773c0666638b4`; the 16-file standalone archive remains unchanged. These are local/offline results, not native Windows, MobileWork, vendor or external-security acceptance.

No maintained source was edited. Review ownership is released; the verified head may proceed through the authorized PR/integration workflow.

Standards: zero open findings. Spec: zero open findings. User-owned client, native Windows and external security acceptance remain pending.
