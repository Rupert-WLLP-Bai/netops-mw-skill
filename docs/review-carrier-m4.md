# Carrier M4 final review

Two independent Sol reviewers assessed frozen source `45a07434c506c76b4f609d71d97282e31a88e380`
against merged M3 `4087d4e0627fcd08ebaeaf6b9d6d4def7af7741a`. All runtime code, tests,
inputs and packaged references froze before final checks: 210 full and 131 clean-extracted tests passed.
The parent finalized nonpackaged status records afterward. See [the validation record](validation-carrier-m4.md).

Initial Standards review reported two P2s; initial Spec review reported four P2s. R2 Standards
reported one P2 and R2 Spec reported two P2s. All findings were corrected and independently closed
in R3. Earlier reports, failed gates and reproductions remain preserved.

## Standards

# M4 final Standards re-review, R3

Reviewed frozen `45a07434c506c76b4f609d71d97282e31a88e380` against merged M3 `4087d4e0627fcd08ebaeaf6b9d6d4def7af7741a`, focusing on corrections since `c7625bf`. Earlier reviews, failed checks and reproductions remain preserved.

Applied the same repository standards: agent guides, glossary/ADR, README, roadmap, issue #8, M4 plan, seven Skill entries, incident contracts and explicit release inventory/allowlist. Repository requirements override Fowler heuristics; tooling-enforced style is excluded.

**Verdict: Standards pass. Zero remaining documented-standard violations, required corrections, or material baseline-smell findings.**

The R2 categorical aggregation finding is closed. Applicable `profile_aggregation` contradictions now ignore optional unit labels, retain actual opposing references as counterevidence, and yield neutral `profile_conflict` while blocking dependent queue/QoS conditions. Numeric limit comparison still requires matching units. Profile conflicts cover the actually used window, including boundary clock uncertainty; historical and outside-window controls remain usable.

The shared access/transport guard now detects any definitely ordered cumulative decrease within a candidate interval, including `100 → 115 → 110 → 120`. It blocks the outer delta without guessing reset/wrap/source error, and preserves independently valid pairs that do not span the decrease. Reviewed assertion changes prohibit the unsupported outer pair while retaining supported local increments. Original reset and declared-window corrections remain effective.

Independently executed 21 focused public controls covering retained reproductions, profile units/window boundaries/uncertainty, and access/transport counter histories. All passed. Eighteen retained public M3 cases also remain identical. Evidence is retained under `.tools/carrier-m4/standards-probes-r3/` in `retained-reproductions.json`, `boundary-history-controls.json`, `access-parity-results.json`, and `package-checks.json`.

Independently verified every package member against frozen source and manifests, equal double builds, seven individual packages, 30 fixture hashes/sizes, Python 3.10 grammar, standard-library dependencies and Apache licensing. Suite: 55 files, 557675 bytes, SHA-256 `87a53b62eef075c5057bc25539fbb8b4e0e726dd07b6617ffb9c09188d380f83`. Original standalone: unchanged 16 files, SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. Existing entries, controller defaults, collector budget and four states remain compatible; fixtures/private maps/oracle stay outside runtime/package inputs.

Reviewed final logs record 210 full tests in 155.627 seconds and 131 extracted tests in 120.791 seconds, no skips, seven structural validators and managed-PCAP success. The validator-interpreter correction affects development tooling only.

No maintained edits or external actions. Review ownership is released to the parent for authorized integration. Actual M7 client, native Windows and external-security acceptance remain user-deferred and unclaimed.

## Spec

# Spec re-review R3 — M4 / issue #8

Reviewed frozen `45a07434c506c76b4f609d71d97282e31a88e380` against M3 `4087d4e0627fcd08ebaeaf6b9d6d4def7af7741a`, focusing on corrections since `c7625bf3e6646c8cd529358fbb6a1567fe690710`. Both R2 reports and earlier evidence remain preserved.

**Verdict: pass. All prior material specification findings are resolved; no new material regression identified.**

Independent public CLI checks used actual M2-produced bundles:

- Opposing profile limits inside the used queue window, at its end, or overlapping either boundary through clock uncertainty now produce neutral `profile_conflict`, retain actual opposing references, and withhold the dependent queue condition. A contradictory categorical aggregation with a different optional unit label also blocks it. Historical, after-window, fully outside-uncertainty, wrong-direction and incompatible numeric-unit controls preserve the valid original condition.
- Both 100→5→120 and 100→115→110→120 cumulative histories block the unsupported outer transport delta and dependent queue condition, reporting `counter_discontinuity` without guessing a cause. The shared access path also blocks the outer FEC delta. Valid increments entirely before or after the observed fall remain neutral observations.
- Prior ambiguous-flow and zero/null gauge-count cases retain their specific gaps. A positive unique-flow route case still correlates and cites the actual flow record. Matched aggregate reverse windows still satisfy coverage; earlier mismatched-window checks and contracts remain intact.

Retained artifacts include `.tools/carrier-m4/sol-spec-r3-profile-window.*`, `sol-spec-r3-counter-decrease.*`, `sol-spec-r3-boundaries.*`, `sol-spec-r3-regressions.*`, `sol-spec-r3-missing-count.*`, and `sol-spec-r3-positive-flow.json`.

Reviewed final evidence records 210 full tests and 131 clean extracted tests passing, seven validators, Python 3.10 grammar and 30 fixture hashes. The 55-file suite and seven individual archives reproduce; suite SHA-256 is `87a53b62eef075c5057bc25539fbb8b4e0e726dd07b6617ffb9c09188d380f83`. The original 16-file collector remains unchanged. These local/offline results do not establish native Windows, MobileWork, vendor or external-security acceptance.

No maintained source was edited. Review ownership is released for the authorized verified-head PR/integration workflow.

Standards: 0 remaining findings. Spec: 0 remaining findings.
