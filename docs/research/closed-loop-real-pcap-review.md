# Final independent review: closed-loop proposal and real PCAP correction

Reviewed on 2026-11-12 in `/home/pejoy/code/netops-mw-skill`, branch `feat/closed-loop-triage-research`, against unchanged baseline HEAD `c43d3f3d63d47a69f11cf2a73ca12d047fa6f577` and the completed, frozen working tree. Authoring was finished before this review. No implementation or research edit ran concurrently.

**Verdict: approved within the combined review scope; no remaining material findings.** The earlier proposal contradiction is resolved. The expanded research describes a complete human-assisted incident lifecycle without claiming implementation or architecture approval. Three substantial publisher-pinned captures and six traceable derivatives provide actual offline validation, expose a reproducible DNS count defect, and verify its focused correction. They do not establish an executed closed-loop incident, actual network-fault causality, production readiness, or recovery.

## Scope and prior finding dispositions

1. **R1, spontaneous recovery — resolved.** `closed-loop-scenarios.json` now explicitly applies the no-known-action recovery branch to every journey through `shared_contract`. CL-04 and CL-05 accept a justified recorded action or independently documented recovery without a known action, then require original affected operation/account, relevant path/family, SLI and stabilization. Missing vantage, failed checks, inadequate evidence and incomplete coverage remain unresolved. Conditional action-driven wording in CL-09 and other journeys does not override the explicit shared rule. No fabricated action or cause is required.
2. **Old TM Forum directory URL — resolved.** The source table now uses the current OpenAPI Directory. The earlier primary-source review in `/tmp/netops-closed-loop-sol-review.md` remains applicable to the unchanged technical claims. A new broad audit of those same sources was unnecessary.
3. **Real-capture requirement — addressed within offline scope.** The added corpus is three public author-published captures with 12,899, 10,728 and 11,430 frames, and six reproducible variants. These are substantial real capture files, not self-built miniature PCAPs. The proposal acceptance text explicitly requires substantial public captures or traceable derivatives and treats short synthetic PCAPs as unit-test inputs only. All ten lifecycle journeys retain `designed_not_executed`; the actual nine offline runs are distinguished from them.
4. **DNS Boolean serialization defect — corrected and independently reproduced.** I loaded the baseline summarizer directly from `git show c43d3f3:.../pcap.py` in memory, without changing any file, and supplied the same actual retained web EK output to baseline and current code. Baseline produced 167 query / 0 response frames; current code produced 111 / 56, matching separate TShark filters. The historical pre-fix JSON and Markdown retain the failure instead of rewriting it as success. Diagnosis logic did not change.

## Code and validator review

The runtime change is confined to DNS direction counting and two additive summary fields. It recognizes native booleans, integer 0/1 and case-insensitive string True/False/0/1. Missing or unrecognized values increment the unknown counter and do not silently become queries. Repeated values are counted per frame; recognized query and response directions can overlap and increment the mixed-frame counter. A frame can also contain a recognized and an unknown value. Unavailable required fields remain null. The evidence contract states the frame denominator, overlap and related DNS-dissector protocols. No new live traffic, repair authority, diagnosis rules, or collection budget is introduced.

The fresh suite covers string, integer and Boolean representations, missing/unexpected values, repeated mixed directions and unavailable fields. I additionally checked null, object, nested-list and floating-point values: they remain unknown, while recognized scalar forms preserve the documented counts. No material parser defect was found.

The developer validator is outside the distributable. It hashes local inputs before creating output, refuses an existing output path, confines input and artifact/source paths by resolved ancestry, restricts unique per-case names and explicitly rejects an empty input list. It invokes the actual offline CLI and separately invokes TShark in field/filter modes. Its checks compare frozen expected values to independent results and then compare runtime values to that independent result; they do not merely compare the implementation with itself or treat exit zero as success. All advertised checks are evaluated for the actual corpus, including hashes, references, completion, validation errors, scoped diagnosis, frame counts, truncation and DNS directions. It makes no download or live-probe request.

Fresh negative checks independently demonstrated:

| Review input | Observed result |
| --- | --- |
| Increase frozen web response-frame count by one | Exit 1; `independent_dns_responses` fails; recorded `passed` is false |
| Replace input SHA-256 with zeros | Exit 1 before output creation; hash mismatch |
| Empty `files` list | Exit 1 before output creation; manifest has no inputs |
| Input path traverses outside the corpus | Exit 1 before output creation; path escapes its directory |
| Existing output directory | Covered by the passing safety regression; marker content preserved |

These are developer checks of known local test inputs, not a general hostile-manifest security certification.

## Provenance and measurement checks

I read the exact pinned publisher documentation through the GitHub connector:

- [Chris Sanders README at 0412fb1](https://github.com/chrissanders/packets/blob/0412fb1dc0aa671128f9da6689e0dbd4459c0b51/README.md): permission to use shared captures with attribution unless another source is specified, with the repository's malware-content caveat. The corpus correctly does not claim a documented operational environment or root cause for either individual trace.
- [Omar Babba README at 596dae3](https://github.com/omarbabba779xx/network-traffic-monitoring-lab/blob/596dae3acd11144ff2e86bf975a2f0f27664a887/README.md) and [LICENSE](https://github.com/omarbabba779xx/network-traffic-monitoring-lab/blob/596dae3acd11144ff2e86bf975a2f0f27664a887/LICENSE): author reports own-interface browsing/DNS capture, 11,430 packets and MAC/cookie redaction. The repository license is MIT; the local documentation appropriately limits conclusions about individual-trace and third-party rights. The publisher's broad claims about normality or capture ground truth are not adopted as validated production facts.

Original-file SHA-256 checks passed against the pinned local corpus. All six variants were independently regenerated in a new ignored review directory using the exact recorded editcap command, then compared byte-for-byte by SHA-256 to the manifest. Every derived hash matched, and each parent hash points to its corresponding original. Omission removes parent frames 1000–1049; snap96 limits captured bytes while retaining original lengths. Remaining timestamps are not shifted; no keys were obtained or used. The records correctly call these capture impairments, not real packet-loss experiments or repairs.

Separate fresh TShark field extraction verified these original-capture metrics:

| Original | Frames | TCP / UDP streams | TLS handshake frames | Timestamp regressions | First-to-last / extrema span |
| --- | ---: | ---: | ---: | ---: | --- |
| web | 12,899 | 279 / 93 | 0 | 0 | 93.748446 / 93.748446 s |
| slow | 10,728 | 1 / 0 | 0 | 0 | 174.864945 / 174.864945 s |
| lab | 11,430 | 62 / 17 | 12 | 10 | 25.117133 / 100627.919947 s |

The lab's time anomaly is explicitly disclosed and excludes it as a global timing baseline. The slow filename is not treated as a proven bottleneck. Protocol/stream counts remain dissector/version-specific observations. DNS direction counts are frames containing DNS-dissector fields, including LLMNR/mDNS where present; they are neither message nor transaction counts. The slow trace's 0/0 does not test direction parsing. Counter and lost-segment changes are not treated as proof of network loss location, causal responsibility, or recovery.

The original corpus JSON preserves the capinfos GLib critical warning text in every command's stderr, rather than hiding a clean-tool assumption. Independent TShark runs succeed with the documented counts. Download completion times are labeled local file modification timestamps, not independent signed receipts. Raw inputs, derivatives, EK events, pre/post reports and new reviewer outputs remain ignored under `.tools/pcap-corpus/`. Reviewed research records contain aggregate counts, commands and hashes, not packet payloads or TLS keys.

## Fresh execution and artifact checks

- `python3 -B -m unittest discover -s tests -v`: **72 passed**, 32.195 seconds, exit 0. Full reviewer log: `/tmp/netops-sol-final-tests.log`.
- `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/sol-final-independent`: **9/9 passed**, exit 0. Every case's checks and reported frame/truncation/DNS/unknown/mixed counts agree with `real-pcap-postfix-validation.json`. Input, source, run-artifact and evidence-source hashes and diagnosis references passed. All nine correctly remain `insufficient_evidence`; no health or recovery is inferred from parser completion.
- Additional separate TShark original-file metrics, all six exact editcap derivations, baseline-versus-fixed actual EK comparison and validator negative controls passed as described above. No captured payload was printed or added to the repository.
- The two candidate archives have identical SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`, size 209807 bytes. I inspected the candidate ZIP: all 16 allowed members match current source bytes. Captures, research and the developer validator are absent. The author-recorded three extracted-package runs remain available; my fresh nine source runs exercised the same member bytes. No third broad suite or extra rebuild was necessary after these checks.
- Historical `dist/internet-access-triage-0.1.0.zip` remains 207985 bytes, SHA-256 `3395dea80c52d312259215096136f253115d10dc500876c778dcb3789f5f9088`. Historical review and validation records are preserved; README distinguishes that reviewed archive from the new candidate.
- Local Markdown links resolve. The JSON still has ten unique sequential CL IDs, designed status, five ordered stages, three terminal outcomes, failure/reopen descriptions, local test designs and valid source IDs. Original diagnosis state semantics and prior 16 research cases are preserved.

## Proposal quality and limits

The lifecycle includes intake and service impact, dependency/ownership mapping, baseline and freshness, bounded evidence/tests, supported decisions, operator plan/action recording, independent original-business verification, stabilization, rollback assessment, unknown-outcome reconciliation, unresolved handoff, cancellation/resume, linked reopen episodes and learning. Persistent budgets survive retries/resumes. The first slice records actions and evidence; the existing bounded GET collector is not presented as proof of an authenticated checkout or upload. Original-vantage unavailability or inadequate observation produces an unresolved outcome. Administrative ticket closure, alert silence, command success and missing optional tools do not imply recovery.

This approves the research and bounded offline parsing correction. It does not approve an architecture or implement the case controller, external ticket writes, actuation, device adapters, actual service monitoring or the ten designed journeys. Native Windows, actual MobileWork import/triggering, controlled network fault injection/recovery, external security review, publication and production suitability remain unverified. Three public captures and capture impairments are useful real-input validation, not exhaustive operational coverage or a dataset with independently known network-fault truth.

## Frozen artifact identity and allowed follow-up

| File | SHA-256 |
| --- | --- |
| `skills/internet-access-triage/scripts/netops/pcap.py` | `72a30c9e9b5440e259601cd6a32b312420de60c4d061acaa3635d082af1396af` |
| `skills/internet-access-triage/references/evidence-contract.md` | `8c593c82966541d6d738786db9949c6f57b82c1f18f33edb264c2d1583699bca` |
| `tests/test_pcap.py` | `f290e08e767da8c0401c06cffda5d8b16e56d46668427b35fde26fb30809c2a4` |
| `scripts/validate_real_pcap.py` | `f0dfcb2d1fc97b0525b871efdd73998031dfee1bb3cffa8d1e21c83c443da4ef` |
| `tests/test_real_pcap_validator.py` | `283d88608a4c48c93b164aabe01e21202cb81ba8e0a29a0d40c3f81613a71c55` |
| `docs/research/closed-loop-scenarios.json` | `bec41c8cb43b1dc0666befd0aeda0e5e2f9ac1c91b348a5426ffd2dea3dfda88` |
| `docs/research/closed-loop-tools-and-practices.md` | `d12664ea386e995962ddb2344ee95a736db2121ce63bdf3a2ff587d0531aafbe` |
| `docs/research/closed-loop-workflow-proposal.md` | `90fe9c56d8b4090ea63b99287d7a4da2118c6eb5bfb20662b2819f97557676c3` |
| `docs/research/real-pcap-corpus.md` | `e848f0feb1642e7f9191666e351899e0a60b2bf201d91df7e3632159ad01f3d1` |
| `docs/research/real-pcap-corpus.json` | `f6b5849c50615d0219441812c68ad4a13329b161d22ac6493b0332e32e00ec9e` |
| `docs/research/real-pcap-postfix-validation.md` | `c14d9ab8c0d8b37c35d6d1cf232fe35ab47c1685a703f3f2edf92fc2fa9e2d67` |
| `docs/research/real-pcap-postfix-validation.json` | `fe15d6f99baa66cd54b5d70809f59de6607acf6bb6b543b35f1575e753702a0f` |

I approve adding a faithful final review record, mechanically replacing review-pending wording in README and validation records with this scoped result, and committing the reviewed research, correction, tests and validator without another review. This permits documentation-only finalization after this review; it does not permit further runtime changes under this approval. The runtime/contract/validator identities and candidate package hash above remain frozen. No automatic push or merge is approved.

This review changed no project file, index, branch, HEAD or remote. It wrote this temporary report and ignored local verification outputs only. Final repository inspection confirmed unchanged baseline HEAD and the expected four tracked modifications plus nine new files. No probe, install, live capture, external ticket action, device change or operational message was performed.
