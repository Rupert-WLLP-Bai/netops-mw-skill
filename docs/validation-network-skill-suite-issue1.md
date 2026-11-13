# Network skill suite: issue #1 validation

The four controller findings in [issue #1](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/1)
are implemented at source commit `354b402`. This record supersedes the unfinished status of the
[original review](review-network-skill-suite-2026-11-13.md) for those findings. Independent final
[Sol re-review](review-network-skill-suite-issue1.md) passed on both standards and specification with no
required corrections. These local checks do not establish production readiness or target-host integration.

## Corrections and regression evidence

The restored portable reproducer confirmed all four failures before implementation. Four new regressions
then failed on the original source: pre-action evidence allowed recovered closure, a second run reused a
decision, a FIFO import exceeded its two-second test deadline, and unsupported timing values were accepted.
The same regressions pass after the fixes. The source and packaged controller each pass all 46 controller
tests, including existing spontaneous-recovery, failure, reconciliation, cancellation and restart cases.

| Finding | Result after correction |
| --- | --- |
| Old verification window reused after an action | Closure requires a window recorded after the latest relevant action or reconciliation, no earlier than the action time. A fresh qualifying post-action window permits closure; earlier windows and checks remain in history. Event revisions preserve ordering when timestamps coincide and support existing case records. |
| Repeated collection under one decision | The reservation transaction checks durable run-event payloads before charging a budget or starting a provider. Each attempted run consumes its decision, including interrupted reservations. Identical event retries remain idempotent; further work needs a new meaningful decision. |
| FIFO blocks evidence import | The confined reader opens the final descriptor with nonblocking mode, then requires a bounded regular file before reading. The public import regression verifies prompt rejection, unchanged case state and imports, and a subsequently obtainable SQLite write transaction. |
| Tiny or excessive timing values | Policy durations are limited to one microsecond through 3,153,600,000 seconds. Window creation also rejects clock overflow before committing. Invalid stored intervals block closure while Markdown export remains available. Coverage arithmetic avoids overflowing cadence additions. |

The six new controller tests cover those four failures, invalid stored intervals, and clock overflow.
The interrupted-provider regression now also checks that reconciliation alone cannot reuse a consumed
decision and that a new decision with a changed condition can continue. Very large integer and finite
floating-point durations are rejected without a traceback or case creation.

The original portable scenarios were rechecked independently after implementation because the unmodified
script stops at its first expected validation rejection. The old-window closure and second run now raise
`CaseError`; the FIFO reader rejects without timing out; creating the tiny-window policy fails validation.
The private reader reproducer calls Python directly, so its uncaught `CaseError` prints a traceback;
the maintained public CLI regressions exercise handled errors.

## Commands and results

Validation ran on Linux/WSL2 with Python 3.14.7 and TShark 4.6.6. No production target, live capture,
global installation, automatic repair, or external message was used. Existing collector tests include
controlled loopback HTTP/TLS servers.

| Check | Observed result |
| --- | --- |
| `python3 -B -W error::ResourceWarning -m unittest discover -s tests -v` | 125 tests passed in 78.217 seconds |
| Focused controller suite with the same warning setting | 46 tests passed in 31.344 seconds |
| Creator `quick_validate.py` on all five skill folders | Five passes |
| `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/issue1-validation` | Nine cases passed, 20 checks per case |
| Two independent `scripts/build_suite.py` builds with the same archive filename | ZIP and manifest bytes identical; 35 files |
| All controller tests copied into an independent temporary extraction | 46 tests passed in 35.641 seconds |
| Extracted collector/controller entry points and managed web-PCAP collection/import | Passed with empty `PYTHONPATH`; all archive, run-artifact and imported-summary hashes checked |
| `git diff 1d197d1 -- skills/internet-access-triage scripts/build_release.py` | Empty; standalone collector preserved |
| `git diff --check` | Passed |
| Independent Sol standards and specification review of frozen `354b402` | Both passed; zero required corrections |

The local command logs and machine-readable summaries are under `.tools/network-suite/issue1/`.
`regressions-before.log` retains the four original failures; `controller-final.log`, `full-suite.log`,
`extracted-controller-tests.log`, `postfix-portable-results.json`, `skill-validators.json`,
`delivery-verification.json`, and `environment-and-corpus.json` retain the new results. These are ignored
local validation artifacts, not package contents or source-controlled test inputs.

The specification reviewer independently exercised same-timestamp action ordering, prior-episode unknown
action reconciliation, interrupted-reservation retries and a new changed-condition decision. A public
FIFO-artifact import failed cleanly in 0.088 seconds, with unchanged state/imports and an available write
transaction. Inclusive timing bounds, clock overflow, and zero/inverted stored intervals also passed.
The standards reviewer ran seven targeted skill/package tests and checked Python 3.10 grammar compatibility.
These additional checks and the optional maintainability observation are recorded in the re-review.

## Restored real PCAP inputs

The authenticated draft-release transfer was restored using `scripts/restore_handoff.py`. Both transfer
archive hashes, all nine PCAP hashes, and the restored evidence-file checksums matched. The three original
captures are in `.tools/pcap-corpus/downloads/`; the six generated variants are in
`.tools/pcap-corpus/derived/`. The [corpus manifest](research/real-pcap-corpus.json) records their pinned
hashes and independent metrics; the [corpus record](research/real-pcap-corpus.md) and restored provenance
retain publishers, transformation commands, notices and interpretation limits.

| Local file relative to `.tools/pcap-corpus/` | Frames | Truncated frames | DNS query / response frames |
| --- | ---: | ---: | ---: |
| `downloads/lotsofweb.pcapng` | 12,899 | 0 | 111 / 56 |
| `derived/web-omit.pcapng` | 12,849 | 0 | 111 / 56 |
| `derived/web-snap96.pcapng` | 12,899 | 7,949 | 111 / 56 |
| `downloads/download-slow.pcapng` | 10,728 | 0 | 0 / 0 |
| `derived/slow-omit.pcapng` | 10,678 | 0 | 0 / 0 |
| `derived/slow-snap96.pcapng` | 10,728 | 7,141 | 0 / 0 |
| `downloads/own_traffic_capture_01.pcap` | 11,430 | 0 | 13 / 13 |
| `derived/lab-omit.pcapng` | 11,380 | 0 | 12 / 13 |
| `derived/lab-snap96.pcapng` | 11,430 | 7,333 | 13 / 13 |

Each case passed its 20 checks for hashes, references, no live collection, scoped diagnosis,
independently decoded frame/truncation/DNS counts and coverage reporting. All nine diagnoses remain
`insufficient_evidence`. Removing capture records or truncating captured lengths changes visibility;
it does not establish actual packet loss, incident cause or recovery. The new JSON results are in
`.tools/pcap-corpus/issue1-validation/validation.json`.

## Packages and extraction

The suite ZIP SHA-256 is `b693a540b368d3443661e79ffe24ebb29644dc8c9e1de024cdb059b5c914c367`.
Both independent archives contain the same 35 allowlisted files, including five skill roots and the suite
inventory. Their adjacent manifests are byte-identical and record every file hash. The unchanged
16-file standalone collector ZIP retains SHA-256
`f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.

The extracted-package check used a new temporary directory, copied only the controller test module and
the original web capture, and cleared `PYTHONPATH`. It ran all controller tests against extracted code,
then invoked the extracted collector through the extracted controller, imported its four checked
summaries, verified evidence references and artifact hashes, and exported the case without mutation.
The diagnosis remained `insufficient_evidence` under `offline_pcap`; the operation settled with one
charged collection round and no live network collection. This was an independent extraction, not an
operating-system sandbox or a host skill-discovery test.

## Remaining acceptance limits

The original matched R02/R04/R13 behavior results remain historical evidence; they were not rerun or
reinterpreted as production outcomes. Strict R08 no-parser/no-shell isolation, actual host discovery and
invocation, native Windows, and MobileWork remain unvalidated. The paired Packet-Foo TLS captures were
not part of the transferred nine-file corpus and were not rerun. These are declared acceptance limits,
not additional implemented features or evidence that a real service recovered. Publication and merge
remain outside this work.
