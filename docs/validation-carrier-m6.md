# Carrier M6 validation record

Implementation base: merged M5 `6a7eed154889d44a089f9c7fead1f0ed55aa0084`.
Issue: [#10](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/10).

Initial implementation froze at `abfd0cc8fa028444a9cd5ca58090cdb3d3a41dfc` before execution.
Focused scoring passed 10 tests. The first corpus check reported one error in four tests;
the first isolation check reported two failures and one error in five tests. Logs are
`.tools/carrier-m6/focused-{scoring,corpus,isolation}-v1.log`.

Frozen-source diagnostics found an identifier-valued telemetry record whose value did not
match its remapped allowlist. The isolation trace found Python 3.14's script-open path uses
`ioctl(FIOCLEX)`, which the blanket ioctl filter denied. These are failed first gates, not
passing release evidence. All check processes ended before correction authoring began.
The correction also preserves the existing importer's line-size limit when serializing larger
M5 inputs. No checks run during authoring; refreeze, final gates and independent Sol review
remain pending.

Subsequent frozen focused runs retained these results:

| Run | Result | Diagnosed correction |
| --- | --- | --- |
| v2, `53f594e` | Corpus 6 and scoring 10 passed; isolation 4/5 passed | Permit read/write on the exact null device for subprocess input |
| v3, `50fa155` | Isolation 4/5 passed | Use `fcntl` for adapter pipe nonblocking flags; retain the ioctl restriction |
| v4, `c7bfa40` | Isolation 4/5 passed | Permit directory reads for the existing confined reader's ancestor traversal |
| v5, `5f44f74` | Isolation 4/5 passed | Copy the provider's schema dependency and preserve its scripts/schemas layout |

Each failed isolation run retained its working oracle/sibling denial, output cap, process-group
timeout cleanup and unavailable-setup control. The actual provider control remained a failure
until the complete dependency tree was supplied. See `focused-isolation-v2.log` through
`focused-isolation-v5.log` and the corresponding `diagnose-*`/`isolation-strace-*` logs under
`.tools/carrier-m6/`. No failed run is counted as release success.

Later frozen runs retained these results:

| Run | Result | Follow-up |
| --- | --- | --- |
| v6, `363ff2c` | Five isolation controls passed; full regression interrupted with exit 130 | Remove an extra per-job oracle field rejected by the strict CLI contract |
| v7, `661d201` | Corpus execution stopped at case 018 | Keep source-declared ordering rather than infer a source key from its run ID |
| v8, `58d515d` | 36 cases completed, but service semantics were incorrect | Preserve protocol field/criterion IDs and independently expand complete service truth |
| v9, `956a265` | 36 cases / 44 jobs completed; all 36 substantive replays matched | Retain measured citation and coverage limitations |
| v9 focused/full | 56 focused and 257 full tests each reported one failure | A new test selected M6 catalog IDs instead of the intended M5 parent cases; correct inputs only |

The final isolation policy removes the temporary global directory-read grant: Linux `O_PATH`
ancestor handles let the shared confined reader traverse without granting private directory listing.
The final controls also cover combined pipe-EOF timeout/output limits. The original Internet
collector, four diagnosis states and 25-second collection budget remain unchanged.

## Frozen runtime evidence

Runtime and fixtures: `956a265`. Environment: Kali 2026.3 rolling under WSL2 Linux
`6.18.58.1-microsoft-standard-WSL2`, x86-64, Python 3.14.7, Landlock ABI 7.

| Check | Actual result | Local evidence |
| --- | --- | --- |
| Actual restricted providers | 36 cases, 44 completed valid jobs | `.tools/carrier-m6/all-v9/`, `all-v9.log` |
| Canonical replay | 36 compared, zero mismatches | `.tools/carrier-m6/replay-v9/`, `replay-v9.log` |
| Fresh extracted runtime regression | 153 tests passed in 304.418 seconds | `.tools/carrier-m6/delivery-v9.log` |
| Suite and eight individual archives | Double builds, member hashes/manifests and clean extraction passed | `.tools/carrier-m6/delivery-v9/delivery-verification.json` |
| Original standalone Internet archive | 16 files; SHA256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` | Same delivery record |
| Managed original web PCAP | Passed offline; capture hash verified; no live collection | Same delivery record |
| Eight Skill validators | Passed | `skill-validators-v9.log` |
| Python 3.10 grammar | Passed; not an actual Python 3.10 execution | `grammar-v9.log` |

The suite has 61 files / 698,920 bytes, SHA256
`fde2933c383e85a8864b2dac525fa1e1e4b10c70fdaf645c5a6572356f4013dd`.
The shared reader changed, so the fresh extracted regression above supersedes reuse of M5 results.
Developer evaluation files, hidden truth, raw evidence and private mappings are absent from archives.

These deterministic provider measurements are separate dimensions, not a perfect overall grade:
state 34/34; service technical, acceptance and change states each 10/10; grounded fault class and
layer each 28/28; claim recall 336/349; complete claim grounding 78/334; counterevidence precision
and recall each 12/21. Resource localization and unknown token/cost fields remain null. Citation
and coverage shortfalls are measured baseline limitations; independent truth was not weakened to
make them pass. No conclusion about an untested LLM follows from these results.

Final test-only input correction, complete regression and independent Sol review are pending.

Controlled-lab injection plans are unexecuted. No live LLM, MobileWork, native Windows, real-device
or external security acceptance is claimed. Actual M7 client/Windows/security validation remains
explicitly deferred to the user.
