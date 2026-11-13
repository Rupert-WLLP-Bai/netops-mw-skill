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

The existing collector, incident runtime, four diagnosis states and 25-second Internet collection
budget are protected. Developer evaluation files and oracle must remain outside every Skill archive.
M5's exact-source package validation is historical evidence, not a new M6 run.

Controlled-lab injection plans are unexecuted. No live LLM, MobileWork, native Windows, real-device
or external security acceptance is claimed. Actual M7 client/Windows/security validation remains
explicitly deferred to the user.
