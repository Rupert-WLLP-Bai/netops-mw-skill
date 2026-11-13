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

The existing collector, incident runtime, four diagnosis states and 25-second Internet collection
budget are protected. Developer evaluation files and oracle must remain outside every Skill archive.
M5's exact-source package validation is historical evidence, not a new M6 run.

Controlled-lab injection plans are unexecuted. No live LLM, MobileWork, native Windows, real-device
or external security acceptance is claimed. Actual M7 client/Windows/security validation remains
explicitly deferred to the user.
