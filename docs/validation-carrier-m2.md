# Carrier M2 validation

This report records final local validation for [issue #6](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/6) at frozen source commit `f78c8972fffdb44619954afd4eb0b96f4652ca5b`. It covers bounded offline ingestion and suite packaging. It does not establish actual MobileWork, native Windows, vendor interoperability, or external-security acceptance.

## Final results

| Check | Result |
| --- | --- |
| Full repository suite | 162 tests passed in 71.240 seconds; no skips |
| Independent extracted suite | 83 tests passed in 38.321 seconds; no skips |
| Suite archive and manifest | Two builds byte-identical; 42 files; SHA-256 `6d471218b6cc6085c88f6297bc8e0f62458581e33d0c786ad8b773c0666638b4` |
| Standalone collector archive | Unchanged 16-file archive; SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` |
| Archive verification | All member hashes checked; both archive/manifest pairs reproduced identically |
| Legacy managed PCAP check | Passed against the retained local capture; no live network collection |
| Final independent Sol review | Standards and specification both pass; zero open findings |

The Standards reviewer independently repeated all 21 ingestion tests; the Spec reviewer repeated the public count and freshness reproductions. The final suite package excludes fixtures, private alias maps, raw originals, hidden answers, and development dependencies. Existing Skill entry points, diagnosis states, standalone collector, and collector budget remain unchanged.

## Corrections and rerun

The first final Sol review identified two specification findings. JSON and CSV count parsing now accepts finite, non-negative integral numeric values, including `1.0`, while rejecting booleans, fractions, negatives, and non-finite values. Collection age is evaluated for all formats and failure outcomes, independently of per-event age. A stale topology snapshot retains its declared historical links and carries the `stale` quality code.

The first final run also exposed an authoring error in the malformed-CSV golden input: its row had the same number of columns as the header and was valid. The fixture input was corrected to include an actual extra column. Its expected `parse_error` result was preserved, and the input hash was updated in the provenance manifest. Final review checked all 13 fixture provenance hash sets. The passing R2 run and review apply to the corrected fixture at `f78c897`.

## Scope and limits

The adapter uses Python standard-library code and adds no third-party parser dependency. The synthetic fixture provenance manifest declares Apache-2.0, self-authored inputs, no upstream data sources, and no reused parser libraries. No vendor transcript, customer record, or third-party sample is included. Supported input is limited to the six declared generic formats; vendor-specific payloads and binary OTDR/SOR parsing are not claimed.

Results are local and offline. They do not establish execution on native Windows or inside the actual MobileWork client, and do not claim vendor compatibility or external security review. The user's M7 client/native Windows/security execution remains deferred and pending user evidence.

## Retained evidence

Local review and execution evidence is retained under `.tools/carrier-m2/`:

- `full-suite-reviewed.log` — final full-suite output.
- `delivery-reviewed.log` and `review-fix-delivery/delivery-verification.json` — final package verification and extracted-suite result.
- `sol-standards-r2.md` and `sol-spec-r2.md` — final independent Sol reports.
- `full-suite-final.log`, `delivery-final.log`, and `final-delivery/` — earlier final-gate artifacts, before the two review corrections.

These local evidence files are not part of the distributable package.
