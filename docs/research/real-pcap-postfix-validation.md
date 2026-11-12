# Real capture corpus: post-fix validation

**Result: the [combined independent review](closed-loop-real-pcap-review.md) approved the DNS direction fix and research within its stated scope; all 72 tests and nine offline corpus checks passed.** The [pre-fix corpus](real-pcap-corpus.md) retains the original failing evidence and capture provenance. The ten [closed-loop journeys](closed-loop-scenarios.json) remain designs. These checks do not establish production network health, incident recovery, or architecture approval.

The public lotsofweb EK originally produced 167 query and 0 response frames, while independent TShark filters produced 111 and 56. The parser now recognizes TShark `"True"`/`"False"` strings, native booleans and integer/string 0/1. Missing or unrecognized direction values are counted as unknown. Multiple directions in one frame can increment both frame counts; mixed frames and unknown frames have additive counts. The [evidence contract](../../skills/internet-access-triage/references/evidence-contract.md) defines the overlap and field-unavailability behavior. The diagnostic decision logic did not change.

The new regression failed before the fix; focused tests then passed. The real public capture EK was also checked before the fix and failed against independent 111/56 counts. The completed full suite ran `python3 -B -m unittest discover -s tests -v`: **72 tests passed** in 32.122 seconds. An intentionally altered frozen response count made the validator exit 1, confirming it reports an actual mismatch.

Run the local-only developer tool with `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/validation-new`. It requires the files and hashes in [the original corpus manifest](real-pcap-corpus.json), refuses changed inputs and an existing output directory, and does not download or probe. It executes the actual CLI, independently obtains TShark frame, truncation and DNS-direction frame counts, and checks captured input, source, artifact and evidence-source hashes, diagnosis references, tool completion and scoped status. Full run artifacts stay ignored under `.tools/pcap-corpus/`; [aggregate machine-readable results](real-pcap-postfix-validation.json) contain no packet payload.

| Case | Frames | Truncated frames | Query / response frames | Unknown / mixed frames | CLI seconds | Status |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| web/original | 12899 | 0 | 111 / 56 | 0 / 0 | 2.215 | insufficient_evidence |
| web/omit | 12849 | 0 | 111 / 56 | 0 / 0 | 1.983 | insufficient_evidence |
| web/snap96 | 12899 | 7949 | 111 / 56 | 0 / 0 | 2.087 | insufficient_evidence |
| slow/original | 10728 | 0 | 0 / 0 | 0 / 0 | 1.975 | insufficient_evidence |
| slow/omit | 10678 | 0 | 0 / 0 | 0 / 0 | 1.952 | insufficient_evidence |
| slow/snap96 | 10728 | 7141 | 0 / 0 | 0 / 0 | 1.858 | insufficient_evidence |
| lab/original | 11430 | 0 | 13 / 13 | 0 / 0 | 1.863 | insufficient_evidence |
| lab/omit | 11380 | 0 | 12 / 13 | 0 / 0 | 1.704 | insufficient_evidence |
| lab/snap96 | 11430 | 7333 | 13 / 13 | 0 / 0 | 1.882 | insufficient_evidence |

All nine rows passed the listed checks. The slow capture contains no DNS-dissector direction fields, so its 0/0 result is not a direction-parsing test. `dns_queries` and `dns_responses` count frames, including DNS-dissector fields in LLMNR and mDNS; they do not count individual messages or prove response pairing. Capture omissions are simulated missing records, not confirmed network loss. The lab capture has non-monotonic timestamps and is not a timing baseline.

Two separately named builds of the 16-file candidate archive matched at **SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`**, 209807 bytes. The extracted package CLI was run on web original, web snap96 and lab original. All three matched input/source/artifact hashes, DNS and truncation counts, evidence references and scoped `insufficient_evidence` status; the lab run covered a TLS-bearing capture. The candidate is `dist/internet-access-triage-0.1.0-real-pcap.zip`, distinct from the historical reviewed v0.1 archive. The [combined independent review](closed-loop-real-pcap-review.md) approved the fixed runtime and candidate within its stated scope.

The tested working tree is based on `c43d3f3d63d47a69f11cf2a73ca12d047fa6f577` with uncommitted changes; `pcap.py` SHA-256 is `72a30c9e9b5440e259601cd6a32b312420de60c4d061acaa3635d082af1396af` and developer validator SHA-256 is `f0dfcb2d1fc97b0525b871efdd73998031dfee1bb3cffa8d1e21c83c443da4ef`. Native Windows, actual MobileWork import, controlled injection/recovery, external security review and publication remain unverified as previously recorded.
