# v0.1 implementation validation — 2026-11-12

This record covers the implementation and candidate package built from base commit `6dad363bd3e0c5aff73a064a100e2be9578187f5` with the v0.1 implementation changes in this branch. The independent final review is pending. If review changes any packaged file, rebuild and repeat package validation before relying on these hashes. These results do not constitute M2 or publication acceptance.

## Environment and automated checks

- Linux x86-64 on WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`; Python 3.14.8; curl 8.23.0; TShark 4.7.4.
- `python3 -B -m unittest discover -s tests -v`: 60 tests passed, exit 0. The output is retained locally at `/tmp/netops-v01-unittest.log` while that temporary directory exists. The tests include real loopback HTTP, real TShark with a synthetic capture, adapter and contract checks, bounded process checks, and eleven package-builder checks.
- `python3 /home/pejoy/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/internet-access-triage`: `Skill is valid!`, exit 0.
- `tests/test_diagnosis.py` independently supplies expected states, candidate domains, evidence IDs and claim boundaries for INET-01, 05, 06, 07, 10, 18, 20, 23, 24, 25, 26 and 27. All twelve passed, as did seven additional diagnosis and report regressions. These are deterministic replays of supplied observations. They do not establish that an injection worked, that a same-IP comparison isolated a resolver, or that any specific device, queue, server or network was responsible. INET-24 uses a replayed capture summary; the separate package check below exercises a real parser on a different synthetic capture.

## Reproducible package and extraction

Two invocations of `python3 -B scripts/build_release.py --out <new-directory>/internet-access-triage-0.1.0.zip` produced byte-identical ZIPs and byte-identical sidecars (`cmp` exit 0 for each). Each ZIP is 196,720 bytes, contains the explicit 16-file allowlist, and has SHA-256 `b8bf4b65672fcbb1662b8cfc17af0c26951ad0a57c94affca60adb618ee90cb7`. The first archive was extracted into `/tmp/netops-v01-final/extracted`, independently of the source tree. Package files, manifests, raw output, the test input and check script remain under `/tmp/netops-v01-final/` while that temporary directory exists; they are not included in the distributable.

- Extracted CLI, controlled local HTTP service on `127.0.0.1`, `--allow-http --max-response-wait-ms 1000`: exit 0 in 0.162 s; three complete HTTP 200 responses; `healthy_within_scope`; eight evidence records; no diagnosis or evidence validation errors. The synthetic query token did not appear in the four agent-visible output files. The test environment exposed curl but no DNS or ping executables, so no DNS or ping requests were made. Nine artifact hashes and all 16 packaged source hashes matched the manifest.
- Extracted CLI, `--pcap <synthetic-http.pcap> --tshark /usr/sbin/tshark`: exit 0 in 1.206 s; six selected frames and one paired final HTTP response; `insufficient_evidence`; one evidence record; no validation errors. Six artifact hashes and all 16 packaged source hashes matched the manifest. The capture SHA-256 was `a0a7c6e84f2e28158b71b6bdddb5c89e4f4cad897fcb27f80ed3e112bbc4587a` and matched the external-input reference.
- No existing capture was found in the project, sibling workspace or `/tmp`. The test input was generated outside the package using `make_http_capture` in `tests/test_pcap.py`: six synthetic Ethernet/IPv4/TCP packets with documentation-only addresses, a three-way handshake and an HTTP request/response. This is an offline file, not captured production traffic or a live probe.

The first package-check harness incorrectly treated the dictionary `{"diagnosis": [], "evidence": []}` as a failing nonempty result. The harness was corrected to check both lists, then the final package was rebuilt and both checks were rerun. No earlier result is represented as a pass here.

## Outstanding work

Independent Sol review and any review-driven changes remain pending. Controlled DNS/TCP/response/load injection, independent confirmation and recovery checks (T08), native Windows execution, actual MobileWork import and workflow/screenshots, external security checks, and publication have not been performed. The synthetic replay and local loopback checks do not establish public-network accuracy. The earlier discovery validation and checkpoint observations are separate from this record.
