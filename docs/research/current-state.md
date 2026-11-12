# Project Baseline and Delivery Gaps

Reviewed on 2026-11-12, before v0.1 implementation. The repository initially contained only an Apache-2.0 LICENSE at commit `4f9cd7c`. Reusable offline tools existed in the parent workspace. This record preserves that baseline; see the root README for implementation status.

## Existing Assets

The original working tree was clean on `main`; the remote is `Rupert-WLLP-Bai/netops-mw-skill`, a public GitHub repository. There was no runtime, test suite, README, agent configuration, glossary, architecture decision directory, or multi-package structure.

| Asset | Observed implementation | Reuse opportunity | Missing Internet-access capabilities |
| --- | --- | --- | --- |
| `../network-inspection-analyst` | 507-line CSV analyzer and 621-line test module; snapshot comparison, source hashes, physical line references, coverage, unknown values, JSON/Markdown reports | Evidence provenance, explicit data contracts, CLI behavior tests | HTTP/DNS/ping/path collection and Internet-specific reasoning |
| `../pcap-evidence-analyst` | 342-line Python/TShark extractor; streamed EK records, HTTP/1.x pairing, packet references, filters, parser version, source hash | Offline adapter with reproducible packet evidence | Shared deadline, input/output limits, field discovery, bounded session state, durable regression tests |
| Internet-lag research archive | 30 case definitions, five injection designs, collection budgets, draft schemas, pinned sources | Evaluation scope and reasoning boundaries | Executable Skill, actual tool output samples, injection controller, evaluator, execution results |

The CSV device/interface/neighbor state machine is specific to inspection snapshots. Reuse its evidence discipline rather than transplanting its classifications. The PCAP extractor's `ok: true` means parsing completed; it does not mean the service was healthy.

The parent directories are not repository dependencies. Selected code must be brought into the distributable with source attribution; the resulting Skill must run without parent-workspace paths.

Source locations in the old implementations: CSV evidence `scripts/analyze.py:58`, coverage `:174`, report `:437`; PCAP process execution `scripts/analyze_pcap.py:74`, analysis `:99`, CLI `:306`. Source hashes are recorded in [source-manifest.json](source-manifest.json).

## Checks Actually Executed During Discovery

Environment: WSL2/Linux, Python 3.14.7, curl 8.21.0, TShark/dumpcap/capinfos 4.6.6. Native ping was available. dnslookup, doggo, q, fping, trip, and mtr were absent. This describes the observed environment, not a certified platform matrix.

| Check | Method | Result | Scope |
| --- | --- | --- | --- |
| Legacy CSV behavior | `python3 -B -m unittest discover -s tests -v` in its directory | 19 tests passed in 1.446 seconds | Existing CSV synthetic inputs |
| Legacy PCAP CLI | Existing public sample, `--http-headers-only`, new temporary output directory | Exit 0; 271 frames; 48 paired HTTP transactions; input hash matched | One HTTP sample and the stated decoder setting |
| TShark interface | Version/field discovery, fields/json/ek, invalid field, input-frame limit | Recorded in [TShark research](tshark-integration.md) | Offline compatibility only |
| Archive integrity | Recomputed internal SHA-256 entries | 47 entries matched | Integrity, not correctness of research claims |
| Case structure | JSON parsing, required keys, enum/constants, nonempty arrays, unique IDs | INET-01 through INET-30; 14 adapted, 16 derived; all design_not_executed | Basic structure, not full JSON Schema or behavioral validation |

Commands, hashes, results, and exclusions are recorded in [validation-2026-11-12.json](validation-2026-11-12.json). Historical checks mentioned in the legacy READMEs were not automatically counted as newly executed checks.

## Changes Needed in the Research Contracts

1. Tighten nested types, units, scope, collection status, artifact location, and reference validation. The draft schemas mostly require keys and leave many values unconstrained.
2. Add structured observations for DNS answers, TTL/CNAME, response codes, addresses, and repeated packet fields. Numeric measurements alone cannot represent these facts. Keep capture time separate from analysis time.
3. Distinguish missing tools, permissions, timeout, cancellation, parser failure, and business failure. An unexecuted command may have no artifact; represent that absence rather than inventing a path/hash.
4. Enforce the shared deadline around discovery, context reads, process execution, termination, and report completion. Start ping after the first actual target address becomes available; retain fewer samples when time runs out.
5. Treat collection budgets as limits, not latency thresholds. Three HTTP observations support raw values, median, and range. A claim of slowness requires a relevant baseline, valid comparison, or explicit business failure.
6. Separate development files, controller truth, and the evaluated Agent's accessible files. A directory called controller does not enforce isolation.

The initial 12-case set is already defined: INET-01/05/06/07/10/18/20/23/24/25/26/27.

## Publication Requirements Read from the Supplied Documents

The supplied Word template, security specification, and presentation were read locally. Originals remain outside this public repository. The source manifest uses English aliases while retaining original-byte hashes.

| Source section | Observed requirement | Project implication |
| --- | --- | --- |
| User validation template: instructions | One report per Skill version; each record includes package SHA-256, environment, tester, date; screenshots are original to that run | Freeze the release, then record V-01/02/03 against that exact hash; remove the template's contact-search example and preselected pass result |
| V-01/02/03 | Installation/loading, default core workflow, input/output | CLI checks and actual MobileWork import/trigger/execution are distinct |
| Publication presentation, slides 2-3 | Normal, changed, failed, and invocation cases; recheck original failures and important regressions after fixes | Exercise missing permissions/tools, process failures, paths with spaces, misleading tickets, relevant and irrelevant requests |
| Presentation, slides 5-7 | New submission versions preserve previous packages; local validation and external reports precede publication | Separate runtime ZIP and validation attachments; development checks do not complete external review |
| Skills-001/002 | Avoid compiled executables and unnecessary document types in the package | Package necessary source and references; declare external tools rather than bundling Wireshark/Npcap/Office documents |
| Skills-003/004 | Example thresholds of 100 files and 10 MB | Conservative internal budgets are useful, but the examples do not establish the actual scanner configuration |
| Skills-005/021/023 | Archive paths, command injection, path traversal | Explicit release file list, path confinement, argument-array subprocess calls, validated inputs |
| Skills-011/024/030/040/041 | Remote download-and-execute, privilege escalation, system changes, permission consistency | Discover capabilities and degrade; no automatic driver, DNS, or interface reconfiguration |
| Skills-028/029/033 | Sensitive logs, storage, external disclosure | Raw local evidence and Agent-visible output need deliberate export boundaries |

Three publication questions remain for the actual submission:

- **Entry file spelling.** Skills-006 specifies `Skills.md`. Existing Skills and the locally inspected MobileWork 2026.2.2-34 `electron/mobilework/skill-filesystem.mjs:346` read `SKILL.md`. Keep the actual client entry file and confirm the scanner's expectation before submission. Source inspection is not client import validation.
- **External GPL tools.** Skills-036 mentions GPL/AGPL. Declare TShark's license and invocation method honestly. Excluding its executable reduces the redistributed material but does not establish acceptance under that scanner rule. See [TShark delivery considerations](tshark-integration.md#privacy-and-distribution).
- **Diagnostic protocols.** Skills-032 requires encrypted communication. HTTPS can be the default business/API transport; plain DNS and ICMP are themselves subjects of measurement. Replacing system DNS with DoH changes the observed path. Document the exact protocols/data/budgets for the reviewer instead of claiming the replacement measures the original path.

These are compatibility questions found in the supplied materials, not legal conclusions or external approval results. No reviewer was contacted and no submission or notification email was sent.

## Implementation Direction

Use Python's standard library to coordinate external CLI adapters. Each adapter produces traceable observations; diagnosis and rendering consume the same contract. Tool-provided verdicts remain unverified hints.

curl exposes structured write-out, timeouts, and cumulative connection timings; version-specific transfer limits need actual sample-output checks. dnslookup exposes JSON, explicit record types, and DNS transports; its repository states MIT licensing. Discovery did not install or validate that DNS client. [curl manual](https://curl.se/docs/manpage.html), [dnslookup repository](https://github.com/ameshkov/dnslookup).

Start with optional offline TShark. Add live capture, path probes, external measurements, HAR, and WebRTC statistics only when their collection and validation boundaries are implemented. The [delivery plan](../delivery-plan.md) defines the staged scope.
