# Final scoped independent v0.1 re-review — 2026-11-12

Reviewed commit: `87df280e33c204e5dd85151a45b570b8adcfbaae` on `feat/complete-v0.1`.
Previous reviewed commit: `984674be71ec2bac369c704d40ef980ad4a54019`.

This is the final independent re-review of the five findings in `/tmp/netops-v01-sol-review.md`, the complete fix diff, and the touched interfaces and regressions. It also checked `/tmp/netops-v01-fixes.md`, [the review-fix validation record](validation-v0.1-review-fixes-2026-11-12.md), the replay contract, package identity and the retained extracted-package results. The scope remains T01–T07 and the reproducible release-building portion of T09. No agents were spawned and no tracked file, index, HEAD, branch or remote state was changed.

## Verdict

**All five findings are resolved. No residual actionable finding was identified in this scoped re-review.**

**Spec verdict: pass for the current v0.1 goal and reviewed scope.** The fixes now enforce literal URL attempts, preserve observed timeout failures, exclude credential-bearing proxy diagnostics, supply bounded interface context, and exercise the required same-IP DNS and independent target TLS replay comparisons. The outstanding M2/native-client/controlled-experiment work remains explicitly excluded and unclaimed.

**Quality verdict: pass. Ready for integration within this scope.** The full suite independently passed all 68 tests, including the real local reproductions that previously failed. Additional missingness, proxy-variable and IPv6 replay checks passed. The independently rebuilt package exactly matches the new recorded package. This review verdict does not authorize a merge, push or publication operation.

## Per-finding dispositions

### 1. Proxy credential disclosure — resolved

The fix is at [live.py:269](../skills/internet-access-triage/scripts/netops/live.py#L269) and the safe-stderr selection around line 663. When HTTP, HTTPS or ALL proxy environment values contain userinfo, curl diagnostic text is withheld before it is written to the stderr artifact, observation or failure. Structured curl metadata and return codes are still parsed from the in-memory output, preserving the failure classification.

The real curl regression passed for malformed SOCKS4, SOCKS4a, SOCKS5, SOCKS5h, HTTP, HTTPS and scheme-less proxy values. It verifies that both synthetic credential components are absent from `manifest.json`, `evidence.jsonl`, `diagnosis.json`, `report.md` and retained stderr files. Additional independent actual CLI checks passed for lowercase and uppercase HTTP/HTTPS proxy variables and ALL_PROXY using a loopback target and a locally rejected proxy value. These artifacts are in `/tmp/netops-sol-final-extra-7bffb9q7/`.

The original SOCKS syntax-error leak no longer reaches visible or redacted artifacts. The conservative diagnostic suppression is acceptable: it preserves the structured result while avoiding dependence on curl's error wording.

### 2. Curl URL expansion and request accounting — resolved

`_curl_command` at [live.py:307](../skills/internet-access-triage/scripts/netops/live.py#L307) now includes `--globoff`, as does the recorded safe command. This prevents brace/range expansion before any network transfer.

Real loopback regressions passed for `/sample/{one,two,three,four}` and `/sample/[1-4]`: the server sees the literal path exactly three times and the manifest records three attempts. A two-target test observes and records exactly six requests. A real IPv6 loopback test also passes with three requests. No IPv6 test was skipped in the independently executed suite.

The fix restores the relationship between a configured literal URL, one curl invocation and one attempted HTTP transfer under the existing request limits.

### 3. Stalled 5xx/3xx bodies lose timeout classification — resolved

The HTTP status rewrite at [live.py:683](../skills/internet-access-triage/scripts/netops/live.py#L683) now applies only when the adapter outcome is `response`. A curl exit-28 timeout therefore survives independently of any previously received HTTP status.

The actual CLI regressions for both status 500 and status 302 passed. All three attempts for each endpoint retain the header status, exit code 28, `outcome: timeout` and `transfer_complete: false`; diagnosis reports `fault_observed` with a `request_timeout` candidate. Incomplete transfers stay out of successful HTTP groups. Existing budget-expiry replay coverage still reports insufficient evidence rather than inventing a business timeout.

### 4. Available interface counters missing — resolved

The new `_interface_counters` at [live.py:191](../skills/internet-access-triage/scripts/netops/live.py#L191) reads a bounded Linux `/proc/net/dev` snapshot for the default-route interface. It records interface identity, source, timestamp, values and units. It checks the shared budget before and after reading and handles missing interfaces, unreadable sources, malformed rows, negative values, oversized input and unsupported platforms with explicit missingness. No rate or load cause is inferred from a single snapshot.

The sample-input, budget and local-context tests passed. Additional independent checks passed for absent rows, malformed rows, negative counters, oversized input, missing interface and expired budget. The retained extracted-package live output contains a complete `eth2` snapshot; its artifact and source hashes were independently rechecked. This remains a Linux/WSL implementation check, not native Windows validation.

### 5. Required replay comparisons missing — resolved

The same-IP comparator at [diagnosis.py:383](../skills/internet-access-triage/scripts/netops/diagnosis.py#L383) requires at least three complete normal/pinned HTTPS pairs within the replay window. It requires explicit matching URL, Host, SNI, certificate verification, actual IP/family, GET method, direct proxy path, vantage, fresh connection and pin state. The measurement must be finite and the DNS-stage difference must exceed the configured comparison limit. The candidate cites the exact six request records and preserves the limits on causation, resolver CPU and responsibility.

INET-01 now exercises the positive comparison and rejects mismatched context and stale-window inputs. Additional independent checks confirmed the positive IPv6 comparison, rejection of missing context fields and exclusion of these derived comparisons from live mode. No live pinned collector or controlled DNS isolation is claimed.

The independent TLS reader at [diagnosis.py:452](../skills/internet-access-triage/scripts/netops/diagnosis.py#L452) accepts a separately identified same-target HTTPS observation only with the matching hostname/SNI, enabled verification, boolean result and valid window. Failed observations join supporting evidence; passed observations join counterevidence. INET-06 verifies both roles with exact references and rejects unrelated, unverified, wrong-SNI, curl-tool and stale-window observations. The candidate explicitly states that this does not establish a shared path or responsibility.

## Verification performed

- `python3 -B -m unittest discover -s tests -v`: **68 tests passed**, exit 0, 31.688 seconds. This includes all twelve core replay tests, the new real curl regressions, IPv6 loopback, real TShark parsing, contracts, runner cleanup and deterministic packaging tests.
- Additional independent checks: eleven proxy-variable/interface-missingness checks passed in `/tmp/netops-sol-final-extra-7bffb9q7/`; IPv6 same-IP positive/reference checks, missing-field negatives and live-mode exclusion also passed.
- Two independent builds in `/tmp/netops-sol-final-release-8ehozqf8/` produced byte-identical ZIPs and byte-identical sidecars. Each archive has **16 files**, **207985 bytes**, and SHA-256 **`3395dea80c52d312259215096136f253115d10dc500876c778dcb3789f5f9088`**. All archived files match their sidecar hashes.
- Independently rechecked retained extracted-package artifact hashes (nine live, six PCAP), all 16 source hashes in each run, equality of extracted sources with the frozen repository, zero validation errors and the recorded local outcomes. The retained checks report three complete HTTP 200 responses with an explicit baseline and `healthy_within_scope`, plus a real TShark parse of the six-frame generated capture with one paired final response and `insufficient_evidence`. These checks remain disclosed as local/synthetic validation.
- `git diff --check` passed. HEAD remains `87df280e33c204e5dd85151a45b570b8adcfbaae` and the worktree remains clean. Documentation, comments, tests and reported output remain in English. Accepted engineering configuration was preserved.

## Explicit exclusions

This review does not validate T08 fault injection, independent causal confirmation or recovery/cleanup; native Windows execution; MobileWork import, trigger, workflow or screenshots; external security checks; publication; public-network accuracy; or device/AS/server/queue responsibility. Deterministic replay, WSL2 and generated captures do not substitute for those activities. The accepted triage labels were not changed or reclassified.

The re-review was scoped to the five reported findings, their implementation changes, affected interfaces and regressions. It is not a new claim of exhaustive correctness for every preexisting or future behavior.

## Final documentation recording

A mechanical documentation-only follow-up may record this passing result, preserve this report, replace the pending-review wording and identify the reviewed commit and package hash. **No further full code review or package rebuild is needed for that recording**, provided it changes no packaged file, runtime behavior, test expectation or stated acceptance scope, and preserves the exclusions above. This is approval of that review-record update only; no merge, push or publication authorization is implied.
