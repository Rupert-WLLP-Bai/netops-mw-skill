# Internet Access Triage and Evidence Localization

> **Controller fixes verified:** The four findings in [issue #1](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/1) are fixed at `354b402`. All 125 tests, nine real-PCAP cases, extracted-package checks, and [Sol re-review](docs/review-network-skill-suite-issue1.md) passed. See the [current validation record](docs/validation-network-skill-suite-issue1.md) for package hashes and remaining host/platform acceptance limits.

A runnable Skill for one target and symptom: bounded local collection, explicit counterevidence, and at most two supported investigation directions. It also analyzes an existing PCAP independently of live probing.

## Network skill suite

The versioned suite combines the existing collector with four direct-entry skills: incident coordination, offline capture analysis, recovery verification, and handoff drafting. The incident skill includes an optional local case controller for evidence, budgets, decisions, and recovery records; the other new skills also work directly from supplied inputs. They do not perform repairs or send handoffs. The [current suite validation record](docs/validation-network-skill-suite-issue1.md) describes the checks and remaining limits.

A local build is available at `dist/network-skill-suite-0.1.0.zip` with its adjacent manifest in this workspace. Build a new archive from source with `python3 -B scripts/build_suite.py --out dist/network-skill-suite-new.zip`; the builder refuses to overwrite an archive or manifest. Extract the five skill directories and use the host's supported discovery or explicit loading method. Discovery and target-host installation have not been established by the local package tests. The inventory describes the optional collector interface; it does not require an assumed sibling installation path.

The case CLI lives at `skills/netops-incident/scripts/case.py`. Run it with `--help` and read the [case contract](skills/netops-incident/references/case-contract.md) for JSON input, authorization, evidence, and lifecycle details. For standalone capture analysis use the existing offline command below; recovery verification and handoff drafting can also use supplied records without the controller.

### Carrier domain contracts (M1)

The incident controller also accepts optional, versioned carrier service context and evidence metadata.
The [domain glossary](GLOSSARY.md) defines service, circuit, device, interface and related objects across
six network layers. The bundled [carrier contract](skills/netops-incident/references/carrier-evidence-contract.md)
defines source-qualified identifiers, declared topology relationships, raw measurements, clock uncertainty,
redaction hashes and comparison gaps. Context changes invalidate earlier verification and decision eligibility;
legacy records without carrier fields retain their existing behavior.

M1 supplies contracts and validation for offline operator-provided records. Access diagnostics, transport
diagnostics, vendor parsers, service acceptance, and live platform integration are later milestones in
[the carrier expansion](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/3).
See the [M1 implementation plan](docs/implementation/carrier-m1-plan.md) for scope and validation order.
The [M1 validation record](docs/validation-carrier-m1.md) records 141 passing tests, 62 tests against
an independent package extraction, reproducible package hashes and [final Sol review](docs/review-carrier-m1.md).
M1 was merged through [PR #12](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/pull/12).
It does not establish vendor, MobileWork or native Windows support. Subsequent work is tracked in the
[carrier milestone tracker](docs/implementation/carrier-completion-tracker.md).

### Offline carrier evidence ingestion (M2)

The incident bundle includes `scripts/ingest.py` for explicitly selected, versioned JSON/CSV telemetry,
topology and optical exports, generic CLI key/value records, and a safe syslog-header subset. Its
[ingestion contract](skills/netops-incident/references/offline-ingestion.md) defines format detection,
budgets, private raw storage, allowlisted visible derivatives and import into existing cases.
Unknown vendor text and binary OTDR/SOR are not interpreted as supported formats. Import does not
establish service health, source authenticity or a fault cause. See the
[M2 plan](docs/implementation/carrier-m2-plan.md) for implementation and verification scope. The
[M2 validation record](docs/validation-carrier-m2.md) records final regression and reproducible packages;
[Sol review](docs/review-carrier-m2.md) passed both review axes.

The historical [final scoped independent re-review](docs/review-v0.1-2026-11-12.md) passed at source commit `87df280e33c204e5dd85151a45b570b8adcfbaae`. All 68 tests passed, and the reproducible package SHA-256 is `3395dea80c52d312259215096136f253115d10dc500876c778dcb3789f5f9088`. The [validation record](docs/validation-v0.1-review-fixes-2026-11-12.md) records the checks and limitations; the original discovery checks remain separate.

A subsequent real-capture validation found and corrected a DNS direction-count defect. The [pre-fix corpus record](docs/research/real-pcap-corpus.md) and [post-fix validation](docs/research/real-pcap-postfix-validation.md) describe the evidence and candidate package. The [combined independent review](docs/research/closed-loop-real-pcap-review.md) approved the correction and research within its stated scope: 72 tests and all nine corpus checks passed; the candidate package SHA-256 is `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.

## Run

Python 3.10 or later is required. curl supplies HTTP observations. dnslookup and native ping are optional collection capabilities; TShark is required for offline packet analysis. Missing tools produce explicit coverage limits.

Replace the example URL with the service you intend to diagnose. Output must name a new directory; use a parent directory that already exists.

```bash
python3 -B skills/internet-access-triage/scripts/diagnose.py \
  --url https://service.example/health \
  --symptom 'intermittent timeout' \
  --out ./triage-run-001
```

Add an approved comparison with `--control-url`. HTTPS is the default; an intended plain-HTTP diagnostic/test request requires `--allow-http`. No public target is chosen automatically.

For an existing capture:

```bash
python3 -B skills/internet-access-triage/scripts/diagnose.py \
  --pcap /path/to/capture.pcapng \
  --out ./pcap-run-001
```

Use `--tshark /path/to/tshark` when it is not on PATH. Run `--help` for resolver, filter, and explicit latency-baseline options.

The output directory contains `report.md`, `diagnosis.json`, `evidence.jsonl`, `manifest.json`, and local `raw/` evidence. The manifest records tool versions, redacted command records, actual collection counts, validation failures, runtime-source hashes, and artifact hashes. Review raw evidence before sharing it.

## Verify and Build

```bash
python3 -B -m unittest discover -s tests -v
python3 -B scripts/build_release.py --out dist/internet-access-triage-0.1.0.zip
```

For the optional real-capture check, obtain the pinned capture files and derived variants described in the corpus record, then run `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/validation-new`. The validator checks local hashes and does not download or probe; choose a new output directory. It is a developer tool outside the package.

The release uses an explicit file list and deterministic ZIP metadata. Its sidecar records package and file SHA-256 values. Existing outputs are preserved; choose a different destination for a new build.

## Interpretation

The live collection budget is 25 seconds including a two-second completion reserve. HTTP is limited to three requests per endpoint and two endpoints; optional DNS and ping share the same deadline. Offline mode has separate time, input, frame, and event-output limits.

A short successful window ordinarily means `not_reproduced`. `healthy_within_scope` requires an explicit applicable baseline and sufficient observations. Other states are `fault_observed` and `insufficient_evidence`. Extraction success, ping alone, intermediate-hop silence, and TCP decoder warnings cannot establish a root cause.

The initial validation platform is Linux/WSL. Native Windows, actual MobileWork import/triggering, controlled fault-injection and recovery, external security review, and publication remain separate acceptance work. Path collection, Globalping, live capture, HAR, WebRTC, active load generation, and automatic repair are later extensions.

## Project Records

| Document | Purpose |
| --- | --- |
| [Current suite validation](docs/validation-network-skill-suite-issue1.md) | Controller fixes, 125 tests, restored nine-file corpus, reproducible packages, and limitations |
| [Suite re-review](docs/review-network-skill-suite-issue1.md) | Final Sol standards and specification verdicts for the corrected source |
| [Earlier suite validation](docs/validation-network-skill-suite.md) | Historical checks before issue #1 corrections |
| [Implementation plan](docs/delivery-plan.md) | Scope, tasks, twelve core cases, release criteria |
| [v0.1 validation](docs/validation-v0.1-review-fixes-2026-11-12.md) | Test, candidate package, extraction checks, and outstanding work |
| [Final scoped review](docs/review-v0.1-2026-11-12.md) | Independent review verdict and exclusions |
| [Project baseline](docs/research/current-state.md) | Existing assets and discovery/publication gaps |
| [Real PCAP corpus](docs/research/real-pcap-corpus.md) | Public captures, reproducible impairment variants, and pre-fix results |
| [Post-fix PCAP validation](docs/research/real-pcap-postfix-validation.md) | Corrected results, candidate package checks, and review |
| [TShark integration](docs/research/tshark-integration.md) | Offline interfaces and interpretation boundaries |
| [Upstream pattern review](docs/research/upstream-patterns.md) | Pinned sources and verified reuse patterns |
| [Source manifest](docs/research/source-manifest.json) | Original-byte hashes and archive structure checks |
| [Discovery validation](docs/research/validation-2026-11-12.json) | Legacy checks, distinct from v0.1 runtime tests |
| [Engineering configuration](AGENTS.md) | GitHub Issues, triage labels, domain documents |

Tasks live in [GitHub Issues](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues). Edit `docs/agents/*.md` directly when conventions change.
