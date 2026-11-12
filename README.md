# Internet Access Triage and Evidence Localization

A runnable Skill for one target and symptom: bounded local collection, explicit counterevidence, and at most two supported investigation directions. It also analyzes an existing PCAP independently of live probing.

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
