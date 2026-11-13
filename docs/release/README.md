# Release handoff

This directory contains operator instructions, copy-ready prompts, sample validation cases, and evidence templates for the Network Skill Suite. These are preparation materials. MobileWork client behavior, native Windows behavior, and all 60 external security checks remain `pending_user`.

## Contents

- [Client validation cases](client-cases.md): V-01 installation/loading, V-02 default workflow, V-03 input/output, and normal, change, error, and invocation cases.
- [Expert routing prompt](expert-routing-prompt.md): a manual prompt for the eight Skills.
- [Per-Skill validation ledger](per-skill-validation-ledger.md): evidence fields and pending results.
- [Security criteria ledger](security-criteria-ledger.md): all 43 static and 17 dynamic source criteria.
- [Dependency inventory](dependency-inventory.md): runtime and optional tools, development packages, and licensing.
- [PCAP index](pcap-index.md): public-source provenance for three original and six derived capture inputs.

Use a fresh output directory when preparing the self-authored validation inputs. The generated bundle and request files are samples for offline analysis, not evidence of current network health or business recovery. Resolve the portable request template on the user's host as described beside the input set.

## Run the three incident examples

After extracting the handoff and the standalone `netops-incident` 0.2.0 package, place both directories side by side. From their parent directory, create a separate work folder and resolve each portable request. The materializer writes only the request file; preserve the command output in the work folder as the sample result.

```sh
mkdir -p user-work
python3 validation-inputs/materialize_request.py --root validation-inputs --template normal/request.template.json --out user-work/normal-request.json
python3 netops-incident/scripts/review_service.py --input user-work/normal-request.json > user-work/normal-result.json
python3 validation-inputs/materialize_request.py --root validation-inputs --template missing-reverse/request.template.json --out user-work/missing-reverse-request.json
python3 netops-incident/scripts/review_service.py --input user-work/missing-reverse-request.json > user-work/missing-reverse-result.json
python3 netops-incident/scripts/review_service.py --input validation-inputs/malformed-input.json > user-work/malformed-stdout.txt 2> user-work/malformed-stderr.txt
```

The normal output should report technical conformance for the supplied historical sample while leaving human signoff pending. The changed example has five forward measurements and lacks reverse measurements; expect A-to-B reviewable, B-to-A unverified, and overall technical conformance unverified. Malformed JSON must be rejected. Save the exact package hashes, exit statuses, client/environment versions, original screenshots, and observed result files in the user's ledger. All actual results remain `pending_user` until the user runs these commands and any required target-client checks.

Do not place private source maps, raw captures, customer records, credentials, or evaluator expectations into a release package. Preserve pending results until the named user performs the relevant check and records source evidence.
