# Carrier M5 validation record

This record covers issue #9, “C4 / M5: Add enterprise service delivery, circuit acceptance and change-review workflows,” following the M4 merge. It records implementation and validation evidence as it becomes available. No validation pass is claimed at this authoring stage; independent review and user-owned platform/security acceptance remain separate gates.

## Scope and boundaries

M5 adds an independently usable service-acceptance Skill and an optional incident-owned offline provider. Its outputs are local drafts grounded in checked, source-qualified evidence. The existing incident controller, recovery eligibility, collection behavior, original five Skills, and 25-second collection budget remain authoritative and unchanged. The provider does not approve or execute a plan, change a network, dispatch tickets or messages, or claim standards compliance.

All fixture and evaluation inputs are synthetic and pseudonymous. Any evaluator oracle remains outside Skills and provider inputs; this file boundary alone is not an operating-system isolation claim. Actual MobileWork, native Windows, production interoperability, and external security acceptance remain for their owners.

## Initial engineering gate: failures remain under diagnosis

The initial gate ran against frozen source `0446781`. The full suite ran 217 tests in 185.584 seconds and finished with 7 failures and 15 errors. The clean extracted suite ran 138 tests in 154.533 seconds and also finished with 7 failures and 15 errors. These results are failures, not a partial or final pass.

The logs show M2 materialization cases reporting `parse_error` where the tests expected `complete`, a nonzero service-review invocation for `case-001`, and repeated `FileExistsError` errors while materializing service cases. The causes have not been established; Terra is diagnosing the failures read-only. This record does not assign root causes or imply which fix will resolve them.

Eight Skill validators, Python 3.10 grammar validation, all 80 fixture hashes, and the 17-case unique-scenario count passed. Product package builds were produced under `.tools/carrier-m5/initial-delivery/`. The delivery verifier stopped when the extracted suite failed, so managed-PCAP verification was not reached. No final acceptance gate or independent Sol review has completed.

The recorded commands were:

```sh
.tools/carrier-m1/schema-venv/bin/python -B -W error::ResourceWarning -m unittest discover -s tests -v > .tools/carrier-m5/full-suite.log 2>&1
CARRIER_PHASE=m5 CARRIER_VERIFY_OUT=.tools/carrier-m5/initial-delivery .tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/verify_delivery.py > .tools/carrier-m5/delivery.log 2>&1
```

Evidence is retained in `.tools/carrier-m5/full-suite.log`, `.tools/carrier-m5/delivery.log`,
`.tools/carrier-m5/auxiliary.log`, `.tools/carrier-m5/skill-validators.json`, and the generated
artifacts and build logs under `.tools/carrier-m5/initial-delivery/`. Actual MobileWork, native
Windows, production interoperability, and external security acceptance remain separate user-owned
validation.

## Read-only diagnosis and corrections in progress

Terra's read-only diagnosis is recorded in `.tools/carrier-m5/diagnosis-initial/results.log`,
`shape-and-units.log`, and `fixture-audit.log`. It identified these causes for the initial failures:

- Eleven criteria-source rows placed a timestamp string in `unit` and left the original event time
  null, so M2 ingestion rejected the criteria source. The fixture owner is correcting the source
  metadata with explicit synthetic original event times; collection time will not be used to invent
  them.
- Nine case scenario files included `case_id` inside the strict provider request, where that key is
  not part of the request contract. The fixture owner is removing this request-only field while
  preserving outer scenario identity and oracle truth.
- A failed ingestion attempt left its test-cache directory behind, which caused 15 subsequent
  materialization collisions. Terra is correcting per-attempt test-cache isolation while preserving
  exclusive product directories and the parse assertions.

These fixture and test-harness corrections are in progress. No product runtime or contract change is
currently planned. No renewed tests or final-gate claims are recorded here; the initial failures above
remain part of the validation history.

## Second engineering gate: reference failures remain under correction

The second gate ran against frozen source `c09c18e`. The full suite ran 218 tests in 194.019 seconds
and ended with 21 errors. The extracted suite ran 139 tests in 161.842 seconds and also ended with 21
errors. These results do not pass the gate.

The frozen-source audit `.tools/carrier-m5/diagnosis-second/reference-audit.json` found 104 unresolved
logical evidence references. Of these, 48 point to obsolete criteria-authority labels; the other 56
are case-012 references for endpoint-B equivalence rows that the fixture intentionally omits. The
staged request still referenced those absent rows. The fixture owner is correcting the references,
using null where optional equivalence is omitted, and removing obsolete optional authority entries
while preserving endpoint-B requirements and oracle outcomes. Terra is adding a fast fixture-reference
integrity control so dangling logical tokens are reported before later test materialization.

The test logs show `unknown logical row reference` during request materialization. No product runtime
or contract change is reported for this correction round. Corrections are in progress, no renewed
gate or pass is claimed, and all earlier failure records remain preserved. Evidence is in
`.tools/carrier-m5/full-suite-corrected.log`, `.tools/carrier-m5/delivery-corrected.log`,
`.tools/carrier-m5/diagnosis-second/reference-audit.json`, and generated package artifacts under
`.tools/carrier-m5/corrected-delivery/`. The delivery run did not complete extracted tests, so this
record makes no managed-PCAP result claim.
