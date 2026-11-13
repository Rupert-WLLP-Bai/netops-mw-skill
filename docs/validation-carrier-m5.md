# Carrier M5 validation record

This record covers issue #9, “C4 / M5: Add enterprise service delivery, circuit acceptance and change-review workflows,” following the M4 merge. The R6 engineering gate passed at frozen source `155e00c` before review. Both independent Sol reviews have now completed and require corrections; the work is in a correction phase, not final review approval or user-owned platform/security acceptance.

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

## Third engineering gate: acceptance-result mismatches under diagnosis

The third gate ran against frozen source `e98f528`. All fixtures reached the provider. The full suite
ran 219 tests in 207.036 seconds and ended with 20 failures and no errors. The extracted suite ran
140 tests in 171.778 seconds and also ended with 20 failures and no errors.

The observed failures are outcome assertions: the positive normal case `case-009` returns
`nonconformant`; the positive pre-change and post-change reviews are `blocked`; and targeted wrong-VLAN
and wrong-VRF mismatch assertions fail. Terra is performing read-only diagnosis under
`.tools/carrier-m5/diagnosis-third/`; the cause has not been established. These are test failures, not
findings that the scenarios or provider are correct, and this record does not assign a cause.

The fixture logical-reference graph check passed, along with eight Skill validators, Python 3.10
grammar validation, all 80 fixture hashes, and the 17-case unique-scenario count. Evidence is retained
in `.tools/carrier-m5/full-suite-r3.log`, `.tools/carrier-m5/delivery-r3.log`,
`.tools/carrier-m5/fixture-check-r3.log`, `.tools/carrier-m5/auxiliary-r3.log`, and the diagnostic
artifacts under `.tools/carrier-m5/diagnosis-third/`. The delivery run did not pass the extracted
tests, so no managed-PCAP result or final acceptance pass is claimed. All earlier gate failures and
diagnoses above remain preserved.

## Third-gate diagnosis and correction scope

The read-only diagnosis under `.tools/carrier-m5/diagnosis-third/` identified two independent
reference-semantic issues behind the observed results. First, controlled alias fields were compared
by literal spelling across distinct source namespaces instead of applying the checked five-row
equivalence relation: a valid `declared_equal` relation must match aliases with different spellings,
while `declared_different` must report a mismatch even when spellings match. Missing, malformed,
conflicting, or inapplicable mappings remain unverified. Numeric values continue to use exact raw
type/unit/value comparison; mappings do not convert or override numeric quantities. The relation is an
operator source assertion, not authenticated truth.

Second, `.tools/carrier-m5/diagnosis-third/qualified-run-audit.json` found 344 fixture references
using logical run labels instead of the actual configured per-case M2 run IDs: 332 request refs and
12 oracle refs. The fixture owner is replacing those labels with the configured IDs while preserving
case semantics and expected outcomes. Terra is implementing the relation-valued comparison and its
focused controls. Source references include
`.tools/carrier-m5/diagnosis-third/detail.log`, `summary.log`, and `qualified-run-audit.json`.

These corrections are in progress. They do not convert the third gate into a pass; all previous
failure records remain, and renewed full/extracted gates, delivery verification, and independent
review are still pending.

## Focused criterion-output gate: one assertion remains

At frozen source `af2e00f`, the focused service test run exercised 10 test methods in 51.416 seconds
and had one failure, in `case-007`. Its oracle expected an explicit `unverified` test-matrix row for
the required throughput criterion whose method evidence is missing. The provider returned the
overall criterion as unverified but omitted that matrix row. The remaining focused public/golden
outcomes passed; this focused result is not a full-suite, extracted-suite, delivery, or final M5 pass.

Terra is correcting matrix construction so incomplete required criteria emit explicit unverified
rows using only independently checked, current, scoped, conflict-free direction evidence. A proven
`both` direction yields separate A-to-B and B-to-A rows; a proven single direction yields that row;
missing, unsupported, or conflicted direction is null. Only validated criterion refs are included;
unknown measurement, measurement point, or method remains null with `missing_criterion_evidence`.
Oracle expectations are preserved. Evidence for this focused run is
`.tools/carrier-m5/service-check-r4.log`. No renewed full/extracted gate or final pass is claimed.

## R5 focused integration run: one test-only reference failure

The R5 focused run at frozen source `3b41fa3` exercised 11 test methods in 57.420 seconds and had
one failure in `test_complete_control_and_blocked_change_stay_separate`. The test's reused `result`
variable held the prior unknown-direction negative case when constructing support refs for the
positive complete case, so the resulting support list contained null refs. The existing incident
controller correctly rejected those refs as unknown or unqualified. Static inspection confirmed the
test overwrote the baseline result before the support construction. This is a test-state error; it is
not a reason to weaken controller reference validation or change provider/runtime behavior.

The correction is tests-only: Terra is preserving an immutable `baseline_result` for the complete
positive case while keeping the unknown-direction negative assertions. All 17 visible oracle cases
and the other focused controls passed in this run. No full-suite or extracted-suite gate was launched;
this focused run is not an overall M5 pass. Evidence is `.tools/carrier-m5/service-check-r5.log`.

## R6 final engineering gate passed; Sol reviews pending

The final engineering gate passed at frozen source `155e00c`. The full suite ran 221 tests in
238.726 seconds with no failures or skips. The clean extracted suite ran 142 tests in 201.647 seconds
with no failures or skips. Eight Skill validators, Python 3.10 grammar validation, all 80 fixture
hashes, and the 17 unique-scenario count passed.

The reproducible suite archive contains 61 files, is 675971 bytes, and has SHA-256
`9f796ddc6fcb6c7fc2a398d304ae7a07962a84a74caabd87561ec20f74199475`. Two suite builds and their
manifests were identical, all eight individual Skill archives were produced, and all member hashes
were checked. The managed offline PCAP check passed with the existing input hash
`92e06382a4f2e12bd569a104ceeecf908b89ccdb801f3dc4ae430b0f1a967f9b`, with no live network
collection. The original 16-file `internet-access-triage` collector remains SHA-256
`f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.

The commands were:

```sh
.tools/carrier-m1/schema-venv/bin/python -B -W error::ResourceWarning -m unittest discover -s tests -v > .tools/carrier-m5/full-suite-r6.log 2>&1
CARRIER_PHASE=m5 CARRIER_VERIFY_OUT=.tools/carrier-m5/r6-delivery .tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/verify_delivery.py > .tools/carrier-m5/delivery-r6.log 2>&1
```

Evidence is retained in `.tools/carrier-m5/full-suite-r6.log`,
`.tools/carrier-m5/delivery-r6.log`, `.tools/carrier-m5/auxiliary-r6.log`,
`.tools/carrier-m5/skill-validators-r6.json`, and the duplicate builds, manifests, extracted-test
log, verification record, and eight individual Skill archives under `.tools/carrier-m5/r6-delivery/`.
The engineering gate is complete; both independent Sol reviews remain active and pending. Actual M7
MobileWork, native Windows, production interoperability, and external-security validation remain
user-deferred.

## Sol review findings: corrections required

The two independent Sol reviews examined frozen source `155e00c` against merged M4 `8b210eb`.
The Standards axis reported three P2 findings; the Spec axis reported five P2 findings. The
pre-review R6 engineering gate above remains a successful gate at that source, but it is not a
post-correction result or a final review pass.

The findings identify seven correction categories, with planned-change semantics shared by both
reviews: (1) actual and postcheck evidence must support the criterion's actual direction, not merely
share its source/resource; (2) actual conflicts must be compared within compatible role, scope, and
time rather than treating measurements as timeless static facts; (3) planned postcheck metric,
method, criterion, comparator, and direction must be validated in both pre-change and post-change
reviews; (4) supported physical measurements must satisfy their nonnegative domains, with L3 MTU a
positive integral packet-size quantity; (5) approval and related change metadata must be tied to the
selected change's checked source identity; (6) the complete event-time uncertainty interval must
fit inside the applicable actual window; and (7) output references must point only to validated,
applicable evidence, with unavailable roles represented as null and unrelated static gaps excluded.

Terra's implementation report maps these cases to existing gaps: `missing_test_evidence` or
`change_review_incomplete` for unusable direction-role support; `conflicting_observations` only for
role-compatible actual observations with overlapping event-time uncertainty; `change_review_incomplete`
for absent or unsupported planned semantics and mismatched selected-change identity;
`test_measurement_mismatch` or `missing_criterion_evidence` for invalid measurement/criterion domains;
`test_window_mismatch` or `change_review_incomplete` when complete uncertainty does not fit the
actual window. Actual configured field values and their field-target rows must also carry equal
direction metadata; both can explicitly be `unknown`, while a mismatch uses `field_scope_mismatch`.
No new gap codes or output fields were added. The provider and manual references now state these
rules and retain existing gap vocabulary. Terra confirmed the documented behavior
matches the statically completed correction implementation. For planned checks, `eq` accepts a
controlled enum or finite numeric criterion; `gte`/`lte` require a finite numeric criterion with an
explicit unit, with the physical-domain rules applied for supported capability metrics. No renewed
checks, tests, package builds, or post-correction review results are recorded here. Evidence:
`.tools/carrier-m5/sol-standards.md` and
`.tools/carrier-m5/sol-spec.md`. Earlier gate failures and the successful pre-review R6 record
remain preserved. Actual M7 MobileWork, native Windows, production interoperability, and
external-security validation remain user-deferred.

## Sol R2 findings and resumed pre-review gates

Both independent Sol R2 axes reviewed frozen source `c358bdd` and released review ownership. The
Standards axis identified one P2 gap: the complete uncertainty interval was not checked for every
actual supporting observation in a test or postcheck window. The Spec axis identified three P2
categories: that same interval gap; numeric values accepted in categorical method/change roles; and
unrelated method, direction, or window refs emitted when a postcheck measurement was absent. The
original reports and probes remain unchanged in `.tools/carrier-m5/sol-standards-r2.md`,
`.tools/carrier-m5/sol-spec-r2.md`, and their probe directories.

Correction authors are addressing these cases using the existing contracts and result vocabulary.
For tests, the measurement and each actual supporting method, aggregation, window-boundary,
direction-mapping, and instrument observation must have its complete event-time uncertainty interval
inside the applicable test window. Calibration authority and validity-date records remain static
source facts; check their authority and interval coverage separately. For postchecks, apply interval
containment to the measurement and actual method, direction-mapping, and window-boundary observations
in the existing postcheck contract. Required categorical roles must use source-backed string labels
or aliases; numeric `7` is not a method, impact, approval reference, rollback trigger/owner, or
residual risk. A missing or invalid postcheck must not expose unassociated method, direction, or
window refs. These clarifications add no gap codes or output fields. The three maintained references
are being updated alongside the runtime correction; static code/document agreement and renewed gates
remain pending.

The actual resumed gates recorded before R2 review were:

- Focused service check: 16 tests in 78.280 seconds, passed, in
  `.tools/carrier-m5/service-check-resumed.log`.
- Full suite: 226 tests in 272.154 seconds, passed with no skips, in
  `.tools/carrier-m5/full-suite-resumed.log`.
- Resumed delivery's extracted suite: 147 tests in 242.386 seconds, passed with no skips, in
  `.tools/carrier-m5/resumed-delivery/extracted-tests.log`.
- The suite archive has 61 files, 687432 bytes, SHA-256
  `3e8478d2ad3ba0ba430a5c0c2994045b88770f6c04ca09b2d9644d2c300254c1`. Two archives/manifests
  matched; all member hashes and eight individual Skill packages passed, as did the managed offline
  PCAP check. The original 16-file collector remains SHA-256
  `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.
- Eight validators, Python 3.10 grammar validation, 80 fixture hashes, and 17 unique scenarios
  passed; evidence is in `.tools/carrier-m5/auxiliary-resumed.log`.

The resumed focused/full/delivery checks are pre-R2-review evidence, not post-correction results.
The earlier `.tools/carrier-m5/service-check-reviewed.log` process was interrupted by an environment
restart and its sparse tail is incomplete; it is not recorded as a pass. No new tests, validators,
builds, or post-correction review have run for this correction authoring. No final release pass is
claimed. Actual M7 MobileWork, native Windows, and external security acceptance remain deferred to
their user-owned gate.

## Sol R3 findings and resumed pre-review gates

Both independent Sol R3 axes reviewed frozen source
`25da34bc5b2f5b552fb338996e1c19564535b7a0` and released review ownership. The Standards axis passed:
it found the R2 actual-observation interval correction, categorical checks, and missing/invalid
postcheck-reference suppression compliant with the documented contracts. The Spec axis reported
two P2 boundary findings, so the Standards pass does not constitute an overall review pass:

- The incomplete-criterion path could still cite a checked but role-invalid `criterion_method` such
  as numeric `7`. Validate every cited fact under its existing role rule on both complete and
  incomplete paths, omit invalid refs, and preserve other independently valid criterion/direction
  facts. The existing gap is `missing_criterion_evidence`.
- A supplied numeric `instrument_id` could be nulled without making a test with
  `criterion_calibration_policy=not_required` incomplete. An absent optional instrument remains
  absent; an invalid supplied identity makes the affected test unverified with the existing
  `missing_test_evidence` gap. Valid optional instrument/calibration metadata is handled under its
  own role and association checks. Under `not_required`, retain only independently checked, current,
  role-valid status/date facts associated with a valid instrument; do not require
  `calibration_status=valid` or test-window validity coverage, or imply calibration is valid.
  Missing/unusable optional calibration refs do not alone create a required-calibration gap.

The two boundary reproductions and outputs are retained in
`.tools/carrier-m5/sol-spec-r3-boundary.py` and `.tools/carrier-m5/sol-spec-r3-boundary.json`;
the full reports remain `.tools/carrier-m5/sol-standards-r3.md` and
`.tools/carrier-m5/sol-spec-r3.md`. All earlier reports and probes remain preserved. Static review
of the current runtime correction against the provider and manual references confirms the documented
behavior; no new gap codes or output fields were added. The parent still owns source freeze and
renewed gate sequencing.

The actual gates completed before R3 review at frozen source
`25da34bc5b2f5b552fb338996e1c19564535b7a0` were:

- Focused service check: 20 tests in 119.913 seconds, passed, in
  `.tools/carrier-m5/service-check-r3.log`.
- Full suite: 230 tests in 318.608 seconds, passed with no skips, in
  `.tools/carrier-m5/full-suite-25da34b.log`.
- Resumed delivery's extracted suite: 151 tests in 282.733 seconds, passed with no skips, in
  `.tools/carrier-m5/25da34b-delivery/extracted-tests.log`.
- The suite archive has 61 files, 693441 bytes, SHA-256
  `c68f3c4de0a159ab109cd142b3d851ee40d9a61b58e1169fde25e6fea6ebbf78`. Two builds and manifests
  matched; all member hashes and eight individual Skill packages passed, as did the managed offline
  PCAP check. The original 16-file collector remains SHA-256
  `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.
- Eight validators, Python 3.10 grammar validation, 80 fixture hashes, and 17 unique scenarios
  passed; evidence is in `.tools/carrier-m5/auxiliary-25da34b.log`.

These are pre-R3-review gates, not post-correction results. No renewed checks have run for the R3
findings, and no final review/release pass is claimed. Actual M7 MobileWork, native Windows, and
security acceptance remain user-deferred.
