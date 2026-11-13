# Carrier M4 validation

This record covers issue #8 from merged M3 `4087d4e`. Initial frozen source `b9abb33` completed
implementation before any tests, validators, builds or runtime checks. The corrected final gate and
independent Sol review remain pending; no release/client acceptance is claimed.

## Initial final-gate results

- Full suite: 204 tests in 120.526 seconds, failed with five failure records.
- Extracted suite: 125 tests in 87.941 seconds, failed with four failure records.
- Seven Skill structural validators, Python 3.10 grammar checks, and 30 fixture provenance hashes passed.
- The combined suite contains 55 allowlisted files and seven Skill roots. The initial extracted
  runtime failure prevented the delivery harness from reaching its managed-PCAP step.

One full-suite failure came from the transport Skill's cross-Skill relative Markdown link, which
violated independent installation. Its own manual reference remains locally linked; the discovered
optional provider's bundled contract is now named in plain text without an assumed installation path.
The same correction was applied to the standalone manual reference.

Four failures repeated one profile-source authoring problem in queue/QoS cases 005 and 006: the source
contained denominator `1`, but its explicit configuration allowed only unit `%`. M2 correctly rejected
the undeclared denominator. The configuration now includes the supplied denominator unit and its
provenance hash is updated. Source observations, strict ingestion rules and oracle expectations were
preserved. No expected result was changed to conceal a product failure.

Initial evidence is retained in `.tools/carrier-m4/full-suite.log`, `delivery.log` and
`skill-validators.json`. Corrections completed and froze before the next final gate. Product/provider
code uses the standard library under Apache-2.0. Inputs are self-authored synthetic Apache-2.0 data;
source and evaluator answers are excluded from product archives. These developer checks do not prove
OS oracle isolation, live LLM quality, vendor interoperability, native Windows, MobileWork or external
security acceptance. Actual M7 client/platform/security execution remains user-deferred.

