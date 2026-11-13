# M5: source-backed service acceptance and change review

Implement [issue #9](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/9) from merged M4
`8b210ebbdbe09f05933da831e126378b2b0a8981`, on `feat/carrier-m5-service-acceptance`.
Use the existing checked offline evidence contract and single incident controller. Preserve the five
original Skill entries, access/transport interfaces, four diagnosis states, 25-second live collection
budget and original standalone collector archive.

## Interface and decisions

Add independent manual `telecom-service-acceptance` and optional incident-owned
`scripts/review_service.py --input REQUEST.json`. Its private service module uses the existing narrow
checked-loading/binding/time/worker seam. It returns bounded deterministic JSON, including a local
Markdown draft string. It neither creates a case nor sends reports, runs probes, changes a device,
approves a plan or declares recovery.

Compare supplied order/design and actual fields for the selected circuit and distinct A/B sites.
Require an approved source-backed inventory, including service circuit/bandwidth/SLA and both
endpoints' identity, VLAN/QinQ, VRF, addressing, bandwidth, IP MTU, QoS and routing/security policy.
Each endpoint compares to its own design; legitimate A/B differences are allowed. An omitted B side
or inconvenient required field remains incomplete. Cross-source aliases need explicit scoped
equivalence evidence rather than a matching string.

Require an approved source-backed criterion inventory for throughput, delay, loss, jitter and IP MTU.
Keep each test's point, absolute A-to-B/B-to-A mapping, method, aggregation, original unit, source
threshold, window, samples and required instrument/calibration evidence. Neither a ping nor a
configuration match is complete acceptance. Caller omissions cannot reduce approved requirements.
Missing or contradictory facts remain unverified, while a separately supported discrepancy remains
visible. No default threshold, unit conversion, percentile inference or automatic waiver.

Static order/SLA validity is distinct from actual-observation freshness. Business-date endpoints
and planned dates use explicit source numeric `unix_s` values; original event/approval timestamps
remain separate, including unknown timestamps. Recent collection does not create approval, and a
future planned-date value is not a future observation. Current static authority remains an explicit,
unauthenticated source assertion. Do not weaken actual-measurement freshness or topology checks.

Change drafts retain scope, impact, source approval/reference, planned window, rollback trigger/owner,
required prechecks, planned postcheck criteria and residual risks. Pre-change review needs complete
plans without fabricated future results. Post-change review needs actual ordered checks and original
approval chronology. Approved check inventories prevent omission. Human signoff always remains
pending. Acceptance stays blocked if a requested change review is blocked, even when the separate
technical assessment conforms. Nothing executes, accepts a service or changes recovery eligibility.

## Bounds and ownership

Use strict UTF-8 JSON, checked exact hashes and confined regular files. Reuse existing limits: eight
runs, 512 total observations, 512 bindings and 512 topology links as separate caps, one MiB request/result, two MiB per run, 16 MiB total,
depth 16, bounded work/strings/declarations and a five-second trusted worker. All source imports retain
M2 byte/line/row/time/path limits. Count before allocating and do not echo raw paths/source prose.

Terra owns runtime, public/boundary/integration tests and explicit package inventory/allowlists.
Luna owns synthetic source inputs, logical-row-to-produced-reference materialization, independent
oracle and provenance; another Luna owns the standalone manual and installed provider contract.
Agree exact metric/ref/relation/output roles before authoring dependent inputs. The parent owns
integration, this plan, status records, final checks and PR. Tests may be authored during implementation
but no tests, validators, builds, grammar checks or runtime probes run until all owners freeze.

## Verification and limits

Provide at least the eight issue cases plus complete technical, pre-change and post-change positive
controls, distinct valid A/B VLANs, missing B configuration, omitted approved criteria, old-but-current
design versus stale actual evidence, unknown approval chronology and missing/expired calibration.
Add malformed, duplicate, nonfinite, oversized, symlink, wrong-object/source/time/unit/method/window,
mapping and contradictory-source controls. Preserve actual supporting and counterevidence refs.

After the global freeze, run full regression and clean extracted-runtime tests, eight independent
Skill package checks, deterministic archive/manifests, every member/provenance hash, Skill validators,
Python 3.10 grammar and managed offline PCAP compatibility. Then Sol independently reviews Standards
and Spec. Required fixes restart the authoring/freeze/check/review cycle. Submit and merge a separate
verified M5 PR under the active completion authorization.

Developer input/oracle separation is not OS isolation, live Agent evaluation or MobileWork acceptance;
M6 provides the evaluation boundary. Inputs are self-authored synthetic Apache-2.0 data; runtime uses
the standard library. No Y.1564/Y.1731 compliance, vendor interoperability or real service turn-up is
claimed. Actual MobileWork, native Windows and external-security validation remains user-deferred;
M7 prepares files, prompts and acceptance evidence slots for the user.
