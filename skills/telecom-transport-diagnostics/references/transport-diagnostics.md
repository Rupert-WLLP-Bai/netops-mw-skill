# Transport evidence rules

Use these rules for manual analysis and for interpreting analyzer output. The matching machine contract, including exact request and response shapes, is in [the incident transport contract](../../netops-incident/references/transport-analysis.md).

## Scope and time

- Keep control-plane observations (BGP peer/prefix, individual IGP adjacency state or IGP flap, MPLS LSP, SR policy, explicit next-hop label, and LAG state) separate from data-plane observations (forwarding, service operation, and measured traffic behavior). A control event or counter increment alone is neutral.
- Bind an observation to the selected service and resource with an explicit, time-valid mapping that matches the observation's source and source-native identity. A mapping is an operator claim, not authentication or proof of responsibility. Do not merge mappings from different source runs because aliases happen to match.
- Require explicit event and collection times, known synchronized clocks, known uncertainty, freshness, and applicable validity intervals. Preserve stale data, clock uncertainty, resets, missing samples, and conflicting observations as gaps. Missing faults do not establish health or recovery.
- Establish reverse-direction coverage only from valid, positive-sample data-plane measurements for the relevant operation. Match metric, source/native identity, bound resource, compatible units and counter fields, overlapping event-time uncertainty, and applicable observation window. BGP/IGP/LSP/SR/LAG states, topology labels, and descriptive metadata cannot manufacture measured reverse coverage.
- Scope route/service comparisons by explicit equal prefix and VRF aliases, bound service/resource, source, direction, and compatible time. Do not infer subnet containment, customer identity, or a failed next hop from text or topology resemblance.
- Treat a single traceroute as observations from one vantage. It cannot establish a failed router, PE/P, interface, AS, or reverse path. ECMP or asymmetry claims require independently supplied, scoped observations in both directions.

## Counters, queues, and QoS

- Validate a cumulative counter's unit, direction, scope, denominator, sample interval, sample count, and reset/wrap semantics before comparing two ordered observations. A reset, wrap, unknown meaning, stale timestamp, zero/unknown sample count, or incompatible metadata blocks a delta; incompatible ordered samples produce `incompatible_counter_samples`. Do not convert units, derive rates, or infer line rate.
- Treat queue and QoS class drop increments as neutral by themselves. A queue condition requires an applicable cited operator profile, a matching utilization observation that meets the cited limit, and a matching increasing drop counter pair.
- Require source-backed measurement-window boundaries and aggregation for both utilization and counter evidence. Poll cadence and `sample_interval_seconds` describe sampling metadata; neither proves the coverage window. Window subjects, boundaries, aggregation, service/resource, source identity, direction, and clocks must match. Ambiguous or missing windows block queue correlation.
- Keep a profiled queue condition separate from customer impact. A service outage claim needs a separately matched service-flow failure. QoS class analysis also needs a same-scope, same-window observed class; otherwise record `missing_qos_class`. Preserve a real, comparable service pass as counterevidence.

## MTU and path evidence

- Compare packet sizes only when their basis is explicitly the Layer 3 IP packet size. TCP, UDP, ICMP, or application payload bytes are not interchangeable with L3 packet bytes.
- Use only supplied configured/effective MTU, tunnel overhead, probe size, direction, and unit. Do not add assumed headers or encapsulation overhead.
- An MTU discrepancy is a neutral observation. A bounded MTU hypothesis needs comparable small/large probe outcomes in the same scope, direction, and compatible time. Missing reverse direction, size basis, probe sizes, or fragmentation-needed evidence stays a gap; absent or `not_seen` feedback is `missing_pmtud_feedback`, a visibility gap only.
- Missing PMTUD feedback does not establish ICMP filtering or a black hole. Absence of a packet in a capture is not evidence that it was blocked.
- Preserve route, path, LAG, and tunnel state as observed state; do not infer physical cause, ownership, or symmetric routing from it.

## Reporting discipline

For each finding, identify the exact observation and its run-qualified reference. Cite mapping, profile, prefix, VRF, flow, class, and window records when the conclusion relies on them. Include actual counterevidence and explain what the evidence cannot establish. Keep `resource_id` unresolved when causal responsibility is not established. Recommend targeted evidence collection rather than a network change.
