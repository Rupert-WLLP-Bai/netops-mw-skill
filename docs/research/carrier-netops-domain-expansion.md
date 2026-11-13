# Carrier Network Operations Domain Expansion

**Status:** proposal for review, 2026-11-13  
**Baseline:** `main` at `dfe326aac49c17ab3f88f4a82159411787e56ba0`  
**Purpose:** evolve the current Internet-access triage and evidence workflow into a carrier-oriented network build-and-maintain Skill Suite without weakening its evidence, authorization, budget, or recovery guarantees.

This document is a domain expansion proposal. It does not add device adapters, vendor commands, production access, active probes, or automated configuration changes. No production network has been accessed.

## 1. Product direction

The product should become a **Telecom Network Operations Copilot** for network construction, service delivery, operation, maintenance, and incident coordination.

It is not an NMS replacement, network controller, configuration orchestrator, or autonomous repair agent. Its primary job is to:

1. understand the affected service and network scope;
2. identify which evidence is available and which is missing;
3. select bounded, authorized, discriminating checks;
4. correlate evidence across service, access, transport, IP, and application layers;
5. distinguish observations, hypotheses, ownership boundaries, and confirmed causes;
6. preserve operator decisions and action outcomes;
7. verify the original business service after an operator-managed change.

The existing five skills remain valid. The expansion adds carrier-specific domain packs and evidence adapters rather than rewriting the incident lifecycle.

## 2. Operating principles

- **Service-first:** start from the customer's affected service, SLA, site, circuit, APN, access type, and impact—not from a guessed device.
- **Layered localization:** separate customer terminal/CPE, access, aggregation, bearer/IP transport, interconnect/Internet, and destination service.
- **Evidence before attribution:** a metric anomaly is not automatically a root cause; a hop that does not answer ICMP is not proof of forwarding loss.
- **Northbound evidence first:** prefer read-only exports, CLI transcripts, alarms, counters, logs, and existing captures supplied by an authorized operator.
- **No implied access:** a Skill must not infer permission to log in to routers, OLTs, BRAS/BNG, firewalls, EMS/NMS, OSS/BSS, or customer equipment.
- **No automatic repair:** configuration changes, resets, interface shutdowns, route changes, optical power changes, and customer notifications remain operator actions.
- **Original-flow recovery:** validate the affected service with the same site, circuit, identity, endpoint, protocol, address family, proxy, and workload.
- **Deployment honesty:** distinguish Linux/WSL-tested behavior, native Windows behavior, MobileWork invocation, and vendor/platform compatibility.

## 3. Carrier domain map

### 3.1 Service and customer context

Canonical service objects:

- customer / account (use pseudonymous identifiers in shared evidence);
- site / branch / building / room / rack;
- service instance and service type;
- circuit ID / access line ID / logical connection ID;
- SLA profile, committed rate, availability window, and acceptance criteria;
- source vantage, affected user group, application, endpoint and time window.

Service families to support as domain labels (not as assumed implementation capabilities):

- home broadband / FTTH;
- enterprise Internet access;
- dedicated Internet access (DIA);
- leased line / private line;
- L2VPN / L3VPN;
- mobile data service / APN / private APN;
- Wi-Fi access as a customer-side access technology;
- public Internet SaaS / API / voice-video collaboration.

### 3.2 Network layers and evidence

| Domain layer | Typical objects | Evidence examples | Localization boundary |
|---|---|---|---|
| Customer terminal / LAN | endpoint, NIC, OS, Wi-Fi, CPE LAN | route table, interface counters, DHCP lease, WLAN RSSI/retry, local capture | endpoint or local LAN only |
| Access / last mile | ONT/ONU, OLT PON port, splitter, access line, DSLAM where applicable | optical Rx/Tx power, LOS/LOF, FEC/CRC, flap history, port state, line profile | access segment only when source and port mapping are verified |
| Aggregation / subscriber edge | access switch, VLAN/QinQ, BRAS/BNG, PPPoE/IPoE, DHCP, AAA/RADIUS | VLAN mapping, session state, lease, authentication result, accounting, interface drops | aggregation/subscriber session; avoid assigning a physical cause from a session symptom |
| IP bearer / transport | PE/P, VRF, LSP/SR policy, IGP/BGP, LAG, ECMP, MTU | route/next-hop, adjacency, LSP state, interface errors, queue drops, utilization, MTU/PMTUD | transport path or interface only when topology/time correlation is available |
| Internet edge / interconnect | CGNAT, firewall, DNS recursive service, NAT, peering/transit, CDN edge | NAT/session counters, DNS response, route/AS path, BGP prefix, TCP/TLS timings | edge or interconnect direction; no AS responsibility claim from one traceroute |
| Destination / application | CDN, SaaS, API, web, voice/video service | HTTP status, DNS/TCP/TLS/TTFB, application logs, WebRTC stats, service status | application/service only with matching service-side evidence |

The same physical device can participate in several logical layers. Evidence must carry a source-native object ID and a separately verified topology mapping; do not infer ownership from a hostname string.

### 3.3 Network build and service-delivery lifecycle

The suite should also recognize pre-service and change workflows:

1. design / resource readiness;
2. construction and installation;
3. circuit provisioning and configuration;
4. activation / turn-up;
5. acceptance test;
6. service handover;
7. routine maintenance;
8. incident restoration;
9. change verification and closure.

Build/acceptance evidence should include expected versus actual service parameters, measurement method, measurement point, timestamp, test instrument identity/calibration where available, and explicit acceptance criteria. A successful ping is not a dedicated-line acceptance test.

## 4. Recommended Skill Suite structure

Keep the current five skills as the stable workflow core. Add focused carrier workflows only when they have distinct inputs and outputs.

| Skill / domain pack | Main responsibility | Inputs | Output | Priority |
|---|---|---|---|---|
| `internet-access-triage` (existing) | Endpoint-to-public-service diagnosis | URL, symptom, optional control, bounded local evidence | scoped diagnosis and evidence bundle | Keep |
| `netops-incident` (existing) | Incident lifecycle and operator decision records | service impact, scope, evidence, authorization and budget | durable case, decision, action record | Keep |
| `netops-pcap-analysis` (existing) | Offline packet analysis | PCAP/PCAPNG, capture point, question | frame-linked findings and visibility limits | Keep |
| `netops-verify-recovery` (existing) | Original-service recovery and stability | original scope, criterion, independent checks | recovery status and coverage gaps | Keep |
| `netops-handoff` (existing) | Draft transfer / post-incident record | evidence, decisions, actions, open questions | local handoff draft | Keep |
| `telecom-access-diagnostics` | FTTH/enterprise access and subscriber-session evidence correlation | ONT/OLT/ONU exports, optical readings, VLAN/session/DHCP/AAA evidence | access/session direction, missing mapping and next checks | P1 |
| `telecom-ip-transport-diagnostics` | IP bearer, routing, MTU, QoS and interface evidence | sanitized CLI outputs, route/IGP/BGP/LSP/interface/queue snapshots | path/plane/interface hypotheses with corroboration | P1 |
| `telecom-service-acceptance` | Circuit/service activation and acceptance | design parameters, test records, SLA and acceptance template | expected-vs-actual matrix and unresolved deviations | P2 |
| `telecom-change-review` | Pre/post change evidence and rollback readiness | change plan, impact scope, prechecks, postchecks, rollback trigger | change risk checklist and verification record | P2 |

Do not create one Skill per protocol or vendor. Use references and adapters within a domain pack; promote a separate Skill only when a distinct operator task and independent acceptance set justify it.

## 5. Common carrier incident envelope

Extend the current incident scope without breaking the existing internet-access evidence contract. New fields should be optional and versioned.

Suggested `service_context`:

```json
{
  "schema_version": "1.0",
  "service_type": "enterprise_internet",
  "service_id": "redacted-service-id",
  "customer_ref": "pseudonymous-customer",
  "site": {
    "site_ref": "site-001",
    "region": "region-a",
    "access_type": "ftth"
  },
  "circuit_ref": "redacted-circuit-id",
  "sla_ref": "sla-profile-a",
  "impact": {
    "scope": "single_site",
    "affected_users": "unknown",
    "business_operation": "access enterprise SaaS"
  },
  "vantage": {
    "location_ref": "branch-001",
    "source_type": "customer_endpoint",
    "identity_ref": "redacted-user"
  },
  "time_window": {
    "reported_start": "2026-11-13T01:00:00Z",
    "observed_start": null,
    "observed_end": null
  }
}
```

This is illustrative only. Real customer, circuit, account, IP, telephone, IMSI, APN, subscriber, and topology identifiers must be classified and redacted according to the operator's policy before entering a shared Skill context.

Each imported record should retain:

- source system / device role / source-native record ID;
- collection actor and authorization reference;
- event time, collection time, timezone and clock-quality note;
- device identity and verified topology mapping (or an explicit unknown);
- interface / VLAN / VRF / circuit / session / service references where applicable;
- raw unit, normalized unit, direction, sample count and denominator;
- artifact hash, parser/adapter version and redaction relationship;
- visibility and comparability limitations.

Do not force vendor-specific counters into a universal field unless the counter semantics, direction, unit, reset behavior, and sampling interval are known.

## 6. Evidence adapters and vendor neutrality

The current Python standard-library runner and JSON evidence contract are a good base. Extend via explicit read-only import adapters:

- generic text / CLI transcript adapter;
- JSON and CSV telemetry export adapter;
- syslog / alarm export adapter;
- SNMP walk or monitoring export adapter (import-only initially);
- PCAP/PCAPNG adapter (existing);
- OTDR / optical power test result adapter (file import first);
- topology / inventory snapshot adapter (versioned snapshot, not live discovery).

A vendor adapter must declare supported product family, software versions tested, command or export source, required privilege, read-only status, field mapping, parser tests, and unsupported cases. Never present illustrative commands as universally valid. Vendor commands must be checked against the exact device OS/version and local operating procedure before execution.

Initial vendor-neutral acceptance should use sanitized fixtures and source-provenance manifests. Actual vendor interoperability is a later validation stage with an authorized lab and device-owner review.

## 7. Diagnostic workflows to prioritize

### NET-ACCESS-01: FTTH customer reports intermittent disconnection

Required evidence: affected ONT/ONU reference, OLT/PON port mapping, optical power history, LOS/LOF events, FEC/CRC counters, ONT uptime, DHCP/PPPoE session events, and endpoint time window.

Expected behavior: establish whether the evidence is from the same subscriber and time window; distinguish optical/access symptoms from subscriber-session and endpoint symptoms; request missing OLT/ONU mapping instead of inventing a port.

Prohibited conclusion: optical fault based solely on a low-looking value without model-specific threshold, calibrated measurement, and trend/context.

### NET-ACCESS-02: Enterprise broadband authenticates but cannot reach services

Required evidence: PPPoE/IPoE state, DHCP lease, AAA/RADIUS accept/reject and reason (redacted), assigned address/prefix, VLAN/service mapping, route/VRF and endpoint tests.

Expected behavior: separate authentication success, address assignment, forwarding, DNS, and application success.

Prohibited conclusion: “network is normal” because the subscriber session is online.

### NET-TRANSPORT-01: Dedicated line packet loss or latency complaint

Required evidence: both-end service identifiers, measurement endpoints, direction, CIR/PIR, committed test method, interface counters, queue drops, LAG/member state, route/VRF, timestamps and baseline.

Expected behavior: compare both directions and both ends; distinguish service-edge, access, transport and remote endpoint evidence; preserve asymmetric visibility.

Prohibited conclusion: identify a specific PE/P/interface from a single endpoint ping or traceroute.

### NET-TRANSPORT-02: MTU / PMTUD black-hole suspicion

Required evidence: packet size and DF behavior, interface MTU, tunnel/encapsulation overhead, ICMP fragmentation-needed visibility, TCP retransmissions and protocol.

Expected behavior: distinguish MTU mismatch from generic loss; compare small and large payloads under the same path and protocol.

Prohibited conclusion: assert MTU fault from a single large-ping failure.

### NET-IP-01: BGP route or reachability change

Required evidence: before/after RIB/FIB snapshots, peer state and event times, prefix/VRF, next hop, policy context, route collector or control-plane logs.

Expected behavior: identify route change evidence and affected prefix/scope; distinguish control-plane adjacency from data-plane forwarding.

Prohibited conclusion: infer customer impact from a BGP session reset without matching affected prefixes and service checks.

### SERVICE-ACCEPT-01: New enterprise circuit turn-up

Required evidence: approved design, service order, circuit references, endpoints, VLAN/VRF/IP parameters, bandwidth profile, MTU, QoS, routing, security policy and acceptance criteria.

Expected behavior: generate a traceable expected-vs-actual checklist; mark every missing measurement as unverified; require authorized operator confirmation.

Prohibited conclusion: mark service accepted because configuration text exists or a single ping succeeds.

## 8. Evaluation strategy

Preserve the current 12/30 internet cases and existing PCAP corpus. Add a carrier-specific corpus with separate hidden controller truth and agent-visible evidence.

Minimum initial carrier suite:

- 6 true faults: optical degradation, PON flap, DHCP/AAA failure, VLAN/service mapping error, queue congestion, MTU mismatch;
- 6 healthy or misleading cases: normal optical power with endpoint Wi-Fi fault, ICMP rate-limit, BGP event without affected prefix, one-way-only measurement, stale alarm, recovered session;
- 4 unreliable work orders: wrong circuit ID, wrong device/port, wrong cause, false premise;
- 4 evidence insufficiency cases: missing topology map, unknown counter semantics, unsynchronized clocks, no reverse-path evidence;
- 4 service-delivery cases: incomplete provisioning, wrong VLAN/VRF, acceptance threshold not supplied, partial post-change verification.

Scoring is localization-first and evidence-grounded:

1. incident/service state;
2. most specific defensible layer/object;
3. fault class;
4. evidence references and counterevidence;
5. over-attribution penalty;
6. tool completion, elapsed time, and collection cost.

A lucky hidden-root-cause guess without agent-visible support must not pass. A missing topology mapping should reduce localization granularity rather than cause a guessed device/port.

## 9. Security, privacy and production boundary

The default package remains offline-first and read-only.

- No credentials, SNMP communities, API tokens, private keys, customer passwords, or full subscriber identifiers in tickets, fixtures, screenshots, or generated reports.
- No automatic SSH/Telnet/NETCONF/RESTCONF/gNMI connection in the initial carrier expansion.
- No configuration commands, reset, shutdown/no-shutdown, route clear, session clear, optical adjustment, firmware upgrade, or remote reboot.
- No active scan, broad subnet sweep, arbitrary port scan, or unbounded throughput test.
- No external upload of PCAP, syslog, customer data, topology, or device configuration.
- Operator-provided authorization must be explicit, scoped to target/vantage/time/operation, and separately validated by the owning system; a Skill cannot validate enterprise authorization itself.
- Every imported artifact is untrusted input; preserve hashes, size limits, path confinement, parser limits and redaction records.
- A generated change plan or handoff is a draft, not an executed operation.

## 10. Delivery phases

| Phase | Deliverable | Acceptance gate |
|---|---|---|
| C0: domain model | glossary, service/layer vocabulary, service context schema, data classification | terms reviewed by network operations practitioner; backward compatibility test |
| C1: carrier evidence pack | generic CLI/CSV/JSON/syslog import adapters and source provenance | fixtures parse deterministically; invalid/stale/unknown fields preserved as unknown |
| C2: access diagnostics | FTTH/PON/ONT/OLT and PPPoE/IPoE/DHCP/AAA workflows | 12 carrier cases; no guessed port or subscriber attribution |
| C3: IP transport diagnostics | routing, VRF, LAG, QoS, MTU, interface and queue evidence | 12 carrier cases; control/data-plane and direction boundaries tested |
| C4: service delivery | provisioning and acceptance checklist | expected-vs-actual and missing evidence gates pass |
| C5: lab/vendor validation | authorized lab captures and versioned vendor adapters | per-vendor/version evidence, read-only review, independent operator sign-off |
| C6: MobileWork publication | real client import, invocation, screenshots and user self-validation | V-01 install/load, V-02 default flow, V-03 input/output all recorded against exact package SHA |

The current 25-second Internet triage budget remains unchanged. Carrier file imports, PCAP parsing, multi-device correlation and acceptance workflows must have their own bounded budgets and must not silently inherit the 25-second live probe budget.

## 11. Open decisions before implementation

1. Which first operational audience is primary: broadband access maintenance, enterprise private-line delivery, or IP bearer/transport maintenance?
2. Which equipment families and software versions can be represented by authorized, sanitized sample exports?
3. What internal data classification and redaction rules apply to circuit, customer, subscriber, IP, topology and alarm data?
4. Which acceptance templates and SLA metrics are approved for the intended service types?
5. Is the first deployment expected to be a standalone MobileWork Skill pack, a multi-skill expert, or both?

Until these are answered, implement vendor-neutral import and reasoning contracts first; do not hard-code a vendor command set or claim production integration.

## 12. Relationship to existing architecture

This proposal preserves:

- the standalone `internet-access-triage` collector and its 25-second live budget;
- the four diagnosis states and evidence provenance contract;
- the separate incident lifecycle and original-flow recovery checks;
- offline-only PCAP analysis;
- operator-owned actions and local-only handoff drafts;
- explicit release allowlists, deterministic packaging and independent validation.

A carrier domain pack must compose with these contracts through versioned evidence imports. It must not bypass the incident controller, broaden permissions, change the meaning of existing diagnosis states, or turn tool availability into authorization.
