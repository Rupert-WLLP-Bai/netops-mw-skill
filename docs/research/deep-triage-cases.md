# Deep triage: designed operator cases

**Status: designed_not_executed.** These are designed scenarios, not incident records, passing replay tests, or directly runtime-compatible v0.1 evidence fixtures. Domains and addresses are reserved examples. The [machine-readable catalog](deep-triage-case-catalog.json) contains the same fields and source registry. Use existing four scoped statuses and at most two evidence-supported candidate domains. Missing optional evidence limits comparisons but does not erase valid target observations; use insufficient_evidence for a requested conclusion when its essential evidence is missing.

## Source registry

- **curl**: https://curl.se/docs/manpage.html
- **dns**: https://www.rfc-editor.org/rfc/rfc1035
- **dnssec**: https://www.rfc-editor.org/rfc/rfc8914
- **ecs**: https://www.rfc-editor.org/rfc/rfc7871
- **happy**: https://www.rfc-editor.org/rfc/rfc8305
- **tls**: https://www.rfc-editor.org/rfc/rfc6066
- **alpn**: https://www.rfc-editor.org/rfc/rfc7301
- **mtr**: https://github.com/traviscross/mtr/blob/master/man/mtr.8.in
- **icmp**: https://www.rfc-editor.org/rfc/rfc1812#section-4.3.2.8
- **trippy**: https://github.com/fujiapple852/trippy/releases
- **pmtu**: https://www.rfc-editor.org/rfc/rfc8201
- **h3**: https://www.rfc-editor.org/rfc/rfc9114
- **flent**: https://flent.org/tests.html
- **tcp**: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
- **capture**: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html
- **socket**: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/man/man8/ss.8
- **stats**: https://docs.kernel.org/networking/statistics.html
- **global**: https://github.com/jsdelivr/globalping
- **atlas**: https://atlas.ripe.net/docs/getting-started/user-defined-measurements.html

- **apnic**: https://blog.apnic.net/2025/03/11/ipv6-is-hard/
- **google_dns**: https://developers.google.com/speed/public-dns/docs/troubleshooting/domains

## DEEP-01: DNS resolver or CDN steering

**User input:** Our users say https://shop.example is slow with resolver 192.0.2.53. Is DNS slow?

**Symptom:** Slow request with resolver-specific answers. **Competing hypotheses:** Slow resolver processing; resolver-dependent endpoint steering; server delay.

**Proposed sequence:** Query each permitted resolver for A/AAAA and time; compare normal and hostname-preserving pinned HTTPS to a common approved address.

**Required evidence:** Resolver, transport, response code, TTL/answers, timings, actual IP, family, proxy, hostname, SNI and verification.

**Negative controls and falsifiers:** Same resolver and same IP in repeated near-time requests; healthy matched control.

**Allowed conclusion:** Report observed resolver response or request phase within matched conditions. **Prohibited overclaims:** Different answers prove resolver CPU or DNS processing is slow.

**v0.1 support:** DNS and curl partial; matched normal/pinned comparison exists for replay, but live pinned collection and comparison are missing. **Recommended phase:** v0.2.

**Proposed local test:** Use a local authoritative DNS and HTTPS server with two resolver responses; independently delay DNS or HTTP and assert correct scoped output.

**Sources:** [curl](https://curl.se/docs/manpage.html), [dns](https://www.rfc-editor.org/rfc/rfc1035), [ecs](https://www.rfc-editor.org/rfc/rfc7871).

## DEEP-02: DNSSEC and extended errors

**User input:** https://secure.example sometimes fails to resolve; can you check the resolver?

**Symptom:** Intermittent SERVFAIL. **Competing hypotheses:** Validation failure; unreachable authority; resolver or transport failure.

**Proposed sequence:** Query configured authorized resolver and capture status plus EDE if returned; compare same question at an approved independent resolver.

**Required evidence:** Query type, transport, status, EDE code/text if present, time, resolver and responses.

**Negative controls and falsifiers:** Same resolver successfully resolves an approved control name; second resolver resolves the same name.

**Allowed conclusion:** Report SERVFAIL and returned EDE as resolver-provided evidence only. **Prohibited overclaims:** A missing EDE proves DNSSEC is healthy; EDE proves the exact failing server.

**v0.1 support:** DNS partial; EDE and validated comparison missing. **Recommended phase:** v0.2.

**Proposed local test:** Local DNS test server returns SERVFAIL with and without EDE; verify missingness and literal code retention.

**Sources:** [dns](https://www.rfc-editor.org/rfc/rfc1035), [dnssec](https://www.rfc-editor.org/rfc/rfc8914), [google_dns](https://developers.google.com/speed/public-dns/docs/troubleshooting/domains).

## DEEP-03: DNS UDP truncation

**User input:** The name files.example fails only on our office resolver.

**Symptom:** Name lookup fails on one transport. **Competing hypotheses:** Truncated UDP without TCP fallback; resolver failure; filtering.

**Proposed sequence:** Compare bounded explicit UDP and TCP queries for the same name, record TC flag and responses.

**Required evidence:** Resolver, query, transport, response flags, answer and timeout.

**Negative controls and falsifiers:** Small response on the same resolver succeeds over both transports.

**Allowed conclusion:** A transport-specific response difference is observed. **Prohibited overclaims:** A UDP timeout proves a firewall or a broken authoritative server.

**v0.1 support:** DNS partial; transport fallback and TC evidence missing. **Recommended phase:** v0.2.

**Proposed local test:** Local DNS server returns TC on UDP and answer on TCP, plus an unrelated timeout; verify distinctions.

**Sources:** [dns](https://www.rfc-editor.org/rfc/rfc1035), [google_dns](https://developers.google.com/speed/public-dns/docs/troubleshooting/domains).

## DEEP-04: IPv6 fallback

**User input:** https://portal.example loads eventually but is slow on dual-stack laptops.

**Symptom:** Normal request slower than expected. **Competing hypotheses:** IPv6 connectivity degradation; both families slow; server delay.

**Proposed sequence:** Repeat normal and separately forced IPv4 and IPv6 HTTPS with identical hostname and verified TLS.

**Required evidence:** Actual address/family, connection and request results, timings, window and proxy.

**Negative controls and falsifiers:** Repeat both families to approved control and repeat original.

**Allowed conclusion:** Report observed family-specific difference and incomplete fallback visibility. **Prohibited overclaims:** A forced IPv6 failure proves a routing leak or normal client fallback.

**v0.1 support:** curl partial; controlled family comparison missing. **Recommended phase:** v0.2.

**Proposed local test:** Local dual-stack listener delays or rejects IPv6 only; verify force modes and normal address records.

**Sources:** [curl](https://curl.se/docs/manpage.html), [happy](https://www.rfc-editor.org/rfc/rfc8305), [apnic](https://blog.apnic.net/2025/03/11/ipv6-is-hard/).

## DEEP-05: Split VPN and HTTP 403

**User input:** https://intranet.example returns 403 while I am on the VPN, but works off VPN.

**Symptom:** HTTP authorization failure correlated with VPN. **Competing hypotheses:** Different egress or policy; DNS steering; expired credentials.

**Proposed sequence:** Compare authorized on/off VPN observations without changing the VPN; record family, IP, proxy, status and server identity.

**Required evidence:** Redacted URL, response status, actual address/family, route context, timing and comparable identity.

**Negative controls and falsifiers:** Same account and request on original path after comparison; other permitted service on each path.

**Allowed conclusion:** Report a 403 scoped to observed context. **Prohibited overclaims:** Identify a firewall rule or instruct credential changes based only on 403.

**v0.1 support:** HTTP and context partial; cross-context comparison missing. **Recommended phase:** v0.2.

**Proposed local test:** Use local endpoints returning 403 based on controlled source/context; verify that status stays an application observation.

**Sources:** [curl](https://curl.se/docs/manpage.html), [happy](https://www.rfc-editor.org/rfc/rfc8305), [apnic](https://blog.apnic.net/2025/03/11/ipv6-is-hard/).

## DEEP-06: HTTPS identity

**User input:** https://billing.example says certificate verification failed after an address change.

**Symptom:** TLS verification fails. **Competing hypotheses:** Wrong certificate or SNI; trust chain problem; interception.

**Proposed sequence:** Perform verified normal HTTPS and hostname-preserving pinned comparison to approved address; capture error and negotiated metadata where available.

**Required evidence:** Hostname, SNI, verified certificate result, IP, proxy, ALPN, TLS error and time.

**Negative controls and falsifiers:** Verified request to known-good authorized endpoint; original request repeated.

**Allowed conclusion:** Report certificate verification failure for that connection. **Prohibited overclaims:** Disable verification or assert certificate ownership from error alone.

**v0.1 support:** curl TLS partial; matched normal/pinned comparison exists for replay, but live pinned collection and comparison are missing. **Recommended phase:** v0.2.

**Proposed local test:** Use local CA and virtual-host server with matching and mismatching certificates; assert verification remains enabled.

**Sources:** [curl](https://curl.se/docs/manpage.html), [tls](https://www.rfc-editor.org/rfc/rfc6066), [alpn](https://www.rfc-editor.org/rfc/rfc7301).

## DEEP-07: Intermediate hop silence

**User input:** A trace to api.example shows a hop with missing replies. Is that router dropping traffic?

**Symptom:** Intermediate hop responses missing. **Competing hypotheses:** ICMP rate limiting; forwarding loss; ECMP.

**Proposed sequence:** Run one finite numeric path report and compare endpoint responses and HTTPS in same window.

**Required evidence:** Probe type, cycles, hop response counts, destination responses, business result and time.

**Negative controls and falsifiers:** Later hops and endpoint respond while the business request succeeds.

**Allowed conclusion:** Report missing hop responses and downstream observations. **Prohibited overclaims:** Blame router or calculate forwarded packet loss from hop reply loss.

**v0.1 support:** Ping and HTTP partial; path adapter missing. **Recommended phase:** v0.2.

**Proposed local test:** Replay versioned path samples with missing middle-hop replies and normal destination; assert no router blame.

**Sources:** [mtr](https://github.com/traviscross/mtr/blob/master/man/mtr.8.in), [icmp](https://www.rfc-editor.org/rfc/rfc1812#section-4.3.2.8).

## DEEP-08: Path variation and ECMP

**User input:** The hops to app.example change on each trace. Is the route flapping?

**Symptom:** Different intermediate addresses. **Competing hypotheses:** ECMP per-flow variation; actual route change; asymmetric replies.

**Proposed sequence:** Compare repeated bounded flow-aware reports with fixed tuple where supported, timestamps and destination outcomes.

**Required evidence:** Protocol, ports/strategy, hop hosts, family, counts and timestamps.

**Negative controls and falsifiers:** Repeated fixed-flow traces and stable endpoint results.

**Allowed conclusion:** Report observed path variation and method. **Prohibited overclaims:** Infer routing instability or geographical location from hop variation alone.

**v0.1 support:** Path adapter missing. **Recommended phase:** v0.2.

**Proposed local test:** Replay flow-aware multi-address samples and changed-flow samples; preserve both without asserting flapping.

**Sources:** [trippy](https://github.com/fujiapple852/trippy/releases).

## DEEP-09: PMTU and tunnel

**User input:** Small requests to upload.example work through the tunnel, but larger uploads stall.

**Symptom:** Large transfer failure. **Competing hypotheses:** PMTU black hole; upload server limit; tunnel congestion.

**Proposed sequence:** Record tunnel/interface context; compare authorized small and size-sensitive bounded probes and PMTU discovery.

**Required evidence:** Probe protocol and sizes, family, PMTU feedback, endpoint result, tunnel context, time.

**Negative controls and falsifiers:** Same small request succeeds and an approved alternate path is measured.

**Allowed conclusion:** Report size-dependent observations and PMTU as a candidate if supported. **Prohibited overclaims:** Prove a black hole from silence or change MTU automatically.

**v0.1 support:** Small HTTP partial; PMTU and size comparison missing. **Recommended phase:** later_path.

**Proposed local test:** Local isolated tunnel with known MTU and filtered ICMP, followed by restored feedback; verify recovery and no automatic mutation.

**Sources:** [pmtu](https://www.rfc-editor.org/rfc/rfc8201), [apnic](https://blog.apnic.net/2025/03/11/ipv6-is-hard/).

## DEEP-10: HTTP/3 and TCP

**User input:** video.example works in a browser sometimes but fails when HTTP/3 is used.

**Symptom:** Protocol-specific failure. **Competing hypotheses:** UDP/QUIC filtering; HTTP/3 service failure; TCP path difference.

**Proposed sequence:** If client supports it, compare bounded HTTP/3 and HTTP/2 requests to the same hostname and record actual negotiation and result.

**Required evidence:** Requested and negotiated version, address/family, status, error, proxy and timing.

**Negative controls and falsifiers:** Repeat HTTP/2 and HTTP/3 on same approved alternative path.

**Allowed conclusion:** Report protocol-specific behavior where negotiation is proven. **Prohibited overclaims:** Claim UDP firewall rule or HTTP/3 support merely from a fallback success.

**v0.1 support:** HTTP and negotiated http_version metadata exist; controlled HTTP/3 versus HTTP/2 selection and comparison are missing. **Recommended phase:** later_protocol.

**Proposed local test:** Local HTTP/2 and HTTP/3 services with UDP blocked in an isolated network; verify fallback is distinguished from HTTP/3 success.

**Sources:** [curl](https://curl.se/docs/manpage.html), [h3](https://www.rfc-editor.org/rfc/rfc9114).

## DEEP-11: Latency under load

**User input:** Calls to voice.example become choppy while someone uploads.

**Symptom:** Interactive latency increases during upload. **Competing hypotheses:** Queueing; host CPU contention; remote service issue.

**Proposed sequence:** With explicit test authorization, compare repeated idle, bounded load and recovery windows with throughput and latency.

**Required evidence:** Load direction/rate, interval samples, latency, endpoints, CPU/context and recovery.

**Negative controls and falsifiers:** Repeated idle and post-load windows and an unloaded control.

**Allowed conclusion:** Report repeatable load-associated latency within tested scope. **Prohibited overclaims:** Declare bufferbloat or name a queue without independent evidence.

**v0.1 support:** Finite ping partial; load and repeated windows missing. **Recommended phase:** later_load.

**Proposed local test:** Isolated test server and controlled bottleneck; validate injection independently, remove load, and verify recovery.

**Sources:** [flent](https://flent.org/tests.html).

## DEEP-12: Retransmission or capture artifact

**User input:** This capture of api.example shows TCP retransmissions. Where is the loss?

**Symptom:** TCP analysis flags. **Competing hypotheses:** Actual retransmission; reordering; capture drops or midstream capture.

**Proposed sequence:** Analyze offline capture with frame references and capture metadata; compare opposite-end capture if available.

**Required evidence:** Capture hash, frame IDs, stream, timing, flags, visibility, drops and truncation.

**Negative controls and falsifiers:** Independent complete capture covering same flow and interval.

**Allowed conclusion:** Report suspected retransmission or missing captured segments with limits. **Prohibited overclaims:** Compute path loss or blame a hop based on one capture.

**v0.1 support:** Offline PCAP discovers fields and retains capture hash, timestamps, frame/stream metadata and expert flags in hashed raw events, plus summary and coverage; structured per-stream timeline, finding-to-frame links, richer capture-origin/drop metadata and opposite-end correlation are missing. **Recommended phase:** v0.2.

**Proposed local test:** Use locally generated captures with known reorder, dropped capture frames and actual retransmission; assert distinct limitations.

**Sources:** [tcp](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html), [capture](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html).

## DEEP-13: TCP zero window

**User input:** The transfer from db.example pauses even though the route looks fine.

**Symptom:** Transfer stalls with possible zero window. **Competing hypotheses:** Receiver application pressure; loss or path interruption.

**Proposed sequence:** Inspect offline TCP window and optional scoped socket details in a matching time window.

**Required evidence:** Frame references, direction, advertised window, connection identity, timestamps and socket visibility.

**Negative controls and falsifiers:** Matched healthy transfer and receiver window reopening.

**Allowed conclusion:** Report observed receiver-advertised zero window for the flow. **Prohibited overclaims:** Name the process or blame the network without endpoint evidence.

**v0.1 support:** Offline PCAP retains and counts zero-window flags where supported; detailed advertised-window and socket correlation are missing. **Recommended phase:** later_telemetry.

**Proposed local test:** Local receiver deliberately stops reading then resumes; verify zero-window observation and scope.

**Sources:** [tcp](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html), [socket](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/man/man8/ss.8).

## DEEP-14: Interface counters

**User input:** The connection to backup.example drops during backups. Are there interface errors?

**Symptom:** Possible local interface errors. **Competing hypotheses:** NIC errors; unrelated shared traffic; remote path failure.

**Proposed sequence:** Read relevant route/interface and two timestamped snapshots of read-only interface and driver counters.

**Required evidence:** Interface identity, counter names, units, driver, timestamps, values and reset/missing state.

**Negative controls and falsifiers:** Same interface idle interval and known-good control flow.

**Allowed conclusion:** Report counter deltas on the interface during the window. **Prohibited overclaims:** Attribute shared counters to one flow or equate every driver counter with drops.

**v0.1 support:** Read-only context partial; typed deltas missing. **Recommended phase:** later_telemetry.

**Proposed local test:** Use a controlled virtual interface with known counter changes and reset; test missing/driver-specific counters.

**Sources:** [stats](https://docs.kernel.org/networking/statistics.html).

## DEEP-15: External vantage

**User input:** Is service.example unreachable only from our network?

**Symptom:** A local target request fails. **Competing hypotheses:** Local path issue; wider provider outage; service selection.

**Proposed sequence:** After explicit disclosure approval, compare bounded local observation with selected external probes and record public measurement identifiers.

**Required evidence:** Public target, probe location/ASN/ID, time, protocol, actual address and completion.

**Negative controls and falsifiers:** A known permitted control from the same probes and repeated local target.

**Allowed conclusion:** Report observed differences among named vantage points. **Prohibited overclaims:** Claim global outage or local blame from a few nonrepresentative probes.

**v0.1 support:** Local HTTP partial; external vantage missing. **Recommended phase:** later_external.

**Proposed local test:** Use a mocked API and predefined probe outputs including unavailable/partial probes; verify disclosure and cost limits.

**Sources:** [global](https://github.com/jsdelivr/globalping), [atlas](https://atlas.ripe.net/docs/getting-started/user-defined-measurements.html).

## DEEP-16: Intermittent normal window

**User input:** Users say dashboard.example failed yesterday, but it works now. Is it fixed?

**Symptom:** Historical intermittent complaint. **Competing hypotheses:** Recovered transient failure; not reproduced; insufficient coverage.

**Proposed sequence:** Run bounded normal target checks and approved control; record time and missing capabilities.

**Required evidence:** Window, sample counts, HTTP status, actual endpoint and failed/unavailable measurements.

**Negative controls and falsifiers:** Known-good control and repeated original during available window.

**Allowed conclusion:** A valid short target success supports not_reproduced; the same success with optional DNS, ping or control absent still supports not_reproduced with limitations. Missing required target observations or evidence essential to a specifically requested comparison supports insufficient_evidence for that requested conclusion. **Prohibited overclaims:** Claim permanent health, deny historical fault or infer a root cause.

**v0.1 support:** Existing scoped states and HTTP partial; longer observation missing. **Recommended phase:** v0.2.

**Proposed local test:** Check three cases: valid short target success yields not_reproduced; the same success with optional DNS, ping or control absent remains not_reproduced with limitations; missing required target observation or evidence essential to a specifically requested comparison yields insufficient_evidence for that requested conclusion.

**Sources:** [curl](https://curl.se/docs/manpage.html).
