# TShark Integration and Validation Boundaries

Reviewed on 2026-11-12 using local source, an existing PCAP, Wireshark documentation, and protocol standards. The discovery checks below did not capture live traffic, send public probes, inject failures, install software, or validate native Windows execution.

## Recommended First Integration

Provide TShark as an optional offline evidence adapter. INET-24 is its primary diagnosis acceptance case. Keep the default 25-second Internet collection round focused on curl, structured DNS, finite ping, and read-only context. Existing PCAP input enters an independent offline mode; bounded live capture can follow later.

The parent workspace already contains `pcap-evidence-analyst/scripts/analyze_pcap.py`: standard-library Python, `tshark -2 -n -T ek`, streaming events, source SHA-256, command/version, filter scope, truncated-frame counts, HTTP pairing coverage, and retained raw fields. Reuse these properties, then add deadlines, field discovery, resource limits, and the common evidence contract.

The first integration does not require live capture, key collection, HTTP/2 or HTTP/3 transaction pairing, or full WebRTC analysis.

## Discovery Checks Actually Executed

| Check | Observed result | Meaning |
| --- | --- | --- |
| tshark/dumpcap/capinfos version | 4.6.6, Linux/WSL2 | Installed executables; live capture permission remains untested |
| Locale | C.UTF-8 | Does not validate native Windows or its localized command output |
| `tshark -G fields` | Required/selected optional fields registered, exit 0 | Registration does not guarantee values in every capture |
| Existing sample | 47,804 bytes, 271 frames | One existing offline compatibility input |
| Sample SHA-256 | ff432a6b71d06cd20720f7763e584014edd0a43c3b55981c682d1b7640207abc | Identifies the actual input |
| First two frames | fields/json/ek exports exited 0 | All three formats available in this version |
| EK shape | Alternating index and packet records; underscored field names; arrays | Skip index records and preserve repeated values |
| `-c 2 -Y 'frame.number > 2'` | Exit 0, no output records | Limit counts input frames rather than matching frames |
| Invalid selected field | `-e netops.invalid.field` exited 1 with stderr | Unsupported fields are not zero anomalies |
| TCP export below | Exit 0; 542 EK lines; 91,451 bytes | Export compatibility, not diagnosis accuracy |

These checks are not a 12-case diagnosis result or a fault-injection, capture, or cross-platform acceptance report.

## Tool Interface

| Option | Adapter treatment |
| --- | --- |
| `-r FILE` | Required for offline mode; omission can enter live capture |
| `-n` | Disable address/name resolution during analysis |
| `-T ek -e FIELD` | Stream selected fields and skip index records |
| `-T fields` | Narrow queries; define escaping and repeated-value handling |
| `-T json` | Suitable for small inputs; forced termination can leave an incomplete array |
| `-G fields` | Cache field registration per version; mark missing optional fields unsupported |
| `-2` | Two-pass offline analysis; include its extra work in the deadline |
| `-Y` versus `-f` | Display filter versus capture filter; neither replaces an external resource limit |
| `-c N` | Limit input frames, including those not selected for output |
| `-a duration/filesize` | Live capture stop conditions; offline CPU time still needs external enforcement |
| `-b files` | Retained ring-file count, not an automatic termination condition |

Source: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

capinfos can provide tabular counts, size, and time range. Example: `capinfos -T -m -Q -c -s -a -e -S capture.pcapng`. It reads the input too, so it must share the analysis deadline. [capinfos manual](https://www.wireshark.org/docs/man-pages/capinfos.html).

## Proposed Offline Budgets

These are product defaults to implement and validate, not Wireshark guarantees.

| Resource | Limit |
| --- | --- |
| Input | Regular local PCAP/PCAPNG, at most 64 MiB; no streams or compressed input initially |
| Total elapsed time | 25 seconds including hashing, discovery, parsing, and completion |
| Input frames | 100,000; reaching the limit conservatively yields partial coverage |
| Retained event output | 8 MiB; stop and record truncation |
| Retained stderr | 64 KiB; record truncation separately |
| Aggregation | Bound retained sessions, addresses, and transactions as well as reading one line at a time |
| Result | Distinguish complete, partial, timeout, parse_error, unsupported; missing values stay null with a reason |

Use argument arrays, separate stderr, terminate and reap processes at the deadline, and retain only complete NDJSON records after interruption. A narrow display filter can still require substantial scanning and reassembly.

The old extractor lacks shared timeout, input/output hard limits, field registration checks, and bounded in-memory transaction/session sets. Its parser completion flag must not become a health verdict.

## Offline Query Example

Check `tshark --version` and `tshark -G fields` first. This export was checked against the existing sample. A production adapter must add the external deadline and output limits.

```bash
tshark -2 -n -r capture.pcapng -c 100000 -Y tcp -T ek \
  -e frame.number -e frame.time_epoch -e frame.cap_len -e frame.len \
  -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst \
  -e tcp.stream -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.reset \
  -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission \
  -e tcp.analysis.lost_segment -e tcp.analysis.zero_window
```

| Branch | Registered fields checked locally | Interpretation boundary |
| --- | --- | --- |
| DNS | dns.id, dns.response_to, dns.response_in, dns.time, dns.qry.name/type, dns.resp.ttl, dns.cname | Pair using transport, endpoints/ports, question and time, not ID alone |
| TCP | tcp.analysis.initial_rtt, tcp.analysis.ack_rtt, tcp.completeness, tcp.analysis.zero_window | Capture-point ACK timing is not automatically full end-to-end RTT |
| TLS | tls.handshake.extensions_server_name, tls.alert_message.desc | Missing fields do not establish success |
| QUIC | quic.connection.number, quic.version | Protocol recognition does not expose HTTP/3 application content |
| Media | rtp.seq/timestamp/ssrc, stun.type | Require correct protocol recognition and session context; arbitrary UDP is not RTP |

[DNS fields](https://www.wireshark.org/docs/dfref/d/dns.html), [TCP fields](https://www.wireshark.org/docs/dfref/t/tcp.html), [QUIC fields](https://www.wireshark.org/docs/dfref/q/quic.html). Rolling documentation must be reconciled with the actual installed version.

## Common Evidence Mapping

Record tool source/version, adapter version, exact decoding options, registered fields, capture location/interface/direction, actual endpoints, application protocol, and the relationship to the complaint. Unknown capture location remains unknown; a WSL interface is not automatically the Windows application's interface.

Keep the capture window and clock information separate from analysis time. Preserve raw values/units, metric denominator and direction, original PCAP SHA-256, derived event hashes, frame numbers, stream identifiers, display filters, and event line references. Record truncation, unavailable capture-drop counters, sessions starting before capture, and one-way visibility.

Structured observations must carry addresses, response codes, DNS answers, and arrays; the research draft's numeric measurements cannot carry them faithfully. Redacted exports receive their own hashes and a recorded transformation relationship.

## Interpretation and Counterevidence

TCP retransmission, out-of-order, and lost-segment flags are dissector observations. Missing capture frames, late capture start, one-way visibility, and reordering affect them. Describe observed indicators and compare with business outcomes; do not label a lost_segment flag as confirmed public-network packet loss. [TCP analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html).

Outbound checksum errors can reflect offloading. Retain capture context; do not change interface configuration or infer corruption from the flag alone. [Checksums](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html).

TLS content and validation causes are not always visible. TLS 1.3/ECDHE is not generally decrypted with an ordinary RSA server private key. Initial integration does not collect secrets. [Wireshark TLS](https://wiki.wireshark.org/TLS).

QUIC Initial protection differs from application-data protection; recognizing QUIC does not establish HTTP/3 response content or media quality. [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html).

For meetings, obtain same-session WebRTC statistics: selected candidate path, direction, time, loss, jitter, RTT, and relevant decoding/playback metrics. PCAP adds transport evidence; successful HTTPS does not clear the media path. [WebRTC Stats](https://www.w3.org/TR/webrtc-stats/).

No decoded DNS, no visible HTTP, and no TCP warning flags are insufficient to establish healthy_within_scope.

## Role in the Twelve Core Cases

All entries below describe planned responsibilities. Discovery did not execute diagnosis scoring.

| Case | TShark contribution | Other evidence or limit |
| --- | --- | --- |
| INET-01 DNS delay | Visible plain-DNS pairing, timing, answers | Same-IP curl comparison; encrypted DNS visibility gap |
| INET-05 TCP timeout | SYN sequence, observed responses/RST | Connection outcomes and controls; no automatic ISP attribution |
| INET-06 TLS failure | Visible handshake/alerts | Independent TLS verification or curl error |
| INET-07 response/transfer delay | Decoded HTTP/1.x pairing and TCP timeline | curl/HAR/server timing; encrypted gaps are not CPU time |
| INET-10 upload contention | Directional traffic timeline and TCP indicators | Actual load/interface counters and idle/recovery comparison |
| INET-18 missing hop responses | Business flow as counterevidence | Path/end-host/business observations remain necessary |
| INET-20 verified healthy | Transactions within a defined scope | Independently verified controller health; parsing success is insufficient |
| INET-23 not reproduced | Observed capture window only | Align historical complaint time |
| INET-24 PCAP only | Primary acceptance: extraction, hash, packet references, limits | No invented live commands or invisible loss location |
| INET-25 incorrect DNS claim | Visible normal DNS versus later HTTP wait | curl/HAR for encrypted traffic; no server-CPU inference |
| INET-26 missing path privileges | Continue offline if PCAP exists | Tool permission failure is not business failure |
| INET-27 one-target failure | Target/control session scope | Matched protocol/time; no Internet-wide inference |

Controller truth, injection parameters, accepted conclusions, and scoring rules stay outside the evaluated Agent's accessible files. Adapter regression cases should cover empty input, damaged data, missing fields, nonzero exit, filtered-empty output, paths with spaces, timeout/output cap, truncated frames, one-way flows, repeated fields, and unavailable TLS content.

## Later Live Capture

A URL diagnosis request does not by itself specify whole-machine capture scope. Use an already authorized interface/time/traffic scope, or obtain that missing scope before capture. Prefer dumpcap for capture and TShark for subsequent offline analysis.

The following is an unexecuted design example. `192.0.2.10` is a documentation address; substitute the actual approved interface and target.

```bash
dumpcap -i APPROVED_INTERFACE -p \
  -f 'host 192.0.2.10 and (tcp port 443 or udp port 443)' \
  -s 256 -a duration:20 -a filesize:8000 -c 20000 \
  -w target-window.pcapng
```

The 20-second, 8,000-kB, and 20,000-packet limits also need an external timeout and actual output-size check. File-size thresholds are not exact byte truncation. A 256-byte snapshot reduces payload but can truncate useful fields and does not guarantee anonymization. DNS needs a separately scoped filter for the actual resolver/transport. Ring-file counts require an additional stop condition. [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html).

Probe capture permission independently from offline readability. Windows live capture requires an appropriate Npcap installation; reading existing files does not. Do not automatically change groups, capabilities, or drivers. [Capture privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges), [Windows installation](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).

## Privacy and Distribution

The runtime ZIP contains necessary Skill instructions, adapter source, contracts, configuration, and dependency/license declarations. Test inputs and executed validation records belong in separate validation material. Do not bundle customer captures, keys, raw URL queries, Cookie/Authorization values, tool binaries, or full payloads.

IP addresses, DNS names, and SNI can also be sensitive. Apply the allowed-field/redaction policy before output reaches a cloud-backed Agent, not only in the final report. PCAPNG can contain decryption-secret blocks. [PCAPNG secrets](https://wiki.wireshark.org/TLS#embedding-decryption-secrets-in-a-pcapng-file).

The installed tools declare GPL version 2 or later. Wireshark discusses communicating with separate programs through pipes or sockets; this does not establish compliance with the supplied publication rules. Npcap has separate redistribution terms. [Wireshark FAQ](https://www.wireshark.org/faq.html), [Npcap OEM](https://npcap.com/oem/).

The supplied security specification includes Skills-001 concerning executables, Skills-036 concerning GPL/AGPL, and Skills-032 concerning encrypted communication. Declaring TShark as an optional external executable reduces packaged dependencies but does not settle the scanner's treatment of external GPL tools or diagnostic DNS/ICMP. Confirm the actual submission interpretation; do not misstate these as cleared checks.
