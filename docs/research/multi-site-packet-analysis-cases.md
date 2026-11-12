# Multi-site packet-analysis cases

Research snapshot: 2026-11-12; source commit `42b2c36`. 19 case entries from 11 publisher families; 6 new capture files from five distributing families; individual capture ownership is not established for all of them. The entries include documented incidents, deliberately reconstructed labs and teaching references; they are not all independent incidents. Novell Connection and Chappell University are different publishers but share author Laura Chappell, so the publisher count is not a count of independent analysts. The [machine-readable registry](multi-site-packet-analysis-cases.json) records metrics and provenance.

**No new capture is claimed as a substantial primary operational validation input.** The 1,172-frame HTTP transfer contains a full session but its asserted teardown and ownership are disputed; it does not demonstrate a production fault. The controlled IKE capture contains a meaningful failure-to-recovery experiment but exercises a protocol the Skill does not diagnose. The two incident TLS traces were heavily redacted and are small; the browsing sample has unspecified origin. Their value is reference and exploratory execution. Existing captures and their prior validation remain in [the earlier corpus](real-pcap-corpus.md); lifecycle scenarios in the [proposal](closed-loop-workflow-proposal.md) remain unexecuted.

## Bounded capture results

Original archive bytes and extracted files are kept only under ignored `.tools/packet-case-library/`. The ZIP hashes and retrieval timestamps, extract hashes, timestamps, protocol mix, stream counts, packet and truncation counts, and all validation checks are in JSON. Reuse terms are unknown for all five distributors; seek permission before redistribution. Extracted ZIP members are unchanged original capture bytes; no keys were downloaded, imported or used. Commands inspect only aggregate packet metadata, not payloads. Local modification times record retrieval completion, not signed receipts.

| Capture | Frames / bytes | UTC extrema | TCP / UDP streams | Truncated | CLI status |
| --- | ---: | --- | ---: | ---: | --- |
| ike | 1054 / 337102 | 2017-06-27T14:31:18.604685+00:00 to 2017-06-27T14:39:47.801326+00:00 | 0 / 4 | 0 | `insufficient_evidence` |
| networkwalks | 107 / 31158 | 2025-10-12T06:20:00.401809+00:00 to 2025-10-12T06:20:07.532963+00:00 | 5 / 7 | 0 | `insufficient_evidence` |
| client | 128 / 28848 | 2020-05-20T15:56:09.395012+00:00 to 2020-05-20T15:56:45.458192+00:00 | 4 / 33 | 0 | `insufficient_evidence` |
| server | 60 / 25820 | 2020-05-20T15:54:42.588940+00:00 to 2020-05-20T15:55:20.088683+00:00 | 3 / 7 | 0 | `insufficient_evidence` |
| tcp | 1172 / 1153109 | 2012-07-12T06:04:41.439558+00:00 to 2012-07-12T06:04:45.638362+00:00 | 1 / 0 | 0 | `insufficient_evidence` |
| chappell | 36 / 59828 | 2008-07-16T00:52:11.321640+00:00 to 2008-07-16T00:53:11.330728+00:00 | 1 / 0 | 0 | `insufficient_evidence` |

All six files have zero timestamp regressions. TShark and capinfos 4.7.4 independently report the counts and time extrema; JSON protocol counts are per-frame labels, so a frame can appear under multiple protocols. Wire bytes differ from file bytes. The paired TLS files have different capture clocks/windows, so compare packet identity and direction before timing across files. IKE spans 509.196641 seconds and contains 226 IKE and 542 ESP-labelled frames; an ESP count is not proof that a service recovered.

Each file ran `python3 -B skills/internet-access-triage/scripts/diagnose.py --pcap INPUT --out NEW_DIRECTORY` on the full file. All six exited 0, selected all frames, emitted `insufficient_evidence`, and recorded no parser failures or output truncation. Input hashes, manifest artifact hashes, top-level diagnosis evidence references and independent frame/truncation counts matched, and subprocess records report no network requests. This validates bounded execution and evidence integrity, not diagnosis accuracy or incident root cause. The 36-frame Chappell sample produced one transport-indicator candidate based on 11 retransmission-indicator frames; this is not a diagnosis of network loss. The Skill cannot correlate the paired TLS traces, firewall log, IKE configuration or recovery. Its output cannot reproduce the authors’ conclusions from these inputs.

PacketBomb’s Tomcat article fetch returned 502 and a direct request failed with TLS EOF; its advertised trace could not be obtained. A direct Networkwalks page request returned 406, but its indexed page exposed a working ZIP. The Chappell iperf file exceeded the 64 MiB cap and was not imported. Two Wireshark Resource Hub download links returned 404; the Packet-Foo 2017 hands-on ZIP contained short exercises and was not adopted as an input. The Chappell rights document request failed with TLS EOF. Failed downloads and unprocessed archives are not counted as captures.

The [distributor README](https://raw.githubusercontent.com/EthicalHackingLabs/tcp-packet-analysis-wireshark/main/README.md) describes a 1,172-frame HTTP capture ending in a reset; the [author write-up](https://khalif.vercel.app/blogs/how-i-used-wireshark-to-dissect-a-real-tcp-connection-from-handshake-to-teardown-9de) presents its analysis. Local TShark finds FINs at frames 1170 and 1171 and no reset frames. An [older university exercise](https://kevincurran.org/com320/labs/wireshark/lab-tcp.pdf) depicts the same trace name and endpoints. Its linked capture was not downloaded or hashed for comparison, so original ownership and byte identity are not established. The file is a bounded execution and packet-level reference, not fault-cause validation.

## Case registry

Each finding below is attributed to the publisher. `Partial` describes available aggregate signals, not an ability to localize a cause. Dates and individual authors are marked unknown where the accessible source does not establish them. Source descriptions and local observations are distinguished explicitly.

### PACKET-01: Two views of failed Skype TLS

**Source:** [Packet-Foo](https://blog.packet-foo.com/2020/07/analyzing-a-failed-tls-connection/); Eddi; 2020-07-13. **Provenance:** documented incident; publisher redacted trace. **Capture:** [publisher link](https://www.packet-foo.com/blog/TLS/Skype.zip); downloaded.

**Symptom and evidence:** Firewall permit log yet Skype TLS exchange fails. Eddi describes TCP termination at firewall inferred from sequence/TTL differences, opposing FINs and short server-side interval. A later firewall drop log and configuration change supported that diagnosis. Capture is heavily redacted, including hex edits; successful reverse flow is a control. Independent TShark confirms client handshake frames 47–49, ClientHello 50 and FIN 53; server handshake frames 24–26, ClientHello 27, ServerHello 28 and FIN 29. Neither capture alone proves who sent FIN or why.

**Alternatives and falsifiers:** Missing packets, proxy termination, offload or time skew; compare both views, independent firewall logs and a matched successful flow.

**Current Skill:** Partial: TCP/TLS metadata and FIN counts; no paired-vantage correlation, TLS policy or firewall logs. **Adoption:** Downloadable pair is small and redacted; strong reference for a paired-vantage workflow, not a primary operational accuracy benchmark.

### PACKET-02: SMB2 slow reads and writes

**Source:** [Packet-Foo](https://blog.packet-foo.com/2016/10/trace-file-case-files-smb2-performance/); Eddi; 2016-10-28. **Provenance:** documented incident; captures linked by original questioner, unavailable here. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** SMB2 reads across a WAN slower than writes. Eddi reports 23 ms handshake RTT, up to 2.5 s read service time, a sawtooth pattern, and overlapping data in frames 734 and 824. The author infers missing reverse ACKs; device and underlying cause were not confirmed.

**Alternatives and falsifiers:** Capture loss, asymmetry, endpoint behavior, ACK delay and application pacing; simultaneous sender capture and counters can challenge the inference.

**Current Skill:** Partial TCP indicators; no SMB service-time, credit analysis or multi-vantage correlation. **Adoption:** High-value operator reference; seek original full captures and rights before any adoption.

### PACKET-03: Intermittent enterprise capture search

**Source:** [Packet-Foo](https://blog.packet-foo.com/2015/01/diagnosing-intermittent-network-problems/); Jasper; 2015-01-07. **Provenance:** documented operator experience; no accessible capture. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Intermittent problem with uncertain time and location in a complex virtual environment. Jasper describes multi-vantage capture, encryption without keys and a large capture job; a small example isolates a slow handshake from millions of packets. He cautions about capture points and missing records.

**Alternatives and falsifiers:** SPAN drops, timestamp offsets, proxies and missing symptom windows can imitate network loss; verify tap placement, coverage and source clocks.

**Current Skill:** Partial bounded offline summaries; no multi-file case selection, multi-vantage mapping or symptom timeline. **Adoption:** Reference only; full case files and per-incident boundaries not publicly established.

### PACKET-04: HTTP transfer pauses at client

**Source:** [plantegg](https://plantegg.github.io/2024/10/10/一次抓包分析过程/); plantegg; 2024-10-10. **Provenance:** documented incident; no accessible capture. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Recurring ~100 ms pauses during HTTP transfer. Author reports a 28 MB client trace over ~600 ms and ACKs before a sending gap; sender process or file reads are hypotheses. They explicitly could not access the environment, could not reproduce and reached no confirmed cause.

**Alternatives and falsifiers:** Network loss or capture artifacts and sender scheduling remain possibilities; compare synchronized server trace, host scheduling and application logs.

**Current Skill:** Partial TCP counts; no per-flow sequence/timing plateau analysis or host evidence. **Adoption:** High-value substantial capture candidate if author shares it; never label root cause as proven.

### PACKET-05: MySQL streaming disconnect in a large capture

**Source:** [plantegg](https://plantegg.github.io/2023/08/23/如何从几百万个抓包中找到一个异常的包/); plantegg; 2023-08-23. **Provenance:** documented incident; no accessible capture. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** One of 160 concurrent database streams fails after minutes; other sessions then close. Author describes ~10 GB of captures, finds first failing stream via FIN/RST and reports server FIN during result transfer; MySQL bug is a hypothesis and final cause remained open.

**Alternatives and falsifiers:** Server timeout, process exit, proxy behavior, capture position and clock/order issues; correlate server log, matched session and complete handshake.

**Current Skill:** Partial FIN counts; 64 MiB and 100,000 frame input bounds prohibit full original, no MySQL interpretation. **Adoption:** Reference for bounded extraction with parent hashes and offsets; seek author-approved full or traceable extracted session.

### PACKET-06: SSH and TLS intermittent VPN MTU mismatch

**Source:** [7th Zero](https://7thzero.com/blog/mtu-mismatch-and-tcp-retransmissions); 7th Zero (individual author not stated); May 16; year not stated on accessible page. **Provenance:** documented incident; screenshots only. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Some SSH/TLS sessions fail despite successful TCP handshake. Author reports opposite-end capture showing ICMP fragmentation needed with next-hop MTU 1446, duplicate ACK and retransmission; lowering appliance MTU to 1440 cleared reported symptoms.

**Alternatives and falsifiers:** Host offload, capture loss and other path MTU bottlenecks; compare both sides and repeat original service operation after controlled change.

**Current Skill:** Partial TCP/TLS metadata; no ICMP MTU correlation or same-path recovery verification. **Adoption:** High-value real case; seek trace pair and context, do not infer cause from TCP flags alone.

### PACKET-07: NFS metadata succeeds while bulk operations hang

**Source:** [Why Is The Internet Broken?](https://whyistheinternetbroken.wordpress.com/2017/04/03/osi-troubleshooting/); Justin Parisi; 2017-04-03. **Provenance:** author lab demonstration; no accessible capture. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** NFS mount and small operations work while reads and writes hang on a new 10 Gb network. Author reports two endpoint captures: server replies and retransmits READDIRPLUS while client does not see reply. He investigates jumbo MTU through the path after basic ping succeeds.

**Alternatives and falsifiers:** Capture loss, incorrect vantage or route, host MTU and switch path differences; compare matching packet IDs and full-sized traffic at each boundary.

**Current Skill:** Partial retransmission flags; no NFS operation mapping, paired capture, MTU path or recovery check. **Adoption:** Retain as lab reference; obtain source traces and exact working/failing paths before validation.

### PACKET-08: IKE failures and recovery in controlled lab

**Source:** [Weberblog](https://weberblog.net/ike-challenges/); Johannes Weber; 2017-09-27. **Provenance:** author lab demonstration; downloaded. **Capture:** [publisher link](https://weberblog.net/wp-content/uploads/2017/09/IKE-Challenges-final.zip); downloaded.

**Symptom and evidence:** Four VPN connections fail before deliberate firewall configuration correction. Weber describes intentionally wrong phase-one proposals, peer ID, proxy ID and pre-shared key. His source identifies failed traffic around frames 63–250 and corrected exchanges around 475–570 followed by ESP; comment confirms two silent-drop causes cannot be distinguished from trace alone. Independent aggregate sees 226 IKE and 542 ESP frames.

**Alternatives and falsifiers:** Same absence of replies can result from loss, policy or capture placement; separate configuration and logs are needed to distinguish silent-drop causes.

**Current Skill:** Missing IKE interpretation and comparison of failing versus recovered episodes; generic protocol counts only. **Adoption:** Complete bounded controlled capture, valuable exploratory regression but not production proof or a TCP fault benchmark.

### PACKET-09: Path MTU discovery at two bottlenecks

**Source:** [Weberblog](https://weberblog.net/path-mtu-discovery/); Johannes Weber; 2025-03-24. **Provenance:** source-described capture, incident context unspecified. **Capture:** [publisher link](https://weberblog.net/the-ultimate-pcap/); not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Router troubleshooting produced IPv6 packet-too-big responses. Weber reports ICMPv6 MTU 1492 followed by 1480, and smaller subsequent transmissions. His IPv4 example uses ICMP type 3 code 4 and MTU 1492.

**Alternatives and falsifiers:** PTB may be unrelated to target flow or missing; correlate quoted original packet, endpoints and capture vantage.

**Current Skill:** Missing ICMP error-to-flow correlation and PMTU progression. **Adoption:** Reference only: source points to a multi-year merged Ultimate PCAP, unsuitable for global timing; derive an attributed session only after obtaining the exact version and rights.

### PACKET-10: SFTP constrained by window and RTT

**Source:** [Cisco](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215092-analyze-firepower-firewall-captures-to-e.html); Mikis Zafeiroudis and Ilkin Gasimov; 2024-07-31. **Provenance:** reconstructed TAC-based lab; no downloadable capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** SFTP reaches about 5 Mbps despite a 100 Mbps path. Cisco compares handshake-derived window scaling and RTT with a faster example; the two comparison flows have different endpoints. The theoretical window/RTT estimate is a ceiling under stated assumptions, not an independent measurement of cause.

**Alternatives and falsifiers:** Congestion, disk/application pacing and capture overhead; compare matched endpoints, RTT, receiver window and retransmissions.

**Current Skill:** Partial TCP metadata; missing window-scale interpretation and comparable baseline checks. **Adoption:** Use as lab-derived design reference; no original trace available here.

### PACKET-11: Slow FTP with retransmission indicators

**Source:** [Cisco](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215092-analyze-firepower-firewall-captures-to-e.html); Mikis Zafeiroudis and Ilkin Gasimov; 2024-07-31. **Provenance:** reconstructed TAC-based lab; no downloadable capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** FTP download is slow through firewall. Cisco shows out-of-order, retransmission and missing-segment indications, and recommends simultaneous capture to locate the affected segment.

**Alternatives and falsifiers:** Reordering, capture drops, offload and incomplete capture can produce similar indicators; compare synchronized end captures and interface counters.

**Current Skill:** Partial TCP retransmission and lost-segment counts; no path localization. **Adoption:** Reference only; screenshots cannot provide a replayable fault capture.

### PACKET-12: Corruption across firewall capture points

**Source:** [Cisco](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215092-analyze-firepower-firewall-captures-to-e.html); Mikis Zafeiroudis and Ilkin Gasimov; 2024-07-31. **Provenance:** reconstructed TAC-based lab; no downloadable capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** TCP connectivity failure with changed packet bytes. Cisco describes a comparison across capture points and reports two extra bytes from a switch interface driver in its scenario.

**Alternatives and falsifiers:** Capture format, offload and other rewriting or middleboxes; compare matching packets at independent points and device counters.

**Current Skill:** Missing packet-byte comparison and multi-vantage correlation. **Adoption:** Reference only; requires traceable dual captures and external owner evidence.

### PACKET-13: Missing UDP syslog packets

**Source:** [Cisco](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215092-analyze-firepower-firewall-captures-to-e.html); Mikis Zafeiroudis and Ilkin Gasimov; 2024-07-31. **Provenance:** reconstructed TAC-based lab; no downloadable capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Syslog messages do not arrive at receiver. Cisco shows zero packets on two firewall capture points for the configured filter and investigates connection and path information. Zero observations at a point do not alone prove source or network failure.

**Alternatives and falsifiers:** Incorrect filter, wrong interface, alternate route, capture loss or silent sender; compare capture configuration and source/receiver records.

**Current Skill:** Partial UDP counts; no multiple capture point reconciliation or topology. **Adoption:** Reference only; input coverage must be explicit before considering absence evidence.

### PACKET-14: Slow FTP upload after firewall replacement

**Source:** [PacketBomb](https://packetbomb.com/troubleshooting-slow-ftp-uploads/); Kary; Nov 29; year not established. **Provenance:** documented subscriber incident; capture access not established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Video FTP uploads slowed after firewall replacement. Kary describes Peter having identified the issue, and presents an analysis of why; accessible text does not establish packet-level conclusion or measured values.

**Alternatives and falsifiers:** Window, RTT, path change, server performance and capture gaps; obtain trace and matched pre/post settings before attribution.

**Current Skill:** Partial TCP counts; missing window/RTT throughput analysis. **Adoption:** Reference lead only; main page returned 502 during review and no trace was obtained.

### PACKET-15: Tomcat large-file throughput on Windows

**Source:** [PacketBomb](https://packetbomb.com/solving-tomcat-throughput-issues-on-windows/); Kary; Apr 14; year not established. **Provenance:** documented subscriber incident; linked capture not obtained. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Large files served by Tomcat are slow; Apache and IIS comparison did not show the same symptom. Kary reports Simon diagnosed the issue and found a solution; accessible page summary does not expose the packet finding.

**Alternatives and falsifiers:** Application configuration, disk I/O, TCP window and changed workloads; use matched same-host capture and application settings.

**Current Skill:** Partial TCP metadata; no application comparison or throughput bottleneck analysis. **Adoption:** Reference lead; page advertised downloadable trace but direct page requests failed, so trace and cause remain unverified.

### PACKET-16: Spurious TCP retransmission interpretation

**Source:** [Chappell University](https://www.chappell-university.com/post/spurious-retransmissions-a-concern); Laura Chappell; 2019-07-06. **Provenance:** source-unspecified filtered reference capture. **Capture:** [publisher link](https://www.chappell-university.com/traces); not downloaded / no accessible standalone capture established.

**Symptom and evidence:** TCP analyzer flags retransmissions after an ACK. Chappell describes 22 filtered frames, including frame 11 ACK and frame 14 flagged retransmission; an ACK observed at the client may not have reached sender before its timer.

**Alternatives and falsifiers:** Late/lost ACK, host stack behavior or capture artifacts; sender-side trace checks whether ACK arrived.

**Current Skill:** Partial spurious retransmission count and explicit limitations; no direction-specific ACK timing. **Adoption:** Small filtered teaching reference only; no claim it validates incident performance.

### PACKET-17: Saved website browsing capture

**Source:** [Networkwalks Academy](https://networkwalks.com/wireshark/); Networkwalks Academy; individual author not stated; date not stated. **Provenance:** source unspecified; downloaded teaching reference. **Capture:** [publisher link](https://networkwalks.com/wp-content/uploads/2022/06/WK1-PM4.c-Practice-Lab-Wireshark-PCAP-Analysis-v1.zip); downloaded.

**Symptom and evidence:** Teaching task asks readers to inspect a saved website visit. Publisher identifies a saved microsoft.com capture but does not establish its operational origin. Independent count is 107 frames, including 14 DNS and 32 TLS protocol-labelled frames; no fault is asserted.

**Alternatives and falsifiers:** Absence of abnormal packets is not service health; capture duration, target and independent baseline govern interpretation.

**Current Skill:** Partial DNS and TLS metadata; no business-health inference from offline trace. **Adoption:** Small reference capture only; not a primary accuracy benchmark.

### PACKET-18: Coop logistics Java application stalls

**Source:** [Allegro Packets](https://allegro-packets.com/en/case-studies/coop); Allegro Packets; individual author not stated; date not stated. **Provenance:** vendor-described customer incident; no public capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Coop logistics reported delays in a Java application and automated data exchange. Allegro reports application-layer pauses, no TCP retransmission indicators and short TCP responses; it sent captured protocol streams to the application supplier. The vendor reports the supplier attributed resets to jumbo-frame handling in the Java Socket Selector library and that an update resolved the issue. The capture and supplier records are unavailable, so the causal chain is not independently verified.

**Alternatives and falsifiers:** A lack of TCP retransmission indicators alone does not eliminate network, host or capture problems; compare application logs, both endpoint traces, traffic size and a matched service operation after the change.

**Current Skill:** Partial TCP metadata; no proprietary application transaction timing, Java diagnostics or business recovery check. **Adoption:** Strong incident narrative for future acquisition; obtain original capture and supplier and recovery records before causal validation.

### PACKET-19: Slow login with absent service and misleading DNS

**Source:** [Novell Connection](https://support.novell.com/techcenter/articles/nc2002_03.html); Laura Chappell; 2002-03-01. **Provenance:** documented onsite company incident; screenshots, no public capture established. **Capture:** not downloaded / no accessible standalone capture established.

**Symptom and evidence:** Slow logins and application launches affected an IPX and NetWare network. Chappell reports WINS lookup sequences adding 46 seconds to login and unanswered UDP port 34716 transmissions around six seconds apart at source-reported frames 354–356. She associates the latter with a retired Sitemeter service and DNS entries pointing at a non-serving address; onsite staff removed those entries and she reports quicker resolution. Her detailed service sequence includes explicitly labeled inferences.

**Alternatives and falsifiers:** Test whether the intended service is running, compare DNS answers and application logs, and reproduce the same login with before/after evidence. Missing captures and undocumented dependencies limit independent attribution.

**Current Skill:** Partial DNS/UDP frame counts; no legacy IPX/SAP or end-to-end application dependency and startup-delay analysis. **Adoption:** Historical 2002 operator case and reference only; do not generalize its legacy NetWare/WINS configuration or disable WINS without establishing present dependencies.

## Priorities and limits

The highest-value next acquisitions are the Packet-Foo paired TLS incident with its external firewall log and a fuller capture window, the 7th Zero two-ended MTU incident, and the plantegg HTTP transfer pause with server-side evidence. These exercise mutually different ambiguity: proxy-induced endpoint appearance, path MTU evidence, and a sender gap without a settled cause. The Packet-Foo pair is already available as a small reference, but its redaction and abbreviated context limit validation. All require permission and suitable context before broader distribution or claims of operational accuracy.

No live probe, remote device action, ticket update or runtime change was performed. Operational verification still requires substantial public incident captures or traceable derived sessions with original hashes and frame mapping, independently documented controls and explicit capture scope.
