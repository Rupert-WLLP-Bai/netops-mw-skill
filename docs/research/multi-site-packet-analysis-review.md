# Final independent verdict

Date: 2026-11-12. Source HEAD remains `42b2c36`. Scope: targeted verification of the sole P2 source-traceability correction after authoring froze again. The broader source audit and six-input integrity/metadata review in `/tmp/netops-packet-cases-sol-review.md` continue to apply.

**APPROVED for documentation delivery. No unresolved material findings.**

The HTTP `tcp` capture now has three labeled `supporting_sources`: distributor README, author write-up, and older university exercise. The Markdown links the same three sources and preserves the narrow distinction between a depicted trace name/endpoint match and unestablished original ownership or byte identity. It retains local FIN frames 1170/1171 and no RST, and does not promote the reference to causal validation.

Fresh targeted verification passed: after removing only the added `supporting_sources` field, the six capture records exactly equal the saved pre-correction records; all six capture SHA-256 values still match local originals; all substantive case fields correspond between Markdown and JSON; sequential IDs and totals remain 19 cases, 11 publisher families, 6 files, 5 distributing families, and 0 primary validation captures. The earlier limits remain explicit: attributed incidents, controlled labs, teaching references and unverified leads are distinct; the Skill's bounded executions do not reproduce complete author diagnoses.

The two reviewed research artifacts and a faithful mechanical copy of the review record may now be committed without an additional review cycle. Copying this verdict and the prior review faithfully, recording the P2 as resolved, and making the documentation-only commit require no new substantive review. Any new substantive authoring falls outside this approval. This review makes no authorization or claim concerning push, merge or operational deployment.

No source/runtime, index, branch, remote, raw capture, run output or project file was changed by this targeted review. No new download, probe, diagnostic execution or full unit-suite run was needed.

---

# Final independent review of the frozen packet-analysis research library

Date: 2026-11-12. Reviewed workspace: `/home/pejoy/code/netops-mw-skill`, branch `feat/packet-analysis-case-library`, source HEAD `42b2c36`. Reviewed the two untracked research deliverables after the authoring freeze, the handoff, and retained ignored evidence. No project file, branch, index, commit, runtime, test, package, service or device was changed by this review.

## Verdict

**One P2 research traceability correction is required before recording approval.** No incorrect packet metric, manifest integrity failure, overstated operational validation result, or material defect in the 19 case descriptions was found. The library is otherwise suitable as attributed research and acquisition guidance. It does not establish new substantial operational accuracy validation.

### P2: Preserve supporting sources for the disputed HTTP sample provenance

Locations: `docs/research/multi-site-packet-analysis-cases.md:5`, `docs/research/multi-site-packet-analysis-cases.json:4`, `:9` and the `tcp` capture record beginning at `:236`.

The catalog disputes the downloaded HTTP sample's asserted teardown/ownership and states that older teaching material depicts the same trace name/endpoints. However, neither deliverable links the article/README making those assertions or the older teaching reference. The only HTTP source URL retained is a raw binary URL. Unlike the 19 case entries, this downloaded input has no source narrative or source-reference list. A later reader can verify its bytes but cannot reproduce the provenance assessment from the saved catalog. This matters to the user's explicit requirement for traceable real captures and is not a request to turn this reference into an operational benchmark.

Minimal correction: retain a source URL for the EthicalHackingLabs README/article and the older university exercise alongside the `tcp` capture, and link them in a short Markdown provenance note. Keep the precise finding: the accessible teaching material depicts the same named trace and endpoints; original ownership and byte identity to its linked capture have not been independently established. Retain the independent FIN/no-RST observation and zero-primary-validation decision. No extra download, runtime change, new case or changed totals is required.

Supporting primary references found during review:

- [Distributor README](https://raw.githubusercontent.com/EthicalHackingLabs/tcp-packet-analysis-wireshark/main/README.md): describes 1,172 frames and a reset teardown, and links the author's write-up.
- [Author write-up](https://khalif.vercel.app/blogs/how-i-used-wireshark-to-dissect-a-real-tcp-connection-from-handshake-to-teardown-9de): search-indexed primary page describes the client as the author's machine. The linked dev.to URL was unavailable through the fetch tool.
- [University TCP exercise](https://kevincurran.org/com320/labs/wireshark/lab-tcp.pdf): indexed document depicts `trace-tcp.pcap` and the same client/server endpoint pair and links a trace. The related [TCP/UDP exercise](https://kevincurran.org/com320/labs/wireshark/lab-tcp%26udp.pdf) also depicts it. I did not download/hash the older linked capture, so I make no byte-identity claim.

This review does not require a second broad review cycle after this exact documentary correction. Verify that the links and conservative wording are present, preserve the six capture/run records and totals, then record this finding as resolved. Any substantive new authoring should be reviewed separately.

## Fresh structural and integrity checks

A separate, read-only Python check parsed JSON, compared every substantive per-case value with its Markdown section, checked the full ID sequence, and recomputed all capture/archive digests. All checks passed:

- 19 sequential IDs, `PACKET-01` through `PACKET-19`; 11 distinct case publisher families; 6 new files from 5 distributing families; 0 primary validation captures. Publisher and analyst independence are explicitly distinguished. Laura Chappell's two publishing venues are not counted as independent analysts.
- All titles, publishers, authors, dates, landing URLs, provenance grades, capture status, symptoms, source observations, alternatives, coverage and adoption decisions correspond between Markdown and JSON.
- Three adopted ZIP archives match their recorded SHA-256 and sizes. Each of the four corresponding extracted captures matches its original ZIP member bytes. The unadopted 2017 Packet-Foo training ZIP is not counted as an adopted archive or capture.
- All six original capture sizes and SHA-256 values match. All six paths and the three adopted ZIPs remain ignored by Git.
- All 36 manifest artifact hashes match retained files. Every recorded Skill source hash matches the current source. All six input hashes match the manifest scope.
- Top-level and candidate evidence references resolve: one reference occurrence for each of the first five runs, two occurrences (same evidence ID used at top level and candidate) for Chappell. Every run has zero validation errors, zero manifest failures, complete successful subprocess records, and no recorded network request or output truncation.
- Each diagnosis and manifest status is `insufficient_evidence`. Five runs have zero candidates; Chappell has one explicitly scoped transport-indicator candidate.

Independently reran TShark metadata extraction against all six files, comparing frame count, wire bytes, UTC extrema, timestamp regressions, stream counts, protocol-label counts and truncation counts with JSON. All values matched. Independently ran capinfos packet-count/extrema/order checks: all six packet counts and extrema agree and all have strict timestamp order. capinfos displayed local UTC+8 times; comparison used the corresponding UTC instants.

| Input | Frames | File bytes | Truncated frames | Candidates |
| --- | ---: | ---: | ---: | ---: |
| IKE controlled lab | 1054 | 337102 | 0 | 0 |
| Networkwalks website reference | 107 | 31158 | 0 | 0 |
| Packet-Foo client | 128 | 28848 | 0 | 0 |
| Packet-Foo server | 60 | 25820 | 0 | 0 |
| HTTP reference | 1172 | 1153109 | 0 | 0 |
| Chappell McAfee reference | 36 | 59828 | 0 | 1 |

Full PCAPNG block walks completed for all three PCAPNG files: client 130 blocks, server 62 blocks, Chappell 39 blocks, and zero decryption-secrets blocks. No payload object was extracted or executed; no key or decryption workflow was used.

Independent packet metadata checks confirm HTTP FIN at frames 1170/1171 and no RST. The Packet-Foo failed client flow has handshake 47–49, ClientHello 50 and FIN 53; the server has handshake 24–26, ClientHello 27, ServerHello 28 and FIN 29. These facts are observational and do not independently identify the middlebox policy or prove the source's root cause.

## Primary-source assessment

Reopened the catalog's primary landing pages using web fetch/search; used a bounded direct HTTP retrieval when the Novell web fetch timed out. No active network probes, device actions, external messages, uploads, installations, or fresh capture downloads occurred.

- **PACKET-01 / Packet-Foo TLS:** The [primary article](https://blog.packet-foo.com/2020/07/analyzing-a-failed-tls-connection/) supports Eddi/date attribution, two-endpoint analysis, heavy redaction including hex edits, later firewall drop log and reported configuration recovery. The catalog correctly uses actual ServerHello frame 28 rather than the article's typo. Firewall log/context remains external evidence.
- **PACKET-02 / SMB2:** The [primary article](https://blog.packet-foo.com/2016/10/trace-file-case-files-smb2-performance/) supports the numerical observations and author inference. It explicitly asks for further verification before blaming Nexus; the catalog does not present Nexus or an underlying device cause as confirmed. Reader commentary offers other interpretations; author attribution and alternatives adequately preserve uncertainty.
- **PACKET-03 / intermittent capture search:** The [primary article](https://blog.packet-foo.com/2015/01/diagnosing-intermittent-network-problems/) is operator experience plus a separate illustrative extraction. The catalog avoids treating its heterogeneous examples as a replayable single capture or settled cause.
- **PACKET-04/05 / plantegg:** Both [HTTP](https://plantegg.github.io/2024/10/10/一次抓包分析过程/) and [MySQL](https://plantegg.github.io/2023/08/23/如何从几百万个抓包中找到一个异常的包/) sources support the stated publication dates and quantities. HTTP author explicitly lacked environment access and failed reproduction; MySQL's final cause remained open. The catalog preserves both limits.
- **PACKET-06 / 7th Zero:** The [primary article](https://7thzero.com/blog/mtu-mismatch-and-tcp-retransmissions) supports the 1446 next-hop MTU and reported 1440 workaround. The accessible page gives May 16 without year; the catalog does not invent one.
- **PACKET-07 / NFS:** The [primary article](https://whyistheinternetbroken.wordpress.com/2017/04/03/osi-troubleshooting/) describes the author's NetApp internal-lab experience, separate endpoint observations and jumbo-MTU investigation. The catalog labels it a lab reference, with capture coverage and path alternatives retained.
- **PACKET-08/09 / Weber:** The [IKE source](https://weberblog.net/ike-challenges/) explicitly documents deliberate misconfiguration, correction, frame intervals, and two indistinguishable silent-drop causes. The [PMTUD source](https://weberblog.net/path-mtu-discovery/) supports the two MTUs and points to Ultimate PCAP. The catalog does not infer service health from ESP counts or treat a merged multi-year file as a single timing experiment.
- **PACKET-10–13 / Cisco:** [Document 215092](https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/215092-analyze-firepower-firewall-captures-to-e.html) explicitly says specific lab devices/default configuration and scenarios based on real TAC cases. Its date is an update date, correctly retained as the accessible document date. Authors and four chosen scenarios agree. The catalog does not claim untouched customer PCAPs or a public downloadable trace.
- **PACKET-14/15 / PacketBomb:** Direct pages still returned 502. Search-indexed primary summaries support the authors, partial dates, subscriber narratives and advertised Tomcat trace, but not independently verified packet causes. The catalog correctly keeps these as leads and does not manufacture a year or diagnosis.
- **PACKET-16 / Chappell spurious retransmissions:** The [primary article](https://www.chappell-university.com/post/spurious-retransmissions-a-concern) supports date, 22 filtered frames, ACK 11/retransmission 14 and the client-vantage limitation. The downloaded 36-frame McAfee file is a distinct reference, as JSON explicitly states; it is not replay evidence for PACKET-16.
- **PACKET-17 / Networkwalks:** The [primary page](https://networkwalks.com/wireshark/) describes a saved microsoft.com teaching capture and links its ZIP. It establishes distribution rather than independent operational ownership. The catalog makes no fault claim.
- **PACKET-18 / Allegro Coop:** The [vendor case study](https://allegro-packets.com/en/case-studies/coop) supports application pauses, short TCP replies, sent PCAP streams, supplier attribution to Java Socket Selector/jumbo handling, and reported library-update recovery. The catalog attributes these claims and explicitly withholds independent causal validation.
- **PACKET-19 / Novell:** A bounded direct retrieval of the [primary article](https://support.novell.com/techcenter/articles/nc2002_03.html) confirmed Laura Chappell, 01 March 2002, onsite incident framing, 46 seconds of WINS delay, UDP 34716, frames 354–356 with roughly six-second spacing, the retired Sitemeter service and explicitly inferential reconstruction. The catalog correctly avoids general advice to disable WINS.

## Limits and follow-up opportunities

The six historical executions were verified from their retained manifests, outputs, source digests and raw inputs; I did not rerun the diagnostic CLI or its full unit suite because no runtime change is part of this task. Integrity and bounded execution do not prove causal diagnosis. Publisher narratives remain attributed evidence, not independently established root-cause truth. Redistribution rights and original ownership are not settled by a download.

The existing three-capture substantive corpus is separate and is not counted as new. Acquiring fuller paired TLS evidence with the external firewall record, the 7th Zero capture pair, or the plantegg server-side trace would improve future validation. Missing multi-vantage, PMTU, IKE, window and application analysis are future capability opportunities; they are not requirements to implement in this research-only change.
