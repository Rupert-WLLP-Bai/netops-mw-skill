# Collection limits

## Live mode

One live run has a 25-second wall-clock budget including capability/version discovery. Collection stops at 23 seconds to reserve two seconds for final artifacts. Each URL receives at most three fresh GET requests; at most two URLs are measured and at most two curl requests run at once. Curl uses a three-second connection timeout, a six-second total timeout, no retry, no redirect following, and a 64 KiB stdout body cap enforced by the runner. Certificate verification remains enabled. The tool honors the host's proxy environment; if a proxy is present or its use is uncertain, the report avoids direct-path stage attribution.

The optional `dnslookup` client runs one A and one AAAA query for each measured hostname, with JSON output and a two-second client timeout. Missing DNS measurements are not replaced by `getaddrinfo`. Ping sends at most ten one-second probes to each distinct default gateway or IP address actually reached by curl; it never pings a hostname as a substitute for the connected address.

The run records only basic local context: operating system, a readable default route/interface when available, proxy presence, and VPN state as unknown. It does not enumerate host data or retain proxy secrets.

## Offline PCAP mode

Offline parsing has its own 25-second budget. The input must be a regular file no larger than 64 MiB. TShark reads at most 100,000 frames, the retained structured event stream is capped at 8 MiB, and retained stderr is capped at 64 KiB. Field registration is a separate bounded capability probe. An empty or filtered capture, parser failure, timeout, missing tool, unsupported fields, and a reached cap have distinct collection outcomes.

Capture timestamps describe the packet file; analysis timestamps describe this run. TShark flags such as retransmission or lost-segment indicators describe selected captured packets and are not proof of end-to-end loss. A missing decode is not a successful transaction. This mode never starts a live capture.
