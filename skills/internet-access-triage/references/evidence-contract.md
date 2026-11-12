# Evidence contract

Each line in `evidence.jsonl` is one structured observation. Evidence IDs are unique within a run. Tool status describes collection, not the health of the network. Supported statuses are `complete`, `partial`, `timeout`, `permission_denied`, `unsupported`, `not_executed`, `budget_exhausted`, `parse_error`, and `tool_error`.

Measurements carry a numeric value, unit, and sample count. Missing values are `null` with a `missing_reason`. Structured observations retain text, arrays, protocol facts, and per-sample values without forcing them into numeric measurements. Source artifacts use relative paths confined to this run's `raw/` directory and include SHA-256 hashes. The PCAP input remains at its original local path; its basename and hash identify it without copying it into the output.

`diagnosis.json` cites only IDs present in the evidence stream. It records scope, status, at most two candidate domains, supporting IDs, counterevidence, limitations, and next steps. The report is a readable rendering of that record, not a separate source of facts.

## Derived replay evidence

Replay may include a `load_comparison` evidence record to test reasoning over observations collected separately. It is derived evidence: it does not start a load test and must not be presented as a live collection result. Diagnosis accepts this record only in replay mode. The replay scope and record comparison window must enclose all measured phase windows; samples from an older or unrelated window are not current evidence.

The record scope identifies one redacted `target`, `protocol`, `address_family`, and non-empty `vantage`. Its observation contains two chronological cycles. Each cycle has exactly three phases named `idle`, `load`, and `recovery`, in that order. Every phase has UTC `started_at_utc` and `ended_at_utc` timestamps, the same vantage, and at least three finite, non-negative samples for `rtt_ms` or `response_wait_ms`. A load phase also records measured activity as either positive `uploaded_bytes` with positive `duration_ms`, or a positive `upload_rate_bytes_per_s`.

A load-related latency candidate requires both cycles to show a higher phase median during load than idle, followed by a lower phase median during recovery, for the same metric. This supports a repeated load-related latency correlation only. It does not confirm bufferbloat, identify a queue or responsible device, or establish that an unmeasured live session would behave the same way.

A Linux live run records a bounded `/proc/net/dev` snapshot for the default-route interface when readable. Each counter has a value and unit, with the source, interface and UTC collection time. An unavailable interface, source, malformed or oversized input, unsupported platform, or exhausted budget has an explicit missing reason. One snapshot is not a rate and cannot establish a load cause.

Replay can compare at least three normal and pinned HTTPS request pairs using `http_probe` records with a shared `comparison_id` per pair and explicit `resolve_mode` (`normal` or `pinned`). Each request must be complete, successful and within the replay window, with a fresh connection and finite `dns_ms`. URL, Host header, SNI, certificate verification, address family, actual connected IP, GET method, direct proxy context and vantage must match. The pinned record must identify the connected IP as `pinned_ip`; the normal record must not be pinned. The median normal-minus-pinned DNS-stage timing must exceed the explicit `max_dns_ms` comparison limit. This is a timing observation, not proof of resolver CPU, causation or responsibility. The live collector does not perform pinned requests.

Replay may provide an independent `tls_observation` for the same HTTPS target and window: the tool must be identified separately from curl, the hostname and SNI must match the target, verification must be enabled, and `certificate_verified` must be boolean. A failed check supports a target TLS-validation finding; a passed check is counterevidence. Different tools, paths or times do not by themselves establish common responsibility.
