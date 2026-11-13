# Dependency and license inventory

This inventory distinguishes shipped runtime code from optional host tools and development-only packages. The release builder's package manifests are the authority for files included in each archive.

| Component | Use | Classification | License / distribution note |
|---|---|---|---|
| Python 3.10+ standard library | Runtime for the Skills and local command-line tools | Required runtime; not bundled | External runtime; Python Software Foundation License, subject to the exact user-installed distribution and version. |
| Apache-2.0 license and bundled carrier Skill sources | Carrier Skills and local analyzers | Bundled | Apache License 2.0; preserve the repository `LICENSE` in each applicable package. |
| `curl` | Optional HTTP observations for `internet-access-triage` | External optional executable | Not bundled; absence reduces collection coverage. |
| `dnslookup` | Optional DNS observations | External optional executable | Not bundled; absence reduces collection coverage. |
| `ping` | Optional latency observations | External optional executable | Not bundled; platform-specific behavior must be recorded. |
| TShark / Wireshark | Offline PCAP analysis | External optional executable; required only for the PCAP workflow | Not bundled; record the user-installed version and license from its distribution metadata. |
| `jsonschema` 4.26.0 | Schema checks in development | Development-only | Not required by packaged runtime; MIT license. |
| PyYAML 6.0.3 | Development tooling | Development-only | Not required by packaged runtime; MIT license. |

The implementation uses Python's standard library for its packaged runtime. Optional tools are invoked as external programs only where documented. The cited research projects and packet-capture publishers are provenance references, not software dependencies; no upstream project code or capture data is bundled in Skill ZIPs by this inventory. Verify exact package members and license notices against the built manifests before redistribution.
