# Per-Skill validation ledger template

Create one record per Skill and per target environment. Populate package version and SHA-256 from the exact built artifact manifest. Actual client and environment results remain `pending_user` until the user performs and documents them.

| Skill | Version | Package SHA-256 | Environment / OS | Client and version | V-01 | V-02 | V-03 | Normal | Change | Error | Invocation | Tester / UTC date | Screenshot evidence | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `netops-incident` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `internet-access-triage` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `netops-pcap-analysis` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `netops-verify-recovery` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `netops-handoff` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `telecom-access-diagnostics` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `telecom-transport-diagnostics` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |
| `telecom-service-acceptance` | `<from-manifest>` | `<from-manifest>` | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | pending_user | |

For each check, retain the exact command or client action, input artifact hash, output artifact hash where applicable, verifier, UTC date, original screenshot path, and pass/fail/blocked reason. A blank or `pending_user` cell is not a pass.
