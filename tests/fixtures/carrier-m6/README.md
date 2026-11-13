# M6 carrier corpus

The catalog contains 36 self-authored cases that compose the self-authored M3, M4, and M5 source fixtures. `catalog.json` contains only opaque case IDs, neutral operator prompts, parent fixture selectors, provider kinds, and tickets. `oracle-enrichment.json` is evaluator-only and augments the independently authored parent oracles with per-claim support and counterevidence sets.

The M3.5 counter example uses `counter_increase` as a neutral observation with `insufficient_evidence`; it is not classified as a fault. Each M6 job is materialized independently with opaque run and source identifiers. Compound cases contain two domain jobs and explicitly prohibit causal joins without identity and time bindings.

No external operational dataset is included. The provenance manifest describes the synthetic source families and is never copied into a visible task.
