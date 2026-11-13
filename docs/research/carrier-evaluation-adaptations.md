# Carrier evaluation design references

Source review date: 2026-11-13. These are primary-source observations and explicit local adaptations.
No upstream benchmark, live network agent, source code or dataset was executed or copied.

| Reference snapshot | Source observation | Local adaptation |
| --- | --- | --- |
| [NIKA `ac4422d`](https://github.com/sands-lab/nika/blob/ac4422d8a4a03be2b905e28edf72993d467e1b81/docs/benchmarks/root-cause-evaluation.md) | Separates anomaly detection, resource localization and fault-type evaluation; scenario fault implementations supply truth | Independently authored case truth and separate scoring axes; no adoption of its live fault runtime |
| [FaulT-Bench `ab8c45f`](https://github.com/Overlxrd-uwu/FaulT-Bench/blob/ab8c45f808fb0c2a1ae5c029bcfe0194617c36f2/faultbench/src/faultbench/scenario.py) | Separates prompt, injection, post-injection checks, truth, fix and scoring fields | Fresh false-premise and wrong-cause tickets, bounded visible task serialization and deterministic required/forbidden claims |
| [NetOpsBench `6691406`](https://github.com/NetX-lab/NetOpsBench/blob/6691406dd3bda4b4fad0562043e3968cb94d46eb/docs/content/docs/run-benchmarks/methodology.mdx) | Separates verdict, device/interface localization, fault type and efficiency; uses declared measurement windows and baseline/recovery checks | Preserve declared evidence windows; separate trial validity, completion, grounding and recovery from diagnosis correctness |

The local corpus reuses this repository's independently authored M3/M4/M5 source evidence and
oracle assertions, with new tickets and compound correlation traps. It is an offline deterministic
provider evaluation, not a reproduction, compatibility implementation, external benchmark score,
LLM comparison or MobileWork run. Observation scopes without proven cross-job identity stay separate.

License boundaries also differ. NIKA's [README](https://github.com/sands-lab/nika/blob/ac4422d8a4a03be2b905e28edf72993d467e1b81/README.md)
claims MIT, but no root LICENSE text was available at that snapshot; its license was not verified.
FaulT-Bench has [MIT code](https://github.com/Overlxrd-uwu/FaulT-Bench/blob/ab8c45f808fb0c2a1ae5c029bcfe0194617c36f2/LICENSE)
and a separate [CC BY 4.0 dataset](https://github.com/Overlxrd-uwu/FaulT-Bench/blob/ab8c45f808fb0c2a1ae5c029bcfe0194617c36f2/dataset/LICENSE).
NetOpsBench supplies [MIT text](https://github.com/NetX-lab/NetOpsBench/blob/6691406dd3bda4b4fad0562043e3968cb94d46eb/LICENSE).
These references are not dependencies or redistributed materials.

## Local worker isolation inference

Directory names alone cannot hide truth from a same-user evaluated process. Landlock restricts
handled filesystem rights after enforcement, inherits into descendants and does not revoke existing
descriptors. Its documented limitations include metadata operations. Those facts motivate narrow
read grants, closed inherited descriptors, explicit mutation handling and supplementary syscall
denials in the local design. This is an inference from the [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html),
not evidence that any particular host or implementation has passed.

The restrictions require checked installation of [no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html)
and [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html). Syscall architecture and
x32 need explicit handling; seccomp alone is not a complete sandbox. See [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html).
Socket operations can also use [io_uring](https://man7.org/linux/man-pages/man2/io_uring_enter.2.html),
so denying familiar socket syscalls alone is insufficient. Actual direct, spawn/exec, mutation,
network and provider controls must verify the exact frozen implementation. Unsupported setup must
fail closed. This boundary does not cover a compromised privileged host, evaluator or kernel.

Controlled-lab plans use [netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html),
[Toxiproxy's documented API](https://github.com/Shopify/toxiproxy/blob/main/README.md) and
[CoreDNS templates](https://coredns.io/plugins/template/). These optional tools are not bundled;
their plans remain unexecuted until a person records the complete experiment lifecycle.
