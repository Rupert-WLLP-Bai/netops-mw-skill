# Independent final review: network skill suite design

Reviewed on 2026-11-12 against baseline `cdc536904044ee9946650a5be7215df24665c56a` in `/home/pejoy/code/netops-mw-skill`. This pass began after authoring was frozen and reviewed the three proposed documentation artifacts, not an implemented suite. No project files, index, branch, commits, remotes, installed skills or tools were changed by this review. No diagnostic probes, upstream scripts or external mutations were run.

## Verdict

**Spec compliance: approved for presentation as a written architectural proposal.** The artifacts answer the requested research and composition question with official guidance, four pinned open-source implementations, three alternatives, and a recommended group of independently useful workflows with conditional branches, handoffs and bounded loops.

**Quality: approved; no material factual contradiction or architectural gap found at this design stage.** There are no required corrections from this pass. The documents may be recorded and committed as reviewed documentation if otherwise authorized. This is not approval to implement the architecture or a claim that the proposed suite works. The user's architecture decision remains pending.

## Reviewed artifacts and identity

The SHA-256 hashes matched the frozen handoff:

| Artifact | SHA-256 |
| --- | --- |
| `docs/research/skill-composition-patterns.md` | `8742ff6e7db7c87cb16ade33683483cf1ae642c9b14d1261dd22809d61edbdde` |
| `docs/research/network-skill-suite-proposal.md` | `35406ebc85e6e9e5bde0bf5e6ff7e5492d6b9bfe4f14fbf7745b064ede6cc845` |
| `docs/research/network-skill-suite-routing-cases.json` | `35bb14296367c0fa3e55ede5281d7ef7bd5bf0164112b4b0ba4b239fac858e5b` |

Read the repository's `AGENTS.md` and `docs/agents/domain.md`. No root glossary or ADR directory exists. This work neither handles tickets nor changes triage labels. Read the invoked local skill creator and its `references/openai_yaml.md`; their hashes matched the research record (`6656e547…e1e66` and `ffac3931…150c`).

## Findings and evidence

No material findings require changes. The following checks support that result:

| Area | Evidence and conclusion |
| --- | --- |
| Standards versus orchestration | Research lines 7–11 correctly distinguish the open directory/frontmatter/resource format, host loading behavior, product-specific UI metadata and MCP tool dependencies. Official sources do not establish a native skill DAG, scheduler, cross-skill API, retry engine or durable case store. Experimental `allowed-tools` is described with host variation and is not used as an authorization shortcut. |
| Upstream accuracy | The fetched files at the four stated commits contain the described progressive resources, description-evaluation loop, named handoffs, review/fix loops, persistent tracker map, feedback loop, focused handoff output and layered network comparisons. The fetched licenses agree with the table. The research does not treat those repositories' host tools, mandatory agents, reviewers, approval rules, long probes or external writes as universal requirements. |
| Coherent boundaries | Proposal lines 17–27 define distinct goals for incident coordination, existing-capture interpretation, original-operation recovery checks and handoff drafting. The legacy collector remains available and self-contained. DNS, TLS, path and device topics start as conditional references; creating empty specialist skills is explicitly deferred. A one-skill alternative remains viable if behavior tests fail to justify the split. |
| Trigger overlap and direct access | The existing collector and proposed PCAP skill overlap intentionally. The proposal promises no host-enforced automatic precedence, requires real discovery/selection tests and preserves explicit user choice. R02, R05 and R07 cover direct PCAP, handoff and legacy offline entry. A full incident pipeline is not made a prerequisite for those goals. The untested overlap is an acknowledged validation question, not a demonstrated defect. |
| Missing capabilities and scope | Proposal lines 75–84 require discovery of actually installed skills, permit reading accessible instructions where supported, and forbid invented invocation APIs or sibling paths. Missing skills/tools lead to bounded findings or unresolved transfer; they do not authorize installation, live fallback, broader collection or invented results. R08 and R09 exercise those intended outcomes. Explicit choices and existing authorization remain controlling. |
| Branches, loops and recovery | The graph and prose agree that another round needs a meaningful new decision or changed condition, permission and remaining budget. No progress, access limits, exhausted budget or cancellation stop work. Verification requires the original business operation and comparable vantage/identity/workload with an agreed stability window. A ping, action report, quiet capture or handoff cannot establish recovery or a cause. Recurrence and unknown action outcomes have bounded reentry/reconciliation paths; resumes do not reset budget. R10–R15 cover the relevant negative paths. |
| Evidence and state | Proposal lines 88–103 keep the four existing diagnosis values separate from proposed workflow status. The envelope namespaces evidence by run, separates event time from collection time, records visibility and unknowns, and distinguishes restricted originals from shareable exports. Persistent revisions, idempotent events, cancellation and remote-outcome reconciliation remain explicit future controller responsibilities. They are not attributed to Markdown or the existing collector. |
| Deployment closure | Proposal lines 111–121 recognize that today's builder packages one skill with a 16-file allowlist. Individual self-contained artifacts and a versioned suite/shared CLI are explicit planning alternatives, with dependency closure and clean extraction required. There is no undocumented sibling import or assumed callable shared tool. Plugins are optional and host-specific; Linux/WSL results do not imply native Windows or MobileWork compatibility. |
| Claims of validation | All three new artifacts identify the suite and cases as proposals. The existing 72-test and nine-capture results are historical and are not presented as new suite or incident-recovery acceptance. The nine historical diagnoses are accurately described as `insufficient_evidence`. Audit “Gap, P1” rows describe roadmap gaps, not newly confirmed runtime bugs. |
| Future evaluation | The JSON has 16 unique R01–R16 IDs and an explicit `designed_not_executed` status. Prompts include positive, unrelated, direct-entry, explicit-choice, missing-tool/skill, false-cause, budget, no-progress, reentry, recurrence, cancellation and authorization-boundary situations. Expected outcomes are in separate `private_rubric` fields, and the protocol expressly excludes those fields and routing labels from evaluator input. These are future fixture descriptions, not existing test inputs or results. |

## Primary sources checked

Official pages were opened directly. These support the format/host distinction, coherent workflow boundaries and the proposed evaluation approach:

- [Agent Skills specification](https://agentskills.io/specification), [creator best practices](https://agentskills.io/skill-creation/best-practices), and [evaluation guidance](https://agentskills.io/skill-creation/evaluating-skills).
- OpenAI [Build skills](https://developers.openai.com/plugins/build/skills.md), [Plugin architecture](https://developers.openai.com/plugins/concepts/plugins.md), and [Testing Agent Skills Systematically with Evals](https://developers.openai.com/blog/eval-skills.md).

Actual pinned source files and licenses were fetched through the connected GitHub tool; upstream code was read, not executed:

- `anthropics/skills` at `2c5958ecac7cee2b583967a2c4981d0f4a75c579`: [skill creator](https://github.com/anthropics/skills/blob/2c5958ecac7cee2b583967a2c4981d0f4a75c579/skills/skill-creator/SKILL.md), [description loop](https://github.com/anthropics/skills/blob/2c5958ecac7cee2b583967a2c4981d0f4a75c579/skills/skill-creator/scripts/run_loop.py), and [Apache-2.0 license](https://github.com/anthropics/skills/blob/2c5958ecac7cee2b583967a2c4981d0f4a75c579/skills/skill-creator/LICENSE.txt).
- `obra/superpowers` at `22f0b463e7a5e579904dd6211a520321035526f7`: [brainstorming](https://github.com/obra/superpowers/blob/22f0b463e7a5e579904dd6211a520321035526f7/skills/brainstorming/SKILL.md), [subagent-driven development](https://github.com/obra/superpowers/blob/22f0b463e7a5e579904dd6211a520321035526f7/skills/subagent-driven-development/SKILL.md), and [MIT license](https://github.com/obra/superpowers/blob/22f0b463e7a5e579904dd6211a520321035526f7/LICENSE).
- `mattpocock/skills` at `5863806dd4e15c63174bee4e7515a4256792ecfa`: [wayfinder](https://github.com/mattpocock/skills/blob/5863806dd4e15c63174bee4e7515a4256792ecfa/skills/engineering/wayfinder/SKILL.md), [diagnosing bugs](https://github.com/mattpocock/skills/blob/5863806dd4e15c63174bee4e7515a4256792ecfa/skills/engineering/diagnosing-bugs/SKILL.md), [handoff](https://github.com/mattpocock/skills/blob/5863806dd4e15c63174bee4e7515a4256792ecfa/skills/productivity/handoff/SKILL.md), and [MIT license](https://github.com/mattpocock/skills/blob/5863806dd4e15c63174bee4e7515a4256792ecfa/LICENSE).
- `daymade/claude-code-skills` at `0474b763684f064053900a44e009b62a07c47f38`: [network skill](https://github.com/daymade/claude-code-skills/blob/0474b763684f064053900a44e009b62a07c47f38/debugging-network-issues/SKILL.md), [layered probe](https://github.com/daymade/claude-code-skills/blob/0474b763684f064053900a44e009b62a07c47f38/debugging-network-issues/scripts/layered-isolation-probe.sh), and [MIT license](https://github.com/daymade/claude-code-skills/blob/0474b763684f064053900a44e009b62a07c47f38/LICENSE).

Local evidence included the actual 22-line `skills/internet-access-triage/SKILL.md`, `scripts/build_release.py`, the existing CLI help/default budget configuration, the prior lifecycle proposal, and original/post-fix capture reports. The CLI help inspection did not collect evidence or contact a target.

## Verification and limits

Independent local checks confirmed JSON validity, 16 unique IDs, required per-case fields, every linked local Markdown target, the frozen hashes, unchanged baseline HEAD and an empty staged diff. Status still contained precisely the three proposed untracked artifacts. The parent-reported existing creator validation applies only to the unchanged current skill; it was not repeated or extended into a claim about uncreated skills.

No full unit suite, behavioral forward test, corpus run, package build or host deployment test was run in this documentation-only review. No new skill scaffold exists to validate. The number of entry points, legacy PCAP trigger overlap, actual host selection, dependency closure and enforceable controller behavior remain the explicitly planned next-stage questions. They do not prevent presenting this honest, reviewable proposal to the user.
