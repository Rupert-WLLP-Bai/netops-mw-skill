# Issue Tracker: GitHub

Tasks and specifications live at https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues.
Prefer connected GitHub tools. When an operation is unavailable there, use `gh` with `--repo Rupert-WLLP-Bai/netops-mw-skill`.

## Operations

- Read a ticket: `gh issue view <number> --repo Rupert-WLLP-Bai/netops-mw-skill --json number,title,body,labels,comments`.
- List tickets: `gh issue list --repo Rupert-WLLP-Bai/netops-mw-skill --state open --json number,title,labels`; add label filters as needed.
- Publish an authorized specification or task as an issue. Pass multiline text as a structured tool argument or write a temporary file and use `--body-file`.
- Read `docs/agents/triage-labels.md` before adding or removing state labels.
- Prefer native sub-issues. If unsupported, add `Part of #<parent>` to the child and maintain a checklist in the parent.
- Prefer native issue dependencies. If unsupported, put `Blocked by: #<number>` at the top of the ticket. A ticket is available only after all blockers close.
- When a skill says "fetch the relevant ticket," read the complete issue and comments. When it says "publish to the issue tracker," create an issue within the authorized task scope.

## Pull Requests as a Triage Surface

**PRs as a request surface: no.**

GitHub issues and pull requests share a number space. Resolve the type of a bare reference such as `#42` before acting on it.
