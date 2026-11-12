# Domain Documents

This repository uses a single domain context. The root `GLOSSARY.md` holds domain terms; `docs/adr/` holds architecture decisions.

Before exploring, read the glossary if it exists and any decisions relevant to the task. If either is absent, continue. Create domain documents when actual terms or decisions have been settled, using `domain-modeling` as appropriate.

Use defined terms consistently in tickets, interfaces, tests, and designs. Check existing code and documentation before introducing a new term. When a proposal conflicts with an existing architecture decision, identify that decision and explain why it should be reconsidered.

Introduce `GLOSSARY-MAP.md` and documents for separate contexts only when the project actually develops distinct domain contexts.
