# Compare service aliases through scoped source mappings

Service acceptance compares controlled identifiers from orders and observed configuration. Their
spellings are local to a source-qualified namespace. A valid mapping that names the exact expected
and actual run/evidence pair determines their semantic relation: `declared_equal` supports a match,
and `declared_different` supports a discrepancy. Repeating literal string equality after applying
that mapping would discard its meaning and falsely reject equivalent circuit or endpoint aliases.

Require the complete checked mapping, source authority, selected service/resource scope, applicable
validity and supporting references. Missing, malformed, contradictory or inapplicable mappings leave
the comparison unverified. Names alone never create cross-source identity, and mappings remain
unauthenticated operator/source assertions. Human signoff remains a separate pending decision.

Within one source-qualified namespace, controlled values compare literally. Numeric quantities use
their supplied numeric values and exact raw units; alias mappings do not convert or override them.
This rule extends the existing offline evidence workflow and does not change incident states,
recovery eligibility or device permissions.
