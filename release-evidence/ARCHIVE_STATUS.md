# Archive packaging correction

Source remains 8ae9090b560871d1e584d717734693bb570fffae. The first non-release archive 3594586a388bf63ce539f779cc91992e569492c2 at tag evidence/local-workbench-20261116 omitted some already-generated files because repository Git ignore rules applied during staging. Public-byte verification caught this packaging defect; no complete-public-archive claim was accepted.

This complete follow-up archive explicitly includes every reviewed release-evidence file, including ignored logs/packages/coverage outputs. It preserves the first immutable tag and does not rewrite source or tags. Final test results are scoped to the same source, not to either evidence-only commit. The software readiness decision remains PARTIAL.
