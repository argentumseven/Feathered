Instruction assessment

Accepted: repair order, one PR per item, regressions demonstrated before fixes,
compatibility wrappers, exact artifact comparisons for later refactors, separate
package-family semantics, and the item-1 merge prerequisite.

Corrections required before later implementation:
1. The preceding review inspected all 1,255 outcome markers under Xvfb; it did not
   rely solely on the defective headline. The new recorder independently confirms
   the same baseline with complete per-test phase evidence.
2. Similarity scores do not prove equivalent dependency lookup. APT wrappers must
   preserve module monkeypatch behavior. A failing compatibility test requires
   investigating the refactor, not assuming the test is defective.
3. Section 7 mixes behavior repairs with extraction while its standing rules
   prohibit that. Separate those repairs and explicitly revise their expectations.
4. Cached digests must be tied to verified file content and invalidated when it
   changes. A package-object digest alone is insufficient. Measure performance;
   do not present a hypothetical 40-second saving as evidence.
5. Native package-manager oracles and live refresh can run on suitably equipped
   Linux hosts. Their absence in this local validation is a capability/evidence
   limitation, not an inherent impossibility of Linux review.

Application code remains at the reviewed behavior; this delivery implements only
release-gate and CI evidence changes. Later items await item 1 being merged.
