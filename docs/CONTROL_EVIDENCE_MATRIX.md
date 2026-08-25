# DORAOps v0.8 Control / Evidence Matrix

DORAOps v0.8 adds a machine-readable mapping between selected DORA regulatory references, institution-owned controls, expected evidence types, accountable roles and verification methods.

The reference matrix lives at `configs/dora-control-evidence-matrix.json`.

## Semantics

A mapping answers five bounded questions:

1. Which DORA source/article/topic is being referenced?
2. Which institution-owned control identifier is used?
3. Which evidence types are expected to be represented?
4. Which accountable role owns the represented control/evidence relationship?
5. Which verification method is expected before human review?

The runtime assessment has only two coverage states:

- `represented` — every expected evidence type for the mapping has at least one structurally valid evidence binding;
- `gap` — one or more expected evidence types are not represented.

These states are **evidence-coverage states**, not legal compliance states.

## Fail-closed boundaries

Evidence bindings fail closed when they:

- reference an unknown control;
- use an evidence type not expected by that mapping;
- use an accountable role different from the mapped responsible role;
- are duplicated;
- contain an invalid digest;
- are timestamped after the assessment time.

The matrix and assessment both structurally require:

- `dora_compliance_determined=false`;
- `legal_applicability_determined=false`;
- `supervisory_acceptance_determined=false`;
- `requires_human_review=true`.

The reference matrix additionally requires `complete_legal_mapping_claimed=false` and `applicability_basis=institution_determined` for every mapping.

## No percentage or maturity score

DORAOps deliberately does not convert represented controls into a compliance percentage, maturity score or supervisory conclusion. Counts of represented controls and evidence gaps are operational inventory information only.

## Regulatory references

The checked-in reference matrix includes selected mappings to Regulation (EU) 2022/2554 Articles 5, 6, 8, 9, 10, 11, 12, 17, 18, 19, 24, 28 and 30. This list is not represented as a complete legal mapping. Institutions remain responsible for applicability, interpretation, national/supervisory context and legal review.
