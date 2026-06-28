# Submission Note

## Manuscript

**PySecPatch: Measuring the Synthetic-to-External Generalization Gap in Python Security Repair**

The manuscript reports a controlled base-model comparison, an independent SALLM evaluation, two repository-format splits, and a frozen end-to-end acceptance suite. Its main contribution is empirical: large gains on family-disjoint generated data do not imply reliable secure-functional generation or applicable repository patches.

## Fit and Contribution

The work is appropriate for software-security, empirical software-engineering, secure-code-generation, and reproducibility venues interested in evaluation methodology, synthetic-to-external generalization, clean-negative behavior, functional-security conjunction, patch applicability, and transparent negative results.

## Artifact Availability

The release contains the adapter, 72,000 generated and licensed records, split and contamination audits, paired predictions, external benchmark outputs, frozen manifests, environment records, checksums, evaluation scripts, and both successful and failed patch evidence. A DOI should be inserted after the GitHub release is archived.

## Claims Boundary

The submission does not claim state-of-the-art performance or production-ready autonomous repair. It claims a statistically supported controlled improvement over the base model, documents weaker external transfer, and identifies free-form patch serialization as the dominant end-to-end bottleneck.
