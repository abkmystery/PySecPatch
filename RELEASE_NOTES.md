# PySecPatch 0.1.1 Reproducible Research Release

This patch release corrects the structured author name to given name `Ahmed` and family name `Bin Khalid`, adds the Zenodo concept DOI, and hardens the isolated Hugging Face publisher. Model weights, datasets, and evaluation results are unchanged from `0.1.0`.

Archived release DOI: [`10.5281/zenodo.21015885`](https://doi.org/10.5281/zenodo.21015885). All-versions DOI: [`10.5281/zenodo.21015503`](https://doi.org/10.5281/zenodo.21015503).

This release provides a reproducible defensive Python security specialization and its complete evaluation record.

## Included

- PySecPatch-7B PEFT adapter for Qwen2.5-Coder-7B-Instruct.
- PySecPatch-72K generated corpus with Stage A and Stage B configurations.
- Family-disjoint test and holdout evaluation.
- Paired 3,200-record base-versus-final comparison.
- Pinned SALLM functional and CodeQL evidence.
- Repository-format and frozen Stage 6 evaluations.
- Raw predictions, environment records, and SHA-256 manifests in the archival evidence bundle.
- Manuscript and machine-readable citation metadata.

## Headline Results

- Holdout classification F1: 9.18% base, 93.40% PySecPatch.
- Holdout security-control pass: 1.63% base, 88.08% PySecPatch.
- Clean-negative preservation: 0% base, 100% PySecPatch.
- SALLM secure-functional pass: 9.58%.
- Repository-format holdout security-control pass: 34.38%.
- Frozen Stage 6 accepted repairs: 0/12.

## Release Status

Research preview. PySecPatch is suitable for defensive triage, CWE classification, explanation, and candidate repair research. Repository-level autonomous repair remains experimental. Generated patches require human review and automated verification.
