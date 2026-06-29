# PySecPatch

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21015503.svg)](https://doi.org/10.5281/zenodo.21015503)

PySecPatch is an open defensive Python security model and evaluation suite for vulnerability triage, CWE classification, secure-code explanation, and candidate repair generation. The release combines a two-stage QLoRA adapter for `Qwen/Qwen2.5-Coder-7B-Instruct`, a deterministic 72,000-record Python security corpus, and reproducible internal and external evaluations.

PySecPatch is best used as a human-reviewed triage and secure-coding assistant. Repository-level patch application remains experimental.

## Verified Results

The final adapter and the unmodified base model were evaluated on the same 3,200-record family-disjoint holdout under identical prompts, decoding settings, and seed.

| Metric | Qwen base | PySecPatch | Difference |
|---|---:|---:|---:|
| Classification accuracy | 4.81% | 90.72% | +85.91 pp |
| Classification F1 | 9.18% | 93.40% | +84.22 pp |
| Strict JSON | 91.53% | 99.44% | +7.91 pp |
| Clean-negative preservation | 0.00% | 100.00% | +100.00 pp |
| Security-control pass | 1.63% | 88.08% | +86.46 pp |
| Normalized exact repair | 0.17% | 83.33% | +83.17 pp |
| Parseable fixed code | 6.42% | 99.21% | +92.79 pp |

The paired classification comparison contains 2,770 PySecPatch-only correct predictions and 21 base-only correct predictions. The exact two-sided McNemar result is `log10(p) = -787.25`.

External SALLM evaluation is materially harder. On the 96 prompts with fixtures at the pinned upstream revision, PySecPatch achieved 26.77% functional pass, 31.88% security-test pass, and 9.58% secure-functional pass. Four upstream prompts lacked fixtures; the report preserves these exclusions and full-benchmark bounds.

Repository repair remains the principal limitation. The repo-format holdout achieved 38.00% patch application and 34.38% security-control pass. On the frozen 24-case Stage 6 suite, detection and clean preservation were perfect, but none of 12 proposed repository patches passed the complete acceptance gate.

## Training Lineage

The published adapter was trained in two consecutive stages:

| Stage | Corpus | Train | Validation | Test | Holdout |
|---|---:|---:|---:|---:|---:|
| A | 12,000 | 8,400 | 1,200 | 1,200 | 1,200 |
| B | 60,000 | 48,000 | 4,000 | 4,000 | 4,000 |

Only train splits entered optimization. The combined released corpus contains 72,000 records; 56,400 records were used for training. Both stages are generated Python examples released under Apache-2.0. Exact normalized duplicate overlap between stages is zero; the audit records 702 shared abstract structures.

## Install

```bash
python -m pip install -r requirements.txt
```

The model repository contains a PEFT adapter. Set `HF_TOKEN` only when access or rate limits require it; PySecPatch never stores credentials.

## Run

Local repository scan:

```bash
python agent.py --repo /path/to/repository
```

Generate and verify candidate patches:

```bash
python agent.py --repo /path/to/repository --fix
```

Explicit GitHub repository:

```bash
python agent.py --github https://github.com/OWNER/REPOSITORY
```

## Reproduce Evaluation

```bash
python eval.py --self-test
python repo_eval.py self-test
python sallm_score.py self-test
```

See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for frozen hashes, exact commands, paired statistics, and evidence layout. [RELEASE_MANIFEST.json](RELEASE_MANIFEST.json) records the principal metrics and artifact hashes; [RELEASE_VALIDATION.json](RELEASE_VALIDATION.json) records the offline package audit.

## Intended Use

- Defensive review of Python code supplied by the user.
- Classification and explanation of suspicious snippets.
- CWE identification and candidate secure-code generation.
- Human-reviewed repair assistance.
- Research on specialization and security generalization.

## Not Intended For

- Autonomous deployment of unreviewed patches.
- Offensive scanning or unauthorized repository analysis.
- Exploit generation, persistence, credential theft, phishing, or evasion.
- Claims that a clean result proves a repository is secure.

## Research Position

PySecPatch demonstrates a large controlled-benchmark improvement over its base model and a substantial gap between synthetic holdout performance and external or repository-level repair. The release does not claim state-of-the-art or production-ready autonomous repair.

## Citation

[CITATION.cff](CITATION.cff) and [paper/references.bib](paper/references.bib) provide copy-ready citation records. Cite the current `v0.1.1` archive as [`10.5281/zenodo.21015885`](https://doi.org/10.5281/zenodo.21015885). The all-versions DOI is [`10.5281/zenodo.21015503`](https://doi.org/10.5281/zenodo.21015503), and the initial `v0.1.0` snapshot is [`10.5281/zenodo.21015504`](https://doi.org/10.5281/zenodo.21015504).

The independently archived PySecPatch-72K dataset should be cited as [`10.5281/zenodo.21016753`](https://doi.org/10.5281/zenodo.21016753).

## License

Code, generated data, and adapter artifacts are released under Apache License 2.0. The base model is not redistributed.
