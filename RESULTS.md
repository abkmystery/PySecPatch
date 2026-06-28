# Results

## Controlled Holdout

The final adapter and base model were evaluated on exactly the same 3,200 Stage B holdout records. The split contains 2,400 vulnerable examples and 800 clean negatives across 50 template-family clusters.

| Metric | Base | Final | Final minus base |
|---|---:|---:|---:|
| Accuracy | 0.0481 | 0.9072 | +0.8591 |
| Balanced accuracy | 0.0321 | 0.9381 | +0.9060 |
| Precision | 0.1614 | 1.0000 | +0.8386 |
| Recall | 0.0642 | 0.8762 | +0.8121 |
| F1 | 0.0918 | 0.9340 | +0.8422 |
| MCC | -0.8859 | 0.7994 | +1.6853 |
| Strict JSON | 0.9153 | 0.9944 | +0.0791 |
| Schema validity | 0.0516 | 0.9944 | +0.9428 |
| Clean preservation | 0.0000 | 1.0000 | +1.0000 |
| Security-control pass | 0.0163 | 0.8808 | +0.8646 |
| Normalized exact repair | 0.0017 | 0.8333 | +0.8317 |
| Structural exact repair | 0.0021 | 0.8683 | +0.8663 |
| Parseable fixed code | 0.0642 | 0.9921 | +0.9279 |
| No dangerous regression | 0.0642 | 0.9925 | +0.9283 |
| Line-localization F1 | 0.0000 | 0.4407 | +0.4407 |

The paired classification table has 2,770 final-only wins, 21 base-only wins, and 2,791 discordant records. Exact two-sided McNemar `log10(p) = -787.25`. Family-clustered bootstrap intervals are stored in `results/paired_base_final_holdout.json`.

## External SALLM

| Metric | Scored subset |
|---|---:|
| Prompts with upstream fixtures | 96/100 |
| Samples | 960/1,000 |
| Compilable | 1.0000 |
| Functional pass | 0.2677 |
| Security-test pass | 0.3188 |
| Secure-functional pass | 0.0958 |
| CodeQL finding-free | 0.6260 |

The four missing prompt fixtures are an upstream benchmark limitation and are reported separately rather than counted as model failures.

## Repository Tasks

| Metric | Test | Holdout |
|---|---:|---:|
| Finding-ID exact | 0.9988 | 0.9925 |
| Strict JSON | 1.0000 | 0.9925 |
| Relevant-file only | 1.0000 | 0.9925 |
| Patch applies | 0.3525 | 0.3800 |
| Patched code exact | 0.3063 | 0.2975 |
| Security-control pass | 0.3188 | 0.3438 |

## Frozen Stage 6

The 24-case paired suite contains 12 vulnerable and 12 clean repositories. Detection was 12/12 with no false positives, clean preservation was 12/12, and strict JSON was 100%. No vulnerable patch passed every acceptance gate. Verifier-guided retries did not improve acceptance. Primary failure modes were non-applicable unified diffs, malformed hunks, one regression-test failure, and whitespace rejection.

## Interpretation

The evidence supports controlled vulnerability triage, CWE classification, and candidate snippet repair. It does not support autonomous repository repair or state-of-the-art claims. The central empirical result is the sharp drop from controlled family-disjoint evaluation to external and repository-level verification.
