# Reproducibility

## Frozen Components

- Base model: `Qwen/Qwen2.5-Coder-7B-Instruct`
- Final adapter model file SHA-256: `4c2b5c7c0d2982b99de9c319e998274fc12f3aae5bf8d2c3b5db58c5864dc65b`
- Stage B holdout SHA-256: `bae963584f22cf5d7d32f5c8bdb74458ff1626ae057e0ad7d6b7c7fe8af5d8f1`
- Stage 6 suite SHA-256: `d688af9447ca5ce73ab2f0eb5722709e76634d21e872ab755e673a8e971c3d83`
- SALLM revision: `0159a63daed0a88f461bbd69dd1160893e394a67`
- SALLM official input SHA-256: `33eb9c9ad2fce20d174ec84ff5e94cec35c8bd46fe1cf2cc47f01406f5c2a2ac`
- Seed: `20260627` for Stage B evaluation; `20260619` for SALLM generation

## Environment

Final holdout inference used Python 3.11.10, PyTorch 2.5.1+cu124, Transformers 5.12.1, PEFT 0.19.1, TRL 1.6.0, and bitsandbytes 0.49.2 on an NVIDIA A40. The base comparison used the same prompt and batch size on an NVIDIA L40S with PyTorch 2.4.1+cu124 and the same Transformers, PEFT, TRL, and bitsandbytes versions.

## Dataset Boundaries

Only `stage_a_train.jsonl` and `stage_b_train.jsonl` entered optimization. Validation, test, and holdout records were not training inputs. Splits are assigned by template family rather than row. The published contamination reports record exact normalized hashes and structural overlap checks.

## Base and Final Holdout

```bash
python eval.py \
  --model Qwen/Qwen2.5-Coder-7B-Instruct \
  --tag qwen-base-v2 \
  --split holdout \
  --confirm-holdout \
  --limit 0 \
  --batch-size 8 \
  --max-new-tokens 900 \
  --bootstrap-samples 2000

python eval.py \
  --model Qwen/Qwen2.5-Coder-7B-Instruct \
  --adapter adapters/pysecpatch \
  --tag pysecpatch \
  --split holdout \
  --confirm-holdout \
  --limit 0 \
  --batch-size 8 \
  --max-new-tokens 900 \
  --bootstrap-samples 2000
```

Paired comparison:

```bash
python paired_compare.py \
  --base results/eval_qwen-base-v2_holdout.predictions.jsonl \
  --final results/eval_pysecpatch-v2_holdout.predictions.jsonl \
  --dataset data/stage_b_holdout.jsonl \
  --output results/paired_base_final_holdout.json \
  --bootstrap-samples 10000
```

## SALLM

SALLM generation used temperature 0.2, ten samples per prompt, batch size 8, and a 700-token output limit. Functional tests ran in ten GitHub Actions shards against the pinned upstream revision. CodeQL `security-extended` results are reported separately because the upstream study does not pin the exact CodeQL CLI and query revision used in its original experiments.

## Evidence Policy

Raw predictions, console logs, scorer outputs, environment captures, and SHA-256 manifests are distributed in the archival evidence bundle. Summary files alone are insufficient for independent verification.
