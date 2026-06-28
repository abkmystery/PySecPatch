"""Fine-tune an audited PySecPatch base model with QLoRA."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import platform
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
RESULTS_DIR = PROJECT_DIR / "results"
CONFIG_PATH = PROJECT_DIR / "config.yaml"
AUDIT_PATH = RESULTS_DIR / "license_audit.json"
CONTAMINATION_PATH = RESULTS_DIR / "contamination_v2_report.json"
DATA_STATS_PATH = RESULTS_DIR / "data_v2_stats.json"
TRAIN_PATH = DATA_DIR / "v2_train.jsonl"
VAL_PATH = DATA_DIR / "v2_val.jsonl"
TRAIN_CONFIG_PATH = RESULTS_DIR / "train_v2_config.json"
TRAIN_LOG_PATH = RESULTS_DIR / "train_v2_log.json"
MODEL_CARD_PATH = RESULTS_DIR / "model_v2_card.md"
RUNPOD_COMMAND_PATH = PROJECT_DIR / "runpod_v2_training_command.txt"
PRIMARY_BASE = "Qwen/Qwen2.5-Coder-7B-Instruct"
FALLBACK_BASE = "Virtue-AI-HUB/VulnLLM-R-7B"
SYSTEM_PROMPT = (
    "You are PySecPatch, a defensive Python secure coding model. Identify vulnerabilities, "
    "explain risk, and produce minimal safe patches. Return strict JSON only."
)
ANALYSIS_FIELDS = {
    "is_vulnerable",
    "cwe",
    "vuln_type",
    "vulnerable_lines",
    "explanation",
    "fixed_code",
    "patch_summary",
    "safe_test",
}
AGENT_FIELDS = {"finding_id", "summary", "patch"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"Required file is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected a JSON object: {path}")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_versions() -> dict[str, str | None]:
    packages = ("torch", "transformers", "datasets", "peft", "trl", "bitsandbytes")
    found: dict[str, str | None] = {}
    for package in packages:
        try:
            found[package] = version(package)
        except PackageNotFoundError:
            found[package] = None
    return found


def _load_config() -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required; install pysecpatch/requirements.txt.") from exc
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise RuntimeError(f"Invalid configuration: {CONFIG_PATH}")
    required = {"max_seq_len", "lora_r", "lora_alpha", "learning_rate", "epochs", "batch_size"}
    missing = sorted(required - set(config))
    if missing:
        raise RuntimeError(f"config.yaml is missing: {', '.join(missing)}")
    return config


def _select_base(requested: str, audit: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    records = {record.get("model_id"): record for record in audit.get("models", [])}

    def allowed(model_id: str) -> bool:
        return records.get(model_id, {}).get("train_allowed") is True

    if requested == "auto":
        if allowed(PRIMARY_BASE):
            return PRIMARY_BASE, "Audited Qwen primary selected because train_allowed=true.", records[PRIMARY_BASE]
        if allowed(FALLBACK_BASE):
            return FALLBACK_BASE, "Qwen was not approved; the audited fallback was selected.", records[FALLBACK_BASE]
        raise RuntimeError("Neither the Qwen primary nor the fallback base is train-allowed.")
    if requested == PRIMARY_BASE and not allowed(PRIMARY_BASE):
        if allowed(FALLBACK_BASE):
            return FALLBACK_BASE, "Requested Qwen primary was rejected by the audit; audited fallback selected.", records[FALLBACK_BASE]
        raise RuntimeError("The requested Qwen primary and fallback are not train-allowed.")
    if not allowed(requested):
        status = records.get(requested, {}).get("status", "not_audited")
        raise RuntimeError(f"Training base {requested!r} is not allowed by the audit (status={status}).")
    return requested, "Explicit base selected because its license audit has train_allowed=true.", records[requested]


def _read_split(path: Path, expected_split: str) -> list[dict[str, Any]]:
    if not path.is_file():
        raise RuntimeError(f"Dataset split is missing: {path}. Run data.py --build first.")
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
            if record.get("split") != expected_split:
                raise RuntimeError(f"Unexpected split at {path}:{line_number}")
            if record.get("language") != "python" or record.get("source") != "generated":
                raise RuntimeError(f"Unapproved data provenance at {path}:{line_number}")
            if record.get("source_license") != "Apache-2.0":
                raise RuntimeError(f"Unapproved source license at {path}:{line_number}")
            if record.get("task") not in {"detect", "repair", "repo_patch"}:
                raise RuntimeError(f"Unknown task at {path}:{line_number}")
            messages = record.get("messages")
            if not isinstance(messages, list) or [item.get("role") for item in messages] != ["system", "user", "assistant"]:
                raise RuntimeError(f"Invalid training conversation at {path}:{line_number}")
            target = record.get("target")
            expected = AGENT_FIELDS if record["task"] == "repo_patch" else ANALYSIS_FIELDS
            if not isinstance(target, dict) or set(target) != expected:
                raise RuntimeError(f"Invalid target contract at {path}:{line_number}")
            try:
                assistant_target = json.loads(messages[-1]["content"])
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Assistant target is not strict JSON at {path}:{line_number}") from exc
            if assistant_target != target:
                raise RuntimeError(f"Conversation target mismatch at {path}:{line_number}")
            records.append(record)
    if not records:
        raise RuntimeError(f"Dataset split is empty: {path}")
    return records


def _validate_contamination(train_records: list[dict[str, Any]], val_records: list[dict[str, Any]]) -> dict[str, Any]:
    report = _read_json(CONTAMINATION_PATH)
    if report.get("status") != "pass" or report.get("final_duplicate_pairs") != 0:
        raise RuntimeError("Dataset contamination report is not clean; refusing to train.")
    family_overlap = {record["family"] for record in train_records} & {record["family"] for record in val_records}
    if family_overlap:
        raise RuntimeError(f"Train and validation template families overlap: {sorted(family_overlap)}")
    protected = ("train:test", "train:holdout", "test:holdout")
    for section in ("family_overlap", "normalized_pair_overlap", "structural_pair_overlap"):
        checks = report.get(section, {})
        for pair in protected:
            if checks.get(pair, {}).get("count") != 0:
                raise RuntimeError(f"Contamination check failed: {section} {pair}")
    return report


def _resolve_output(path: Path) -> Path:
    if path.is_absolute():
        return path
    if path.parts and path.parts[0].lower() == PROJECT_DIR.name.lower():
        return (PROJECT_DIR.parent / path).resolve()
    return (PROJECT_DIR / path).resolve()


def _messages(record: dict[str, Any]) -> list[dict[str, str]]:
    return record["messages"]


def _format_record(record: dict[str, Any], tokenizer: Any) -> str:
    messages = _messages(record)
    if getattr(tokenizer, "chat_template", None):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    return "\n\n".join(f"<{item['role']}>\n{item['content']}" for item in messages)


def _runpod_instructions(
    selected_base: str,
    output_argument: str,
    dataset_count: int,
    seed: int,
    init_adapter_argument: str | None,
) -> str:
    init_flag = f" --init-adapter {init_adapter_argument}" if init_adapter_argument else ""
    return f"""# Run on a RunPod NVIDIA CUDA image with at least 24 GB VRAM.
# Upload or clone PySecPatch to /workspace/PySecPatch first.
cd /workspace/PySecPatch

# HF_TOKEN is optional for public models but recommended for rate limits.
# Set it in RunPod Secrets or the shell; never write its value to a file.
test -n "${{HF_TOKEN:-}}" || echo "HF_TOKEN is unset; continuing with public access"
export HF_HOME=/workspace/huggingface-cache
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

python -m pip install --upgrade pip
python -m pip install --no-cache-dir --upgrade --force-reinstall \
  torch==2.5.1 torchvision==0.20.1 torchaudio==2.5.1 \
  --index-url https://download.pytorch.org/whl/cu124
python -m pip install -r pysecpatch/requirements.txt
# The verified {dataset_count}-record corpus (seed {seed}) is included in the training archive.
mkdir -p pysecpatch/results
nohup python pysecpatch/train.py --base {selected_base} --out {output_argument}{init_flag} \
  > pysecpatch/results/runpod_train_console.log 2>&1 &
echo $! > pysecpatch/results/runpod_train.pid

# Monitor with: tail -f pysecpatch/results/runpod_train_console.log
# Re-run the same nohup command after a restart; training resumes the latest checkpoint.
"""


def _model_card(config: dict[str, Any], status: str, detail: str) -> str:
    return f"""# PySecPatch Adapter (Draft)

## Status

`{status}`: {detail}

## Base model

- Model: `{config['selected_base']}`
- Selection: {config['selection_reason']}
- Audited license: `{config['base_license']}`
- License audit generated: `{config['license_audit_generated_at']}`

## Training data

- Training mode: `{config['training_mode']}`
- Initial adapter: `{config['init_adapter']}`
- Initial adapter SHA-256: `{config['init_adapter_sha256']}`
- Train records: {config['train_records']}
- Validation records: {config['val_records']}
- Source: deterministic synthetic Python only
- Source license: Apache-2.0
- Test and holdout used for training: no
- Contamination report: pass

## QLoRA configuration

- Quantization: 4-bit NF4 with double quantization
- Sequence length: {config['max_seq_len']}
- LoRA rank/alpha: {config['lora_r']}/{config['lora_alpha']}
- Learning rate: {config['learning_rate']}
- Epochs: {config['epochs']}
- Per-device batch size: {config['batch_size']}
- Gradient accumulation: {config['gradient_accumulation_steps']}
- Sequence packing: disabled to preserve example boundaries
- Checkpoint interval: every {config['checkpoint_steps']} optimizer steps
- Checkpoint retention: {config['checkpoint_retention']} most recent checkpoints
- Automatic restart behavior: resume the newest valid checkpoint

## Intended use

Defensive Python vulnerability identification and minimal repair. The model must return strict JSON. It is not intended for exploit generation or unauthorized scanning. This draft makes no state-of-the-art claim; disjoint test and holdout evaluation is required.
"""


def _record_blocked(
    train_config: dict[str, Any], status: str, detail: str, started_at: str, output_argument: str
) -> dict[str, Any]:
    log = {
        "status": status,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "selected_base": train_config["selected_base"],
        "adapter_output": train_config["adapter_output"],
        "detail": detail,
        "metrics": {},
        "log_history": [],
    }
    _write_json(TRAIN_LOG_PATH, log)
    MODEL_CARD_PATH.write_text(_model_card(train_config, status, detail), encoding="utf-8")
    RUNPOD_COMMAND_PATH.write_text(
        _runpod_instructions(
            train_config["selected_base"],
            output_argument,
            train_config["total_dataset_records"],
            train_config["seed"],
            train_config.get("init_adapter_argument"),
        ),
        encoding="utf-8",
    )
    return log


def _environment_blocker() -> str | None:
    required = ("torch", "transformers", "datasets", "peft", "trl", "bitsandbytes")
    missing = [module for module in required if importlib.util.find_spec(module) is None]
    if missing:
        return f"Missing training dependencies: {', '.join(missing)}."
    try:
        import torch
    except (ImportError, OSError) as exc:
        return f"PyTorch could not be loaded: {exc}"
    if not torch.cuda.is_available():
        return "CUDA is unavailable; 7B QLoRA training requires an NVIDIA GPU."
    if not hasattr(torch.nn.Module, "set_submodule"):
        return "PyTorch 2.5.1 or newer is required because PEFT uses torch.nn.Module.set_submodule."
    capability = torch.cuda.get_device_capability(0)
    memory_gib = torch.cuda.get_device_properties(0).total_memory / (1024**3)
    if memory_gib < 15:
        return f"GPU has {memory_gib:.1f} GiB VRAM; at least 15 GiB is required for this QLoRA configuration."
    if capability[0] < 7:
        return f"GPU compute capability {capability[0]}.{capability[1]} is unsupported for this training path."
    return None


def _supported_kwargs(callable_object: Any, values: dict[str, Any]) -> dict[str, Any]:
    parameters = inspect.signature(callable_object).parameters
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return values
    return {key: value for key, value in values.items() if key in parameters}


def _train(train_config: dict[str, Any], config: dict[str, Any], train_records: list[dict[str, Any]], val_records: list[dict[str, Any]], output_path: Path) -> tuple[dict[str, Any], str]:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, PeftModel, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from transformers.trainer_utils import get_last_checkpoint
    from trl import SFTConfig, SFTTrainer

    selected_base = train_config["selected_base"]
    if output_path.exists() and not output_path.is_dir():
        raise RuntimeError(f"Adapter output path exists but is not a directory: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(selected_base, trust_remote_code=False, use_fast=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    train_texts = [_format_record(record, tokenizer) for record in train_records]
    val_texts = [_format_record(record, tokenizer) for record in val_records]
    max_length = int(config["max_seq_len"])
    token_lengths = [len(tokenizer(text, add_special_tokens=False)["input_ids"]) for text in train_texts + val_texts]
    oversized = sum(length > max_length for length in token_lengths)
    if oversized:
        raise RuntimeError(
            f"{oversized} training conversations exceed max_seq_len={max_length}; refusing silent truncation."
        )
    train_config["token_length_audit"] = {
        "records": len(token_lengths),
        "maximum": max(token_lengths),
        "mean": sum(token_lengths) / len(token_lengths),
        "over_limit": oversized,
    }
    _write_json(TRAIN_CONFIG_PATH, train_config)
    train_dataset = Dataset.from_list([{"text": text} for text in train_texts])
    val_dataset = Dataset.from_list([{"text": text} for text in val_texts])
    bf16 = bool(torch.cuda.is_bf16_supported())
    compute_dtype = torch.bfloat16 if bf16 else torch.float16
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype,
    )
    model = AutoModelForCausalLM.from_pretrained(
        selected_base,
        quantization_config=quantization_config,
        device_map={"": 0},
        trust_remote_code=False,
        dtype=compute_dtype,
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    init_adapter = train_config.get("init_adapter")
    if init_adapter:
        model = PeftModel.from_pretrained(model, init_adapter, is_trainable=True)
        lora_config = None
    else:
        lora_config = LoraConfig(
            r=int(config["lora_r"]),
            lora_alpha=int(config["lora_alpha"]),
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules="all-linear",
        )

    steps_per_epoch = max(1, len(train_records) // (int(config["batch_size"]) * train_config["gradient_accumulation_steps"]))
    interval = max(10, steps_per_epoch // 5)
    checkpoint_steps = min(100, interval)
    warmup_steps = max(1, int(steps_per_epoch * float(config["epochs"]) * 0.03))
    sft_values: dict[str, Any] = {
        "output_dir": str(output_path),
        "num_train_epochs": float(config["epochs"]),
        "per_device_train_batch_size": int(config["batch_size"]),
        "per_device_eval_batch_size": int(config["batch_size"]),
        "gradient_accumulation_steps": train_config["gradient_accumulation_steps"],
        "gradient_checkpointing": True,
        "learning_rate": float(config["learning_rate"]),
        "lr_scheduler_type": "cosine",
        "warmup_steps": warmup_steps,
        "logging_steps": 10,
        "eval_strategy": "steps",
        "evaluation_strategy": "steps",
        "eval_steps": interval,
        "save_strategy": "steps",
        "save_steps": checkpoint_steps,
        "save_total_limit": 3,
        "save_safetensors": True,
        "bf16": bf16,
        "fp16": not bf16,
        "optim": "paged_adamw_8bit",
        "report_to": "none",
        "seed": train_config["seed"],
        "data_seed": train_config["seed"],
        "packing": False,
        "padding_free": False,
        "dataset_text_field": "text",
        "max_length": int(config["max_seq_len"]),
        "max_seq_length": int(config["max_seq_len"]),
        "push_to_hub": False,
    }
    sft_config = SFTConfig(**_supported_kwargs(SFTConfig, sft_values))
    trainer_values: dict[str, Any] = {
        "model": model,
        "args": sft_config,
        "train_dataset": train_dataset,
        "eval_dataset": val_dataset,
        "processing_class": tokenizer,
        "tokenizer": tokenizer,
    }
    if lora_config is not None:
        trainer_values["peft_config"] = lora_config
    trainer = SFTTrainer(**_supported_kwargs(SFTTrainer, trainer_values))
    last_checkpoint = get_last_checkpoint(str(output_path)) if output_path.is_dir() else None
    result = trainer.train(resume_from_checkpoint=last_checkpoint)
    eval_metrics = trainer.evaluate()
    output_path.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(output_path))
    tokenizer.save_pretrained(str(output_path))
    metrics = {**result.metrics, **{f"final_{key}": value for key, value in eval_metrics.items()}}
    log = {
        "status": "complete",
        "started_at": train_config["started_at"],
        "finished_at": _utc_now(),
        "selected_base": selected_base,
        "adapter_output": str(output_path),
        "detail": "QLoRA training and adapter save completed.",
        "resumed_from_checkpoint": last_checkpoint,
        "metrics": metrics,
        "log_history": trainer.state.log_history,
    }
    return log, f"QLoRA completed with {len(train_records)} training records."


def run_training(
    requested_base: str,
    output_argument: Path,
    init_adapter_argument: Path | None = None,
) -> dict[str, Any]:
    started_at = _utc_now()
    config = _load_config()
    audit = _read_json(AUDIT_PATH)
    selected_base, selection_reason, audit_record = _select_base(requested_base, audit)
    train_records = _read_split(TRAIN_PATH, "train")
    val_records = _read_split(VAL_PATH, "val")
    _validate_contamination(train_records, val_records)
    data_stats = _read_json(DATA_STATS_PATH)
    output_path = _resolve_output(output_argument)
    init_adapter_path: Path | None = None
    init_adapter_config: dict[str, Any] | None = None
    if init_adapter_argument is not None:
        init_adapter_path = _resolve_output(init_adapter_argument)
        if not init_adapter_path.is_dir():
            raise RuntimeError(f"Initial adapter directory is missing: {init_adapter_path}")
        adapter_weight = init_adapter_path / "adapter_model.safetensors"
        init_adapter_config = _read_json(init_adapter_path / "adapter_config.json")
        if not adapter_weight.is_file():
            raise RuntimeError(f"Initial adapter weight is missing: {adapter_weight}")
        if init_adapter_config.get("base_model_name_or_path") != selected_base:
            raise RuntimeError(
                "Initial adapter base does not match the selected training base: "
                f"{init_adapter_config.get('base_model_name_or_path')!r} != {selected_base!r}"
            )
        if output_path == init_adapter_path:
            raise RuntimeError("Adapter output must differ from the initial adapter path.")
    effective_batch_size = 16
    gradient_accumulation_steps = max(1, effective_batch_size // int(config["batch_size"]))
    train_config = {
        "started_at": started_at,
        "requested_base": requested_base,
        "selected_base": selected_base,
        "selection_reason": selection_reason,
        "base_license": audit_record.get("license"),
        "base_train_allowed": audit_record.get("train_allowed") is True,
        "license_audit_generated_at": audit.get("generated_at"),
        "adapter_output": str(output_path),
        "training_mode": "continue_adapter" if init_adapter_path else "new_adapter",
        "init_adapter": str(init_adapter_path) if init_adapter_path else None,
        "init_adapter_argument": init_adapter_argument.as_posix() if init_adapter_argument else None,
        "init_adapter_sha256": (
            _sha256_file(init_adapter_path / "adapter_model.safetensors") if init_adapter_path else None
        ),
        "init_adapter_lora_r": init_adapter_config.get("r") if init_adapter_config else None,
        "init_adapter_lora_alpha": init_adapter_config.get("lora_alpha") if init_adapter_config else None,
        "train_file": str(TRAIN_PATH),
        "val_file": str(VAL_PATH),
        "train_records": len(train_records),
        "val_records": len(val_records),
        "total_dataset_records": int(data_stats["total_records"]),
        "test_records_used": 0,
        "holdout_records_used": 0,
        "max_seq_len": int(config["max_seq_len"]),
        "lora_r": int(init_adapter_config["r"]) if init_adapter_config else int(config["lora_r"]),
        "lora_alpha": (
            int(init_adapter_config["lora_alpha"]) if init_adapter_config else int(config["lora_alpha"])
        ),
        "learning_rate": float(config["learning_rate"]),
        "epochs": float(config["epochs"]),
        "batch_size": int(config["batch_size"]),
        "gradient_accumulation_steps": gradient_accumulation_steps,
        "effective_batch_size": int(config["batch_size"]) * gradient_accumulation_steps,
        "checkpoint_steps": 100,
        "checkpoint_retention": 3,
        "automatic_resume": True,
        "quantization": "4-bit NF4 double-quant",
        "optimizer": "paged_adamw_8bit",
        "packing": False,
        "seed": int(data_stats["seed"]),
        "dataset_generator_sha256": data_stats.get("generator_sha256"),
        "train_sha256": _sha256_file(TRAIN_PATH),
        "val_sha256": _sha256_file(VAL_PATH),
        "contamination_report_sha256": _sha256_file(CONTAMINATION_PATH),
        "system_prompt": SYSTEM_PROMPT,
        "target_contracts": {
            "detect_and_repair": sorted(ANALYSIS_FIELDS),
            "repo_patch": sorted(AGENT_FIELDS),
        },
        "task_counts": data_stats.get("counts_by_split_and_task", {}),
        "push_to_hub": False,
        "hf_token_present": bool(os.getenv("HF_TOKEN")),
        "package_versions": _package_versions(),
        "python": sys.version,
        "platform": platform.platform(),
    }
    _write_json(TRAIN_CONFIG_PATH, train_config)

    blocker = _environment_blocker()
    if blocker:
        return _record_blocked(train_config, "blocked_environment", blocker, started_at, output_argument.as_posix())
    try:
        log, detail = _train(train_config, config, train_records, val_records, output_path)
    except Exception as exc:
        status = "blocked_gpu_memory" if "out of memory" in str(exc).lower() else "failed"
        return _record_blocked(
            train_config, status, f"{type(exc).__name__}: {exc}", started_at, output_argument.as_posix()
        )
    _write_json(TRAIN_LOG_PATH, log)
    model_card = _model_card(train_config, "complete", detail)
    MODEL_CARD_PATH.write_text(model_card, encoding="utf-8")
    (output_path / "README.md").write_text(model_card, encoding="utf-8")
    _write_json(output_path / "training_metadata.json", {"config": train_config, "log": log})
    RUNPOD_COMMAND_PATH.unlink(missing_ok=True)
    return log


def merge_adapter(base_model: str, adapter_argument: Path, output_argument: Path) -> dict[str, Any]:
    audit = _read_json(AUDIT_PATH)
    audit_record = next(
        (record for record in audit.get("models", []) if record.get("model_id") == base_model),
        None,
    )
    if not audit_record or audit_record.get("train_allowed") is not True:
        status = audit_record.get("status") if audit_record else "not_audited"
        raise RuntimeError(f"Merge base {base_model!r} is not train-allowed (status={status}).")
    adapter_path = _resolve_output(adapter_argument)
    output_path = _resolve_output(output_argument)
    if not adapter_path.is_dir() or not (adapter_path / "adapter_config.json").is_file():
        raise RuntimeError(f"Completed adapter not found: {adapter_path}")
    if output_path.exists() and not output_path.is_dir():
        raise RuntimeError(f"Merged output path is not a directory: {output_path}")
    if output_path.exists() and any(output_path.iterdir()):
        raise RuntimeError(f"Merged output directory is not empty: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError("torch, transformers, and peft are required for merging.") from exc
    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
    base = AutoModelForCausalLM.from_pretrained(
        base_model,
        dtype=dtype,
        device_map="auto",
        low_cpu_mem_usage=True,
        trust_remote_code=False,
    )
    model = PeftModel.from_pretrained(base, str(adapter_path))
    merged = model.merge_and_unload(safe_merge=True)
    merged.save_pretrained(
        str(output_path),
        safe_serialization=True,
        max_shard_size="4GB",
    )
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=False, use_fast=True)
    tokenizer.save_pretrained(str(output_path))
    weight_manifest = [
        {
            "file": path.name,
            "bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in sorted(output_path.glob("*.safetensors"))
    ]
    metadata = {
        "status": "complete",
        "generated_at": _utc_now(),
        "base_model": base_model,
        "base_license": audit_record.get("license"),
        "adapter_path": str(adapter_path),
        "adapter_sha256": _sha256_file(adapter_path / "adapter_model.safetensors"),
        "merged_output": str(output_path),
        "dtype": str(dtype),
        "weight_manifest": weight_manifest,
        "total_weight_bytes": sum(item["bytes"] for item in weight_manifest),
        "push_to_hub": False,
    }
    _write_json(RESULTS_DIR / "merge_config.json", metadata)
    _write_json(output_path / "merge_metadata.json", metadata)
    source_card = adapter_path / "README.md"
    card_text = source_card.read_text(encoding="utf-8") if source_card.is_file() else "# PySecPatch\n"
    card_text += (
        "\n## Standalone Merged Artifact\n\n"
        f"This checkpoint merges the PySecPatch LoRA adapter into `{base_model}`. "
        "It is provided for standalone inference; the base-plus-adapter form is the "
        "authoritative benchmark artifact. See `merge_metadata.json` for provenance and "
        "per-shard SHA-256 hashes. No upload was performed by the training script.\n"
    )
    (output_path / "README.md").write_text(card_text, encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the PySecPatch LoRA adapter with audited 4-bit QLoRA.")
    parser.add_argument("--base", required=True, help="audited model ID or 'auto'")
    parser.add_argument("--out", type=Path, required=True, help="output path, relative to pysecpatch/")
    parser.add_argument("--merge-only", action="store_true", help="merge a completed adapter into the base")
    parser.add_argument("--adapter", type=Path, help="completed adapter path for --merge-only")
    parser.add_argument(
        "--init-adapter",
        type=Path,
        help="existing compatible LoRA adapter whose weights should be continued",
    )
    args = parser.parse_args()
    try:
        if args.merge_only:
            if args.base == "auto":
                parser.error("--merge-only requires an explicit --base model ID")
            if args.adapter is None:
                parser.error("--merge-only requires --adapter")
            merge = merge_adapter(args.base, args.adapter, args.out)
            print(json.dumps(merge, indent=2))
            return 0
        log = run_training(args.base, args.out, args.init_adapter)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(
        json.dumps(
            {
                "status": log["status"],
                "selected_base": log["selected_base"],
                "adapter_output": log["adapter_output"],
                "detail": log["detail"],
                "next_eval_command": "python pysecpatch/eval.py --all",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
