"""Model registry, license auditing, and strict-JSON local inference."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CANDIDATE_BASE_MODELS = (
    "Virtue-AI-HUB/VulnLLM-R-7B",
    "Qwen/Qwen2.5-Coder-7B-Instruct",
)

BENCHMARK_MODELS = (
    "Virtue-AI-HUB/VulnLLM-R-7B",
    "Qwen/Qwen2.5-Coder-7B-Instruct",
    "segolilylabs/Lily-Cybersecurity-7B-v0.2",
    "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B",
    "fdtn-ai/Foundation-Sec-8B-Reasoning",
)

ALL_MODELS = tuple(dict.fromkeys((*CANDIDATE_BASE_MODELS, *BENCHMARK_MODELS)))
RESULTS_DIR = Path(__file__).resolve().parent / "results"
DEFAULT_AUDIT_PATH = RESULTS_DIR / "license_audit.json"

APACHE_RE = re.compile(r"apache(?: license)?[- ]?2(?:\.0)?", re.IGNORECASE)
CUSTOM_RESTRICTION_TERMS = (
    "non-commercial",
    "noncommercial",
    "research use only",
    "acceptable use policy",
    "additional restrictions",
    "custom license",
    "responsible ai license",
)


def _http_json(url: str, timeout: int = 15) -> tuple[dict[str, Any] | None, str | None]:
    request = Request(url, headers=_request_headers())
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), None
    except HTTPError as exc:
        return None, f"http_{exc.code}"
    except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _http_text(url: str, timeout: int = 15) -> tuple[str | None, str | None]:
    request = Request(url, headers=_request_headers())
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace"), None
    except HTTPError as exc:
        return None, f"http_{exc.code}"
    except (URLError, TimeoutError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _request_headers() -> dict[str, str]:
    headers = {"User-Agent": "PySecPatch/0.1 defensive-license-audit"}
    token = os.getenv("HF_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_huggingface_metadata(model_id: str) -> dict[str, Any]:
    """Fetch only public metadata and the model card; failures remain auditable."""
    metadata, metadata_error = _http_json(f"https://huggingface.co/api/models/{model_id}")
    card, card_error = _http_text(f"https://huggingface.co/{model_id}/raw/main/README.md")
    return {
        "metadata": metadata,
        "metadata_error": metadata_error,
        "card_text": card,
        "card_error": card_error,
    }


def _license_value(metadata: dict[str, Any] | None) -> str | None:
    if not metadata:
        return None
    card_data = metadata.get("cardData") or {}
    value = card_data.get("license")
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    if value:
        return str(value)
    for tag in metadata.get("tags") or []:
        if isinstance(tag, str) and tag.startswith("license:"):
            return tag.split(":", 1)[1]
    return None


def classify_model(model_id: str, fetched: dict[str, Any]) -> dict[str, Any]:
    metadata = fetched["metadata"]
    card_text = fetched["card_text"] or ""
    license_value = _license_value(metadata)
    card_data = (metadata or {}).get("cardData") or {}
    license_name = card_data.get("license_name")
    license_link = card_data.get("license_link")
    license_evidence = " ".join(filter(None, (license_value, card_text)))
    apache = bool(APACHE_RE.search(license_value or "")) or (
        license_value is None and bool(APACHE_RE.search(card_text))
    )
    restriction_hits = sorted(
        term for term in CUSTOM_RESTRICTION_TERMS if term in license_evidence.lower()
    )
    gated_value = metadata.get("gated") if metadata else None
    gated = gated_value not in (None, False, "false")
    missing_metadata = fetched["metadata_error"] == "http_404"
    custom_license = not apache and bool(
        restriction_hits
        or str(license_value).lower() in {"other", "custom"}
        or license_name
        or license_link
    )
    unknown_license = not apache and not custom_license

    if missing_metadata:
        status = "skipped"
        reason = "model metadata is missing"
    elif gated:
        status = "skipped"
        reason = "model is gated"
    elif apache and not restriction_hits and model_id in CANDIDATE_BASE_MODELS:
        status = "train_allowed"
        reason = "candidate base has Apache-2.0 metadata and no detected restrictions"
    elif custom_license:
        status = "baseline_only"
        reason = "custom license or additional license restrictions detected"
    elif apache:
        status = "baseline_only"
        reason = "Apache-2.0 benchmark model not selected as a training candidate"
    else:
        status = "unknown"
        reason = "license could not be positively classified as Apache-2.0"

    return {
        "model_id": model_id,
        "roles": {
            "candidate_base": model_id in CANDIDATE_BASE_MODELS,
            "benchmark": model_id in BENCHMARK_MODELS,
        },
        "status": status,
        "train_allowed": status == "train_allowed",
        "reason": reason,
        "license": license_value,
        "license_name": license_name,
        "license_link": license_link,
        "apache_2_0_detected": apache,
        "custom_license_detected": custom_license,
        "custom_restrictions_detected": bool(restriction_hits),
        "unknown_license": unknown_license,
        "restriction_signals": restriction_hits,
        "gated": gated,
        "gated_value": gated_value,
        "missing_metadata": missing_metadata,
        "metadata_fetched": metadata is not None,
        "metadata_error": fetched["metadata_error"],
        "model_card_fetched": fetched["card_text"] is not None,
        "model_card_error": fetched["card_error"],
        "model_card_sha256": (
            hashlib.sha256(card_text.encode("utf-8")).hexdigest() if card_text else None
        ),
    }


def run_license_audit(output_path: Path = DEFAULT_AUDIT_PATH) -> dict[str, Any]:
    records = [classify_model(model_id, fetch_huggingface_metadata(model_id)) for model_id in ALL_MODELS]
    summary = {status: 0 for status in ("train_allowed", "baseline_only", "skipped", "unknown")}
    for record in records:
        summary[record["status"]] += 1
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": "Training is permitted only when train_allowed is true in this audit.",
        "summary": summary,
        "models": records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def require_train_allowed(model_id: str, audit_path: Path = DEFAULT_AUDIT_PATH) -> None:
    if not audit_path.is_file():
        raise RuntimeError(f"License audit not found: {audit_path}. Run models.py --license-audit first.")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    record = next((item for item in audit.get("models", []) if item.get("model_id") == model_id), None)
    if not record or record.get("train_allowed") is not True:
        status = record.get("status") if record else "not_audited"
        raise RuntimeError(f"Training base {model_id!r} is not allowed by the audit (status={status}).")


class TransformersRepairModel:
    """Lazy local Transformers runtime that returns parsed JSON or raw evidence."""

    def __init__(
        self, model_id: str, adapter_path: str | None = None, max_seq_len: int = 4096
    ) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("Install requirements.txt to enable model inference.") from exc

        local_only = os.getenv("PYSECPATCH_LOCAL_FILES_ONLY", "").lower() in {"1", "true", "yes"}
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            trust_remote_code=False,
            local_files_only=local_only,
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            model_id,
            dtype="auto",
            device_map="auto",
            trust_remote_code=False,
            local_files_only=local_only,
        )
        if adapter_path and Path(adapter_path).exists():
            try:
                from peft import PeftModel
            except ImportError as exc:
                raise RuntimeError("peft is required to load a LoRA adapter.") from exc
            self.model = PeftModel.from_pretrained(self.model, adapter_path)
        self.model.eval()
        self.max_seq_len = max_seq_len
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id
        self._torch = torch

    def _render_prompt(self, prompt: str) -> str:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a defensive Python security repair model. Return exactly one JSON object, "
                    "with no markdown or surrounding text. Never provide exploit instructions."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        if hasattr(self.tokenizer, "apply_chat_template"):
            return self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        return "\n\n".join(item["content"] for item in messages)

    @staticmethod
    def _parse_output(raw: str) -> dict[str, Any]:
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("top-level JSON must be an object")
            return {"invalid_json": False, "output": parsed, "raw_output": raw}
        except (json.JSONDecodeError, ValueError) as exc:
            return {
                "invalid_json": True,
                "output": None,
                "raw_output": raw,
                "json_error": str(exc),
            }

    def infer_batch(self, prompts: list[str], max_new_tokens: int = 900) -> list[dict[str, Any]]:
        if not prompts:
            return []
        rendered = [self._render_prompt(prompt) for prompt in prompts]
        original_padding_side = self.tokenizer.padding_side
        self.tokenizer.padding_side = "left"
        encoded = self.tokenizer(
            rendered,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=self.max_seq_len,
        )
        self.tokenizer.padding_side = original_padding_side
        device = next(self.model.parameters()).device
        encoded = {key: value.to(device) for key, value in encoded.items()}
        with self._torch.inference_mode():
            output = self.model.generate(
                **encoded,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
            )
        input_width = encoded["input_ids"].shape[1]
        return [
            self._parse_output(
                self.tokenizer.decode(sequence[input_width:], skip_special_tokens=True).strip()
            )
            for sequence in output
        ]

    def infer(self, prompt: str, max_new_tokens: int = 900) -> dict[str, Any]:
        return self.infer_batch([prompt], max_new_tokens=max_new_tokens)[0]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit PySecPatch model licenses.")
    parser.add_argument("--license-audit", action="store_true", help="audit all registered models")
    parser.add_argument("--output", type=Path, default=DEFAULT_AUDIT_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.license_audit:
        build_parser().print_help()
        return 0
    report = run_license_audit(args.output)
    print(json.dumps({"output": str(args.output), "summary": report["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
