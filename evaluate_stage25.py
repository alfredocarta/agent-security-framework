#!/usr/bin/env python3
"""
Evaluate a DeBERTa injection classifier on deepset test and OPI stratified samples.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
import torch
from datasets import Dataset, load_dataset
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding

SEED = 42
PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = PROJECT_DIR / "models" / "deberta-v3-injection-ft"
OPI_PATH = Path("/Users/alfredo/Projects/agent-security-evaluation/benchmarks/open_prompt_injection.json")
MAX_LENGTH = 256
INTENTS = ["spam", "jfleg", "gigaword", "hsol", "mrpc", "rte", "sentiment"]


def allocation(total: int, groups: Iterable[str]) -> Dict[str, int]:
    ordered = sorted(groups)
    base, remainder = divmod(total, len(ordered))
    return {group: base + (idx < remainder) for idx, group in enumerate(ordered)}


def resolve_model_path(value: str) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_DIR / path
    return str(path)


def load_deepset_test() -> Dataset:
    ds = load_dataset("deepset/prompt-injections", split="test")
    return ds.select_columns(["text", "label"])


def load_opi_stratified(label: int, total: int = 500) -> Dataset:
    if not OPI_PATH.exists():
        raise FileNotFoundError(f"OPI dataset not found: {OPI_PATH}")

    rng = random.Random(SEED + label)
    by_intent: Dict[str, List[dict]] = {intent: [] for intent in INTENTS}

    with OPI_PATH.open("r", encoding="utf-8") as fh:
        rows = json.load(fh)

    for row in rows:
        intent = row["intent"]
        if int(row["label"]) == label and intent in by_intent:
            by_intent[intent].append({"text": row["text"], "label": label, "intent": intent})

    selected: List[dict] = []
    for intent, n in allocation(total, INTENTS).items():
        bucket = by_intent[intent]
        if len(bucket) < n:
            raise ValueError(
                f"Not enough OPI samples for label={label}, intent={intent}: "
                f"need {n}, found {len(bucket)}"
            )
        selected.extend(rng.sample(bucket, n))

    rng.shuffle(selected)
    return Dataset.from_list(selected).select_columns(["text", "label"])


def choose_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def predict(model, tokenizer, ds: Dataset, batch_size: int = 32) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH)

    tokenized = ds.map(tokenize, batched=True, remove_columns=["text"])
    tokenized = tokenized.rename_column("label", "labels")
    tokenized.set_format(type="torch")

    collator = DataCollatorWithPadding(tokenizer=tokenizer)
    loader = DataLoader(tokenized, batch_size=batch_size, shuffle=False, collate_fn=collator)

    device = next(model.parameters()).device
    labels: List[np.ndarray] = []
    preds: List[np.ndarray] = []
    injection_probs: List[np.ndarray] = []

    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            batch_labels = batch.pop("labels")
            logits = model(**batch).logits
            probs = torch.softmax(logits, dim=-1)
            labels.append(batch_labels.cpu().numpy())
            preds.append(torch.argmax(probs, dim=-1).cpu().numpy())
            injection_probs.append(probs[:, 1].cpu().numpy())

    return np.concatenate(labels), np.concatenate(preds), np.concatenate(injection_probs)


def metrics_for(labels: np.ndarray, preds: np.ndarray) -> Dict[str, float]:
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        preds,
        average="binary",
        pos_label=1,
        zero_division=0,
    )
    # Force both labels so single-class groups still produce a 2x2 matrix.
    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def print_metrics(name: str, labels: np.ndarray, preds: np.ndarray) -> None:
    m = metrics_for(labels, preds)
    print(
        f"{name}: precision={m['precision']:.4f} "
        f"recall={m['recall']:.4f} f1={m['f1']:.4f} fpr={m['fpr']:.4f}"
    )


def print_distribution(name: str, probs: np.ndarray) -> None:
    p10, p25, p50, p75, p90 = np.percentile(probs, [10, 25, 50, 75, 90])
    print(
        f"{name} injection probability percentiles: "
        f"p10={p10:.4f} p25={p25:.4f} p50={p50:.4f} p75={p75:.4f} p90={p90:.4f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH), help="Fine-tuned model path")
    parser.add_argument("--batch-size", type=int, default=32)
    args = parser.parse_args()

    model_path = resolve_model_path(args.model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    device = choose_device()
    model.to(device)

    print(f"Model: {model_path}")
    print(f"Device: {device}")

    datasets = {
        "deepset_test": load_deepset_test(),
        "opi_benign_500": load_opi_stratified(label=0, total=500),
        "opi_injection_500": load_opi_stratified(label=1, total=500),
    }

    outputs = {}
    for name, ds in datasets.items():
        labels, preds, probs = predict(model, tokenizer, ds, batch_size=args.batch_size)
        outputs[name] = (labels, preds, probs)
        print_metrics(name, labels, preds)

    print_distribution("OPI benign", outputs["opi_benign_500"][2])
    print_distribution("OPI injection", outputs["opi_injection_500"][2])


if __name__ == "__main__":
    main()
