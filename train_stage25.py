#!/usr/bin/env python3
"""
Fine-tune deepset/deberta-v3-base-injection on deepset prompt injections plus
Open Prompt Injection (OPI) hard negatives.

This is intentionally a training script only. Run it manually when ready.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
from datasets import Dataset, concatenate_datasets, load_dataset
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
    set_seed,
)

SEED = 42
BASE_MODEL = "deepset/deberta-v3-base-injection"
PROJECT_DIR = Path(__file__).resolve().parent
OPI_PATH = Path("/Users/alfredo/Projects/agent-security-evaluation/benchmarks/open_prompt_injection.json")
OUTPUT_DIR = PROJECT_DIR / "models" / "deberta-v3-injection-ft"
MAX_LENGTH = 256
INTENTS = ["spam", "jfleg", "gigaword", "hsol", "mrpc", "rte", "sentiment"]


def allocation(total: int, groups: Iterable[str]) -> Dict[str, int]:
    """Deterministically split total samples as evenly as possible across groups."""
    ordered = sorted(groups)
    base, remainder = divmod(total, len(ordered))
    return {group: base + (idx < remainder) for idx, group in enumerate(ordered)}


def load_deepset_all() -> Dataset:
    ds = load_dataset("deepset/prompt-injections")
    combined = concatenate_datasets([ds["train"], ds["test"]])
    combined = combined.select_columns(["text", "label"])
    combined = combined.map(lambda row: {"source": "deepset", "intent": "deepset"})
    return combined


def load_opi_stratified(samples_per_label: int = 2000) -> Dataset:
    if not OPI_PATH.exists():
        raise FileNotFoundError(f"OPI dataset not found: {OPI_PATH}")

    rng = random.Random(SEED)
    by_label_intent: Dict[Tuple[int, str], List[dict]] = {
        (label, intent): [] for label in (0, 1) for intent in INTENTS
    }

    with OPI_PATH.open("r", encoding="utf-8") as fh:
        rows = json.load(fh)

    for row in rows:
        label = int(row["label"])
        intent = row["intent"]
        if label in (0, 1) and intent in INTENTS:
            by_label_intent[(label, intent)].append(
                {
                    "text": row["text"],
                    "label": label,
                    "source": "opi",
                    "intent": intent,
                }
            )

    selected: List[dict] = []
    per_intent = allocation(samples_per_label, INTENTS)
    for label in (0, 1):
        for intent, n in per_intent.items():
            bucket = by_label_intent[(label, intent)]
            if len(bucket) < n:
                raise ValueError(
                    f"Not enough OPI samples for label={label}, intent={intent}: "
                    f"need {n}, found {len(bucket)}"
                )
            selected.extend(rng.sample(bucket, n))

    rng.shuffle(selected)
    return Dataset.from_list(selected)


def stratified_train_val_split(ds: Dataset, test_size: float = 0.2) -> Tuple[Dataset, Dataset]:
    # Stratify by source + label so both deepset and OPI class proportions survive the split.
    strata = [f"{source}_{label}" for source, label in zip(ds["source"], ds["label"])]
    train_idx, val_idx = train_test_split(
        np.arange(len(ds)),
        test_size=test_size,
        random_state=SEED,
        shuffle=True,
        stratify=strata,
    )
    return ds.select(train_idx.tolist()), ds.select(val_idx.tolist())


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        preds,
        average="binary",
        pos_label=1,
        zero_division=0,
    )
    return {"precision": precision, "recall": recall, "f1": f1}


class SplitEvalTrainer(Trainer):
    """Trainer that keeps eval_f1 for best-model selection and logs source splits too."""

    def __init__(self, *args, split_eval_datasets: Dict[str, Dataset] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.split_eval_datasets = split_eval_datasets or {}

    def evaluate(self, eval_dataset=None, ignore_keys=None, metric_key_prefix: str = "eval"):
        metrics = super().evaluate(eval_dataset, ignore_keys, metric_key_prefix)

        # During normal epoch evaluation, also report deepset-only and OPI-only validation metrics.
        if eval_dataset is None and metric_key_prefix == "eval" and self.split_eval_datasets:
            for split_name, split_ds in self.split_eval_datasets.items():
                split_output = self.predict(
                    split_ds,
                    ignore_keys=ignore_keys,
                    metric_key_prefix=f"eval_{split_name}",
                )
                self.log(split_output.metrics)
                metrics.update(split_output.metrics)

        return metrics


def main() -> None:
    set_seed(SEED)

    deepset_ds = load_deepset_all()
    opi_ds = load_opi_stratified(samples_per_label=500)
    combined = concatenate_datasets([deepset_ds, opi_ds])

    print(f"Loaded deepset samples: {len(deepset_ds)}")
    print(f"Loaded OPI samples: {len(opi_ds)}")
    print(f"Combined samples: {len(combined)}")

    train_ds, val_ds = stratified_train_val_split(combined, test_size=0.2)
    val_deepset = val_ds.filter(lambda row: row["source"] == "deepset")
    val_opi = val_ds.filter(lambda row: row["source"] == "opi")

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH)

    train_tok = train_ds.map(tokenize, batched=True, remove_columns=["text", "source", "intent"])
    val_tok = val_ds.map(tokenize, batched=True, remove_columns=["text", "source", "intent"])
    val_deepset_tok = val_deepset.map(tokenize, batched=True, remove_columns=["text", "source", "intent"])
    val_opi_tok = val_opi.map(tokenize, batched=True, remove_columns=["text", "source", "intent"])

    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label={0: "LEGIT", 1: "INJECTION"},
        label2id={"LEGIT": 0, "INJECTION": 1},
    )
    model.config.id2label = {0: "LEGIT", 1: "INJECTION"}
    model.config.label2id = {"LEGIT": 0, "INJECTION": 1}

    args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=3,
        learning_rate=2e-5,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=8,
        gradient_accumulation_steps=2,
        use_mps_device=True,
        dataloader_pin_memory=False,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_f1",
        greater_is_better=True,
        seed=SEED,
        save_total_limit=2,
        logging_strategy="steps",
        logging_steps=25,
        report_to="none",
    )

    trainer = SplitEvalTrainer(
        model=model,
        args=args,
        train_dataset=train_tok,
        eval_dataset=val_tok,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
        split_eval_datasets={"deepset": val_deepset_tok, "opi": val_opi_tok},
    )

    trainer.train()
    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    deepset_metrics = trainer.predict(val_deepset_tok, metric_key_prefix="final_deepset").metrics
    opi_metrics = trainer.predict(val_opi_tok, metric_key_prefix="final_opi").metrics
    print(f"Final deepset validation F1: {deepset_metrics['final_deepset_f1']:.4f}")
    print(f"Final OPI validation F1: {opi_metrics['final_opi_f1']:.4f}")
    print(f"Saved model and tokenizer to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
