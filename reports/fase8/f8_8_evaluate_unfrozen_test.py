#!/usr/bin/env python3
"""F8.8 -- Internal evaluation of the F8.7 UNFROZEN (full fine-tune) checkpoint
on the held-out TEST split (never touched during training or model selection).

Reports: macro-F1 (primary), per-class precision/recall/F1, confusion matrix.
"""
import json
import pathlib
import sys

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, confusion_matrix

NETFOUND_SRC = "/home/mobisec/nfm-fase8/netFound/src"
sys.path.insert(0, NETFOUND_SRC)
sys.path.insert(0, f"{NETFOUND_SRC}/modules")

import torch
from sklearn.preprocessing import LabelEncoder
from transformers import TrainingArguments

from modules import utils
from modules.netFoundDataCollator import DataCollatorForFlowClassification
from modules.netFoundModels import netFoundFinetuningModel
from modules.netFoundTrainer import netFoundTrainer
from modules.netFoundTokenizer import netFoundTokenizer
from netFoundFinetuning import FineTuningDataTrainingArguments

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
SPLIT_DIR = REPO_ROOT / "data" / "finetune_raw" / "final" / "split"
UNFROZEN_MODEL_DIR = str(REPO_ROOT / "models" / "finetune_unfrozen")
REPORT_DIR = REPO_ROOT / "reports" / "fase8"


def main():
    logger = utils.get_logger(__name__)
    utils.LOGGING_LEVEL = 30

    with open(REPORT_DIR / "f8_7_label_classes.json") as f:
        class_names = json.load(f)
    label_encoder = LabelEncoder()
    label_encoder.classes_ = np.array(class_names)
    num_classes = len(class_names)

    model_args = utils.ModelArguments(model_name_or_path=UNFROZEN_MODEL_DIR, size="base")
    data_args = FineTuningDataTrainingArguments(
        train_dir=str(SPLIT_DIR / "train_dir"),
        test_dir=str(SPLIT_DIR / "test_dir"),
        num_labels=num_classes,
        problem_type="single_label_classification",
    )
    training_args = TrainingArguments(
        output_dir=str(REPO_ROOT / "models" / "_eval_scratch_unfrozen"),
        per_device_eval_batch_size=16,
        bf16=True,
        report_to=[],
        dataloader_num_workers=2,
    )

    from datasets import load_dataset
    test_dataset = load_dataset("arrow", data_dir=data_args.test_dir, split=None)
    test_dataset = test_dataset[list(test_dataset.keys())[0]]
    test_dataset = test_dataset.add_column("total_bursts", [0] * len(test_dataset))

    def encode_labels(_batch):
        _batch["labels"] = label_encoder.transform(_batch["labels"])
        return _batch

    test_dataset = test_dataset.map(function=encode_labels, batched=True)

    config = utils.update_config(model_args, data_args, training_args, config=None)
    config.p = 0
    tokenizer = netFoundTokenizer(config=config)
    test_dataset = test_dataset.map(function=tokenizer, batched=True, num_proc=utils.get_90_percent_cpu_count())

    data_collator = DataCollatorForFlowClassification(tokenizer.pad_token_id, torch.long)

    logger.warning(f"Loading UNFROZEN best checkpoint from {UNFROZEN_MODEL_DIR}")
    model = netFoundFinetuningModel.from_pretrained(UNFROZEN_MODEL_DIR, config=config)

    utils.init_tbwriter(training_args.output_dir)
    trainer = netFoundTrainer(
        model=model,
        args=training_args,
        tokenizer=tokenizer,
        data_collator=data_collator,
    )

    pred_output = trainer.predict(test_dataset)
    logits = pred_output.predictions[0] if isinstance(pred_output.predictions, tuple) else pred_output.predictions
    label_ids = pred_output.label_ids.astype(int)
    preds = logits.argmax(axis=1)

    labels_range = np.arange(num_classes)
    macro_f1 = f1_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)
    weighted_f1 = f1_score(label_ids, preds, average="weighted", zero_division=0, labels=labels_range)
    accuracy = accuracy_score(label_ids, preds)
    macro_prec = precision_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)
    macro_recall = recall_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)

    per_class_f1 = f1_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)
    per_class_prec = precision_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)
    per_class_recall = recall_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)

    cm = confusion_matrix(label_ids, preds, labels=labels_range)

    report = {
        "regime": "unfrozen_full_finetune",
        "split": "test (held out, never used in training or model selection)",
        "n_test_rows": int(len(label_ids)),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "accuracy": float(accuracy),
        "macro_precision": float(macro_prec),
        "macro_recall": float(macro_recall),
        "per_class": {
            class_names[i]: {
                "precision": float(per_class_prec[i]),
                "recall": float(per_class_recall[i]),
                "f1": float(per_class_f1[i]),
                "support": int((label_ids == i).sum()),
            }
            for i in range(num_classes)
        },
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": class_names,
    }

    out_json = REPORT_DIR / "f8_8_unfrozen_test_metrics.json"
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)

    import csv
    with open(REPORT_DIR / "f8_8_unfrozen_confusion_matrix.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["true\\pred"] + class_names)
        for i, row in enumerate(cm):
            writer.writerow([class_names[i]] + row.tolist())

    print(json.dumps({k: v for k, v in report.items() if k not in ("confusion_matrix",)}, indent=2))
    print(f"\nSaved -> {out_json}")


if __name__ == "__main__":
    main()
