#!/usr/bin/env python3
"""W6 -- Fine-tuning regime 1: FROZEN (linear-probe), on the W1 INTERIM
23-class VM snapshot (17 effective classes with data; 5 SCTP classes are
NO_DATA and excluded, per INGEST_TRAIN_WSL.md).

Imbalance strategy (per INGEST_TRAIN_WSL.md W6 note): BOTH subsampling and
class weighting, not just one --
  1. Any train-split class with more than SUBSAMPLE_CAP=3000 flows is
     randomly subsampled down to 3000 (seed=42). This caps benign
     (20597->3000) and the 5 Tier-0 flood classes (3958-11229 -> 3000 each)
     so they can no longer dominate every batch by sheer count.
  2. Balanced (inverse-frequency) class weighting is still applied ON TOP of
     the subsampled distribution, so the ~17-250-flow 5G/new-attack classes
     still get a meaningfully larger per-sample loss weight than the capped
     flood/benign classes.
This combination was chosen over subsampling-only or weighting-only because
with 17 classes spanning a count range of 50 (pfcp) to 20597 (benign) pre-cap,
weighting alone still means >99% of *steps* are dominated by benign/flood
rows (gradient variance), while subsampling alone would still leave a 60x
gap (3000 vs 50) for the smallest classes. Combining both keeps batches
balanced AND keeps small-class loss contribution meaningful.
"""
import json
import pathlib
import sys

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score

NETFOUND_SRC = "/home/mobisec/nfm-fase8/netFound/src"
sys.path.insert(0, NETFOUND_SRC)
sys.path.insert(0, f"{NETFOUND_SRC}/modules")

from transformers import TrainingArguments

from modules import utils
from modules.netFoundDataCollator import DataCollatorForFlowClassification
from modules.netFoundModels import netFoundFinetuningModel
from modules.netFoundTrainer import netFoundTrainer
from modules.netFoundTokenizer import netFoundTokenizer
from netFoundFinetuning import get_label_encoder, FineTuningDataTrainingArguments

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
SPLIT_DIR = REPO_ROOT / "data" / "finetune_raw" / "final" / "split"
CHECKPOINT_DIR = str(REPO_ROOT / "models" / "netFound-base")
OUTPUT_DIR = str(REPO_ROOT / "models" / "w6_finetune_frozen")
REPORT_DIR = REPO_ROOT / "reports" / "fase8"

SEED = 42
SUBSAMPLE_CAP = 3000


class WeightedTrainer(netFoundTrainer):
    def __init__(self, *args, class_weights=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.get("labels")
        outputs = model(**inputs)
        logits = outputs.logits
        weight = self.class_weights.to(device=logits.device, dtype=torch.float32)
        loss_fct = nn.CrossEntropyLoss(weight=weight)
        loss = loss_fct(logits.view(-1, model.num_labels).float(), labels.view(-1))
        return (loss, outputs) if return_outputs else loss


def subsample_train(dataset, cap, seed):
    labels = np.array(dataset["labels"])
    rng = np.random.RandomState(seed)
    keep_idx = []
    before = {}
    after = {}
    for c in np.unique(labels):
        idx = np.where(labels == c)[0]
        before[int(c)] = len(idx)
        if len(idx) > cap:
            idx = rng.choice(idx, size=cap, replace=False)
        after[int(c)] = len(idx)
        keep_idx.extend(idx.tolist())
    keep_idx = sorted(keep_idx)
    return dataset.select(keep_idx), before, after


def make_compute_metrics(class_names, save_path):
    num_classes = len(class_names)
    labels_range = np.arange(num_classes)

    def compute_metrics(p):
        logits = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
        label_ids = p.label_ids.astype(int)
        preds = logits.argmax(axis=1) if logits.ndim == 2 else logits.astype(int)

        macro_f1 = f1_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)
        weighted_f1 = f1_score(label_ids, preds, average="weighted", zero_division=0, labels=labels_range)
        accuracy = accuracy_score(label_ids, preds)
        macro_prec = precision_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)
        macro_recall = recall_score(label_ids, preds, average="macro", zero_division=0, labels=labels_range)

        per_class_f1 = f1_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)
        per_class_prec = precision_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)
        per_class_recall = recall_score(label_ids, preds, average=None, zero_division=0, labels=labels_range)

        cm = np.zeros((num_classes, num_classes), dtype=int)
        for t, pr in zip(label_ids, preds):
            cm[t, pr] += 1

        report = {
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
        with open(save_path, "w") as f:
            json.dump(report, f, indent=2)

        return {"macro_f1": macro_f1, "weighted_f1": weighted_f1, "accuracy": accuracy}

    return compute_metrics


def main():
    logger = utils.get_logger(__name__)
    utils.LOGGING_LEVEL = 30

    model_args = utils.ModelArguments(
        model_name_or_path=CHECKPOINT_DIR,
        size="base",
        freeze_base=True,
    )
    data_args = FineTuningDataTrainingArguments(
        train_dir=str(SPLIT_DIR / "train_dir"),
        test_dir=str(SPLIT_DIR / "val_dir"),
        num_labels=None,  # set after label encoding
        problem_type="single_label_classification",
    )
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        overwrite_output_dir=True,
        do_train=True,
        do_eval=True,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="epoch",
        learning_rate=1e-3,
        num_train_epochs=10,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=2,
        bf16=True,
        seed=SEED,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to=[],
        dataloader_num_workers=2,
    )

    logger.warning("Loading datasets")
    train_dataset, val_dataset = utils.load_train_test_datasets(logger, data_args)

    label_encoder, le_mapping_function = get_label_encoder(
        data_args.problem_type, train_dataset, batch_size=1024
    )
    train_dataset = train_dataset.map(function=le_mapping_function, batched=True)
    val_dataset = val_dataset.map(function=le_mapping_function, batched=True)

    data_args.num_labels = len(label_encoder.classes_)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORT_DIR / "w6_label_classes.json", "w") as f:
        json.dump(list(label_encoder.classes_), f, indent=2)

    train_dataset, before_counts, after_counts = subsample_train(train_dataset, SUBSAMPLE_CAP, SEED)
    train_dataset = train_dataset.shuffle(seed=training_args.seed)

    subsample_report = {
        label_encoder.classes_[c]: {"before": before_counts[c], "after": after_counts[c]}
        for c in before_counts
    }
    with open(REPORT_DIR / "w6_subsample_report.json", "w") as f:
        json.dump(subsample_report, f, indent=2)
    logger.warning(f"Subsample (cap={SUBSAMPLE_CAP}): {subsample_report}")

    train_labels = np.array(train_dataset["labels"])
    class_counts = np.bincount(train_labels, minlength=len(label_encoder.classes_))
    n_samples = class_counts.sum()
    n_classes = len(class_counts)
    class_weights = n_samples / (n_classes * np.maximum(class_counts, 1))
    class_weights = torch.tensor(class_weights, dtype=torch.float32)

    weights_report = {
        label_encoder.classes_[i]: {"count": int(class_counts[i]), "weight": float(class_weights[i])}
        for i in range(n_classes)
    }
    with open(REPORT_DIR / "w6_class_weights.json", "w") as f:
        json.dump(weights_report, f, indent=2)
    logger.warning(f"Class weights (post-subsample): {weights_report}")

    logger.warning("Tokenizing datasets")
    config = utils.update_config(model_args, data_args, training_args, config=None)
    training_tokenizer = netFoundTokenizer(config=config)
    from copy import deepcopy
    eval_config = deepcopy(config)
    eval_config.p = 0
    eval_tokenizer = netFoundTokenizer(config=eval_config)

    params = {"batched": True, "num_proc": utils.get_90_percent_cpu_count()}
    train_dataset = train_dataset.map(function=training_tokenizer, **params)
    val_dataset = val_dataset.map(function=eval_tokenizer, **params)

    data_collator = DataCollatorForFlowClassification(training_tokenizer.pad_token_id, torch.long)

    logger.warning(f"Loading pretrained weights from {model_args.model_name_or_path}")
    # protoEmbedding grew 18->133 rows for SCTP support (see SCTP_SUPPORT.md S5);
    # the pretrained checkpoint still has the old 18-row tensor for that one small
    # layer, so ignore_mismatched_sizes lets HF reinit just that mismatched tensor
    # while loading everything else (base_transformer, etc.) from pretrained as usual.
    model = netFoundFinetuningModel.from_pretrained(
        model_args.model_name_or_path, config=config, ignore_mismatched_sizes=True
    )
    model = utils.possibly_freeze(model, model_args)

    n_trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    n_total = sum(p.numel() for p in model.parameters())
    logger.warning(f"Trainable params: {n_trainable:,} / {n_total:,} ({100 * n_trainable / n_total:.2f}%)")
    with open(REPORT_DIR / "w6_frozen_param_summary.json", "w") as f:
        json.dump({"trainable_params": n_trainable, "total_params": n_total}, f, indent=2)

    compute_metrics = make_compute_metrics(list(label_encoder.classes_), REPORT_DIR / "w6_frozen_val_eval_last.json")

    utils.init_tbwriter(training_args.output_dir)

    trainer = WeightedTrainer(
        class_weights=class_weights,
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        tokenizer=eval_tokenizer,
        compute_metrics=compute_metrics,
        data_collator=data_collator,
    )

    train_result = trainer.train()
    trainer.save_model()
    trainer.save_state()

    with open(REPORT_DIR / "w6_frozen_train_metrics.json", "w") as f:
        json.dump(train_result.metrics, f, indent=2)

    logger.warning("*** Final eval on VAL (best checkpoint) ***")
    final_metrics = trainer.evaluate(eval_dataset=val_dataset)
    with open(REPORT_DIR / "w6_frozen_val_eval_final.json", "w") as f:
        json.dump(final_metrics, f, indent=2)

    log_history = trainer.state.log_history
    with open(REPORT_DIR / "w6_frozen_log_history.json", "w") as f:
        json.dump(log_history, f, indent=2)

    print("DONE")
    print(json.dumps(final_metrics, indent=2))


if __name__ == "__main__":
    main()
