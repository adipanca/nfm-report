#!/usr/bin/env python3
"""S5 gate: load netFound-base + run a forward pass on an SCTP-tokenized batch
(the single ngap_malformed flow) without any dimension/shape error. Also
checks the actual token IDs produced for the 32-bit SCTP fields (verification
tag, TSN) to confirm they land inside the existing vocab range (no resize).
"""
import sys
import pathlib

import numpy as np
import torch

NETFOUND_SRC = "/home/mobisec/nfm-fase8/netFound/src"
sys.path.insert(0, NETFOUND_SRC)
sys.path.insert(0, f"{NETFOUND_SRC}/modules")

from datasets import load_dataset
from transformers import TrainingArguments

from modules import utils
from modules.netFoundDataCollator import DataCollatorForFlowClassification
from modules.netFoundModels import netFoundFinetuningModel
from modules.netFoundTokenizer import netFoundTokenizer
from netFoundFinetuning import FineTuningDataTrainingArguments

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
SCTP_SHARD_DIR = REPO_ROOT / "data" / "test" / "sctp_dev" / "final" / "shards" / "ngap_malformed" / "T3-03_up"
CHECKPOINT_DIR = str(REPO_ROOT / "models" / "netFound-base")


def main():
    model_args = utils.ModelArguments(model_name_or_path=CHECKPOINT_DIR, size="base")
    data_args = FineTuningDataTrainingArguments(
        train_dir=str(SCTP_SHARD_DIR),
        num_labels=2,
        problem_type="single_label_classification",
    )
    training_args = TrainingArguments(output_dir="/tmp/s5_scratch", report_to=[])

    config = utils.update_config(model_args, data_args, training_args, config=None)
    print(f"vocab_size={config.vocab_size}  model_max_length={config.model_max_length}  "
          f"max_burst_length={config.max_burst_length}  max_bursts={config.max_bursts}")

    ds = load_dataset("arrow", data_dir=str(SCTP_SHARD_DIR), split="train")
    ds = ds.add_column("total_bursts", [0] * len(ds))
    ds = ds.add_column("labels_int", [0] * len(ds))  # dummy label for the forward-pass smoke test
    ds = ds.remove_columns(["labels"]).rename_column("labels_int", "labels")

    tokenizer = netFoundTokenizer(config=config)
    ds = ds.map(function=tokenizer, batched=True, load_from_cache_file=False)
    # the tokenizer adds new keys (input_ids, direction, ...) without dropping all
    # original pre-tokenization columns; the real Trainer prunes these via
    # _remove_unused_columns (netFoundTrainer._set_signature_columns_if_needed),
    # but this standalone smoke test has to select the same set manually.
    keep_cols = [
        "input_ids", "attention_mask", "direction", "iats", "bytes",
        "pkt_count", "protocol", "flow_duration", "dataset_burst_sizes",
        "total_bursts", "labels",
    ]
    ds = ds.select_columns(keep_cols)

    print(f"\nTokenized row count: {len(ds)}")
    row = ds[0]
    burst_tokens = row["input_ids"]
    flat_tokens = [t for burst in burst_tokens for t in burst]
    print(f"num bursts: {len(burst_tokens)}, total tokens: {len(flat_tokens)}")
    print(f"token id range in this flow: min={min(flat_tokens)} max={max(flat_tokens)} "
          f"(vocab_size={config.vocab_size})")
    out_of_range = [t for t in flat_tokens if t < 0 or t >= config.vocab_size]
    print(f"tokens OUT OF vocab range: {len(out_of_range)} (expect 0)")

    data_collator = DataCollatorForFlowClassification(tokenizer.pad_token_id, torch.long)
    batch = data_collator([ds[0]])
    print("\nBatch tensor shapes:")
    for k, v in batch.items():
        if torch.is_tensor(v):
            print(f"  {k}: {tuple(v.shape)} dtype={v.dtype}")

    print(f"\nLoading netFoundFinetuningModel from {CHECKPOINT_DIR} ...")
    # protoEmbedding grew from 18 to 133 rows (see netFoundEmbeddings.py) to fit the
    # SCTP=132 index -- shape no longer matches the pretrained checkpoint's saved
    # 18-row tensor for that one layer, so ignore_mismatched_sizes lets HF skip/
    # reinit just that tensor while loading everything else (base_transformer, etc.)
    # from the pretrained weights as usual.
    model = netFoundFinetuningModel.from_pretrained(
        CHECKPOINT_DIR, config=config, ignore_mismatched_sizes=True
    )
    model.eval()

    with torch.no_grad():
        outputs = model(**batch)

    print("\nForward pass SUCCEEDED.")
    print(f"logits shape: {tuple(outputs.logits.shape)}  (expect (1, num_labels=2))")
    print(f"logits: {outputs.logits}")


if __name__ == "__main__":
    main()
