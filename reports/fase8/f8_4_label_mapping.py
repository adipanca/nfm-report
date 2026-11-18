#!/usr/bin/env python3
"""F8.4 -- Final label mapping (class merge) and build the finetune-ready raw folder.

Merges sbi_http2_dos + sbi_attack_over_tls into one class `sbi_http2_attack`
(both are h2load HTTP/2-over-TLS traffic, near-identical; keeping them
separate makes per-class metrics misleading). All other classes are kept
as-is -- this now also includes the 6 new classes added in the W1 (INTERIM)
VM snapshot: bidding_down, gtpu_teid_injection, n6_exfiltration,
nas_replay_n1, nas_tamper_registration, sbi_nf_impersonation. The script
discovers label directories dynamically, so no code change was needed to
pick these up -- LABEL_MAP only overrides the two sbi_* classes; everything
else defaults to itself.

Result (original 17-class dataset): 16 final classes = benign + 15 attacks.
Result (W1 23-class VM snapshot):    22 final classes = benign + 21 attacks
(5 of which -- ngap_malformed, ngap_ngsetup_flood, bidding_down,
nas_replay_n1, nas_tamper_registration -- run over SCTP and will come out
NO_DATA at the F8.5/W4 preprocessing step until SCTP_SUPPORT (step b) lands;
this is expected and documented, not a bug).

Per user instruction: training uses the ORIGINAL (unmasked) PCAPs in
data/labeled/ -- netFound's tokenizer config (DefaultConfigNoTCPOptions.json)
never encodes raw IP address bits (see reports/fase8/f8_2_masking_notes.md),
and the constant-IP-masked copies in data/labeled_masked/ break forward/
backward packet-direction detection (is_internal_ip check in Tokenize.py),
so they are NOT used here -- they exist only as evidence for the F8.2 gate.

Output: data/finetune_raw/raw/<16 classes>/*.pcap (symlinks to the originals
in data/labeled/, to avoid duplicating ~313MB of PCAP data).
"""
import json
import pathlib

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
LABELED_DIR = REPO_ROOT / "data" / "labeled"
FINETUNE_RAW_DIR = REPO_ROOT / "data" / "finetune_raw" / "raw"
REPORT_DIR = REPO_ROOT / "reports" / "fase8"

# original_label -> final_label
LABEL_MAP = {
    "sbi_http2_dos": "sbi_http2_attack",
    "sbi_attack_over_tls": "sbi_http2_attack",
}


def main():
    label_dirs = sorted(
        d for d in LABELED_DIR.iterdir() if d.is_dir() and d.name != "__pycache__"
    )

    final_label_files = {}  # final_label -> list of (original_label, pcap_path)
    for label_dir in label_dirs:
        original_label = label_dir.name
        final_label = LABEL_MAP.get(original_label, original_label)
        pcaps = sorted(label_dir.glob("*.pcap"))
        final_label_files.setdefault(final_label, []).extend(
            (original_label, p) for p in pcaps
        )

    if FINETUNE_RAW_DIR.exists():
        import shutil

        shutil.rmtree(FINETUNE_RAW_DIR)
    FINETUNE_RAW_DIR.mkdir(parents=True, exist_ok=True)

    import shutil as _shutil

    summary = {}
    for final_label, items in sorted(final_label_files.items()):
        out_dir = FINETUNE_RAW_DIR / final_label
        out_dir.mkdir(parents=True, exist_ok=True)
        for original_label, pcap_path in items:
            # prefix with original_label to avoid filename collisions when merging
            # (e.g. sbi_http2_dos/T4-01_cp.pcap and sbi_attack_over_tls/T5-04_cp.pcap)
            # NOTE: real copies, not symlinks -- netFound's 2_pcap_splitting.sh uses
            # `find -type f`, which does NOT follow symlinks (type "l"), so symlinked
            # PCAPs would silently be skipped (zero files processed, no error).
            link_name = f"{original_label}__{pcap_path.name}"
            out_path = out_dir / link_name
            _shutil.copy2(pcap_path, out_path)
        summary[final_label] = {
            "n_pcap_files": len(items),
            "source_original_labels": sorted(set(o for o, _ in items)),
        }

    print(f"Final class count: {len(summary)}")
    for label, info in sorted(summary.items()):
        print(f"  {label:25s} n_pcap_files={info['n_pcap_files']:3d}  from={info['source_original_labels']}")

    out_json = REPORT_DIR / "label_map.json"
    with open(out_json, "w") as f:
        json.dump(
            {
                "label_map": LABEL_MAP,
                "final_classes": sorted(summary.keys()),
                "n_final_classes": len(summary),
                "per_class_pcap_counts": summary,
            },
            f,
            indent=2,
        )
    print(f"\nSaved -> {out_json}")
    print(f"Raw finetune folder built -> {FINETUNE_RAW_DIR}")


if __name__ == "__main__":
    main()
