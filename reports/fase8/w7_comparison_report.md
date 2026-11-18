# W7 — Perbandingan Run INTERIM (benign bersih, 17 kelas efektif) vs Run 14-Kelas Lama

## Ringkasan setup
- **Lama (14-kelas):** benign tercemar/campuran 3 sesi lama (~117k train, tidak di-subsample), 14 kelas efektif (2 NGAP = NO_DATA).
- **Interim (sekarang):** benign baru bersih, 1 sesi besar (29.424 flow total), 22 kelas final, **17 efektif** (5 kelas SCTP = NO_DATA: ngap_malformed, ngap_ngsetup_flood, bidding_down, nas_replay_n1, nas_tamper_registration). Strategi imbalance: **subsample flood/benign ke cap 3000 flow di train + class-weighting balanced di atasnya** (lihat `w6_subsample_report.json` / `w6_class_weights.json`).
- ⚠️ **Caveat penting:** run interim juga mengubah strategi training (subsampling baru), jadi perbandingan bukan isolasi murni "benign bersih vs benign kotor" — ada 2 variabel berubah sekaligus. Angka di bawah tetap dilaporkan apa adanya, dengan catatan ini.

## Macro-F1 test set

| Regime | Lama (14-kelas) | Interim (17-kelas efektif) |
|---|---|---|
| Frozen | 0,6086 | **0,6924** |
| Unfrozen | 0,6577 | **0,7428** |

## (a) Apakah benign bersih memperbaiki flood & mengurangi kebocoran flood→benign?

**Kebocoran flood→benign (dari confusion matrix, jumlah baris flood yang diprediksi "benign"):**

| Regime | Lama (dari 7.796 baris flood test) | Interim (dari 7.796 baris flood test) |
|---|---|---|
| Frozen | 26 (0,33%) | 3 (0,04%) |
| Unfrozen | **772 (9,90%)** | **2 (0,03%)** |

→ **Ya, dramatis** — terutama di regime **unfrozen**, kebocoran flood→benign turun dari 9,9% ke hampir nol (772→2). Benign bersih (tanpa sisa sesi lama yang mungkin tercampur pola non-benign) menghilangkan jalur termudah model untuk "menyontek" ke kelas benign.

**F1 per-flood (Tier-0), unfrozen, lama → interim:**

| Kelas | Lama | Interim | Δ |
|---|---|---|---|
| dos_httpflood | 0,254 | 0,340 | +0,086 |
| dos_icmpflood | 0,349 | 0,342 | −0,007 |
| dos_slowrate | 0,475 | 0,417 | −0,058 |
| dos_synflood | 0,454 | 0,503 | +0,049 |
| dos_udpflood | 0,225 | 0,210 | −0,015 |
| **Rata-rata** | 0,351 | 0,362 | +0,011 |

→ **Tidak banyak membantu untuk sesama-flood.** Begitu kebocoran ke benign hilang, kesalahan flood **dialihkan ke flood lain** (lihat confusion matrix: `dos_slowrate` paling banyak salah ke `dos_icmpflood` — 1072/2406), bukan dihilangkan. Jadi: **benign bersih menyelesaikan masalah flood↔benign, tapi masalah flood↔flood (sesama Tier-0) tetap ada** — ini pola error yang berbeda dari yang coba diperbaiki.

## (b) Apakah 3 serangan baru non-SCTP terdeteksi?

| Kelas | F1 Frozen | F1 Unfrozen | Support (test) |
|---|---|---|---|
| sbi_nf_impersonation | 0,982 | 0,982 | 29 |
| gtpu_teid_injection | 0,970 | **1,000** | 17 |
| n6_exfiltration | 0,882 | 0,968 | 15 |

→ **Ya, ketiganya terdeteksi dengan sangat baik** (F1 0,88–1,00) di kedua regime, walau dengan support test sangat kecil (15–29 baris) — hasil ini menjanjikan tapi presisi estimasinya rendah karena sampel sedikit.

## (c) Apakah kelas 5G lama tetap ~1,0?

| Kelas | Lama (unfrozen) | Interim (unfrozen) |
|---|---|---|
| gtpu_malformed | 0,971 | **1,000** |
| pfcp_session_delete | 1,000 | 1,000 |
| pfcp_session_modify | 1,000 | 1,000 |
| sbi_http2_attack | 1,000 | 0,990 |
| tls_handshake_flood | 1,000 | 0,999 |
| pfcp_estab_flood | 0,671 | 0,535 ↓ |
| pfcp_rule_misconfig | **0,000** | 0,515 ↑ |

→ **Sebagian besar (5/7) tetap ~1,0.** Tapi pasangan `pfcp_estab_flood`/`pfcp_rule_misconfig` **bergeser**, bukan rusak: dulu model selalu menebak `estab_flood` (membuat `estab_flood` terlihat bagus di 0,671 dan `rule_misconfig` gagal total 0,000). Sekarang keduanya terbagi ~50/50 (lihat confusion matrix: estab_flood→{estab:27,misconfig:23}, misconfig→{estab:24,misconfig:25}) — model berhenti menebak satu kelas secara sistematis, tapi juga belum bisa membedakan keduanya. Ini **bukan regresi murni**, tapi pengungkapan bahwa kedua kelas ini secara representasi (level burst-token netFound) nyaris identik, terlepas dari regime training.

## File terkait
- `w6_train_frozen.py`, `w6_train_unfrozen.py` — skrip training dengan strategi subsample+weighting
- `w6_subsample_report.json`, `w6_class_weights.json` — detail strategi imbalance
- `w6_frozen_test_metrics.json`, `w6_unfrozen_test_metrics.json` — metrik lengkap + confusion matrix
- `w6_frozen_confusion_matrix.csv`, `w6_unfrozen_confusion_matrix.csv`
- `w1_class_distribution.csv` — distribusi file/paket per kelas pasca-extract VM
- `f8_6_split_distribution.csv` — distribusi train/val/test per kelas (termasuk NO_DATA SCTP)
