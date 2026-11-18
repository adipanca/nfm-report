# INGEST_TRAIN_WSL.md — Baca Data Terbaru dari VM & Latih Ulang (dikerjakan DI WSL2)

Spesifikasi kerja untuk **Claude Code CLI yang dijalankan DI WSL2** (`~/nfm-fase8`), dengan GPU. Tujuan: **menarik data terbaru dari VM**, lalu menjalankan ulang pipeline netFound (preprocess → split → train → evaluasi) pada dataset yang sudah membesar dengan serangan baru.

> Jalankan dokumen ini **setelah** VM menyelesaikan `SERANGAN_BARU_VM.md` dan berkata "Data VM siap". VM = pabrik data; WSL = pelatihan. Ini bagian WSL.

> **Dokumen ini dijalankan DUA KALI:**
> 1. **SEKARANG = run INTERIM** — tanpa patch SCTP. 5 kelas SCTP (2 NGAP + `bidding_down`, `nas_replay_n1`, `nas_tamper_registration`) sengaja dilewati (`NO_DATA`). Tujuan interim: **menguji apakah benign bersih memperbaiki kebingungan flood↔benign**, dan apakah 3 serangan baru non-SCTP (`sbi_nf_impersonation`, `gtpu_teid_injection`, `n6_exfiltration`) terdeteksi. ~18 kelas efektif.
> 2. **NANTI = run PENUH** — setelah `SCTP_SUPPORT.md` (langkah b) selesai, jalankan ulang untuk 23 kelas lengkap termasuk SCTP.

---

## Aturan (WAJIB)
- `set -euo pipefail`. Reprodusibel (seed tetap). Checkpoint/dataset besar di-gitignore.
- Jangan bangkitkan serangan di sini — itu tugas VM. Dokumen ini hanya konsumsi + latih.
- Split tetap **per-episode/per-waktu** (jangan per-paket) — aturan anti-bocor sama seperti F8.6.

---

## W1 — GATE: Tarik data terbaru dari VM (handoff)
Ini langkah yang membuat "WSL membaca data terbaru dari VM" eksplisit dan tak membingungkan.
```bash
cd ~/nfm-fase8
# backup data lama dulu
mv data/labeled data/labeled_prev_$(date +%Y%m%d) 2>/dev/null || true
# tarik snapshot dari VM (coba langsung; jika gagal, lewat Windows /mnt/c)
scp ubuntuserver26@192.168.56.50:/tmp/labeled_latest.tgz ~/nfm-fase8/ \
  || cp /mnt/c/Users/<Anda>/Downloads/labeled_latest.tgz ~/nfm-fase8/
tar xzf labeled_latest.tgz        # mengisi data/labeled + data/ground_truth.csv terbaru
```
**LULUS jika:** `data/labeled/` berisi kelas lama **+** kelas baru dari VM; `ls data/labeled | wc -l` bertambah; `ground_truth.csv` memuat episode baru. Bandingkan daftar kelas dengan yang diharapkan dari `SERANGAN_BARU_VM.md`.

## W2 — GATE opsional: dukungan SCTP (untuk kelas Grup 2)
Kelas dari Grup 2 VM (`nas_tamper_registration`, `nas_replay_n1`, `bidding_down`) berjalan di **SCTP** dan **tidak akan tertokenisasi** tanpa patch SCTP (langkah **b**).
- Jika **(b) SCTP_SUPPORT sudah diterapkan** di netFound → lanjut, kelas SCTP akan dapat baris.
- Jika **belum** → lanjutkan saja; kelas SCTP akan muncul `NO_DATA` (seperti NGAP sekarang) dan **dikecualikan** dari training, didokumentasikan. Jangan blokir pipeline karena ini.

## W3 — Pemetaan label final
Perbarui `f8_4_label_mapping.py`: tambahkan kelas baru ke daftar final (dan pertimbangkan penggabungan bila perlu). Hasilkan `label_map.json` baru dengan jumlah kelas final yang diperbarui.
**LULUS jika:** daftar kelas final + jumlah flow per kelas tercatat.

## W4 — Preprocess semua (F8.5)
Jalankan `preprocess_data.py` (action finetune, config `DefaultConfigNoTCPOptions.json`) pada **PCAP asli** `data/labeled` (bukan ter-mask). Catat kelas yang menghasilkan 0 baris (mis. SCTP bila (b) belum ada).
**LULUS jika:** semua kelas non-SCTP tertokenisasi; jumlah baris per kelas dilaporkan.

## W5 — Split anti-bocor (F8.6)
Jalankan `f8_6_split.py` (per-episode untuk kelas ≥3 episode; fallback flow-random hanya untuk <3). Karena kelas baru dibuat ≥100 episode di VM, semuanya harus masuk jalur **per-episode**.
**LULUS jika:** tak ada episode menyeberang split; distribusi per-kelas dilaporkan; kelas baru pakai `episode_time_ordered`.

## W6 — Training (F8.7) + Evaluasi (F8.8)
Jalankan **dua regime** seperti sebelumnya:
- Frozen (linear-probe) sebagai baseline cepat.
- Unfrozen (`freeze_base=False`, LR 2e-5, 5–10 epoch, early-stop by val macro_f1, bf16, batch 16, grad-accum 2; OOM → batch 8 / accum 4).
Keduanya pakai class-weighting balanced. Lalu F8.8 pada test.

> **Catatan imbalance:** flood Tier-0 masih besar (5–16 ribu flow) vs kelas 5G (~150–220). Agar kelas 5G tak tenggelam, **subsample kelas flood** saat training (mis. batasi tiap flood ke beberapa ribu flow) atau pertahankan class-weighting kuat. Laporkan strategi yang dipakai.

**LULUS jika:** tabel **frozen vs unfrozen** (macro-F1, per-kelas P/R/F1, confusion matrix) untuk dataset yang sudah membesar.

## W7 — Bandingkan & jawab pertanyaan interim
Hasilkan perbandingan terhadap **hasil 14-kelas lama** (benign tercemar), dan jawab eksplisit:
1. **Apakah benign bersih memperbaiki flood?** Bandingkan F1 per-flood (`dos_*`) + kebocoran flood→benign di confusion matrix, interim (benign bersih) vs lama (benign tercemar). Ini pertanyaan utama run interim.
2. **Apakah 3 serangan baru non-SCTP terdeteksi?** F1 `sbi_nf_impersonation`, `gtpu_teid_injection`, `n6_exfiltration`.
3. Apakah menambah kelas mengganggu kelas 5G lama (PFCP/SBI/TLS) yang sebelumnya ~1,0?
Simpan ke `reports/fase8/` dan tempelkan untuk ditinjau.

---

## Ringkas alur
```
VM selesai (SERANGAN_BARU_VM.md) → snapshot /tmp/labeled_latest.tgz
        │  (scp / via Windows)
        ▼
WSL: W1 tarik & ganti data  →  W2 cek SCTP  →  W3 label map  →
     W4 preprocess  →  W5 split  →  W6 train+eval  →  W7 banding
```
Satu putaran training besar untuk semua serangan baru sekaligus — bukan per-serangan.