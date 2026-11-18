# FASE8.md — Fine-tuning netFound (multi-class) di WSL2 + GPU

Spesifikasi kerja untuk **Claude Code CLI yang dijalankan di WSL2** (bukan di VM VirtualBox). Menindaklanjuti dataset hasil `REVISI.md` (verdikt **GO-DENGAN-SYARAT**, target **MULTI-CLASS**). Tujuan: melatih netFound mengenali jenis serangan pada dataset 5G lab, lalu menguji generalisasinya.

- **Lingkungan:** WSL2 Ubuntu di Windows, GPU **RTX 4070 Ti SUPER (16 GB VRAM)**.
- **Kenapa bukan VirtualBox:** VirtualBox tak meneruskan GPU → tak ada CUDA. Fase 8 wajib di WSL2.
- **Syarat tersisa dari audit (GATE):** **IP masking** harus aktif, kalau tidak 9 kelas sumber-container tidak valid. Lihat F8.2 — ini gerbang: training hanya boleh lanjut bila gate lolos.

---

## Aturan untuk Claude Code (WAJIB)

- **Jangan bocorkan data uji.** Split **per-episode / per-waktu**. Satu flow/episode tak boleh ada di dua sisi (train/val/test). Ingat temuan audit: 26.814 5-tuple muncul di benign & serangan karena port efemeral dipakai ulang — karena itu **jangan split per-paket**.
- **Reprodusibel.** Fix seed (python/numpy/torch), simpan semua config & metrik ke `reports/fase8/`, simpan checkpoint.
- **Jujur soal batas.** Catat keterbatasan apa adanya (lihat F8.9). Jangan melaporkan angka test sebelum gate F8.2 lolos.
- **Keamanan:** gunakan token GitHub yang **baru** (yang lama sudah/rotasi). Jangan tulis token/rahasia ke repo atau log.
- **Jaringan boleh** di WSL2 (unduh netFound, pip, 5G-NIDD) — beda dengan VM yang terisolasi.
- `set -euo pipefail` di skrip; checkpoint & dataset besar masuk `.gitignore`.
- Keluaran akhir: **`reports/fase8/FASE8_REPORT.md`**.

---

## F8.0 — Verifikasi lingkungan WSL2 + GPU
- Pastikan di dalam WSL2 (`uname -a` mengandung `microsoft`).
- `nvidia-smi` menampilkan RTX 4070 Ti SUPER (driver dari Windows; tak perlu install driver di WSL2).
- Buat virtualenv/conda; install **PyTorch build CUDA** yang cocok dengan driver.
- **GATE lingkungan — LULUS jika:** skrip python mencetak `torch.cuda.is_available() == True` dan nama GPU benar. Jika `False`, hentikan & laporkan (biasanya driver Windows belum mendukung WSL-CUDA atau PyTorch versi CPU).

## F8.1 — Ambil netFound
- Clone repo netFound (`github.com/SNL-UCSB/netFound`) dan/atau checkpoint `snlucsb/netFound-640M-base` (HF). **Verifikasi** instruksi terkini di README repo — API/skrip bisa berubah sejak dokumen ini.
- Install dependensinya. Jika ada ekstensi yang perlu dikompilasi (tokenizer), siapkan toolchain yang dibutuhkan.
- **LULUS jika:** contoh preprocessing bawaan netFound jalan pada 1 PCAP kecil tanpa error.

## F8.2 — GATE: IP masking (syarat E) — WAJIB sebelum training
Risiko: 9 kelas sumber-container (PFCP/NGAP/SBI/TLS dari IP `172.22/23.0.50`) 100% bisa ditebak dari IP. Jika model melihat IP, ia menghafal, bukan belajar pola.
- Periksa preprocessing/tokenizer netFound: apakah alamat **IP (dan MAC/port identik-per-host)** di-mask/di-nol-kan sebelum tokenisasi? Catat nama file & fungsinya di laporan.
- Jika **tidak** ada masking: terapkan salah satu, lalu dokumentasikan:
  - aktifkan opsi anonymisasi netFound bila tersedia; atau
  - pra-proses PCAP: tulis ulang semua IP ke nilai konstan/pool tunggal (mis. `tcprewrite`/`bittwiste`/scapy) sehingga IP tak membawa sinyal kelas — **grouping flow tetap** memakai 5-tuple asli sebelum penulisan ulang.
- **Uji gate (kunci):** latih **classifier IP-only** (fitur = hanya IP src/dst, sesudah masking) pada data training. Akurasinya **harus turun ke sekitar tebak-acak** (mis. ≤ proporsi kelas mayoritas + margin kecil). Bandingkan dengan sebelum masking (~100% untuk kelas container).
- **GATE LULUS jika:** masking terpasang **dan** classifier IP-only tak lagi bisa memisahkan kelas container. **Jika gagal, JANGAN lanjut ke F8.7** — perbaiki dulu.

## F8.3 — Impor & verifikasi data
- Impor `data/labeled/` dari VM (mis. `scp -r ubuntuserver26@192.168.56.50:~/nfm-testbed-5g/data/labeled ~/nfm-fase8/data/`). Impor juga `data/ground_truth.csv`.
- Verifikasi cepat: jumlah file & kelas cocok dengan `AUDIT_REPORT_v2.md` (17 kelas; nanti jadi 16 setelah F8.4).
- **LULUS jika:** inventaris cocok; tiap kelas kecil tetap ≥120 flow seperti di audit v2.

## F8.4 — Pemetaan label final (penggabungan kelas)
- **Gabungkan** `sbi_http2_dos` + `sbi_attack_over_tls` → satu kelas `sbi_http2_attack` (keduanya h2load HTTP/2-over-TLS, hampir identik; memisahkannya membuat metrik menyesatkan).
- Pertahankan 4 kelas PFCP terpisah (delete/modify/estab/misconfig) — jenis serangan berbeda, masing-masing ≥147 flow.
- Hasil: **16 kelas** = `benign` + 15 serangan. Tulis pemetaan ke `reports/fase8/label_map.json`.
- **LULUS jika:** daftar 16 kelas final tercatat, jumlah flow per kelas final dilaporkan.

## F8.5 — Preprocessing netFound (PCAP → token)
- Jalankan pipeline netFound: pecah PCAP jadi flow/burst, tokenisasi protocol-aware, dengan **masking IP aktif** (F8.2).
- **Catat batasan tokenizer:** netFound asli untuk IP/TCP/UDP umum. Tier 0–1 (N6, GTP-U membungkus IP) terpetakan wajar; **Tier 2–4 (PFCP/NGAP/SBI)** kemungkinan diperlakukan sebagai payload generik → tulis sebagai keterbatasan di laporan riset (bukan kegagalan).
- **LULUS jika:** seluruh kelas tertokenisasi tanpa error; simpan jumlah sampel (flow/burst) per kelas sesudah preprocessing.

## F8.6 — Split train/val/test (anti-bocor)
- Split **per-episode**, stratified per kelas: contoh 70/15/15. Pastikan **semua flow dari satu episode** (satu window ground-truth) masuk ke **satu** split saja.
- Idealnya **berbasis waktu**: episode yang lebih awal → train, yang lebih akhir → test (menguji generalisasi temporal). Minimal, stratified per-episode acak dengan seed tetap.
- Tangani imbalance (benign 123k vs kelas kecil ~150, rasio ~841×): pakai **class weighting** pada loss atau **balanced sampling**; untuk benign boleh **subsample** di training (pertahankan semua kelas kecil).
- **LULUS jika:** tak ada episode yang menyeberang split (buktikan dengan cek id episode); distribusi kelas tiap split dilaporkan.

## F8.7 — Fine-tuning (disetel untuk 16 GB VRAM)
Jalankan **dua regime** (sekaligus jadi bagian hasil):
1. **Frozen** (linear-probe): bekukan encoder, latih head klasifikasi. Ringan, cepat, baseline — verifikasi pipeline dulu di sini.
2. **Unfrozen** (full fine-tune): buka encoder.
- Pengaturan awal untuk 16 GB: **BF16** (4070 mendukung), batch kecil (mulai 8–16) + **gradient accumulation** ke effective batch 32–64, aktifkan **gradient checkpointing** bila perlu.
- **Playbook OOM** (urut): turunkan batch → naikkan grad-accum → aktifkan checkpointing → kurangi panjang urச token/flow → pakai mode frozen. Pakai varian `base`, bukan `large`.
- Simpan checkpoint terbaik (berdasar **macro-F1 val**, bukan akurasi — karena imbalance).
- **LULUS jika:** kedua regime selesai, kurva loss/val tersimpan, checkpoint terbaik ada.

## F8.8 — Evaluasi internal (test set)
- Laporkan: **macro-F1** (utama), F1/precision/recall **per kelas**, dan **confusion matrix**.
- Perhatikan kelas kecil & pasangan yang mudah tertukar (mis. antar-PFCP). Confusion matrix wajib, bukan hanya akurasi agregat.
- **LULUS jika:** metrik lengkap per kelas + confusion matrix tersimpan untuk kedua regime (frozen/unfrozen).

## F8.9 — GATE generalisasi: validasi silang 5G-NIDD
Test set internal ber-IP sama dengan training → bukan bukti generalisasi. Uji di **5G-NIDD** (IP, tool, jaringan berbeda).
- Unduh 5G-NIDD (PCAP), proses dengan pipeline yang sama (masking IP aktif).
- **Petakan kelas yang beririsan saja:** 5G-NIDD punya DoS (SYN/UDP/ICMP/HTTP/Slow-rate) & port scan → cocok dengan kelas **Tier 0** Anda. Uji model pada kelas-kelas ini (zero-shot / few-shot).
- **Batas penting (tulis di laporan):** 5G-NIDD **tidak punya** serangan PFCP/NGAP/SBI. Jadi 9 kelas 5G-spesifik **tak bisa** divalidasi silang di sini — klaim generalisasinya lebih lemah dan bersandar pada (a) IP masking + (b) split per-waktu episode. Nyatakan ini terang-terangan.
- **LULUS jika:** hasil lintas-dataset untuk kelas Tier 0 dilaporkan; batasan untuk kelas 5G-spesifik dinyatakan.

## F8.10 — Baseline pembanding (agar kontribusi NFM terukur)
Supaya bisa menunjukkan NFM memang menambah nilai, bandingkan dengan:
1. **Baseline IP-only** (dari F8.2) — harus ~tebak-acak setelah masking (membuktikan model tak sekadar menghafal IP).
2. **ML klasik** (mis. RandomForest) pada fitur statistik flow (gaya CICFlowMeter) — baseline umum di literatur NIDS.
- Laporkan tabel: netFound (frozen), netFound (unfrozen), RandomForest, IP-only — pada test internal & 5G-NIDD.
- **LULUS jika:** tabel perbandingan lengkap.

## F8.11 — Laporan
Tulis **`reports/fase8/FASE8_REPORT.md`**:
1. Lingkungan (GPU, versi, seed) + status **gate F8.2** (masking: metode + hasil IP-only sebelum/sesudah).
2. Daftar 16 kelas final + jumlah sampel per split.
3. Hasil: tabel metrik (per kelas + macro-F1) frozen vs unfrozen; confusion matrix.
4. Hasil 5G-NIDD (kelas Tier 0) + pernyataan batas kelas 5G-spesifik.
5. Tabel baseline (F8.10).
6. **Keterbatasan** (untuk laporan riset): episode dari tool/param serupa (risiko overfit, dikurangi bukan dihilang); tokenizer belum protocol-aware untuk PFCP/NGAP/SBI; benign SBI-over-TLS tipis (~11 flow) → hati-hati menafsir kelas TLS.
7. Kesimpulan + saran kerja lanjut.

---

## Cara pakai (di WSL2)
```bash
# di terminal WSL2
cd ~/nfm-fase8      # folder kerja Fase 8 (pisah dari VM)
claude
# "Baca FASE8.md. Jalankan F8.0 dulu dan tunjukkan hasil gate GPU sebelum lanjut."
```
Kerjakan **bertahap**, berhenti di tiap **GATE** (F8.0, F8.2, F8.9) untuk konfirmasi. Setelah selesai, tempelkan `reports/fase8/FASE8_REPORT.md` untuk ditinjau.

## Catatan
- Pre-training dari nol **tidak** dilakukan (pakai checkpoint pretrained). GPU 16 GB cukup untuk fine-tuning, bukan pre-training.
- Data lab & generate serangan tetap di VM; WSL2 hanya untuk fine-tuning & evaluasi.
- Pindahkan checkpoint/hasil penting keluar bila ruang WSL2 menipis.