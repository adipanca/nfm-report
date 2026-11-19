# SCTP_SUPPORT.md — Menambah Dukungan SCTP ke netFound (langkah b, dikerjakan DI WSL2)

Spesifikasi kerja untuk **Claude Code CLI di WSL2** (`~/nfm-fase8/netFound`). Tujuan: memperluas pipeline netFound agar memproses trafik **SCTP**, sehingga **5 kelas** yang sekarang `NO_DATA` bisa ditokenisasi: `ngap_malformed`, `ngap_ngsetup_flood`, `bidding_down`, `nas_replay_n1`, `nas_tamper_registration`.

> **Kontribusi inti penelitian** (sesuai permintaan profesor): mengidentifikasi + menambal celah NFM pada signaling 5G berbasis SCTP. Sekaligus membuka beberapa item guideline (Core-6/7/20 + registrasi NAS) — lihat `GUIDELINE_GAP_ANALYSIS.md`.

---

## Aturan (WAJIB)
- **Branch terpisah** (mis. `feat/sctp-support`). Jangan rusak jalur TCP/UDP/ICMP yang sudah jalan — verifikasi regресi di setiap gate.
- **Uji bertahap pada SATU pcap NGAP** dulu (`data/labeled/ngap_malformed/*.pcap`) sebelum menjalankan ke semua kelas.
- `set -euo pipefail`. Dokumentasikan tiap perubahan file + alasannya.
- **Jujur soal batas:** model pra-latih tak pernah melihat SCTP → representasinya *cold-start*. "Bisa memproses SCTP" ≠ "akurat mendeteksi NGAP". Keduanya dilaporkan terpisah (lihat S7).

---

## Pahami dulu: di mana SCTP "hilang"
Dari diagnosis sebelumnya (`f8_6_ngap_sctp_limitation.md`): `3_field_extraction.cpp` tak mengenali IP proto 132 → folder `extracted/` kosong → `Tokenize.py` (hanya punya cabang TCP/UDP/ICMP) skip diam-diam → 0 baris. Jadi perbaikan ada di **dua tempat**: ekstraktor C++ dan tokenizer Python, plus config.

---

## S0 — Baseline & branch
- Buat branch `feat/sctp-support`.
- Rekam perilaku saat ini: jalankan preprocessing pada 1 pcap NGAP → konfirmasi **0 baris** (baseline "sebelum").
- Verifikasi 1 pcap TCP (mis. `sbi_http2_attack`) dan 1 UDP (mis. `pfcp_session_delete`) **tetap** menghasilkan baris (baseline regresi).
- **LULUS jika:** baseline terekam (NGAP=0, TCP/UDP>0).

## S1 — Flow splitting SCTP (`2_pcap_splitting.sh`)
- Pastikan tahap split **tidak membuang** paket SCTP. PcapPlusPlus bisa mem-parse SCTP; cek apakah splitter mengelompokkan paket SCTP ke flow berdasar 5-tuple (IP src/dst + SCTP src/dst port).
- Jika splitter memfilter hanya TCP/UDP, tambahkan SCTP.
- **LULUS jika:** 1 pcap NGAP → folder `split/` berisi file non-kosong dengan paket SCTP.

## S2 — Ekstraksi field SCTP (`3_field_extraction.cpp`)
- Tambahkan cabang untuk **IP proto = 132 (SCTP)**. SCTP berbasis *chunk*; ekstrak minimal:
  - **Common header:** source port, dest port, verification tag.
  - **Per-chunk:** chunk type, chunk flags, chunk length; untuk **DATA chunk**: TSN, stream identifier, stream sequence number, PPID.
- Payload setelah DATA chunk = NGAP (ASN.1 PER) → diperlakukan sebagai **payload generik** (seperti PFCP/SBI sekarang). Jangan parse ASN.1 — cukup byte payload.
- **Prinsip minimalis:** ekstrak field secukupnya. Makin sedikit field baru, makin ringan beban cold-start (S5).
- **LULUS jika:** 1 pcap NGAP → folder `extracted/` non-kosong, kolom field SCTP terisi (cek beberapa baris).

## S3 — Config + tokenizer (`DefaultConfigNoTCPOptions.json`, `Tokenize.py`)
- Tambah daftar **`SCTPFields`** di config (analog `TCPFields`/`UDPFields`), berisi field dari S2.
- Di `Tokenize.py`, tambah cabang **`Protocol.SCTP`** (IP proto 132) yang menokenisasi `IPFields + SCTPFields + Payload`.
- **LULUS jika:** 1 pcap NGAP → shard `.arrow` dengan **baris > 0**. Ini gerbang kunci — SCTP akhirnya tertokenisasi.

## S4 — Arah paket (direction)
- `split_bursts_on_dir` memakai IP vs `internalIPs` → bebas-transport, harusnya jalan untuk SCTP. Verifikasi kolom `directions` terisi benar untuk flow SCTP.
- Pastikan `internalIPs` dikonfigurasi **per-subnet** (mis. UE 10.45.0.0/16, core 172.22/23.0.0/24) agar arah benar.
- **LULUS jika:** `directions` SCTP terisi (ada forward & backward).

## S5 — GATE: Vocabulary / embedding (cold-start)
- **Cek dulu** skema tokenisasi netFound: apakah nilai field dipetakan ke **vocab yang sudah ada** (berbasis nilai/byte, ukuran tetap) atau butuh **token ID baru**?
  - Jika field SCTP masuk ke rentang vocab yang ada → **tak perlu bedah embedding**; model hanya melihat pola baru yang dipelajari saat fine-tune (cold-start distribusional, bukan token baru).
  - Jika butuh ID baru → perluas embedding table (resize) + inisialisasi; embedding baru dipelajari saat fine-tune.
- Uji: muat `netFound-base` + forward-pass pada data SCTP-tertokenisasi tanpa error (dimensi cocok).
- **LULUS jika:** model memuat + forward-pass sukses pada batch SCTP; strategi vocab terdokumentasi.

## S6 — Validasi ujung-ke-ujung
- Jalankan preprocessing pada **semua** data (incl. 5 kelas SCTP).
- Konfirmasi regresi: kelas TCP/UDP/ICMP lama **tetap** menghasilkan baris seperti sebelum (bandingkan jumlah baris).
- **LULUS jika:** 5 kelas SCTP kini **> 0 baris**; kelas lama tak berubah.

## S7 — Dokumentasi jujur (untuk laporan)
Tulis `reports/fase8/sctp_support_notes.md`:
- File yang diubah + apa yang ditambahkan (schema token SCTP).
- **Batas cold-start:** model pra-latih tak melihat SCTP; dengan hanya ~600–1000 flow NGAP + kelas NAS/bidding kecil, representasi SCTP dipelajari dari sedikit data → akurasi mungkin rendah. **Bedakan "bisa diproses" dari "akurat".**
- **Tanpa validasi eksternal:** 5G-NIDD tak punya NGAP/NAS → kelas SCTP hanya proof-of-concept di testbed.

---

## Setelah SCTP selesai → run PENUH
Jalankan ulang `INGEST_TRAIN_WSL.md` (kini W2 aktif: SCTP dapat baris) untuk **23 kelas lengkap**. Bandingkan dengan interim 17-kelas: apakah 5 kelas SCTP terdeteksi, dan seberapa akurat (dengan caveat cold-start).

## Cara pakai
```bash
cd ~/nfm-fase8/netFound
claude
# "Baca SCTP_SUPPORT.md. Kerjakan S0–S6 bertahap, berhenti di tiap GATE (S3, S5) untuk konfirmasi. Uji pada 1 pcap NGAP dulu sebelum semua kelas."
```
Berhenti di **S3** (SCTP akhirnya >0 baris) dan **S5** (embedding/vocab) untuk konfirmasi — dua titik paling berisiko.

---

## HASIL FINAL — pc40 (payload cap SCTP 40B)

**Status: STUDI SELESAI.** Setelah S0–S7 (SCTP berhasil diproses tapi 3 kelas NAS
saling tertukar — lihat `reports/fase8/nas_triplet_investigation.md`), eksperimen
lanjutan `pc40` (cap payload SCTP 12→40 byte + `max_burst_length` 73→109 +
`strip_payload` selektif per-protokol) **ditetapkan sebagai hasil final proyek
SCTP support**, menggantikan run 21-kelas sebelumnya sebagai checkpoint utama.

- **Checkpoint utama**: `models/w6_finetune_unfrozen_pc40` (regime unfrozen/full
  fine-tune — regime frozen tidak relevan untuk fix ini, lihat penjelasan di
  laporan).
- **Laporan utama**: `reports/fase8/w7_comparison_report_pc40.md`.
- **Hasil**: macro-F1 test set 0,7126 → **0,8322**; ketiga kelas NAS
  (`bidding_down`, `nas_replay_n1`, `nas_tamper_registration`) dari F1 0,000–0,317
  menjadi **1,000** masing-masing, nol saling tertukar; 16 kelas non-SCTP tetap
  ≥0,90 tanpa regresi dari cold-start global (`protoEmbedding` + `position_embeddings`
  resize).
- **Kode**: di-commit ke branch `feat/sctp-support` (netFound repo), di-push ke
  `github.com/adipanca/netFound.git`.
- Run baseline sebelumnya (`models/w6_finetune_*` tanpa suffix, tanpa payload SCTP
  diperluas) **tetap disimpan** sebagai referensi historis, tidak dihapus.