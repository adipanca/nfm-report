# Diagnosis: Kenapa Kelas SCTP Cuma 1–16 Baris

**Kesimpulan: `menggabung per-asosiasi` (bukan filter min-paket).** Bukti kuat di bawah.
**Tidak ada data yang diubah/diregenerasi untuk diagnosis ini — murni pembacaan read-only.**

## Metodologi
Membaca field SCTP mentah (src_port, dst_port, verification_tag) langsung dari pcap asli
via scapy, dibandingkan dengan jumlah baris aktual yang dihasilkan pipeline kita.

## Bukti

| File | Total paket | Paket SCTP | **Asosiasi unik** (port+port+vtag) | Baris dihasilkan pipeline |
|---|---|---|---|---|
| `bidding_down/NB2-BID-e1_up.pcap` | 55 | 55 | **15** | 1 |
| `bidding_down/NB2-BID-e5_up.pcap` | 176 | 176 | **48** | 1 |
| `ngap_malformed/T3-03_up.pcap` | 402 | 402 | **114** | 1 |

Satu file episode berisi **puluhan hingga ratusan asosiasi SCTP berbeda** (port
berbeda-beda, verification tag berbeda-beda — persis seperti pola PFCP/UDP yang
memang memakai port efemeral baru per transaksi), tapi pipeline kita menghasilkan
**hanya 1 baris** per file, bukan 1 baris per asosiasi.

## Akar masalah: `PcapSplitter -m connection` (langkah S1/`2_pcap_splitting.sh`)

`PcapSplitter` adalah tool eksternal dari PcapPlusPlus (bukan kode kita). Untuk UDP,
ia memisahkan dengan benar berdasarkan 5-tuple penuh (termasuk port) — terbukti dari
`pfcp_session_delete`: 1 episode (~270 paket UDP dengan port berganti-ganti per
transaksi) menghasilkan **48-49 file connection-split terpisah** → 48-49 baris.

Untuk SCTP, karena **PcapPlusPlus tidak punya `SctpLayer` sama sekali** (sudah
ditemukan sejak S1/S2 — lihat `sctp_s4_s5_notes.md`), `PcapSplitter` tidak bisa
membaca port/verification-tag SCTP sama sekali. Ia jatuh ke pengelompokan yang lebih
kasar (kemungkinan hanya pasangan IP, mengabaikan port) — **menggabung SEMUA asosiasi
SCTP dalam satu file episode menjadi 1 "connection" tunggal**, menghasilkan tepat 1
baris terlepas dari berapa asosiasi sebenarnya ada di dalamnya.

**Bukan filter min-paket** — tidak ditemukan ambang batas jumlah-paket-minimum di mana
pun di pipeline (`1_filter.cpp`, `3_field_extraction.cpp`, `Tokenize.py`) yang akan
membuang flow kecil; bahkan `ngap_ngsetup_flood` (1 episode, kemungkinan sedikit
asosiasi) tetap menghasilkan 1 baris, bukan 0 — konsisten dengan "semua asosiasi
digabung jadi 1", bukan "yang kecil dibuang".

## Jawaban eksplisit: fix WSL atau regen VM?

**Fix di WSL (tanpa perlu regen VM).** Data yang SUDAH ADA di pcap sebenarnya kaya
(15–114 asosiasi/episode) — masalahnya murni di cara pipeline WSL kita *membaca*
granularitasnya, bukan kekurangan data dari VM. Memperbaiki ini di VM (menghasilkan
lebih banyak asosiasi) tidak akan membantu selama `PcapSplitter` tetap menggabungnya
jadi 1 di WSL.

**Perkiraan potensi setelah fix** (asumsi rata-rata asosiasi/episode mendekati sampel
di atas, akan divalidasi penuh saat implementasi):
- `ngap_malformed`: 5 episode × ~50-114 asosiasi ≈ **~250-500+ baris** (dari 5 sekarang)
- `bidding_down`: 16 episode × ~15-48 asosiasi ≈ **~250-750+ baris** (dari 16 sekarang)
- Kelas SCTP lain kemungkinan naik dengan proporsi serupa.

Ini kemungkinan **cukup** untuk masuk ambang training yang wajar, tanpa perlu
regenerasi data baru dari VM.

## Opsi perbaikan (BELUM diimplementasikan — menunggu konfirmasi Anda)
Karena `PcapSplitter` adalah binary eksternal (bukan source kita), opsi realistis:
1. **Tulis pre-splitter SCTP sendiri** (Python/scapy atau tambahan ke `3_field_extraction.cpp`)
   yang mengelompokkan paket SCTP per (src_ip,dst_ip,src_port,dst_port,verification_tag)
   SEBELUM/SEBAGAI PENGGANTI `PcapSplitter` untuk file bertipe SCTP — lalu setiap
   kelompok ditulis sebagai sub-pcap terpisah (mis. di `1_filter.sh`/`2_pcap_splitting.sh`
   atau langkah baru di antaranya), supaya `3_extract_fields.sh`/`Tokenize.py` menerima
   file per-asosiasi seperti halnya UDP.
2. Alternatif lebih berat: fork/patch `PcapSplitter` sendiri (kurang disarankan, repo
   eksternal, pemeliharaan lebih sulit).

**Rekomendasi: opsi 1.** Tidak menyentuh data VM, hanya menambah 1 langkah di pipeline
WSL. Menunggu konfirmasi Anda sebelum diimplementasikan.
