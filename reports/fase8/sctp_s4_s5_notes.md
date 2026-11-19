# SCTP_SUPPORT.md — Catatan S4 & S5 (branch `feat/sctp-support`)

## S4 — Arah paket (direction): LULUS

Setelah perbaikan `internalIPs` (S3) ke subnet lab asli (`10.45.0.0/16`, `172.22-24.0.0/24`,
sebelumnya nilai default placeholder `127.0.0.0/8` yang tak pernah cocok):

| Kelas | Protokol | Forward + Backward? |
|---|---|---|
| ngap_malformed (1 flow) | SCTP | **Ya** — `[False, True, True, False, ...]` |
| sbi_http2_attack (40 flow) | TCP | Ya, semua 40 flow |
| pfcp_session_delete (1 flow) | UDP | Hanya forward |

`pfcp_session_delete` hanya forward **bukan bug** — diverifikasi langsung dari pcap mentah
via scapy: capture ini genuinely cuma 1 arah (`{('172.23.0.50','172.23.0.30')}`, tak ada
paket balik sama sekali di file aslinya — sesuai konvensi capture per-interface `_up` di
testbed). SCTP dan TCP sama-sama menunjukkan kedua arah ada; tidak ada regresi.

## S5 — GATE embedding/vocab: LULUS

### Strategi vocab (jawaban eksplisit)

**Vocab token utama (IPFields/TCPFields/SCTPFields/Payload): TIDAK perlu resize.**
Skema tokenizer netFound adalah **value-based**, bukan simbolik per-field: setiap nilai
field diubah ke bytes mentah lalu dipotong jadi token 16-bit (`TOKEN_BYTES_LENGTH=2`),
nilai token = integer 16-bit itu sendiri (0-65535), dipakai langsung sebagai index ke
*embedding table* yang sama untuk SEMUA field. `vocab_size=65600` checkpoint sudah
mencakup seluruh rentang ini. Field SCTP 32-bit (verification tag, TSN, PPID) pakai
`numberTokens=2` — **mekanisme identik** dengan `TCP_seq`/`TCP_ackn` yang juga 32-bit.
Diverifikasi empiris: token ID pada flow SCTP berkisar 1–65537, nol yang di luar
`vocab_size` (lihat `s5_forward_pass_log.txt`).

**TAPI ada 2 titik yang BUTUH perubahan** (bukan di vocab token utama, tapi di 2 tabel
kecil lain yang di-index pakai nomor protokol mentah):

1. **`protoEmbedding`** (`netFoundEmbeddings.py`) — *embedding* kecil terpisah yang
   di-index langsung pakai nomor IP protocol (6/17/1), ukuran tabel cuma 18 baris
   (`HIGHEST_TRANSPORT_LAYER_PROTOCOL=18`). SCTP=132 meluber. **Diperbesar ke 133
   baris.** Saat memuat checkpoint pretrained, baris 0-17 (TCP/UDP/ICMP) tetap
   dimuat dari bobot pretrained via `ignore_mismatched_sizes=True`; baris 18-132
   (termasuk 132=SCTP) diinisialisasi acak — **cold-start murni**, dipelajari saat
   fine-tuning nanti.
2. **`dataset_burst_sizes`** (`netFoundTokenizer.py`) — bug laten *protocol-agnostic*
   (bukan spesifik-SCTP): dihitung dari token SEBELUM truncation, sedangkan
   `input_ids` aktual sudah di-truncate ke `max_burst_length`(73). Untuk TCP/UDP/ICMP
   kebetulan selalu pas (budget 6×12+1=73 token memang dirancang pas untuk TCP), tapi
   SCTP (6×16+1=97 token/burst penuh) melebihi 73, membuat posisi-embedding index
   out-of-range. **Diperbaiki dengan clamp** `min(len(burst), max_burst_length-1)` —
   ini *no-op* untuk TCP/UDP/ICMP (makanya baru kelihatan sekarang, bukan regresi
   baru) tapi krusial untuk SCTP dan protokol berat lain di masa depan.

### Bukti forward-pass sukses

```
SCTP (ngap_malformed, 1 flow):
  input_ids shape: (1, 876)   # 12 burst x 73 token, sama seperti TCP/UDP
  Forward pass SUCCEEDED.
  logits shape: (1, 2)
  logits: tensor([[ 0.0594, -0.0951]])

TCP (sbi_http2_attack, regresi check):
  input_ids shape: (1, 876)
  Forward pass SUCCEEDED.
  logits shape: (1, 2)
  logits: tensor([[-0.0243,  0.0076]])
```

Checkpoint `netFound-base` dimuat sukses untuk kedua kasus; hanya `protoEmbedding`
(1 layer kecil, sudah dijelaskan di atas) yang mismatch shape dan di-reinit sebagian —
seluruh bagian lain (base_transformer 12 layer, dsb.) tetap dari bobot pretrained.

## File yang diubah sampai S5
1. `pre_process_src/packets_processing_src/1_filter/1_filter.cpp` — deteksi SCTP (ip.protocol==132)
2. `pre_process_src/packets_processing_src/3_field_extraction/3_field_extraction.cpp` — ekstraksi field SCTP
3. `pre_process_src/Tokenize.py` — `Protocol.SCTP`, kolom SCTP, **fix `dataset_burst_sizes` clamp**
4. `configs/DefaultConfigNoTCPOptions.json` + `DefaultConfigWithTCPOptions.json` — `SCTPFields`, `internalIPs` diperbaiki
5. `src/modules/netFoundEmbeddings.py` — `HIGHEST_TRANSPORT_LAYER_PROTOCOL` 18→133
