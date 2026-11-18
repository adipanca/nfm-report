# Temuan Penting — Kelas NGAP Tidak Bisa Diproses netFound (SCTP)

## Masalah

`ngap_malformed` dan `ngap_ngsetup_flood` menghasilkan **0 baris** (0 flow/burst) setelah
preprocessing F8.5, pada SEMUA episode (5 + 1 episode). Ini bukan bug di skrip kita —
diverifikasi langsung di level paket:

```
$ scapy: baca data/labeled/ngap_malformed/T3-03_up.pcap
IP proto field counts (6=TCP, 17=UDP, 1=ICMP, 132=SCTP): {132: 402}
```

**100% paket NGAP di dataset ini berjalan di atas SCTP** (sesuai standar 3GPP — NGAP memang
didesain di atas SCTP, port 38412). netFound (`Tokenize.py`) hanya punya cabang untuk
`Protocol.TCP`, `Protocol.UDP`, dan fallback ICMP (lihat kode: tidak ada `Protocol.SCTP`).
Field extractor C++ (`3_field_extraction.cpp`) tidak mengenali SCTP sama sekali, sehingga
tahap ekstraksi (`extracted/ngap_*/<episode>/`) menghasilkan folder **kosong** untuk setiap
episode NGAP — lalu `Tokenize.py` sendiri mencetak `"No valid tokenizable files found...
Skipping directory"` dan keluar dengan exit code 0 (tanpa error) — karena itu tidak muncul
di log sebagai kegagalan, hanya sebagai silent-skip.

## Dampak

- 2 dari 16 kelas final (`ngap_malformed`, `ngap_ngsetup_flood`) punya **nol sampel
  training/val/test** dengan pipeline netFound saat ini.
- Ini BUKAN kasus "payload generik" seperti disinggung FASE8.md untuk tier 2–4 (PFCP/SBI
  tetap dapat baris karena berjalan di atas UDP/TCP) — NGAP benar-benar tidak terproses
  sama sekali.

## Opsi perbaikan (di luar scope F8.4–F8.6, perlu keputusan sebelum F8.7)

1. **Terima sebagai batasan riset** — laporkan 14/16 kelas efektif punya data; NGAP
   dikeluarkan dari training & metrik, didokumentasikan sebagai keterbatasan tokenizer.
2. **Tambah dukungan SCTP** ke `3_field_extraction.cpp` dan `Tokenize.py` (fork/patch
   netFound) — pekerjaan signifikan, berisiko menyimpang dari tool upstream resmi.
3. **Encapsulate/translate**: tulis ulang PCAP NGAP agar SCTP dibungkus sedemikian hingga
   terlihat sebagai UDP/TCP bagi ekstraktor (hacky, mengubah semantik paket, tidak
   direkomendasikan).

**Rekomendasi:** opsi 1 (terima & dokumentasikan). Keputusan final menunggu konfirmasi Anda
sebelum F8.7.
