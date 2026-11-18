# F8.2 — Catatan GATE IP Masking

## 1. Temuan di kode netFound (sebelum masking tambahan)

- `netFound/configs/DefaultConfigNoTCPOptions.json` → field `IPFields` hanya berisi:
  `IP_hl, IP_tos, IP_tl, IP_Flags, IP_ttl` — **tidak ada** `SrcIP`/`DstIP` atau octet alamat IP apa pun.
- `netFound/pre_process_src/Tokenize.py`:
  - baris 197-205: kolom `SrcIP`/`DstIP` dibaca dari hasil ekstraksi field (`3_field_extraction`), tapi
  - baris 272-292 (`split_bursts_on_dir`): `SrcIP`/`DstIP` hanya dipakai untuk menentukan arah paket
    (forward/backward) relatif ke `internalIPs` dari config — **tidak pernah** dimasukkan ke daftar token.
  - baris 107-114 (`tokenize_file`): daftar field yang benar-benar ditokenisasi = `IPFields + [TCP/UDP/ICMP]Fields + Payload`
    — `SrcIP`/`DstIP` tidak termasuk.
- **Kesimpulan:** tokenizer netFound secara desain **tidak pernah mengenkode alamat IP mentah** ke dalam token
  (hanya metadata header seperti TTL/flags/length). Ini adalah bentuk "masking by omission" di level arsitektur model.

## 2. Masking eksplisit yang diterapkan (defense-in-depth)

Karena tidak ada opsi anonymisasi bawaan yang menulis ulang PCAP (opsi `internalIPs` hanya untuk arah paket,
bukan anonymisasi), diterapkan **opsi 2** dari FASE8.md: pra-proses PCAP dengan menulis ulang semua IP
(src & dst) ke **satu pasangan konstan global** (`10.255.255.1` → `10.255.255.2`), sama untuk semua kelas,
menggunakan scapy. Grouping label/flow tetap memakai metadata asli (`ground_truth.csv`, nama folder kelas)
yang sudah ditetapkan sebelum penulisan ulang — hanya byte alamat IP di paket yang diubah.

- Skrip: `reports/fase8/f8_2_ip_only_classifier.py` (fungsi `write_masked_pcap`)
- Input: `data/labeled/<kelas>/*.pcap` (50 file, 313MB, 2.483.881 paket ber-IP)
- Output: `data/labeled_masked/<kelas>/*.pcap` (struktur identik, IP src/dst konstan di semua paket)

## 3. Uji gate: classifier IP-only sebelum vs sesudah masking

Fitur = **hanya** `(src_ip, dst_ip)` per paket → label kelas. `DecisionTreeClassifier` (seed=42),
split train/test 80/20 stratified.

| Metrik | Sebelum masking | Sesudah masking | Baseline tebak-acak (mayoritas) |
|---|---|---|---|
| **Container-tier vs sisanya** (biner: 9 kelas PFCP/NGAP/SBI/TLS vs lainnya) | **99,47%** | **60,71%** | 60,71% |
| Akurasi 17-kelas penuh | 71,50% | 52,32% | 52,32% |
| Akurasi di dalam 9 kelas container saja (antar sesama container) | 49,53% | 49,01% | 49,01% |

**Interpretasi:**
- Sebelum masking, IP saja hampir sempurna (99,47%) memberi tahu "ini kelas container (PFCP/NGAP/SBI/TLS)
  atau bukan" — ini persis risiko yang diflag audit.
- Sesudah masking, sinyal itu **kolaps total** ke level tebak-acak (60,71% = akurasi dicapai dengan selalu
  menebak kelas mayoritas) — IP tidak lagi membawa sinyal kelas sama sekali (hanya ada 1 pasangan IP unik
  di seluruh dataset ter-mask).
- Akurasi "di dalam 9 kelas container" rendah (~49%) **baik sebelum maupun sesudah** masking — ini **bukan**
  efek masking, melainkan keterbatasan desain testbed: beberapa kelas berbagi IP container yang identik
  (4 kelas PFCP semua dari `172.23.0.50→172.23.0.30`; 3 kelas SBI/TLS semua dari `172.22.0.50→172.22.0.20`),
  sehingga IP tidak pernah bisa membedakan di antara kelas-kelas dalam grup yang sama — dengan atau tanpa masking.

## 4. Hasil GATE

```
GATE_F8_2_PASS = True
```
Kriteria lulus (lihat `f8_2_gate_result.json`):
1. Sebelum masking, deteksi container-tier via IP > 95% (terpenuhi: 99,47%).
2. Sesudah masking, deteksi container-tier via IP turun ke ≤ baseline mayoritas + 5pp (terpenuhi: 60,71% = baseline).
3. Sesudah masking, akurasi 17-kelas penuh turun ke ≤ baseline mayoritas + 5pp (terpenuhi: 52,32% = baseline).

**GATE F8.2 LULUS.** Aman melanjutkan ke F8.3 (impor & verifikasi data) dan seterusnya — menunggu konfirmasi Anda.
