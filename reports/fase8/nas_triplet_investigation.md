# Investigasi: Kebingungan 3 Kelas NAS (bidding_down / nas_replay_n1 / nas_tamper_registration)

**Status: READ-ONLY. Tidak ada data, skrip produksi, atau lab yang diubah/dinyalakan selama investigasi ini.**
Satu-satunya perubahan state adalah instalasi tool `tshark` (apt package) untuk analisis paket — bukan perubahan data.

**Lokasi laporan**: `reports/fase8/nas_triplet_investigation.md` (disamakan dengan konvensi seluruh proyek yang menaruh laporan di `reports/fase8/`; user menulis `reports/nas_triplet_investigation.md` — beri tahu saya jika Anda ingin file dipindah ke `reports/` tanpa subfolder).

**Konteks**: Pada run 21-kelas final (lihat `w7_comparison_report_v3_final21.md`), tiga kelas ini saling tertukar dengan parah:
`bidding_down` F1=0.317, `nas_replay_n1` F1=0.308, `nas_tamper_registration` F1=0.000, vs kelas SCTP lain yang sukses (`ngap_malformed`=0.987, `ngap_ngsetup_flood`=1.000).

---

## P1 — Desain pembeda menurut `nas_attack.py`

**Update**: skrip ditemukan di GitHub (`github.com/adipanca/nfm`, branch `feat/serangan-baru-vm`, path `docker/attacker/tools/nas_attack.py`), diberikan oleh user. Diambil via `git clone --depth 1` (read-only, tidak menyentuh lab/VM maupun data lokal).

**Desain yang eksplisit di kode:**

```python
NAS_HEAD = bytes.fromhex("7e004179000b01020304050607080900")  # header NAS tetap, SAMA untuk ketiga mode
def seccap_ie(nea, nia, eea=0x00, eia=0x00):
    return bytes([0x2e, 0x04, nea, nia, eea, eia])             # UE Security Capability IE

def build_nas(mode):
    if mode == "bidding_down":
        cap = seccap_ie(0x80, 0x80)                             # NEA0/NIA0 saja -> null cipher/integrity
    elif mode == "tamper_registration":
        cap = seccap_ie(random.randint(0,255), random.randint(0,255),
                         random.randint(0,255), random.randint(0,255))  # 4 byte ACAK setiap panggilan
    else:  # replay
        cap = seccap_ie(0xf0, 0xf0, 0xc0, 0xc0)                 # kapabilitas "sah" TETAP, dikirim ulang antar koneksi
    return NAS_HEAD + cap
```

**Pembeda yang didesain**: HANYA 4 byte terakhir IE `UE Security Capability` (`seccap_ie`'s `nea/nia/eea/eia`) — **bukan** jenis pesan NGAP/NAS (ketiganya memakai `InitialUEMessage` + `Registration Request` yang identik), bukan IE lain, dan bukan pola temporal/replay di level NAS payload itu sendiri (replay di sini berarti kapabilitas-security yang SAH dikirim ulang tanpa variasi di koneksi berbeda, bukan duplikasi literal paket yang sama persis dua kali).

**Verifikasi silang kode ↔ wire (cocok 100%)**: 4 byte yang ditemukan secara forensik di P2.3/P2.4 **sama persis** dengan argumen `seccap_ie()` di kode:

| Kelas | Kode (`seccap_ie(nea, nia, eea, eia)`) | Byte observasi di pcap |
|---|---|---|
| bidding_down | `0x80, 0x80, 0x00, 0x00` | `80 80 00 00` ✓ |
| nas_replay_n1 | `0xf0, 0xf0, 0xc0, 0xc0` (konstan) | `f0 f0 c0 c0` ✓ (1 nilai unik di semua sampel) |
| nas_tamper_registration | `random()×4` setiap panggilan | 195 nilai unik di 195 asosiasi ✓ |

Ini mengonfirmasi tuntas bahwa bukti byte-level pada P2.4 bukan kebetulan — itu adalah persis parameter desain attack generator.

**Follow-up check (negatif, didisclose untuk transparansi)**: Saya sempat menduga "replay" akan tampak sebagai **dua DATA chunk dengan payload identik dalam SATU asosiasi SCTP** (karena kode memanggil `sctp_send()` dua kali untuk mode replay). Dicek dengan `nas_p4_replay_sequence_check.py` (scapy, seluruh asosiasi, ketiga kelas) — **hasilnya negatif**: ketiga kelas sama-sama punya ~2 DATA chunk/asosiasi (satu `InitialUEMessage` dari attacker, satu respons dari AMF) dan **0% asosiasi dengan payload DATA yang duplikat** di ketiga kelas. Artinya duplikasi "replay" yang didesain terjadi di level **antar-koneksi dengan source port yang sama** (dua `sctp_send()` call berurutan, masing-masing koneksi SCTP baru), bukan dalam satu asosiasi — sinyal ini TIDAK diperiksa lebih lanjut (butuh korelasi antar-asosiasi/antar-file) karena P3 sudah punya jawaban definitif dari jalur lain (lihat di bawah), tapi dicatat sebagai limitasi/avenue lanjutan jika diperlukan.

---

## P2 — Perbandingan tshark lintas kelas

### P2.1 Hierarki protokol & tingkat malformed
Satu sampel pcap per kelas (`tshark -q -z io,phs`): ketiga kelas menunjukkan hierarki yang **identik**:
```
eth → ip → sctp → ngap → _ws.malformed
```
dengan **~50% frame NGAP flagged malformed** di ketiga kelas (expert info: `"Open type length(65) > available data(19)"` — payload NAS yang dibungkus NGAP terlalu pendek untuk didekode penuh oleh ASN.1 PER decoder tshark).

### P2.2 Urutan chunk SCTP & panjang frame
Ekstraksi field detail (`tshark -T fields`) pada 2 file pertama tiap kelas menunjukkan **setiap asosiasi SCTP, di ketiga kelas, mengikuti urutan chunk dan panjang frame yang IDENTIK**, berulang ~15–16× per file:

| Urutan | Chunk | procedureCode | Malformed? | Panjang frame (byte) |
|---|---|---|---|---|
| 1 | INIT | — | — | 98 |
| 2 | INIT-ACK | — | — | 338 |
| 3 | COOKIE-ECHO | — | — | 310 |
| 4 | COOKIE-ACK | — | — | 50 |
| 5 | DATA | 15 (InitialUEMessage) | **Ya** | 94 |
| 6 | SACK | — | — | 62 |
| 7 | DATA | 9 (DownlinkNASTransport, dll.) | Tidak | 74 |
| 8 | SACK | — | — | 62 |
| 9 | SHUTDOWN | — | — | 54 |
| 10 | SHUTDOWN-ACK | — | — | 50 |
| 11 | SHUTDOWN-COMPLETE | — | — | 50 |

Field `nas-5gs.mm.message_type` / `nas-5gs.sm.message_type` **selalu kosong** di ketiga kelas — dissector NAS-5GS tshark tidak pernah berhasil fire, kemungkinan karena wrapper NGAP yang malformed/truncated menghalangi ASN.1 decoder turun ke payload NAS. **Keterbatasan yang harus saya sampaikan jujur**: ini berarti perbandingan "IE NAS" tingkat semantik (seperti diminta di P1/P2) **tidak bisa dilakukan via tshark's semantic decode** — analisis di bawah adalah perbandingan byte mentah (raw payload bytes), bukan decode IE NAS-5GS formal.

### P2.3 Byte mentah: DATA chunk pertama (procedureCode=15, malformed)
Hex dump frame #5 (satu sampel per kelas) pada bagian setelah SCTP chunk header menunjukkan ~24 byte identik, berbeda hanya pada 4 byte terakhir sebelum 2 byte padding:

| Kelas | 4-byte pembeda |
|---|---|
| bidding_down | `80 80 00 00` |
| nas_replay_n1 | `f0 f0 c0 c0` |
| nas_tamper_registration | `6b 0c 21 24` |

### P2.4 Verifikasi rigor: SEMUA sampel, SEMUA file, ketiga kelas
Untuk memastikan temuan di atas bukan kebetulan dari 1 sampel, saya tulis `nas_p3_payload_window.py` (scapy) yang mem-parse payload NGAP di dalam DATA chunk pertama (`chunk[16:]`, melewati 16-byte fixed header SCTP DATA chunk) untuk **seluruh paket di seluruh file** ketiga kelas, lalu membagi payload itu menjadi:
- **`[0:12]`** — jendela yang **benar-benar ditokenisasi netFound** (field Payload netFound di-cap ke `std::min(data_len, 12)` byte pertama, lihat `3_field_extraction.cpp`)
- **`[12:40]`** — byte yang **dibuang** oleh cap 12-byte tersebut

**Hasil (lengkap, semua sampel):**

```
=== ngap_payload[0:12] — yang ditokenisasi netFound ===
bidding_down:             1 nilai unik →  000f401a002600167e004179
nas_replay_n1:            1 nilai unik →  000f401a002600167e004179
nas_tamper_registration:  1 nilai unik →  000f401a002600167e004179

Union ketiga kelas: 1 nilai unik TOTAL — SAMA PERSIS di ketiga kelas,
di SETIAP paket, tanpa kecuali.

=== ngap_payload[12:40] — yang DIBUANG oleh cap 12-byte netFound ===
bidding_down:             1 nilai unik  →  ...808000000000   (KONSTAN)
nas_replay_n1:            1 nilai unik  →  ...f0f0c0c00000   (KONSTAN)
nas_tamper_registration:  195 nilai unik →  (berubah tiap paket, tampak acak)

Overlap [12:40] antar kelas = 0 di SEMUA pasangan:
  bidding_down vs nas_replay_n1:            0 / (1, 1)
  bidding_down vs nas_tamper_registration:  0 / (1, 195)
  nas_replay_n1 vs nas_tamper_registration: 0 / (1, 195)
```

**Pola tambahan yang menarik** (bukan diminta langsung tapi relevan untuk P1/P3): `nas_replay_n1` dan `bidding_down` masing-masing menghasilkan nilai **konstan** di seluruh paketnya — konsisten dengan nama kelasnya: "replay" secara definisi mengirim ulang pesan yang sama berulang-ulang, dan "bidding down" tampaknya selalu mengirim capability security yang sama yang sudah di-downgrade. Sebaliknya `nas_tamper_registration` menghasilkan 195 nilai berbeda — konsisten dengan "tamper" yang mengacak/memanipulasi field secara acak setiap kali mencoba.

---

## P3 — Diagnosis: Kasus A atau Kasus B?

### Kesimpulan: **Kasus A** — trafik memang berbeda secara nyata, netFound secara struktural tidak menangkapnya.

**Bukti terhadap Kasus B (skrip terlalu mirip → artefak)**: DITOLAK. Bukti di atas menunjukkan ketiga skrip attack menghasilkan payload NAS yang **100% tidak overlap** di byte 12–39 pasca-header SCTP chunk — bidding_down dan nas_replay_n1 masing-masing punya signature byte konstan yang unik, dan nas_tamper_registration punya 195 variasi berbeda yang semuanya juga tidak overlap dengan dua kelas lain. Ini adalah trafik yang **genuinely berbeda by design**, bukan skrip yang kebetulan identik.

**Mekanisme pasti mengapa netFound tidak menangkap perbedaan ini**:
1. Field `Payload` netFound di-cap ke `std::min(data_len, 12)` byte pertama dari payload pasca-header protokol (`3_field_extraction.cpp`) — ini berlaku sama untuk TCP/UDP/ICMP/SCTP, bukan bug khusus SCTP.
2. Untuk ketiga attack ini, 12 byte pertama payload NGAP (`00 0f 40 1a 00 26 00 16 7e 00 41 79`) adalah **envelope NGAP InitialUEMessage + header NAS Registration Request yang sama** untuk ketiganya — wajar, karena ketiga attack sama-sama berbasis "kirim InitialUEMessage berisi Registration Request", hanya berbeda di IE yang lebih dalam.
3. Byte pembeda yang sesungguhnya (4 byte unik per kelas pada contoh yang diperiksa, dan pola penuh di `[12:40]`) **mulai muncul tepat di offset byte ke-12** — persis di luar jendela yang ditokenisasi netFound.
4. Akibatnya: untuk field `Payload` pada paket spesifik ini, model menerima token **yang identik secara byte-for-byte** untuk ketiga kelas, pada setiap sampel, tanpa variasi sama sekali. Tidak ada jumlah data training yang bisa memperbaiki ini — model secara matematis tidak mungkin membedakan tiga distribusi yang token inputnya sama persis di field tersebut.

**Apakah cold-start/data kecil menjelaskan kebingungan ini?** **Tidak sebagai penyebab utama.** Kebutaan ini bersifat **struktural dan deterministik** (fungsi dari desain tokenizer, bukan dari jumlah data), jadi akan tetap terjadi meski data SCTP untuk ketiga kelas ini jauh lebih banyak. Cold-start pada `protoEmbedding` (hanya 1 baris baru yang belum terlatih untuk SCTP=132) mungkin berkontribusi sedikit pada kualitas representasi SCTP secara umum, tapi itu persoalan terpisah dan sekunder — bahkan dengan `protoEmbedding` yang sepenuhnya well-trained, field Payload tetap akan membawa token yang sama untuk ketiga kelas pada paket ini.

**Catatan penting — ini bukan berarti TIDAK ADA sinyal pembeda sama sekali** di field lain (misalnya pola panjang SCTP chunk DATA kedua/procedureCode=9 belum diperiksa mendalam lintas kelas, atau statistik burst/timing). Investigasi ini membuktikan secara spesifik bahwa **signal di field Payload paket InitialUEMessage (paket paling informatif attack-wise) hilang total oleh desain cap 12-byte** — ini adalah penjelasan paling kuat dan paling mudah difalsifikasi untuk confusion yang teramati, tapi bukan klaim bahwa tidak ada signal residual sama sekali di tempat lain.

---

## Yang BELUM dikerjakan (transparansi keterbatasan)

- DATA chunk kedua (procedureCode=9, tidak malformed — teridentifikasi sebagai respons AMF, bukan kiriman attacker) belum diperiksa untuk perbedaan lintas kelas secara serigor DATA chunk pertama.
- Decode IE NAS-5GS semantik (bukan raw byte) tidak berhasil dilakukan karena dissector tshark tidak fire — lihat P2.2. (Tidak lagi krusial: P1 sudah terjawab tuntas lewat source code, bukan lewat decode tshark.)
- Sinyal "replay" antar-koneksi (source port sama dipakai 2× secara berurutan) belum diverifikasi lintas asosiasi/file — lihat follow-up check di P1.

## Tidak ada perubahan dilakukan
Sesuai instruksi, laporan ini dihasilkan TANPA mengubah data, skrip produksi, atau konfigurasi apa pun, dan tanpa menyalakan lab. Menunggu arahan Anda untuk langkah selanjutnya (misalnya: apakah ingin memperluas jendela Payload khusus untuk NGAP/SCTP, menggabungkan ketiga kelas, mendokumentasikan limitasi ini saja, atau memeriksa DATA chunk kedua lebih lanjut).
