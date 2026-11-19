# W7 — Run FINAL 21 Kelas (16 non-SCTP + 5 SCTP, fix per-asosiasi)

## Progres macro-F1 test set lintas semua run

| Run | Frozen | Unfrozen |
|---|---|---|
| 14-kelas lama | 0,6086 | 0,6577 |
| 17-kelas interim | 0,6924 | 0,7428 |
| 16-kelas (benign multi-sesi + merge PFCP) | 0,7260 | 0,7826 |
| **21-kelas FINAL (+ 5 SCTP)** | **0,6311** | **0,7126** |

Macro-F1 **turun** dibanding run 16-kelas — ini **diharapkan, bukan regresi**: menambah
5 kelas baru yang modelnya cold-start (embedding SCTP baru dipelajari dari nol, data
163-457 baris/kelas) otomatis menurunkan rata-rata makro begitu beberapa di antaranya
sulit dipisahkan. Detail per-kelas di bawah.

## Hasil per-kelas SCTP (unfrozen, test set)

| Kelas | F1 | Precision | Recall | Support |
|---|---|---|---|---|
| **ngap_ngsetup_flood** | **1,000** | 1,000 | 1,000 | 68 |
| **ngap_malformed** | **0,987** | 0,974 | 1,000 | 37 |
| bidding_down | 0,317 | 0,271 | 0,382 | 34 |
| nas_replay_n1 | 0,308 | 0,275 | 0,350 | 40 |
| nas_tamper_registration | **0,000** | 0,000 | 0,000 | 26 |

**Temuan jujur:** 2 kelas NGAP (sinyal NGAP, data lebih banyak 163-457 baris) langsung
**sangat baik** bahkan dari cold-start. Tapi 3 kelas NAS (`bidding_down`,
`nas_replay_n1`, `nas_tamper_registration`) **saling tertukar parah** satu sama lain
(confusion matrix: `nas_tamper_registration` 26 sampel → 9 diprediksi `bidding_down`,
16 diprediksi `nas_replay_n1`, 1 ke `sbi_nf_impersonation`, **0 benar**). Pola ini mirip
kasus `pfcp_estab_flood`/`pfcp_rule_misconfig` sebelum di-merge — kemungkinan ketiga
serangan NAS ini (semua di atas asosiasi SCTP N2 yang sama) menghasilkan representasi
token yang nyaris identik di level netFound, DIPERPARAH oleh cold-start embedding
(`protoEmbedding` baris 132 baru, +203 baris data kecil tak cukup untuk encoder yang
belum pernah melihat SCTP mempelajari perbedaan ketiganya).

## Kelas non-SCTP: tetap solid, tidak terganggu

| Kelas | F1 (unfrozen) |
|---|---|
| benign | 0,9997 |
| pfcp_establishment_attack | 1,000 |
| pfcp_session_delete / modify | 1,000 |
| sbi_http2_attack | 0,971 |
| sbi_nf_impersonation | 0,903 |
| tls_handshake_flood | 0,997 |
| gtpu_malformed / gtpu_teid_injection | 0,962 / 1,000 |
| n6_exfiltration | 0,909 |

Semua 16 kelas non-SCTP tetap pada level F1 yang sama/mirip seperti run sebelumnya —
penambahan 5 kelas SCTP **tidak merusak** performa kelas-kelas yang sudah mapan.

## Flood Tier-0 (pola lama tetap sama)

dos_httpflood 0,364 / dos_icmpflood 0,343 / dos_slowrate 0,414 / dos_synflood 0,487 /
dos_udpflood 0,221 — sesuai pola di semua run sebelumnya, flood saling tertukar sesama
mereka, bukan dengan benign atau kelas lain.

## Kesimpulan untuk laporan

- **Fix SCTP per-asosiasi berhasil secara teknis** (data cukup, ≥100 baris/kelas,
  training berjalan tanpa error, nol regresi non-SCTP).
- **"Bisa diproses" ≠ "akurat"** — persis peringatan di `SCTP_SUPPORT.md` S7: 2/5 kelas
  SCTP (NGAP) langsung akurat; 3/5 (NAS) belum, kemungkinan representasi yang terlalu
  mirip + cold-start + data masih relatif kecil (195-222 baris).
- Rekomendasi lanjutan (di luar scope sekarang): pertimbangkan merge
  `bidding_down`+`nas_replay_n1`+`nas_tamper_registration` jika confusion ini konsisten
  di analisis lanjutan, ATAU kumpulkan lebih banyak data NAS dari VM untuk memberi
  encoder SCTP yang baru lebih banyak sinyal untuk belajar membedakan.

File lengkap: `w6_frozen_test_metrics.json`, `w6_unfrozen_test_metrics.json`,
`w6_frozen_confusion_matrix.csv`, `w6_unfrozen_confusion_matrix.csv`.
