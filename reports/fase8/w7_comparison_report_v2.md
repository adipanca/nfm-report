# W7 — Run "Benign Multi-Sesi + Merge PFCP" (16 kelas non-SCTP)

5 kelas SCTP (bidding_down, nas_replay_n1, nas_tamper_registration, ngap_malformed,
ngap_ngsetup_flood) dikecualikan dari run ini (1-16 baris/kelas, terlalu kecil untuk
dilatih) — lihat `sctp_small_class_diagnosis.md` untuk analisis mengapa.

## Progres macro-F1 test set lintas run

| Run | Frozen | Unfrozen |
|---|---|---|
| 14-kelas lama (benign 1 sesi tercampur) | 0,6086 | 0,6577 |
| 17-kelas interim (benign 1 sesi bersih) | 0,6924 | 0,7428 |
| **16-kelas ini (benign 5 sesi + merge PFCP)** | **0,7260** | **0,7826** |

Peningkatan konsisten di setiap iterasi.

## Dampak merge `pfcp_estab_flood + pfcp_rule_misconfig → pfcp_establishment_attack`

| | F1 run sebelumnya (2 kelas terpisah) | F1 run ini (1 kelas gabungan) |
|---|---|---|
| Frozen | estab=0,535 / misconfig=0,515 | **pfcp_establishment_attack = 1,000** |
| Unfrozen | estab=0,535 / misconfig=0,515 (run interim) | **pfcp_establishment_attack = 0,980** |

Menggabungkan kedua kelas **menghilangkan** masalah confusion yang sebelumnya
nyaris 50/50 — sesuai hipotesis bahwa keduanya tak terbedakan di level representasi
netFound, bukan karena kekurangan data.

## Kebocoran flood→benign (confusion matrix)

| Regime | Baris flood salah ke benign (dari 7.796 baris) |
|---|---|
| Frozen | 17 (0,22%) |
| **Unfrozen** | **0 (0,00%)** |

Dengan benign multi-sesi (5 episode asli, bukan 1 sesi tunggal) dan arah paket
terkoreksi, kebocoran flood→benign di regime unfrozen sekarang **benar-benar nol**.

## Titik lemah yang TETAP: flood Tier-0 saling tertukar

| Kelas | F1 Frozen | F1 Unfrozen |
|---|---|---|
| dos_httpflood | 0,037 | 0,379 |
| dos_icmpflood | 0,323 | 0,344 |
| dos_slowrate | 0,352 | 0,419 |
| dos_synflood | 0,362 | 0,492 |
| dos_udpflood | 0,000 | 0,187 |

Unfrozen jauh lebih baik dari frozen di sini, tapi confusion matrix menunjukkan
kelima flood ini **masih saling bertukar satu sama lain** secara dominan (bukan ke
benign lagi) — pola yang konsisten di semua run sejauh ini. Ini tetap jadi batasan
utama arsitektur/representasi netFound untuk membedakan pola volumetrik serupa.

## Kelas lain (gtpu, sbi, tls, pfcp session, n6_exfiltration, sbi_nf_impersonation)

Semua ≥0,80 F1 di kedua regime, kebanyakan ≥0,97-1,00 — tetap solid seperti run-run
sebelumnya, tidak terganggu oleh penambahan 3 kelas baru atau merge PFCP.

File lengkap: `w6_frozen_test_metrics.json`, `w6_unfrozen_test_metrics.json`,
`w6_frozen_confusion_matrix.csv`, `w6_unfrozen_confusion_matrix.csv`.
