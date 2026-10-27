# Key Distribution Scenario — KDC + Alice + Bob (AES manual)

## Isi file
- `aes_manual.py` — AES-128 **manual** (S-Box, key expansion, SubBytes, ShiftRows,
  MixColumns, AddRoundKey ditulis dari nol, tanpa `pycryptodome`). Dipakai untuk
  semua komunikasi Alice<->Bob (step 4, step 5, dan chatting).
  Sudah lolos test vector resmi FIPS-197 (lihat `python3 aes_manual.py`).
- `kdc.py` — Key Distribution Center. Boleh pakai library (`pycryptodome`,
  AES-CBC) sesuai instruksi tugas, untuk mengenkripsi `E(Ka,...)` dan `E(Kb,...)`.
- `peer.py` — dipakai **oleh Alice maupun Bob** (pilih role saat start):
  role `1 INITIATOR` = Alice, role `2 RESPONDER` = Bob. Setelah handshake
  sukses, kedua pihak bisa **sender maupun receiver** (chat dua arah).

Install dependency (hanya dibutuhkan `kdc.py` dan `peer.py`, karena keduanya
membuka pesan `E(Ka,...)`/`E(Kb,...)` dari KDC):
```
pip install pycryptodome
```

## Menjalankan di 3 IP berbeda
Jalankan di 3 komputer/VM berbeda (atau 3 terminal dengan IP berbeda kalau
pakai beberapa interface jaringan):

**Komputer 1 — KDC**
```
python3 kdc.py
```
Akan ditanya IP bind & port (mis. `0.0.0.0` / `9000`), lalu minta didaftarkan
ID+key awal (mis. `ALICE` / `BOB` beserta long-term key ASCII masing-masing).
Key TIDAK hardcode — tersimpan di `kdc_keys.json` dan bisa diubah kapan saja
lewat console (`setkey ALICE kunciBaru123`) tanpa restart.

**Komputer 2 — Bob (responder)**
```
python3 peer.py
→ pilih role 2
→ ID: BOB
→ key (Kb) BOB di KDC: (harus sama dengan yang didaftarkan di KDC)
→ IP bind: 0.0.0.0 (atau IP komputer ini)
→ port: 9100
```
Bob akan menunggu koneksi dari initiator.

**Komputer 3 — Alice (initiator)**
```
python3 peer.py
→ pilih role 1
→ ID: ALICE
→ key (Ka) ALICE di KDC
→ IP KDC: <IP komputer 1>
→ port KDC: 9000
→ ID peer: BOB
→ IP peer: <IP komputer 2>
→ port peer: 9100
```
Alice otomatis menjalankan step 1–5 (hubungi KDC, terima tiket, teruskan ke
Bob, tukar nonce N2/f(N2) pakai AES manual). Begitu "Autentikasi SUKSES"
muncul di kedua sisi, keduanya masuk mode chat dua arah — ketik pesan lalu
Enter untuk kirim (plaintext ASCII, dikirim sebagai ciphertext hex, didekripsi
otomatis di sisi lawan).

Perintah di dalam chat:
- `:showkey` — lihat session key Ks yang sedang dipakai
- `:setkey <baru>` — ganti Ks lokal secara interaktif (berguna untuk test case,
  misal simulasi key salah, tanpa perlu restart program)
- `:quit` — keluar

## Catatan desain
- Step (1) & (2) di diagram: Alice → KDC → Alice, dienkripsi dgn Ka/Kb
  (library AES-CBC, karena instruksi tugas membebaskan bagian KDC).
- Step (3): Alice meneruskan tiket `E(Kb,[Ks||IDA])` apa adanya ke Bob
  (Alice sendiri tidak bisa membukanya karena tidak tahu Kb).
- Step (4) & (5): pertukaran nonce N2 dan f(N2)=N2-1, dienkripsi dengan Ks
  memakai **AES manual** (`aes_manual.py`).
- Setelah step 5 sukses, seluruh chat Alice↔Bob memakai Ks + AES manual,
  ciphertext selalu ditampilkan dalam hex.
