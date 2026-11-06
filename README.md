# paramrecon

Web crawler dan *active parameter discovery* untuk ekstraksi endpoint autentikasi. Dirancang khusus agar berjalan ringan secara native di Termux (Android) tanpa butuh browser headless (Chromium/Playwright).

## Latar Belakang

Sebagian besar tool recon modern terlalu berat untuk dijalankan di lingkungan mobile. `paramrecon` dibangun murni menggunakan `requests` dan `beautifulsoup4`. Tanpa konsumsi RAM besar, cocok untuk operasi pemetaan target (recon) cepat langsung dari perangkat Android.

## Fitur Utama

- **Active Parameter Discovery (`--hunt`)**: Menembak daftar parameter umum secara aktif ke setiap endpoint. Menggunakan teknik *chunking* (kirim banyak parameter sekaligus) dan *anomaly detection* (deteksi perubahan respons) untuk membongkar parameter tersembunyi tanpa membuat server target spamming.
- **Deep JS & Next.js Harvester**: Mampu mengekstrak parameter atau endpoint API tersembunyi dari file JavaScript (`.js`) dan JSON internal Next.js (`__NEXT_DATA__`).
- **Auth Endpoint Scoring**: Memberikan skor 0-100 pada kandidat form login. Tool akan memindai indikator seperti input password, method POST, dan CSRF token.
- **URL Template Deduplication**: Mencegah pemborosan request pada URL dengan pola sama. Contoh: `/product/1` dan `/product/2` hanya akan di-crawl sekali.
- **Soft-404 Detection**: Membedakan antara halaman 404 asli dengan halaman error yang menyamar sebagai status 200, meminimalisir hasil false positive saat brute-force.
- **WAF Fingerprinting**: Mendeteksi keberadaan Web Application Firewall (Cloudflare, Akamai, AWS, Sucuri, dll) langsung dari response header.

## Keterbatasan 

- **Tidak merender SPA penuh.** Hanya membaca HTML awal dan JSON state. Jika form login baru muncul setelah JavaScript berjalan (client-side rendering murni), form tersebut tidak akan terdeteksi.
- Belum bisa me-resolve template literal JavaScript (seperti `fetch('/api/${id}')`).
- Tidak memiliki fitur bypass WAF. Jika diblokir oleh Cloudflare, tool ini tidak akan bisa menembus.

## Instalasi

```bash
pkg install python -y
pip install requests beautifulsoup4 colorama
git clone https://github.com/jackedxdd/paramrecon
cd paramrecon
```

Parameter CLI dan Fungsinya

Flag Fungsi
-m, --max-pages Batasan maksimal halaman yang akan di-crawl (default: 200).
-d, --depth Kedalaman crawl mengikuti link (default: 4).
-t, --threads Jumlah thread/pekerja paralel (default: 10).
--delay Jeda waktu (detik) antar request. Gunakan ini jika target memiliki WAF.
--subdomain Mengizinkan crawler untuk masuk ke subdomain yang ditemukan.
-H, --header Menyisipkan header kustom (misal: -H "Cookie: session=123").
--no-scan-js Mematikan fitur download dan pemindaian file JavaScript.
--js-limit Batasan maksimal file JS yang akan diunduh dan dipindai (default: 30).
-a, --aggressive Mode Agresif. Mengaktifkan --brute, --hunt, dan --scan-js dengan limit tinggi secara otomatis.
--hunt Mengaktifkan mode Active Parameter Discovery (Fuzzing).
--brute Mengaktifkan mode brute-force untuk menebak path admin/login umum.
--brute-wordlist Menggunakan file wordlist kustom untuk brute-force path.
-o, --output Menentukan nama file hasil scan JSON (default: recon_result.json).
--html Mengekspor hasil scan ke dalam format laporan HTML.
--no-banner Menyembunyikan banner ASCII saat tool dijalankan.

Contoh Penggunaan

1. Crawling standar (pasif):

```bash
python paramrecon.py https://target.com
```

2. Crawling dengan mode Brute-Force:

```bash
python paramrecon.py https://target.com --brute
```

3. Pencarian parameter tersembunyi (Active Fuzzing):

```bash
python paramrecon.py https://target.com --hunt -m 50
```

4. Mode Agresif (Semua fitur menyala, gunakan delay agar sopan):

```bash
python paramrecon.py https://target.com -a --delay 1.0 -t 5
```

5. Scan area tertutup (menggunakan cookie login):

```bash
python paramrecon.py https://target.com --brute -H "Cookie: session=abcd1234"
```

Contoh Output (Lab Lokal)

Berikut adalah contoh nyata hasil pemindaian pada lingkungan lab lokal (http://127.0.0.1:8080). 

```text
============================================================
  SCAN SUMMARY
============================================================
  Pages crawled    : 1 (1 unique)
  Real params      : 1
  Suspect params   : 0
  Unique forms     : 1
  JS endpoints     : 1
  JS bundles       : 0
  Sitemap URLs     : 0
  Brute probed     : 71
  Auth hits        : 1
  Errors           : 0
  Elapsed          : 0.0s

------------------------------------------------------------
  AUTH ENDPOINTS (1)
------------------------------------------------------------
   [GET] http://127.0.0.1:8080/api/v1/user (score=20)
       inline-js-endpoint
       variants: 1

------------------------------------------------------------
  PARAMETERS (1 real, 0 suspect)
------------------------------------------------------------
  real params:
    token (2 loc) [auth]
      http://127.0.0.1:8080/api/v1/user?token=abc
      http://127.0.0.1:8080/search.html?q=test
```

Etika dan Legalitas

Tool ini hanya boleh digunakan pada target yang Anda miliki izin resmi untuk mengujinya.

Melakukan pemindaian (scanning) terhadap sistem tanpa izin tertulis adalah tindakan ilegal dan melanggar hukum (misal: UU ITE di Indonesia).
