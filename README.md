# paramrecon

Web crawler untuk ekstraksi parameter dan pemetaan endpoint autentikasi. Dirancang khusus agar berjalan ringan secara native di Termux (Android) tanpa butuh Chromium atau Playwright.

## Latar Belakang

Sebagian besar tool recon modern (seperti katana atau gau) sangat bergantung pada browser headless. Hal ini membuatnya terlalu berat untuk dijalankan di lingkungan mobile. 

`paramrecon` dibangun murni menggunakan `requests` dan `beautifulsoup4`. Tanpa konsumsi RAM besar, cocok untuk operasi pemetaan target (recon) cepat langsung dari perangkat Android.

## Fitur Utama 

- **URL Template Deduplication**: Mencegah pemborosan request pada URL dengan pola sama. Contoh: `/product/1` dan `/product/2` hanya akan di-crawl sekali.
- **Auth Endpoint Scoring**: Memberikan skor 0-100 pada kandidat form login. Tool akan memindai indikator seperti input password, method POST, dan CSRF token.
- **Soft-404 Detection**: Membedakan antara halaman 404 asli dengan halaman error yang menyamar sebagai status 200, meminimalisir hasil false positive saat brute-force.
- **Framework State Parsing**: Mampu mengekstrak parameter atau endpoint tersembunyi dari file JSON internal Next.js (`__NEXT_DATA__`) dan Nuxt (`__NUXT__`).
- **WAF Fingerprinting**: Mendeteksi keberadaan Web Application Firewall (Cloudflare, Akamai, AWS, Sucuri, dll) langsung dari response header.
- **Deep JS Parsing**: Mengekstrak endpoint API yang tersembunyi di dalam file JavaScript (`.js`).

## Keterbatasan 

Tool ini tidak sempurna. Batasan utamanya:
- **Tidak merender SPA.** Hanya membaca HTML awal. Jika form login baru muncul setelah JavaScript berjalan (client-side rendering), form tersebut tidak akan terdeteksi.
- Belum bisa me-resolve template literal JavaScript (seperti `fetch('/api/${id}')`).
- Belum melakukan pengujian submit form secara otomatis.
- Tidak memiliki fitur bypass WAF.

## Instalasi

```bash
pkg install python -y
pip install requests beautifulsoup4 colorama
git clone https://github.com/jackedxdd/paramrecon
cd paramrecon
```

Parameter CLI dan Fungsinya

Berikut adalah flag yang bisa digunakan beserta fungsinya:

Flag Fungsi
-m, --max-pages Batasan maksimal halaman yang akan di-crawl (default: 200).
-d, --depth Kedalaman crawl mengikuti link (default: 4).
-t, --threads Jumlah thread/pekerja paralel (default: 10).
--delay Jeda waktu (detik) antar request. Gunakan ini jika target memiliki WAF.
--subdomain Mengizinkan crawler untuk masuk ke subdomain yang ditemukan.
-H, --header Menyisipkan header kustom (misal: -H "Cookie: session=123").
--no-scan-js Mematikan fitur download dan pemindaian file JavaScript.
--js-limit Batasan maksimal file JS yang akan diunduh dan dipindai (default: 30).
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

2. Crawling dengan mode Brute-Force (mencari halaman admin):

```bash
python paramrecon.py https://target.com --brute
```

3. Scan area tertutup (menggunakan cookie login) + brute-force:

```bash
python paramrecon.py https://target.com --brute -H "Cookie: session=abcd1234"
```

4. Mode hemat kuota (tanpa download file JS, delay sopan):

```bash
python paramrecon.py https://target.com --brute --no-scan-js --delay 0.5 -t 5
```

5. Ekspor hasil ke laporan HTML:

```bash
python paramrecon.py https://target.com --brute --html laporan.html
```

Etika dan Legalitas

Tool ini hanya boleh digunakan pada target yang Anda miliki izin resmi untuk mengujinya ( seperti dilab pribadi )

Melakukan pemindaian (scanning) terhadap sistem orang tanpa izin tertulis adalah tindakan ilegal dan melanggar hukum (misal: UU ITE di Indonesia)
