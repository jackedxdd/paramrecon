# paramrecon

Web crawler untuk ekstraksi parameter dan pemetaan endpoint autentikasi. Dirancang khusus agar berjalan ringan secara native di Termux (Android).

## Latar Belakang

Sebagian besar tool recon modern (seperti katana atau gau) sangat bergantung pada Playwright atau Chromium. Hal ini membuatnya terlalu berat untuk dijalankan di lingkungan mobile. 

`paramrecon` dibangun murni menggunakan `requests` dan `beautifulsoup4`. Tanpa browser headless, tanpa konsumsi RAM besar. Cocok untuk operasi recon cepat langsung dari perangkat Android.

## Fitur Utama

- Crawling rekursif dengan deduplikasi berbasis URL template (contoh: `/news/1` dan `/news/2` hanya akan di-crawl sekali).
- Ekstraksi query parameter, form input, dan endpoint dari file JavaScript.
- Dukungan parser untuk `__NEXT_DATA__` (Next.js) dan `__NUXT__` (Nuxt).
- Brute-force path admin/login umum, dilengkapi deteksi soft-404 untuk meminimalisir false positive.
- Skoring endpoint autentikasi (0-100) berdasarkan indikator keamanan.
- Deteksi WAF (Cloudflare, Akamai, AWS, Sucuri, dll).
- Filter noise untuk parameter dari Cloudflare dan JS minified.
- Ekspor hasil dalam format JSON atau HTML.

## Keterbatasan (Baca Sebelum Pakai)

Tool ini tidak sempurna. Batasan utamanya:
- **Tidak merender SPA.** Hanya membaca HTML awal. Jika form login baru muncul setelah JavaScript berjalan (client-side rendering), form tersebut tidak akan terdeteksi.
- Belum bisa me-resolve template literal JavaScript (seperti `fetch('/api/${id}')`).
- Belum melakukan pengujian submit form secara otomatis.
- Tidak memiliki fitur bypass WAF. Jika diblokir oleh Cloudflare, tool ini tidak akan bisa menembus.

## Instalasi

```bash
pkg install python -y
pip install requests beautifulsoup4 colorama
git clone https://github.com/jackedxdd/paramrecon
cd paramrecon
