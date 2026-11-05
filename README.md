# paramrecon

Crawler buat cari parameter dan endpoint auth. Gua bikin ini karena butuh
tool recon ringan yang bisa jalan di Termux, nggak harus bawa laptop.

## Kenapa

Tool recon lain kayak katana atau gau butuh Playwright/Chromium. Di HP itu
berat, makan RAM, dan sering crash. paramrecon cuma pakai requests + bs4,
jalan di HP kentang juga masih sanggup.

## Bisa apa

- Crawl rekursif, dedup by URL template (jadi /news/1, /news/2, /news/3 cuma di-crawl sekali)
- Extract query param, form input, JS endpoint
- Parse `__NEXT_DATA__` (Next.js) dan `__NUXT__` (Nuxt)
- Brute path admin/login umum, plus deteksi soft-404 biar nggak false positive
- Kasih score 0-100 buat endpoint auth, berdasarkan alasan yang jelas
- Deteksi WAF: Cloudflare, Akamai, AWS, Sucuri, Fastly, Incapsula
- Filter param sampah dari Cloudflare dan JS minified
- Param detail, ada contoh URL-nya
- Export JSON atau HTML

## Nggak bisa apa

Jujur ya, ini masih ada bolongnya:

- Nggak render SPA. Cuma baca HTML awal, jadi kalau form-nya muncul setelah
  JS jalan, bakal kelewat. Kalau target pakai React/Vue full client-side,
  hasilnya bakal minim.
- Belum bisa resolve template literal kayak `fetch('/api/${id}')`
- Belum test form submission otomatis (belum POST dummy buat cek auth)
- Belum bisa bypass WAF. Kalau Cloudflare nge-block, ya udah.

## Install

```bash
pkg install python -y
pip install requests beautifulsoup4 colorama
git clone https://github.com/jackedxdd/paramrecon
cd paramrecon
