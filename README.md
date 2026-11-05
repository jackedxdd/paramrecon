# paramrecon

Crawler buat nyari parameter web dan endpoint auth. Gw bikin ini karena sering banget butuh tool recon pas lagi di luar, tapi males bawa laptop. 

## Kenapa gw bikin ini?

Kita tau lah ya, tool recon kaya katana atau gau itu mantap, tapi butuh Playwright/Chromium. Coba jalanin itu di HP atau Termux, dijamin RAM langsung jebol dan crash. 

Nah, `paramrecon` ini cuma pakai `requests` sama `bs4`. Ringan banget, jalan di HP kentang juga aman. Cocok buat lu yang suka iseng mapping target langsung dari Android.

## Bisa apa aja?

- Crawl website rekursif, plus pinter banget buat dedup URL template (jadi `/news/1`, `/news/2`, `/news/3` cuma di-crawl sekali, hemat kuota).
- Ekstrak query parameter, form input, dan endpoint JS.
- Bisa baca `__NEXT_DATA__` (Next.js) sama `__NUXT__` (Nuxt).
- Brute path admin/login umum, lengkap sama deteksi soft-404 biar nggak dapet false positive.
- Kasih skor 0-100 buat endpoint login, jadi lu tau mana yang paling worth buat di-explore.
- Deteksi WAF (Cloudflare, Akamai, AWS, dll) biar lu tau kalau targetnya lagi nge-block lu.
- Buang parameter sampah dari Cloudflare sama JS minified.
- Tampilin contoh URL biar lu nggak bingung parameternya dari mana.
- Export hasil ke format JSON atau HTML.

## Nggak bisa apa (Jujur)

Biar nggak berharap terlalu tinggi, ini kekurangannya:
- **Nggak bisa render SPA.** Tool ini cuma baca HTML awal. Kalau targetnya pakai React/Vue yang form loginnya baru muncul setelah JS jalan, bakal kelewat.
- Belum bisa resolve template literal kaya `fetch('/api/${id}')`.
- Belum bisa nge-POST data dummy buat ngetes form secara otomatis.
- Kalau Cloudflare nge-block mentah-mentah, ya gw nyerah (belum bisa bypass).

## Cara Install

```bash
pkg install python -y
pip install requests beautifulsoup4 colorama
git clone https://github.com/jackedxdd/paramrecon
cd paramrecon
