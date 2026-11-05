# paramrecon

Parameter and auth endpoint recon crawler. Didesain buat Termux, jalan juga di Linux/macOS.

## DIBUAT KADENA

Tool recon lain kebanyakan butuh Playwright atau Chromium yang berat di HP.
Ini cuma butuh requests + bs4. Ringan, bisa jalan di Android.

## Kemampuan

- Crawl rekursif dengan dedup by URL template
- Extract query param, form input, JS endpoint
- Parse `__NEXT_DATA__` (Next.js) dan `__NUXT__` (Nuxt)
- Brute path common admin/login dengan soft-404 detection
- Auth endpoint scoring 0-100
- WAF detection (Cloudflare, Akamai, AWS, Sucuri, Fastly, Incapsula)
- Param filtering (buang noise Cloudflare dan JS minified)
- Param detail dengan contoh URL
- Export JSON dan HTML

## Batasan

- Nggak render SPA. Cuma baca HTML awal, jadi form yang muncul setelah JS jalan kelewat
- Belum resolve template literal JS
- Belum test form submission otomatis
- Belum bypass WAF

## Install

