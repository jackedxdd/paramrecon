import hashlib
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

COMMON_PARAMS = [
    "id", "user", "username", "admin", "debug", "test", "token", "key",
    "api_key", "page", "q", "search", "redirect", "url", "file", "path",
    "action", "type", "mode", "format", "callback", "jsonp", "return",
    "next", "view", "lang", "category", "sort", "filter", "limit", "offset",
    "email", "password", "auth", "role", "config", "env", "secret", "data",
    "v", "ver", "version", "src", "source", "dest", "target", "link"
]

def get_signature(resp):
    if not resp:
        return None
    content = resp.text.strip()
    return (resp.status_code, len(content), hashlib.md5(content.encode('utf-8', errors='ignore')).hexdigest())

def test_params(fetcher, url, params_list):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for p in params_list:
        query[p] = ["1"]
    new_query = urlencode(query, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        return fetcher.get(test_url)
    except:
        return None

def scan_url(fetcher, url):
    found = []
    try:
        baseline = fetcher.get(url)
        base_sig = get_signature(baseline)
    except:
        return found
        
    if not base_sig:
        return found

    # Coba semua parameter sekaligus (chunking)
    all_resp = test_params(fetcher, url, COMMON_PARAMS)
    all_sig = get_signature(all_resp)
    
    if all_sig and all_sig != base_sig:
        # Anomali terdeteksi, pecah chunk satu per satu
        for p in COMMON_PARAMS:
            resp = test_params(fetcher, url, [p])
            sig = get_signature(resp)
            if sig and sig != base_sig:
                found.append(p)
    return found

def hunt_hidden_params(fetcher, urls, max_urls=20, threads=5):
    urls = urls[:max_urls]
    print(f"\n[+] Active Parameter Discovery: Menguji {len(COMMON_PARAMS)} parameter pada {len(urls)} endpoint...")
    
    found_params = {}
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_url, fetcher, url): url for url in urls}
            # Progress bar biar lu tau prosesnya jalan
            for future in tqdm(as_completed(futures), total=len(urls), desc="Fuzzing", unit="url", ncols=70):
                url = futures[future]
                try:
                    params = future.result()
                    if params:
                        found_params[url] = params
                        tqdm.write(f"  [FOUND] {url} -> {', '.join(params)}")
                except Exception:
                    pass
    except KeyboardInterrupt:
        print("\n[!] Dihentikan paksa oleh user (Ctrl+C).")
        sys.exit(1)
        
    return found_params
