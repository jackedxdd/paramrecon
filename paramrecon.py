#usr/bin/env python3
"""
paramrecon.py v2.2 — Advanced Parameter & Auth Recon Crawler
Termux-friendly. Authorized testing only.

Changelog v2.2:
  + Form dedup by path+method (fix 387→1 bug)
  + Param noise filter (CF, JS minified, single-char)
  + WAF detection (Cloudflare/Akamai/AWS/Sucuri/Incapsula)
  + Soft-404 baseline + content matching
  + Adaptive throttle saat 429/403
  + Param classification (real / suspect / noise)
  + Fix http→https sync ke findings.base
  + Brute grouped by status code
"""

import argparse
import json
import re
import sys
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import (
    urlparse, urljoin, urlunsplit, urldefrag, parse_qs, quote
)
from xml.etree import ElementTree as ET

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Load harvest module — patch paramrecon otomatis

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

VERSION = "2.2"

DEFAULT_UA = (
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122 Mobile Safari/537.36"
)

AUTH_PATH_HINTS = [
    "login", "signin", "sign-in", "sign_in", "auth", "authenticate",
    "logout", "signout", "sign-out", "register", "signup", "sign-up",
    "reset", "forgot", "password", "token", "oauth", "oidc", "saml",
    "session", "admin", "administrator", "account", "verify", "confirm",
    "2fa", "mfa", "callback", "sso", "realms",
    "el_", "_login", "user", "member", "profile", "dashboard",
    "manage", "panel", "backend", "control", "cp_", "wp-admin",
    "phpmyadmin", "myadmin", "moderator", "staff",
]

AUTH_PARAM_HINTS = [
    "user", "username", "email", "login", "pass", "password", "pwd",
    "token", "csrf", "csrf_token", "_token", "session", "sessionid",
    "auth", "apikey", "api_key", "secret", "otp", "code", "redirect",
    "next", "return", "return_to", "continue", "callback", "grant_type",
    "client_id", "client_secret", "response_type", "scope", "state",
    "redirect_uri", "redirect_url", "return_url", "return_to", "rurl",
]

# Param yang hampir pasti noise (CDN, tracker, JS minified)
NOISE_PARAMS = {
    "q", "ray", "dpl", "cfid", "cftoken", "null", "undefined", "true",
    "false", "NaN", "fn", "cf_chl_opt", "__cf_chl_tk", "__cf_chl_jschl_tk__",
    "gclid", "fbclid", "msclkid", "yclid", "_ga", "_gl", "ref", "ref_src",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
}

STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map",
    ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz", ".tar", ".exe",
)

JS_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)((?:/|https?://)[A-Za-z0-9_\-./?=&%:{}#]+)(?:"|'|`)"""
)
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.\w+|axios|\$\.(?:get|post|ajax)|\.open)\(\s*["'`]([^"'`]+)["'`]"""
)
JS_URL_PARAM_RE = re.compile(
    r"""[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=([^&\s"'`<>{}\\]*)"""
)

# WAF signatures — (header name, value pattern)
WAF_SIGNATURES = {
    "cloudflare": [
        ("server", "cloudflare"),
        ("cf-ray", None),
        ("cf-cache-status", None),
    ],
    "akamai": [
        ("server", "akamaighost"),
        ("x-akamai-transformed", None),
        ("akamai-grn", None),
    ],
    "aws_waf": [
        ("server", "awselb"),
        ("x-amzn-requestid", None),
        ("x-amz-cf-id", None),
    ],
    "sucuri": [
        ("x-sucuri-id", None),
        ("server", "sucuri"),
    ],
    "incapsula": [
        ("x-iinfo", None),
        ("visid_incap", None),
    ],
    "fastly": [
        ("x-fastly-request-id", None),
        ("x-served-by", "cache-"),
    ],
}

# Path wordlist
COMMON_PATHS = [
    "/login", "/login.php", "/login.html", "/signin", "/signin.php",
    "/auth", "/auth/login", "/authenticate", "/session/new",
    "/admin", "/admin/", "/admin.php", "/adminpanel", "/adminpanel/",
    "/administrator", "/administrator/", "/admin/login",
    "/admin/login.php", "/admin/login.html",
    "/backend", "/manage", "/dashboard",
    "/panel", "/cpanel", "/controlpanel", "/webadmin", "/sysadmin",
    "/wp-admin", "/wp-login.php", "/wp-admin/", "/administrator/index.php",
    "/user", "/user/login", "/users", "/users/login", "/member",
    "/members", "/account", "/account/login", "/profile",
    "/admin/index.php", "/login/index.php", "/user/index.php",
    "/admin/home.php", "/admin/dashboard.php",
    "/register", "/register.php", "/signup", "/signup.php",
    "/forgot", "/forgot.php", "/reset", "/reset.php",
    "/api", "/api/login", "/api/auth", "/api/v1/login",
    "/api/v1/auth", "/api/v2/auth", "/graphql",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/oauth/authorize", "/oauth/token", "/.well-known/openid-configuration",
    "/realms", "/auth/realms", "/sso", "/saml",
]

BANNER = r"""
   ___                          _
  / _ \__ _ _ __ _ __ ___  _ __| |_ _ __ ___  ___
 / /_)/ _` | '__| '_ ` _ \| '__| __| '__/ _ \/ _ \
/ ___/ (_| | |  | | | | | | |  | |_| | |  __/  __/
\/    \__,_|_|  |_| |_| |_|_|   \__|_|  \___|\___|
"""


# ---------- UI ----------
def print_banner():
    print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  Parameter & Auth Recon Crawler  v{VERSION}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Termux Edition · Authorized testing only{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  {'─'*54}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  by {Fore.GREEN}jackedxd{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  {'─'*54}{Style.RESET_ALL}")
    print()

def hr(char="─", n=60, color=Fore.BLUE):
    print(f"{color}{char*n}{Style.RESET_ALL}")


def conf_bar(score):
    lvl = max(0, min(10, score // 10))
    return "█" * lvl + "░" * (10 - lvl)


def conf_color(score):
    if score >= 60:
        return Fore.RED
    if score >= 30:
        return Fore.YELLOW
    return Fore.WHITE


def print_status(code, url, cur):
    if 200 <= code < 300:
        c = Fore.GREEN
    elif 300 <= code < 400:
        c = Fore.YELLOW
    elif 400 <= code < 500:
        c = Fore.RED
    else:
        c = Fore.MAGENTA
    print(f"  {Fore.CYAN}▸{Style.RESET_ALL} [{c}{code}{Style.RESET_ALL}] "
          f"{Fore.WHITE}{url}{Style.RESET_ALL} "
          f"{Fore.BLUE}(#{cur}){Style.RESET_ALL}")


# ---------- Data ----------
@dataclass
class AuthHit:
    url: str
    method: str = "GET"
    score: int = 0
    reasons: list = field(default_factory=list)
    variants: set = field(default_factory=set)
    source: str = ""


@dataclass
class Form:
    source: str
    action: str
    method: str
    params: list
    has_password: bool = False
    has_csrf: bool = False
    count: int = 1  # berapa kali ditemukan


class Findings:
    def __init__(self, base_url):
        self.base = base_url
        self.pages = {}
        self.params = defaultdict(set)  # name -> set(source_url)
        self.forms = []
        self._form_keys = set()
        self.js_endpoints = set()
        self.auth_hits = {}
        self.errors = []
        self.robots = []
        self.sitemap_urls = set()
        self.js_bundles_scanned = 0
        self.brute_probed = 0
        self.url_templates = defaultdict(set)
        self.crawl_count = 0
        self.waf_detected = None
        self.soft_404 = None

    def add_param(self, name, source_url):
        if not name:
            return
        # hard filter
        if len(name) < 2 or len(name) > 64:
            return
        if name.lower() in NOISE_PARAMS:
            return
        # JS minified pattern: single char, atau 1-2 char + 1 uppercase
        if len(name) <= 2:
            return
        if "cdn-cgi" in source_url or "__cf" in source_url:
            return
        self.params[name].add(source_url)

    def add_auth(self, url, reason, points=10, method="GET", source=""):
        p = urlparse(url)
        key = f"{p.netloc}{p.path}|{method.upper()}"
        hit = self.auth_hits.get(key)
        if not hit:
            hit = AuthHit(
                url=urlunsplit((p.scheme, p.netloc, p.path, "", "")),
                method=method.upper(), source=source,
            )
            self.auth_hits[key] = hit
        if reason not in hit.reasons:
            hit.reasons.append(reason)
            hit.score += points
        if p.query:
            hit.variants.add(p.query)

    def add_form(self, form: Form):
        p = urlparse(form.action)
        key = f"{p.netloc}{p.path}|{form.method.upper()}"
        if key in self._form_keys:
            # increment count yang udah ada
            for f in self.forms:
                fp = urlparse(f.action)
                fk = f"{fp.netloc}{fp.path}|{f.method.upper()}"
                if fk == key:
                    f.count += 1
                    return
        else:
            self._form_keys.add(key)
            self.forms.append(form)

    def classify_params(self):
        """Klasifikasi param: real / suspect / noise."""
        real, suspect = [], []
        for name, urls in self.params.items():
            auth_hit = any(h in name.lower() for h in AUTH_PARAM_HINTS)
            # heuristic real: muncul di >= 2 lokasi ATAU auth-related ATAU panjang >= 5
            if auth_hit or len(urls) >= 2 or len(name) >= 5:
                # filter yang mencurigakan: all uppercase + panjang < 6
                if name.isupper() and len(name) < 6:
                    suspect.append(name)
                else:
                    real.append(name)
            else:
                suspect.append(name)
        return sorted(real), sorted(suspect)

    def to_dict(self):
        real, suspect = self.classify_params()
        return {
            "version": VERSION,
            "base": self.base,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "waf_detected": self.waf_detected,
            "soft_404": self.soft_404,
            "stats": {
                "pages_crawled": len(self.pages),
                "unique_params": len(self.params),
                "real_params": len(real),
                "suspect_params": len(suspect),
                "unique_forms": len(self.forms),
                "js_endpoints": len(self.js_endpoints),
                "auth_hits": len(self.auth_hits),
                "sitemap_urls": len(self.sitemap_urls),
                "js_bundles_scanned": self.js_bundles_scanned,
                "brute_probed": self.brute_probed,
                "errors": len(self.errors),
            },
            "params": {
                "real": {p: sorted(self.params[p]) for p in real},
                "suspect": {p: sorted(self.params[p]) for p in suspect},
            },
            "forms": [
                {"source": f.source, "action": f.action, "method": f.method,
                 "params": f.params, "has_password": f.has_password,
                 "has_csrf": f.has_csrf, "seen_count": f.count}
                for f in self.forms
            ],
            "js_endpoints": sorted(self.js_endpoints),
            "auth_hits": [
                {"url": h.url, "method": h.method, "score": h.score,
                 "reasons": h.reasons, "variant_count": len(h.variants),
                 "variants_sample": sorted(h.variants)[:5],
                 "source": h.source}
                for h in sorted(self.auth_hits.values(), key=lambda x: -x.score)
            ],
            "robots": self.robots,
            "sitemap_urls": sorted(self.sitemap_urls),
            "errors": self.errors,
        }


# ---------- Helpers ----------
def is_auth_path(url):
    p = urlparse(url).path.lower()
    return any(h in p for h in AUTH_PATH_HINTS)

def url_template_key(url):
    """Normalize URL ke template key untuk dedup.
    /news/index.php?id=24 dan ?id=23 -> /news/index.php?id=*
    /news-1.html dan /news-2.html -> /*.html
    /user/123/profile dan /user/456/profile -> /user/*/profile
    """
    p = urlparse(url)
    path = p.path

    # ganti segmen angka murni -> *
    path = re.sub(r"/\d+(?=/|$)", "/*", path)

    # ganti segmen dengan angka di akhir (news-1, post-42) -> *
    path = re.sub(r"/[a-z]+-\d+(?=[./]|$)", "/*", path)

    # ganti nama file yang ada angkanya (news-1.html, page-2.php) -> *.ext
    path = re.sub(r"/[a-z]+-\d+\.(html?|php|asp|aspx|jsp)", "/*.\1", path)

    params = parse_qs(p.query, keep_blank_values=True)
    param_str = "&".join(f"{k}=*" for k in sorted(params)) if params else ""
    return f"{p.netloc}{path}?{param_str}"


def is_static(url):
    p = urlparse(url).path.lower()
    return any(p.endswith(e) for e in STATIC_EXT)


def is_same_scope(url, base_host, allow_sub=False):
    h = urlparse(url).netloc.lower()
    b = base_host.lower()
    if h == b:
        return True
    if allow_sub and h.endswith("." + b):
        return True
    return False


def normalize_url(url, base):
    joined = urldefrag(urljoin(base, url))[0]
    p = urlparse(joined)
    scheme = p.scheme.lower()
    if urlparse(base).scheme == "https" and scheme == "http":
        scheme = "https"
    safe_path = quote(p.path, safe="/:@!$&'()*+,;=-._~")
    safe_query = quote(p.query, safe="=&?/:@!$'()*+,;-._~%")
    return urlunsplit((scheme, p.netloc.lower(), safe_path, safe_query, ""))


def extract_query_params(url):
    qs = urlparse(url).query
    return list(parse_qs(qs, keep_blank_values=True).keys()) if qs else []


def extract_js_endpoints(text, base_url):
    found = set()
    for m in JS_ENDPOINT_RE.findall(text):
        if not any(x in m for x in ("?", "/api", "/v1/", "/v2/", "/v3/",
                                    "/auth", "/graphql", "/admin", "/user",
                                    "/account", "/login", "/register",
                                    "/oauth", "/token", "/session",
                                    "/realms", "/oidc", "/saml")):
            continue
        if is_static(m) or len(m) > 300:
            continue
        found.add(normalize_url(m, base_url))
    for m in FETCH_RE.findall(text):
        if m.startswith(("http://", "https://", "/")):
            found.add(normalize_url(m, base_url))
    return found


def extract_js_url_params(text):
    return {name for name, _ in JS_URL_PARAM_RE.findall(text)}


def detect_waf_from_headers(headers):
    """Detect WAF dari response headers."""
    hl = {k.lower(): (v or "").lower() for k, v in headers.items()}
    found = []
    for waf, sigs in WAF_SIGNATURES.items():
        for hdr, val in sigs:
            if hdr in hl:
                if val is None or val in hl[hdr]:
                    found.append(waf)
                    break
    return found[0] if found else None


# ---------- Fetcher ----------
class Fetcher:
    def __init__(self, headers=None, timeout=12, retries=2):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if headers:
            self.s.headers.update(headers)
        self.timeout = timeout
        self.retries = retries
        self.backoff = 0.0

    def get(self, url):
        # adaptive backoff: kalau banyak 429, jeda lebih lama
        if self.backoff:
            time.sleep(self.backoff)
        last = None
        for i in range(self.retries + 1):
            try:
                r = self.s.get(url, timeout=self.timeout,
                               verify=False, allow_redirects=True)
                # adaptive: kalau 429/403, tambah backoff
                if r.status_code == 429:
                    self.backoff = min(self.backoff + 0.5, 5.0)
                elif r.status_code in (403,) and "cloudflare" in str(r.headers).lower():
                    self.backoff = min(self.backoff + 0.2, 3.0)
                return r
            except Exception as e:
                last = e
                if i < self.retries:
                    time.sleep(0.4 * (i + 1))
        raise last


# ---------- Soft-404 ----------
def detect_soft_404(fetcher, base_url):
    import secrets
    junk = "/__recon_" + secrets.token_hex(6) + "__"
    try:
        r_junk = fetcher.get(base_url.rstrip("/") + junk)
        r_home = fetcher.get(base_url)
        return {
            "junk_code": r_junk.status_code,
            "junk_len": len(r_junk.content),
            "junk_text": r_junk.text[:2000].lower(),
            "home_len": len(r_home.content),
            "is_soft_404": r_junk.status_code == 200,
        }
    except Exception:
        return {"is_soft_404": False, "junk_code": 0, "junk_len": 0,
                "junk_text": "", "home_len": 0}


def is_likely_soft_404(r, baseline, tolerance=0.15):
    if not baseline.get("is_soft_404"):
        return False
    r_len = len(r.content)
    junk_len = baseline["junk_len"]
    if junk_len > 0 and abs(r_len - junk_len) / max(junk_len, 1) < tolerance:
        return True
    r_text = r.text[:2000].lower()
    junk_text = baseline["junk_text"]
    if junk_text and len(r_text) > 100:
        matches = sum(1 for i in range(0, min(len(r_text), len(junk_text)) - 50, 200)
                      if r_text[i:i+50] in junk_text)
        if matches >= 2:
            return True
    return False


# ---------- Parsers ----------
def parse_robots(fetcher, base_url):
    try:
        r = fetcher.get(urljoin(base_url, "/robots.txt"))
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    yield line
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and "*" not in path:
                        yield normalize_url(path, base_url)
    except Exception:
        pass


def parse_sitemap(fetcher, base_url):
    try:
        r = fetcher.get(urljoin(base_url, "/sitemap.xml"))
        if r.status_code != 200:
            return []
        urls = []
        try:
            root = ET.fromstring(r.content)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:loc", ns):
                if loc.text:
                    urls.append(loc.text.strip())
            for el in root.iter():
                if el.tag.endswith("loc") and el.text:
                    u = el.text.strip()
                    if u not in urls:
                        urls.append(u)
        except ET.ParseError:
            for m in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text):
                urls.append(m)
        return urls
    except Exception:
        return []


def walk_json(obj, source_url, findings):
    if isinstance(obj, str):
        for p in extract_query_params(obj):
            findings.add_param(p, source_url)
        if "/" in obj and len(obj) < 500:
            for ep in extract_js_endpoints(obj, source_url):
                findings.js_endpoints.add(ep)
                if is_auth_path(ep):
                    findings.add_auth(ep, "json-payload endpoint", 20,
                                      source="json-payload")
    elif isinstance(obj, dict):
        for v in obj.values():
            walk_json(v, source_url, findings)
    elif isinstance(obj, list):
        for v in obj:
            walk_json(v, source_url, findings)


def parse_next_data(html, url, findings):
    m = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                  html, re.S)
    if not m:
        return
    try:
        walk_json(json.loads(m.group(1)), url, findings)
    except Exception:
        pass


def parse_nuxt(html, url, findings):
    m = re.search(r"window\.__NUXT__\s*=\s*(\{.*?\})\s*;?\s*</script>",
                  html, re.S)
    if not m:
        return
    try:
        walk_json(json.loads(m.group(1)), url, findings)
    except Exception:
        pass


def parse_form(tag, source_url, findings):
    action = tag.get("action") or source_url
    abs_action = urljoin(source_url, action)
    method = (tag.get("method") or "get").lower()
    params = []
    has_pw = False
    has_csrf = False

    for inp in tag.find_all(["input", "textarea", "select"]):
        itype = (inp.get("type") or "").lower()
        if itype in ("submit", "button", "reset", "image"):
            continue
        name = inp.get("name") or inp.get("id") or inp.get("aria-label")
        if not name:
            continue
        params.append(name)
        findings.add_param(name, source_url)
        lname = name.lower()
        if itype == "password" or any(x in lname for x in ("pass", "pwd")):
            has_pw = True
        if any(x in lname for x in ("csrf", "_token", "authenticity", "xsrf")):
            has_csrf = True

    form = Form(source=source_url, action=abs_action, method=method,
                params=params, has_password=has_pw, has_csrf=has_csrf)
    findings.add_form(form)

    if is_auth_path(abs_action):
        findings.add_auth(abs_action, "action-has-auth-kw", 30,
                          method=method, source="form")
    if method == "post" and has_pw:
        findings.add_auth(abs_action, "post-with-password", 35,
                          method=method, source="form")
    if has_csrf:
        findings.add_auth(abs_action, "has-csrf-token", 10,
                          method=method, source="form")
    if any(x in " ".join(params).lower() for x in ("user", "email", "login")):
        findings.add_auth(abs_action, "has-identity-field", 15,
                          method=method, source="form")


def parse_html(html, url, findings):
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for p in extract_query_params(url):
        findings.add_param(p, url)
        if any(h in p.lower() for h in AUTH_PARAM_HINTS):
            findings.add_auth(url, f"auth-param-in-url:{p}", 15, source="url")

    for f_tag in soup.find_all("form"):
        parse_form(f_tag, url, findings)

    for a in soup.find_all("a", href=True):
        nxt = normalize_url(a["href"], url)
        if urlparse(nxt).scheme in ("http", "https"):
            links.append(nxt)

    for s in soup.find_all("script", src=True):
        links.append(normalize_url(s["src"], url))

    for s in soup.find_all("script"):
        if s.string:
            for ep in extract_js_endpoints(s.string, url):
                findings.js_endpoints.add(ep)
                for p in extract_query_params(ep):
                    findings.add_param(p, ep)
                if is_auth_path(ep):
                    findings.add_auth(ep, "inline-js-endpoint", 20,
                                      source="inline-js")
            for p in extract_js_url_params(s.string):
                findings.add_param(p, url)

    parse_next_data(html, url, findings)
    parse_nuxt(html, url, findings)

    for meta in soup.find_all("meta"):
        content = (meta.get("content") or "").strip()
        if "url=" in content.lower():
            u = content.split("=", 1)[1].strip("'\" ")
            if u.startswith(("http", "/")):
                links.append(normalize_url(u, url))

    if is_auth_path(url):
        findings.add_auth(url, "url-path-has-auth-kw", 25, source="url")

    return links


def scan_js_bundle(fetcher, url, findings, base_host, max_bytes=500_000):
    try:
        r = fetcher.get(url)
        if r.status_code != 200:
            return
        text = r.text[:max_bytes]
        findings.js_bundles_scanned += 1
        for ep in extract_js_endpoints(text, url):
            if not is_same_scope(ep, base_host, allow_sub=True):
                continue
            findings.js_endpoints.add(ep)
            for p in extract_query_params(ep):
                findings.add_param(p, ep)
            if is_auth_path(ep):
                findings.add_auth(ep, "js-bundle-endpoint", 20,
                                  source="js-bundle")
        for p in extract_js_url_params(text):
            findings.add_param(p, url)
    except Exception:
        pass


# ---------- Brute ----------
def brute_paths(fetcher, base_url, findings, paths, threads=8, delay=0.0):
    base = base_url.rstrip("/")
    print(f"\n{Fore.YELLOW}[*]{Style.RESET_ALL} "
          f"Brute-forcing {len(paths)} common paths...")

    baseline = detect_soft_404(fetcher, base)
    findings.soft_404 = baseline
    if baseline["is_soft_404"]:
        print(f"  {Fore.RED}[!]{Style.RESET_ALL} "
              f"Target return {baseline['junk_code']} untuk path random → "
              f"{Fore.RED}SOFT-404 terdeteksi{Style.RESET_ALL}")
        print(f"  {Fore.RED}[!]{Style.RESET_ALL} "
              f"Hasil brute difilter content-based")
    else:
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} "
              f"Baseline OK (junk → {baseline['junk_code']})")

    hr("·", 60, Fore.YELLOW)

    def probe(path):
        url = base + path
        try:
            return (url, fetcher.get(url))
        except Exception:
            return (url, None)

    hits_by_status = defaultdict(list)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(probe, p) for p in paths]
        for fut in as_completed(futs):
            url, r = fut.result()
            findings.brute_probed += 1
            if r is None:
                continue
            code = r.status_code

            if code == 200 and is_likely_soft_404(r, baseline):
                continue

            if code in (200, 401, 403):
                hits_by_status[code].append(url)
                findings.pages[url] = {"status": code, "type": "bruteforce"}

                if code in (401, 403):
                    findings.add_auth(url, f"brute-{code}-protected", 40,
                                      source="brute")
                elif code == 200:
                    text = r.text[:5000].lower()
                    if "<form" in text and ("password" in text or "login" in text):
                        findings.add_auth(url, "brute-200-real-login-form", 50,
                                          source="brute")
                        try:
                            parse_html(r.text, url, findings)
                        except Exception:
                            pass
                    elif "password" in text or "signin" in text:
                        findings.add_auth(url, "brute-200-login-text", 35,
                                          source="brute")
                    elif any(x in text for x in ("dashboard", "control panel",
                                                  "administration", "admin panel")):
                        findings.add_auth(url, "brute-200-admin-content", 30,
                                          source="brute")
                    else:
                        findings.add_auth(url, "brute-200-exists-unverified", 5,
                                          source="brute")

            elif code in (301, 302, 307, 308):
                loc = (r.headers.get("Location") or "").lower()
                if any(x in loc for x in ("login", "auth", "signin", "admin")):
                    hits_by_status[code].append(url + f" → {loc[:40]}")
                    findings.add_auth(url, f"brute-{code}-redirects-to-auth",
                                      30, source="brute")

            if delay:
                time.sleep(delay)

    # print grouped
    for code in sorted(hits_by_status):
        c = Fore.GREEN if code == 200 else Fore.YELLOW
        print(f"\n  {c}[{code}]{Style.RESET_ALL} ({len(hits_by_status[code])} hits)")
        for u in hits_by_status[code]:
            print(f"    {Fore.WHITE}{u}{Style.RESET_ALL}")


# ---------- Base resolver ----------
def resolve_base(start_url, fetcher):
    if start_url.startswith("http://"):
        https_ver = "https://" + start_url[7:]
        try:
            r = fetcher.get(https_ver)
            if r.status_code < 500:
                print(f"  {Fore.CYAN}[i]{Style.RESET_ALL} "
                      f"HTTPS tersedia, pakai {https_ver}")
                return https_ver
        except Exception:
            pass
    return start_url


# ---------- Crawler ----------
def crawl(start_url, max_pages=200, depth=4, threads=10, delay=0.0,
          allow_sub=False, headers=None, scan_js=True, js_limit=30,
          use_robots=True, use_sitemap=True):
    findings = Findings(start_url)
    fetcher = Fetcher(headers=headers)
    start_url = resolve_base(start_url, fetcher)
    findings.base = start_url  # FIX: sync base
    base_host = urlparse(start_url).netloc

    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Target     : {Fore.WHITE}{start_url}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Max pages  : {Fore.WHITE}{max_pages}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Depth      : {Fore.WHITE}{depth}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Threads    : {Fore.WHITE}{threads}")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Delay      : {Fore.WHITE}{delay}s")
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Scan JS    : {Fore.WHITE}{scan_js} (limit {js_limit})")
    hr()
    print(f"{Fore.CYAN}  LIVE CRAWL{Style.RESET_ALL}")
    hr("·")

    queue = deque()
    seen = set()

    def enqueue(u, d):
        if u in seen or not is_same_scope(u, base_host, allow_sub) or is_static(u):
            return
        if u.startswith("http://"):
            if ("https://" + u[7:]) in seen:
                return
        seen.add(u)
        queue.append((u, d))

    if use_robots:
        for u in parse_robots(fetcher, start_url):
            if isinstance(u, str) and u.startswith(("http", "/")):
                if u.startswith("http"):
                    enqueue(u, 1)
                elif u.startswith("/"):
                    enqueue(normalize_url(u, start_url), 1)
                else:
                    findings.robots.append(u)

    if use_sitemap:
        for u in parse_sitemap(fetcher, start_url):
            findings.sitemap_urls.add(u)
            enqueue(u, 1)

    enqueue(start_url, 0)

    js_bundles = set()
    js_scanned = 0
    done = 0
    start_time = time.time()
    waf_checked = False

    while queue and len(findings.pages) < max_pages:
        batch = []
        while queue and len(batch) < threads and len(findings.pages) + len(batch) < max_pages:
            batch.append(queue.popleft())
        if not batch:
            break

        # filter by template
        new_batch = []
        for u, d in batch:
            tmpl = url_template_key(u)
            if tmpl in findings.url_templates and findings.url_templates[tmpl]:
                findings.url_templates[tmpl].add(u)
                continue
            findings.url_templates[tmpl].add(u)
            new_batch.append((u, d))
        batch = new_batch

        if not batch:
            continue
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(fetcher.get, u): (u, d) for u, d in batch}
            for fut in as_completed(futs):
                url, d = futs[fut]
                done += 1
                try:
                    r = fut.result()
                except Exception as e:
                    findings.errors.append({"url": url, "error": str(e)[:120]})
                    print(f"  {Fore.RED}✗ {url} — {str(e)[:60]}{Style.RESET_ALL}")
                    continue

                # WAF detection (sekali aja)
                if not waf_checked:
                    waf = detect_waf_from_headers(r.headers)
                    if waf:
                        findings.waf_detected = waf
                        print(f"  {Fore.RED}[!]{Style.RESET_ALL} "
                              f"WAF terdeteksi: {Fore.RED}{waf.upper()}{Style.RESET_ALL} "
                              f"— hati-hati rate limit")
                    waf_checked = True

                ctype = r.headers.get("Content-Type", "").lower()
                print_status(r.status_code, url, done)
                findings.pages[url] = {"status": r.status_code, "type": ctype[:60]}
                findings.crawl_count += 1

                hkeys = {k.lower() for k in r.headers.keys()}
                if "set-cookie" in hkeys and is_auth_path(url):
                    findings.add_auth(url, "set-cookie-on-auth-path", 20,
                                      source="response")
                if "www-authenticate" in hkeys:
                    findings.add_auth(url, "www-authenticate-header", 35,
                                      source="response")

                if "html" in ctype:
                    links = parse_html(r.text, url, findings)
                    for link in links:
                        if link.endswith(".js") and is_same_scope(link, base_host, True):
                            js_bundles.add(link)
                    if d < depth:
                        for link in links:
                            enqueue(link, d + 1)
                elif "javascript" in ctype:
                    js_bundles.add(url)

                if delay:
                    time.sleep(delay)

        if scan_js and js_bundles and js_scanned < js_limit:
            batch_js = list(js_bundles)
            js_bundles.clear()
            for b in batch_js:
                if js_scanned >= js_limit:
                    js_bundles.add(b)
                    continue
                scan_js_bundle(fetcher, b, findings, base_host)
                js_scanned += 1

    elapsed = time.time() - start_time
    return findings, elapsed


# ---------- Summary ----------
def print_summary(f, elapsed):
    s = f.to_dict()["stats"]
    print()
    hr("═", 60, Fore.MAGENTA)
    print(f"{Fore.MAGENTA}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    hr("═", 60, Fore.MAGENTA)

    if f.waf_detected:
        print(f"  {Fore.RED}[!]{Style.RESET_ALL} WAF detected : "
              f"{Fore.RED}{f.waf_detected.upper()}{Style.RESET_ALL}")

    rows = [
        ("Pages crawled",   f'{s["pages_crawled"]} ({len(f.url_templates)} unique)', Fore.CYAN),
        ("Real params",     s["real_params"],         Fore.GREEN),
        ("Suspect params",  s["suspect_params"],      Fore.YELLOW if s["suspect_params"] else Fore.WHITE),
        ("Unique forms",    s["unique_forms"],        Fore.CYAN),
        ("JS endpoints",    s["js_endpoints"],        Fore.CYAN),
        ("JS bundles",      s["js_bundles_scanned"],  Fore.CYAN),
        ("Sitemap URLs",    s["sitemap_urls"],        Fore.CYAN),
        ("Brute probed",    s["brute_probed"],        Fore.CYAN),
        ("Auth hits",       s["auth_hits"],           Fore.YELLOW if s["auth_hits"] else Fore.WHITE),
        ("Errors",          s["errors"],              Fore.RED if s["errors"] else Fore.WHITE),
        ("Elapsed",         f"{elapsed:.1f}s",        Fore.WHITE),
    ]
    for k, v, c in rows:
        print(f"  {Fore.WHITE}{k:<16}{Style.RESET_ALL} : {c}{v}{Style.RESET_ALL}")

    if f.auth_hits:
        print()
        hr("─", 60, Fore.YELLOW)
        print(f"{Fore.YELLOW}{Style.BRIGHT}    AUTH ENDPOINTS ({len(f.auth_hits)}){Style.RESET_ALL}")
        hr("─", 60, Fore.YELLOW)
        for h in sorted(f.auth_hits.values(), key=lambda x: -x.score):
            print(f"  {conf_color(h.score)}{conf_bar(h.score)}{Style.RESET_ALL} "
                  f"{Fore.WHITE}[{h.method}]{Style.RESET_ALL} "
                  f"{Fore.CYAN}{h.url}{Style.RESET_ALL} "
                  f"{Fore.WHITE}(score={h.score}){Style.RESET_ALL}")
            print(f"       {Fore.WHITE}{'; '.join(h.reasons)}{Style.RESET_ALL}")
            if h.variants:
                print(f"       {Fore.BLUE}variants: {len(h.variants)}{Style.RESET_ALL}")

    real, suspect = f.classify_params()
    if real or suspect:
        print()
        hr("─", 60, Fore.CYAN)
        print(f"{Fore.CYAN}{Style.BRIGHT}   PARAMETERS ({len(real)} real, {len(suspect)} suspect){Style.RESET_ALL}")
        hr("─", 60, Fore.CYAN)
        if real:
            print(f"  {Fore.GREEN}real params:{Style.RESET_ALL}")
            for p in real:
                auth_mark = " [auth]" if any(h in p.lower() for h in AUTH_PARAM_HINTS) else ""
                urls = sorted(f.params[p])
                print(f"    {Fore.GREEN}{p}{Style.RESET_ALL} "
                      f"{Fore.BLUE}({len(urls)} loc){Style.RESET_ALL}"
                      f"{Fore.YELLOW}{auth_mark}{Style.RESET_ALL}")
                for u in urls[:3]:
                    print(f"      {Fore.WHITE}{u}{Style.RESET_ALL}")
                if len(urls) > 3:
                    print(f"      {Fore.WHITE}... dan {len(urls) - 3} lainnya{Style.RESET_ALL}")
        if suspect:
            print(f"  {Fore.YELLOW}? suspect (JS var / noise?):{Style.RESET_ALL}")
            for p in suspect[:20]:
                print(f"    {Fore.YELLOW}{p}{Style.RESET_ALL} "
                      f"{Fore.BLUE}({len(f.params[p])} loc){Style.RESET_ALL}")
            if len(suspect) > 20:
                print(f"    ... +{len(suspect) - 20} lagi")

    if f.forms:
        print()
        hr("─", 60, Fore.GREEN)
        print(f"{Fore.GREEN}{Style.BRIGHT}  📝 FORMS ({len(f.forms)} unique){Style.RESET_ALL}")
        hr("─", 60, Fore.GREEN)
        interesting = [fm for fm in f.forms if fm.has_password or fm.method == "post"]
        for fm in interesting[:25]:
            mc = Fore.RED if fm.method == "post" else Fore.GREEN
            flag = " 🔑" if fm.has_password else ""
            cnt = f" (seen {fm.count}x)" if fm.count > 1 else ""
            print(f"  {mc}[{fm.method.upper()}]{Style.RESET_ALL} "
                  f"{Fore.WHITE}{fm.action}{Style.RESET_ALL}{flag}{cnt}")
            print(f"      params: {', '.join(fm.params) or '-'}")
        if len(interesting) > 25:
            print(f"  ... +{len(interesting) - 25} POST/password forms lagi")


# ---------- Reports ----------
def save_json(f, path):
    with open(path, "w") as fp:
        json.dump(f.to_dict(), fp, indent=2)
    print(f"\n  {Fore.GREEN}✓{Style.RESET_ALL} JSON → {Fore.CYAN}{path}{Style.RESET_ALL}")


def save_html(f, path):
    d = f.to_dict()
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                   for k, v in d["stats"].items())
    real_params = d["params"]["real"]
    suspect_params = d["params"]["suspect"]
    params_html = "".join(
        f"<tr><td><code>{p}</code></td><td>{len(real_params[p])}</td></tr>"
        for p in sorted(real_params))
    suspect_html = "".join(
        f"<tr><td><code>{p}</code></td><td>{len(suspect_params[p])}</td></tr>"
        for p in sorted(suspect_params))
    auth = "".join(
        f"<tr><td>{h['score']}</td><td><code>{h['url']}</code></td>"
        f"<td>{h['method']}</td><td>{'; '.join(h['reasons'])}</td></tr>"
        for h in d["auth_hits"])
    forms = "".join(
        f"<tr><td>{x['method'].upper()}</td><td><code>{x['action']}</code></td>"
        f"<td>{', '.join(x['params'])}</td><td>{x['seen_count']}</td></tr>"
        for x in d["forms"])

    waf_banner = ""
    if d.get("waf_detected"):
        waf_banner = (f'<p style="color:#f87171">  WAF detected: '
                      f'<strong>{d["waf_detected"].upper()}</strong></p>')

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recon — {d['base']}</title>
<style>
body {{ font-family:-apple-system,system-ui,sans-serif; margin:20px;
        background:#0f172a; color:#e2e8f0; }}
h1,h2 {{ color:#38bdf8; border-bottom:1px solid #1e293b; padding-bottom:6px; }}
table {{ border-collapse:collapse; width:100%; margin:12px 0;
         background:#111827; }}
th,td {{ padding:8px 12px; border:1px solid #1e293b; text-align:left;
         font-size:14px; }}
th {{ background:#1e293b; color:#38bdf8; }}
code {{ background:#1e293b; padding:2px 6px; border-radius:3px;
        color:#fbbf24; }}
</style></head><body>
<h1>Recon Report — {d['base']}</h1>
<p><em>Scanned: {d['scanned_at']} · v{d['version']}</em></p>
{waf_banner}
<h2>Stats</h2><table>{rows}</table>
<h2>Auth Endpoints ({len(d['auth_hits'])})</h2>
<table><tr><th>Score</th><th>URL</th><th>Method</th><th>Reasons</th></tr>
{auth}</table>
<h2>Parameters — Real ({len(real_params)})</h2>
<table><tr><th>Param</th><th>Locations</th></tr>{params_html}</table>
<h2>Parameters — Suspect ({len(suspect_params)})</h2>
<table><tr><th>Param</th><th>Locations</th></tr>{suspect_html}</table>
<h2>Forms — Unique ({len(d['forms'])})</h2>
<table><tr><th>Method</th><th>Action</th><th>Params</th><th>Seen</th></tr>
{forms}</table>
</body></html>"""
    with open(path, "w") as fp:
        fp.write(html)
    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} HTML → {Fore.CYAN}{path}{Style.RESET_ALL}")


# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(
        description="Advanced Parameter & Auth Recon Crawler (authorized only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
contoh:
  paramrecon.py https://target.com
  paramrecon.py https://target.com --brute
  paramrecon.py https://target.com --brute --delay 0.5 -t 4
  paramrecon.py https://target.com -H "Cookie: session=xxx" --html r.html
        """)
    ap.add_argument("url")
    ap.add_argument("-m", "--max-pages", type=int, default=200)
    ap.add_argument("-d", "--depth", type=int, default=4)
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--subdomain", action="store_true")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("--no-scan-js", dest="scan_js", action="store_false")
    ap.add_argument("--js-limit", type=int, default=30)
    ap.add_argument("--no-robots", dest="use_robots", action="store_false")
    ap.add_argument("--no-sitemap", dest="use_sitemap", action="store_false")
    ap.add_argument("--brute", action="store_true",
                    help="Brute-force common auth/admin paths")
    ap.add_argument("--brute-wordlist",
                    help="Custom wordlist file (one path per line)")
    ap.add_argument("-o", "--output", default="recon_result.json")
    ap.add_argument("--html", help="export HTML report")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        print_banner()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    f, elapsed = crawl(
        args.url,
        max_pages=args.max_pages,
        depth=args.depth,
        threads=args.threads,
        delay=args.delay,
        allow_sub=args.subdomain,
        headers=headers,
        scan_js=args.scan_js,
        js_limit=args.js_limit,
        use_robots=args.use_robots,
        use_sitemap=args.use_sitemap,
    )

    if args.brute:
        brute_list = COMMON_PATHS
        if args.brute_wordlist:
            try:
                with open(args.brute_wordlist) as wf:
                    brute_list = [
                        (l.strip() if l.strip().startswith("/") else "/" + l.strip())
                        for l in wf
                        if l.strip() and not l.strip().startswith("#")
                    ]
            except FileNotFoundError:
                print(f"{Fore.RED}[!] Wordlist tidak ditemukan: "
                      f"{args.brute_wordlist}{Style.RESET_ALL}")
        brute_fetcher = Fetcher(headers=headers)
        brute_paths(brute_fetcher, f.base, f, brute_list,
                    threads=args.threads, delay=args.delay)

    print_summary(f, elapsed)
    save_json(f, args.output)
    if args.html:
        save_html(f, args.html)




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(1)
