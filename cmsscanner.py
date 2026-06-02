#!/usr/bin/env python3
"""
Author: Jonathan Ash
techdetect.py — Web technology / CMS fingerprinter for AUTHORIZED pentest recon.

Passively analyses HTTP responses (headers, cookies, HTML, scripts, meta tags)
to identify: web server, programming language, CMS, server-side framework,
frontend frameworks/libraries, CDN/WAF, and (inferred) database backend.
Optionally fingerprints the favicon (Shodan/mmh3 style) and probes common
sensitive paths.

USE ONLY against systems you own or have explicit written permission to test.

Dependencies:
    pip install requests beautifulsoup4
    pip install mmh3            # optional, enables favicon hashing

Examples:
    python3 techdetect.py https://example.com
    python3 techdetect.py https://example.com --paths --favicon
    python3 techdetect.py https://example.com --json -o report.json
"""

import argparse
import base64
import json
import re
import sys
import warnings
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter("ignore", InsecureRequestWarning)
except ImportError:
    sys.exit("[!] Missing dependency. Run: pip install requests beautifulsoup4")

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import mmh3
    HAVE_MMH3 = True
except ImportError:
    HAVE_MMH3 = False


DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# --------------------------------------------------------------------------- #
# Signatures
# Each signature: category, name, and any of these optional matchers:
#   header   : (header_name, regex)        -> match against a response header
#   cookie   : regex                       -> match against a Set-Cookie name
#   meta_gen : regex                       -> match against <meta name=generator>
#   html     : regex                       -> match against page body
#   script   : regex                       -> match against any <script src=...>
#   version  : regex with one capture group, applied to the matched string
# --------------------------------------------------------------------------- #
SIGNATURES = [
    # ---- Web servers -----------------------------------------------------
    {"cat": "Web Server", "name": "Apache",     "header": ("Server", r"Apache"),      "version": r"Apache/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "nginx",       "header": ("Server", r"nginx"),       "version": r"nginx/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "Microsoft IIS","header": ("Server", r"IIS|Microsoft-IIS"), "version": r"IIS/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "LiteSpeed",   "header": ("Server", r"LiteSpeed")},
    {"cat": "Web Server", "name": "Apache Tomcat","header": ("Server", r"Tomcat|Coyote"), "version": r"Coyote/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "Caddy",       "header": ("Server", r"Caddy")},
    {"cat": "Web Server", "name": "gunicorn",    "header": ("Server", r"gunicorn"),    "version": r"gunicorn/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "Werkzeug",    "header": ("Server", r"Werkzeug"),    "version": r"Werkzeug/?\s*([\d.]+)"},
    {"cat": "Web Server", "name": "OpenResty",   "header": ("Server", r"openresty")},

    # ---- Languages -------------------------------------------------------
    {"cat": "Language", "name": "PHP",     "header": ("X-Powered-By", r"PHP"), "version": r"PHP/?\s*([\d.]+)"},
    {"cat": "Language", "name": "PHP",     "cookie": r"PHPSESSID"},
    {"cat": "Language", "name": "ASP.NET", "header": ("X-AspNet-Version", r".+"), "version": r"([\d.]+)"},
    {"cat": "Language", "name": "ASP.NET", "header": ("X-Powered-By", r"ASP\.NET")},
    {"cat": "Language", "name": "ASP.NET", "cookie": r"ASP\.NET_SessionId"},
    {"cat": "Language", "name": "ASP.NET", "html": r"__VIEWSTATE"},
    {"cat": "Language", "name": "Java",    "cookie": r"JSESSIONID"},
    {"cat": "Language", "name": "Java",    "html": r"\.(jsp|do|action)(\?|\"|')"},
    {"cat": "Language", "name": "Node.js", "header": ("X-Powered-By", r"Express")},
    {"cat": "Language", "name": "Python",  "cookie": r"csrftoken|sessionid"},
    {"cat": "Language", "name": "Ruby",    "cookie": r"_session_id|_rails"},
    {"cat": "Language", "name": "Perl",    "header": ("X-Powered-By", r"Perl")},

    # ---- Server-side frameworks -----------------------------------------
    {"cat": "Framework", "name": "Laravel",     "cookie": r"laravel_session|XSRF-TOKEN"},
    {"cat": "Framework", "name": "Symfony",     "header": ("X-Debug-Token-Link", r".+")},
    {"cat": "Framework", "name": "Symfony",     "cookie": r"sf_redirect|symfony"},
    {"cat": "Framework", "name": "CodeIgniter", "cookie": r"ci_session|ci_csrf"},
    {"cat": "Framework", "name": "Django",      "html": r"csrfmiddlewaretoken"},
    {"cat": "Framework", "name": "Ruby on Rails","header": ("X-Runtime", r".+")},
    {"cat": "Framework", "name": "Ruby on Rails","html": r'csrf-param" content="authenticity_token'},
    {"cat": "Framework", "name": "ASP.NET MVC", "header": ("X-AspNetMvc-Version", r".+"), "version": r"([\d.]+)"},
    {"cat": "Framework", "name": "Spring",      "header": ("X-Application-Context", r".+")},
    {"cat": "Framework", "name": "Express",     "header": ("X-Powered-By", r"Express")},
    {"cat": "Framework", "name": "Next.js",     "html": r"__NEXT_DATA__|/_next/"},
    {"cat": "Framework", "name": "Nuxt.js",     "html": r"__NUXT__|/_nuxt/"},
    {"cat": "Framework", "name": "Flask",       "header": ("Server", r"Werkzeug")},

    # ---- CMS -------------------------------------------------------------
    {"cat": "CMS", "name": "WordPress", "meta_gen": r"WordPress",          "version": r"WordPress\s*([\d.]+)"},
    {"cat": "CMS", "name": "WordPress", "html": r"/wp-content/|/wp-includes/|wp-json"},
    {"cat": "CMS", "name": "WordPress", "header": ("X-Pingback", r".+")},
    {"cat": "CMS", "name": "Joomla",    "meta_gen": r"Joomla",            "version": r"Joomla!?\s*([\d.]+)"},
    {"cat": "CMS", "name": "Joomla",    "html": r"/media/jui/|com_content|/administrator/"},
    {"cat": "CMS", "name": "Drupal",    "header": ("X-Generator", r"Drupal"), "version": r"Drupal\s*([\d.]+)"},
    {"cat": "CMS", "name": "Drupal",    "header": ("X-Drupal-Cache", r".+")},
    {"cat": "CMS", "name": "Drupal",    "html": r"Drupal\.settings|/sites/default/|/core/misc/drupal"},
    {"cat": "CMS", "name": "Magento",   "html": r"/skin/frontend/|Mage\.|/static/version|/js/mage/"},
    {"cat": "CMS", "name": "Magento",   "cookie": r"frontend|X-Magento"},
    {"cat": "CMS", "name": "Shopify",   "html": r"cdn\.shopify\.com|Shopify\."},
    {"cat": "CMS", "name": "Shopify",   "header": ("X-ShopId", r".+")},
    {"cat": "CMS", "name": "Wix",       "header": ("X-Wix-Request-Id", r".+")},
    {"cat": "CMS", "name": "Wix",       "html": r"static\.wixstatic\.com|wix\.com"},
    {"cat": "CMS", "name": "Squarespace","header": ("X-ServedBy", r"squarespace")},
    {"cat": "CMS", "name": "Squarespace","html": r"static1\.squarespace\.com"},
    {"cat": "CMS", "name": "Ghost",     "meta_gen": r"Ghost",             "version": r"Ghost\s*([\d.]+)"},
    {"cat": "CMS", "name": "TYPO3",     "html": r"/typo3conf/|/typo3temp/"},
    {"cat": "CMS", "name": "PrestaShop","meta_gen": r"PrestaShop"},
    {"cat": "CMS", "name": "PrestaShop","cookie": r"PrestaShop"},
    {"cat": "CMS", "name": "Concrete CMS","html": r"/concrete/|CCM_IMAGE_PATH"},
    {"cat": "CMS", "name": "Sitecore",  "cookie": r"SC_ANALYTICS|sitecore"},
    {"cat": "CMS", "name": "AEM (Adobe)","html": r"/etc/clientlibs/|/etc/designs/"},
    {"cat": "CMS", "name": "Blogger",   "meta_gen": r"blogger"},
    {"cat": "CMS", "name": "Webflow",   "html": r"data-wf-page|website-files\.com"},

    # ---- Frontend frameworks / libraries --------------------------------
    {"cat": "Frontend", "name": "React",     "html": r"data-reactroot|react(-dom)?(\.production)?\.min\.js|_reactListening"},
    {"cat": "Frontend", "name": "Vue.js",    "html": r"data-v-[0-9a-f]{8}|vue(\.runtime)?(\.min)?\.js"},
    {"cat": "Frontend", "name": "Angular",   "html": r"ng-version|ng-app|angular(\.min)?\.js"},
    {"cat": "Frontend", "name": "jQuery",    "script": r"jquery[.-]?([\d.]+)?(\.min)?\.js", "version": r"jquery[.-]([\d.]+)"},
    {"cat": "Frontend", "name": "Bootstrap", "html": r"bootstrap(\.min)?\.(css|js)", "version": r"bootstrap[@-]?([\d.]+)"},
    {"cat": "Frontend", "name": "Tailwind",  "html": r"tailwind|tw-[a-z]"},
    {"cat": "Frontend", "name": "Svelte",    "html": r"svelte-[0-9a-z]{6}"},
    {"cat": "Frontend", "name": "Ember.js",  "html": r"ember(\.min)?\.js|ember-application"},
    {"cat": "Frontend", "name": "Backbone.js","html": r"backbone(\.min)?\.js"},
    {"cat": "Frontend", "name": "Alpine.js", "html": r"x-data=|alpinejs"},
    {"cat": "Frontend", "name": "Lodash",    "script": r"lodash(\.min)?\.js"},
    {"cat": "Frontend", "name": "Font Awesome","html": r"font-?awesome"},

    # ---- CDN / WAF / hosting --------------------------------------------
    {"cat": "CDN/WAF", "name": "Cloudflare",   "header": ("Server", r"cloudflare")},
    {"cat": "CDN/WAF", "name": "Cloudflare",   "header": ("CF-RAY", r".+")},
    {"cat": "CDN/WAF", "name": "AWS CloudFront","header": ("X-Amz-Cf-Id", r".+")},
    {"cat": "CDN/WAF", "name": "Fastly",       "header": ("X-Served-By", r"cache.+fastly|Fastly")},
    {"cat": "CDN/WAF", "name": "Akamai",       "header": ("X-Akamai-Transformed", r".+")},
    {"cat": "CDN/WAF", "name": "Sucuri",       "header": ("X-Sucuri-ID", r".+")},
    {"cat": "CDN/WAF", "name": "Incapsula",    "cookie": r"incap_ses|visid_incap"},
    {"cat": "CDN/WAF", "name": "Varnish",      "header": ("Via", r"varnish")},
    {"cat": "CDN/WAF", "name": "Vercel",       "header": ("X-Vercel-Id", r".+")},
    {"cat": "CDN/WAF", "name": "Netlify",      "header": ("X-Nf-Request-Id", r".+")},

    # ---- Database (INFERRED — rarely exposed over HTTP directly) ---------
    {"cat": "Database (inferred)", "name": "MySQL/MariaDB", "html": r"You have an error in your SQL syntax|mysql_fetch|mysqli_"},
    {"cat": "Database (inferred)", "name": "PostgreSQL",    "html": r"PG::|pg_query|PostgreSQL.*ERROR"},
    {"cat": "Database (inferred)", "name": "Microsoft SQL Server", "html": r"Microsoft OLE DB|SQL Server|System\.Data\.SqlClient"},
    {"cat": "Database (inferred)", "name": "Oracle",        "html": r"ORA-[0-9]{5}|Oracle error"},
    {"cat": "Database (inferred)", "name": "MongoDB",       "html": r"MongoError|mongodb://"},
]

# Common paths worth a look during recon (only probed with --paths)
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-login.php", "/wp-json/", "/xmlrpc.php",
    "/administrator/", "/user/login", "/admin", "/admin/login",
    "/.git/config", "/.env", "/config.php.bak", "/server-status",
    "/phpinfo.php", "/info.php", "/README.md", "/CHANGELOG.txt",
    "/.well-known/", "/api/", "/graphql",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]


def fetch(url, timeout, verify, ua, allow_redirects=True):
    try:
        return requests.get(url, timeout=timeout, verify=verify,
                            headers={"User-Agent": ua},
                            allow_redirects=allow_redirects)
    except requests.RequestException as e:
        return e


def extract_version(pattern, text):
    if not pattern or not text:
        return None
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m and m.groups() else None


def analyse(resp, soup, body, script_srcs):
    """Run all signatures against the response. Returns {(cat,name): {evidence, version}}."""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    set_cookie = resp.headers.get("Set-Cookie", "") + " " + \
                 " ".join(f"{c.name}" for c in resp.cookies)
    meta_gen = ""
    if soup:
        tag = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if tag and tag.get("content"):
            meta_gen = tag["content"]

    found = {}
    for sig in SIGNATURES:
        key = (sig["cat"], sig["name"])
        matched_text, evidence = None, None

        if "header" in sig:
            hname, pat = sig["header"]
            val = headers.get(hname.lower())
            if val and re.search(pat, val, re.IGNORECASE):
                matched_text, evidence = val, f"header {hname}: {val}"

        if not evidence and "cookie" in sig and re.search(sig["cookie"], set_cookie, re.IGNORECASE):
            matched_text, evidence = set_cookie, f"cookie matches /{sig['cookie']}/"

        if not evidence and "meta_gen" in sig and re.search(sig["meta_gen"], meta_gen, re.IGNORECASE):
            matched_text, evidence = meta_gen, f"meta generator: {meta_gen}"

        if not evidence and "html" in sig and re.search(sig["html"], body, re.IGNORECASE):
            matched_text, evidence = body, "html body pattern"

        if not evidence and "script" in sig:
            for src in script_srcs:
                if re.search(sig["script"], src, re.IGNORECASE):
                    matched_text, evidence = src, f"script src: {src}"
                    break

        if evidence:
            version = extract_version(sig.get("version"), matched_text)
            # also try meta_gen for version when present
            if not version and sig.get("version"):
                version = extract_version(sig["version"], meta_gen)
            existing = found.get(key)
            if not existing or (version and not existing.get("version")):
                found[key] = {"evidence": evidence, "version": version}
    return found


def favicon_hash(base_url, timeout, verify, ua):
    if not HAVE_MMH3:
        return None
    resp = fetch(urljoin(base_url, "/favicon.ico"), timeout, verify, ua)
    if isinstance(resp, Exception) or resp.status_code != 200 or not resp.content:
        return None
    b64 = base64.encodebytes(resp.content)
    return mmh3.hash(b64)


def probe_paths(base_url, timeout, verify, ua):
    hits = []
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        resp = fetch(url, timeout, verify, ua, allow_redirects=False)
        if isinstance(resp, Exception):
            continue
        if resp.status_code < 400 or resp.status_code in (401, 403):
            hits.append({"path": path, "status": resp.status_code,
                         "length": len(resp.content)})
    return hits


def build_report(url, resp, findings, sec_headers, fav_hash, path_hits):
    grouped = {}
    for (cat, name), info in findings.items():
        grouped.setdefault(cat, [])
        label = name + (f" {info['version']}" if info.get("version") else "")
        grouped[cat].append({"name": name, "version": info.get("version"),
                             "label": label, "evidence": info["evidence"]})
    return {
        "target": url,
        "final_url": resp.url,
        "status": resp.status_code,
        "server_header": resp.headers.get("Server"),
        "technologies": grouped,
        "security_headers": sec_headers,
        "favicon_mmh3": fav_hash,
        "interesting_paths": path_hits,
    }


def print_report(report):
    C = {"hdr": "\033[1;36m", "cat": "\033[1;33m", "ok": "\033[1;32m",
         "warn": "\033[1;31m", "dim": "\033[2m", "rst": "\033[0m"}
    def c(t, k): return f"{C[k]}{t}{C['rst']}"

    print(c("\n" + "=" * 60, "hdr"))
    print(c(f"  techdetect — {report['target']}", "hdr"))
    print(c("=" * 60, "hdr"))
    print(f"  Final URL : {report['final_url']}")
    print(f"  Status    : {report['status']}")
    print(f"  Server    : {report.get('server_header') or 'n/a'}")
    if report.get("favicon_mmh3") is not None:
        print(f"  Favicon   : mmh3={report['favicon_mmh3']}  "
              + c("(search Shodan: http.favicon.hash:%d)" % report['favicon_mmh3'], "dim"))

    print(c("\n--- Detected technologies ---", "cat"))
    if not report["technologies"]:
        print("  (nothing matched — try --paths, or the target may be heavily proxied)")
    order = ["CMS", "Framework", "Language", "Web Server", "Frontend",
             "CDN/WAF", "Database (inferred)"]
    cats = sorted(report["technologies"], key=lambda x: order.index(x) if x in order else 99)
    for cat in cats:
        print(c(f"\n  [{cat}]", "cat"))
        for item in report["technologies"][cat]:
            print(f"    {c('✓', 'ok')} {item['label']:<28} "
                  + c(item['evidence'], "dim"))

    print(c("\n--- Security headers ---", "cat"))
    for h, present in report["security_headers"].items():
        mark = c("present", "ok") if present else c("MISSING", "warn")
        print(f"    {h:<32} {mark}")

    if report.get("interesting_paths"):
        print(c("\n--- Interesting paths (status < 400 / 401 / 403) ---", "cat"))
        for hit in report["interesting_paths"]:
            print(f"    [{hit['status']}] {hit['path']:<30} ({hit['length']} bytes)")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Web technology / CMS fingerprinter for authorized recon.")
    ap.add_argument("url", help="Target URL (e.g. https://example.com)")
    ap.add_argument("-t", "--timeout", type=float, default=10.0)
    ap.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    ap.add_argument("--paths", action="store_true", help="Probe common sensitive paths")
    ap.add_argument("--favicon", action="store_true", help="Compute favicon mmh3 hash")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("-o", "--output", help="Write report to file")
    args = ap.parse_args()

    url = args.url if "://" in args.url else "http://" + args.url
    verify = not args.insecure

    resp = fetch(url, args.timeout, verify, args.user_agent)
    if isinstance(resp, Exception):
        sys.exit(f"[!] Request failed: {resp}")

    body = resp.text
    soup = BeautifulSoup(body, "html.parser") if HAVE_BS4 else None
    script_srcs = ([s.get("src", "") for s in soup.find_all("script")]
                   if soup else re.findall(r'<script[^>]+src=["\']([^"\']+)', body, re.I))

    findings = analyse(resp, soup, body, [s for s in script_srcs if s])
    sec_headers = {h: (h in resp.headers) for h in SECURITY_HEADERS}
    fav = favicon_hash(url, args.timeout, verify, args.user_agent) if args.favicon else None
    if args.favicon and not HAVE_MMH3:
        print("[i] --favicon needs mmh3 (pip install mmh3); skipping.", file=sys.stderr)
    path_hits = probe_paths(resp.url, args.timeout, verify, args.user_agent) if args.paths else []

    report = build_report(url, resp, findings, sec_headers, fav, path_hits)

    if args.json:
        out = json.dumps(report, indent=2)
        if args.output:
            open(args.output, "w").write(out)
            print(f"[+] JSON written to {args.output}")
        else:
            print(out)
    else:
        print_report(report)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"[+] JSON copy written to {args.output}")


if __name__ == "__main__":
    main()
