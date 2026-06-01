#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
js_map_hunter.py - Find exposed JS source maps

Phases:
  1. Fetch target page, extract all JS file URLs
  2. Fetch each JS file, check for //# sourceMappingURL= comment
  3. For every JS file, probe <file>.map and <file>.js.map
  4. Save found maps, optionally extract original source files

Usage:
  python3 js_map_hunter.py -u https://example.com
  python3 js_map_hunter.py -u https://example.com -hf headers.txt -x -v
"""

import argparse
import os
import re
import sys
import json
import threading
import requests
from urllib.parse import urljoin, urlparse
from queue import Queue

requests.packages.urllib3.disable_warnings()


# ------------------------------------------------------------------ #
#  Colours
# ------------------------------------------------------------------ #

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(s):    return "{}{}{}".format(C.RED,    s, C.RESET)
def green(s):  return "{}{}{}".format(C.GREEN,  s, C.RESET)
def yellow(s): return "{}{}{}".format(C.YELLOW, s, C.RESET)
def cyan(s):   return "{}{}{}".format(C.CYAN,   s, C.RESET)
def bold(s):   return "{}{}{}".format(C.BOLD,   s, C.RESET)


# ------------------------------------------------------------------ #
#  Header file loader
# ------------------------------------------------------------------ #

def load_header_file(path):
    """
    Load headers from a file - accepts raw Burp paste.
    Skips request line, blank lines, HTTP/2 pseudo headers.
    """
    headers = {}
    skip_prefixes = ("get ", "post ", "put ", "patch ", "delete ", "head ", "options ")

    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(red("[!] Could not read header file: {}".format(e)))
        return headers

    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if any(line.lower().startswith(p) for p in skip_prefixes):
            continue
        if line.startswith(":"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        headers[key.strip()] = val.strip()

    print(green("[+] Loaded {} header(s) from {}".format(len(headers), path)))
    for k, v in headers.items():
        display = v if k.lower() not in ("cookie", "authorization") else v[:8] + "..."
        print("    {}: {}".format(k, display))

    return headers


# ------------------------------------------------------------------ #
#  Session
# ------------------------------------------------------------------ #

def get_session(proxy=None, extra_headers=None, header_file=None):
    s = requests.Session()
    s.verify = False
    s.timeout = 15

    if proxy:
        s.proxies = {"http": proxy, "https": proxy}

    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
    })

    # Load from header file
    if header_file:
        file_headers = load_header_file(header_file)
        s.headers.update(file_headers)

    # Load from -H flags
    if extra_headers:
        for h in extra_headers:
            key, _, val = h.partition(":")
            s.headers[key.strip()] = val.strip()

    return s


# ------------------------------------------------------------------ #
#  Phase 1 - Discover JS files
# ------------------------------------------------------------------ #

def discover_js_files(session, base_url, verbose=False):
    js_files = set()

    print(bold("\n[Phase 1] Discovering JS files from: {}".format(base_url)))

    try:
        r = session.get(base_url, allow_redirects=True)
        r.raise_for_status()
    except Exception as e:
        print(red("[!] Failed to fetch base URL: {}".format(e)))
        sys.exit(1)

    html = r.text

    # <script src="...">
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    for src in srcs:
        js_files.add(urljoin(base_url, src))

    # Any URL ending in .js in the HTML
    all_js_refs = re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
    for ref in all_js_refs:
        if ref.startswith("http"):
            parsed = urlparse(ref)
            base_parsed = urlparse(base_url)
            if parsed.netloc == base_parsed.netloc:
                js_files.add(ref)
        elif ref.startswith("/"):
            parsed = urlparse(base_url)
            js_files.add("{}://{}{}".format(parsed.scheme, parsed.netloc, ref.split("?")[0]))

    print(green("[+] Found {} JS file(s) in page source".format(len(js_files))))
    for js in sorted(js_files):
        print("    {}".format(cyan(js)))

    return js_files


# ------------------------------------------------------------------ #
#  Phase 2 - Fetch JS files, find sourceMappingURL
# ------------------------------------------------------------------ #

def fetch_js_and_find_maps(session, js_files, verbose=False):
    """
    Fetch every JS file.
    Look for //# sourceMappingURL= or //@ sourceMappingURL=
    Returns explicit map URLs found + all JS content for further analysis.
    """
    explicit_maps = {}   # map_url -> js_url it came from
    js_contents   = {}   # js_url  -> response text

    print(bold("\n[Phase 2] Fetching JS files and scanning for sourceMappingURL..."))

    for js_url in sorted(js_files):
        try:
            r = session.get(js_url, allow_redirects=True)
            if r.status_code != 200:
                print("  {} {} [{}]".format(yellow("[skip]"), js_url, r.status_code))
                continue

            content = r.text
            js_contents[js_url] = content

            # Look for explicit sourceMappingURL comment
            maps = re.findall(r'//[#@]\s*sourceMappingURL=([^\s\r\n]+)', content)
            for m in maps:
                if m.startswith("data:"):
                    continue
                map_url = urljoin(js_url, m)
                explicit_maps[map_url] = js_url
                print("  {} sourceMappingURL found: {}".format(
                    green("[MAP]"), map_url
                ))

            if verbose and not maps:
                print("  {} {} ({} bytes, no sourceMappingURL)".format(
                    cyan("[ok]"), js_url, len(content)
                ))

        except Exception as e:
            print("  {} {} - {}".format(red("[err]"), js_url, e))

    print(green("[+] Fetched {} JS file(s), found {} explicit map reference(s)".format(
        len(js_contents), len(explicit_maps)
    )))

    return explicit_maps, js_contents


# ------------------------------------------------------------------ #
#  Phase 3 - Probe for .map files
# ------------------------------------------------------------------ #

def build_map_candidates(js_contents, explicit_maps):
    """
    Build a full list of map URLs to probe.
    Only use JS files that actually returned 200 - avoids probing .map
    variants of non-existent JS files.
    """
    candidates = {}

    # Explicit maps from sourceMappingURL - highest priority
    for map_url, js_url in explicit_maps.items():
        candidates[map_url] = js_url

    # Only probe JS files that actually returned 200
    for js_url in js_contents.keys():
        clean = js_url.split("?")[0]   # strip query string

        # bundle.js       -> bundle.js.map
        candidates[clean + ".map"] = js_url

        # bundle.min.js   -> bundle.min.js.map
        if not clean.endswith(".js.map"):
            candidates[clean.replace(".js", ".js.map")] = js_url

        # app.a1b2c3d4.js -> app.js.map  (strip chunk hash)
        dehashed = re.sub(r'\.[a-f0-9]{8,20}\.js$', '.js.map', clean)
        if dehashed not in candidates:
            candidates[dehashed] = js_url

        # app.chunk.a1b2c3.js -> app.chunk.js.map
        dehashed2 = re.sub(r'\.[a-f0-9]{8,20}\.js$', '.chunk.js.map', clean)
        if dehashed2 not in candidates:
            candidates[dehashed2] = js_url

    return candidates


def probe_map_candidates(session, candidates, threads=10, verbose=False):
    """
    Hit every candidate URL and check if it returns a valid source map.
    """
    found = {}
    queue = Queue()
    lock  = threading.Lock()
    checked = [0]

    for url in candidates:
        queue.put(url)

    total = queue.qsize()
    print(bold("\n[Phase 3] Probing {} candidate .map URL(s) ({} threads)...".format(
        total, threads
    )))

    def worker():
        while not queue.empty():
            try:
                map_url = queue.get_nowait()
            except:
                break

            try:
                r = session.get(map_url, allow_redirects=True)

                with lock:
                    checked[0] += 1
                    pct = int(checked[0] * 100 / total)
                    sys.stdout.write("\r  Progress: {}/{} ({}%)    ".format(
                        checked[0], total, pct
                    ))
                    sys.stdout.flush()

                if r.status_code == 200:
                    # Validate it actually looks like a source map
                    text = r.text.strip()
                    is_map = (
                        '"sources"'  in text[:2000] or
                        '"mappings"' in text[:2000] or
                        '"version"'  in text[:500]  and '"sources"' in text
                    )
                    if is_map:
                        with lock:
                            found[map_url] = r
                        print("\n  {} {}".format(green("[FOUND]"), map_url))
                    elif verbose:
                        print("\n  {} {} [200 but not a map]".format(yellow("[skip]"), map_url))

                elif verbose and r.status_code not in (404, 403):
                    print("\n  {} {} [{}]".format(
                        yellow("[{}]".format(r.status_code)), map_url, r.status_code
                    ))

            except Exception as e:
                if verbose:
                    print("\n  {} {} - {}".format(red("[err]"), map_url, e))

            queue.task_done()

    thread_list = []
    for _ in range(min(threads, total or 1)):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    print("\n")
    return found


# ------------------------------------------------------------------ #
#  Phase 4 - Save and extract
# ------------------------------------------------------------------ #

def save_maps(found_maps, output_dir, extract=False):
    print(bold("[Phase 4] Saving results..."))

    total_sources = 0

    for map_url, response in found_maps.items():
        print("\n  {} {}".format(bold("[MAP]"), map_url))
        print("       {} bytes".format(len(response.content)))

        # Save raw .map file using actual filename from URL
        filename = map_url.split("/")[-1].split("?")[0]   # strip path and query
        safe = re.sub(r'[^\w\-_.]', '_', filename)
        # Only append .map if the URL didn't already end in .map
        if not safe.endswith(".map"):
            safe = safe + ".map"
        out_path = os.path.join(output_dir, safe)

        with open(out_path, "wb") as f:
            f.write(response.content)
        print("       Saved -> {}".format(out_path))

        # Parse and summarise
        try:
            data = json.loads(response.text)
            sources = data.get("sources", [])
            has_content = bool(data.get("sourcesContent"))
            print("       Sources: {} file(s) {}".format(
                len(sources),
                green("[sourcesContent present - extractable]") if has_content
                else yellow("[no sourcesContent]")
            ))
            for s in sources[:5]:
                print("         - {}".format(s))
            if len(sources) > 5:
                print("         ... and {} more".format(len(sources) - 5))
        except Exception as e:
            print("       {}".format(yellow("[Could not parse map JSON: {}]".format(e))))
            continue

        # Extract source files
        if extract and has_content:
            n = extract_sources(map_url, data, output_dir)
            total_sources += n
            print("       {} Extracted {} source file(s)".format(green("[+]"), n))

    return total_sources


def extract_sources(map_url, data, output_dir):
    sources = data.get("sources", [])
    sources_content = data.get("sourcesContent", [])
    extracted = 0

    map_name = re.sub(r'[^\w\-_.]', '_', map_url.split("/")[-1])
    map_dir = os.path.join(output_dir, map_name + "_sources")
    os.makedirs(map_dir, exist_ok=True)

    for i, (src, content) in enumerate(zip(sources, sources_content)):
        if content is None:
            continue

        # Sanitise path
        src_path = src
        for prefix in ("webpack:///", "webpack://", "./", "../"):
            src_path = src_path.replace(prefix, "")
        src_path = src_path.lstrip("/")

        if not src_path:
            src_path = "source_{}.js".format(i)

        out = os.path.join(map_dir, src_path)
        os.makedirs(os.path.dirname(out), exist_ok=True)

        try:
            with open(out, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            extracted += 1
        except Exception as e:
            print(red("         [!] Could not write {}: {}".format(out, e)))

    return extracted


# ------------------------------------------------------------------ #
#  Main
# ------------------------------------------------------------------ #

def main():
    print(bold(cyan("""
  JS Source Map Hunter
""")))

    parser = argparse.ArgumentParser(
        description="Find exposed JS source maps on a target site"
    )
    parser.add_argument("-u",  "--url",         required=True,      help="Target URL")
    parser.add_argument("-o",  "--output",       default="maps_out", help="Output directory")
    parser.add_argument("-t",  "--threads",      type=int, default=10, help="Threads (default 10)")
    parser.add_argument("-p",  "--proxy",        default=None,       help="Proxy URL e.g. http://127.0.0.1:8080")
    parser.add_argument("-H",  "--header",       action="append", default=[], help="Custom header")
    parser.add_argument("-hf", "--header-file",  default=None,       help="Header file (paste from Burp)")
    parser.add_argument("-x",  "--extract",      action="store_true", help="Extract source files from maps")
    parser.add_argument("-v",  "--verbose",      action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.url.startswith("http"):
        args.url = "https://" + args.url

    os.makedirs(args.output, exist_ok=True)

    session = get_session(
        proxy=args.proxy,
        extra_headers=args.header,
        header_file=args.header_file
    )

    # Phase 1: find JS files
    js_files = discover_js_files(session, args.url, args.verbose)

    # Phase 2: fetch JS, find explicit sourceMappingURL
    explicit_maps, js_contents = fetch_js_and_find_maps(session, js_files, args.verbose)

    # Phase 3: build candidates and probe
    candidates = build_map_candidates(js_contents, explicit_maps)
    found_maps = probe_map_candidates(session, candidates, args.threads, args.verbose)

    # Phase 4: save results
    print(bold("=" * 60))
    if not found_maps:
        print(yellow("[~] No source maps found"))
    else:
        print(green("[+] {} source map(s) found!\n".format(len(found_maps))))
        total_sources = save_maps(found_maps, args.output, args.extract)

        print(bold("\n" + "=" * 60))
        print(green("[+] Maps saved to: {}".format(args.output)))
        if args.extract:
            print(green("[+] {} source file(s) extracted".format(total_sources)))

    print(bold("\n[*] Done\n"))


if __name__ == "__main__":
    main()
