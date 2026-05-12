#!/usr/bin/env python3
"""
Author: Jonathan Ash
Created: 12/05/2026 
pcap-loot: extract interesting artifacts from a packet capture.

USAGE
    python pcap_loot.py capture.pcap                 # text summary to stdout
    python pcap_loot.py capture.pcap -f json         # JSON output
    python pcap_loot.py capture.pcap -o report.txt   # write to file
    python pcap_loot.py capture.pcap --creds-only    # show only credentials

WHAT IT EXTRACTS
    - Endpoints / top talkers (IPv4 + IPv6)
    - DNS queries and responses
    - HTTP requests (method, URL, User-Agent, Host)
    - TLS SNI (the hostnames behind HTTPS connections)
    - Credentials:
        * HTTP Basic Auth
        * HTTP form POSTs containing password-like fields
        * FTP   USER / PASS
        * POP3  USER / PASS
        * IMAP  LOGIN
        * SMTP  AUTH PLAIN / AUTH LOGIN
    - Email addresses appearing in cleartext payloads

REQUIRES
    scapy   (pip install scapy   or   apt install python3-scapy on Kali)
"""

import argparse
import base64
import json
import re
import sys
from collections import Counter, defaultdict

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw
except ImportError:
    sys.stderr.write(
        "error: scapy is required.\n"
        "  pip install scapy        (any system)\n"
        "  apt install python3-scapy  (Kali / Debian)\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Regexes / constants
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")
PASSWORD_FIELD_RE = re.compile(r"(?i)(^|_|-)(pass|pwd|passwd|password|token|secret|api[_-]?key|auth)(_|-|$)")
USER_FIELD_RE = re.compile(r"(?i)(user|usr|login|email|account|name|uid)")

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 65: "HTTPS",
}


# ---------------------------------------------------------------------------
# TLS SNI parser (raw bytes — no scapy TLS layer required)
# ---------------------------------------------------------------------------

def extract_sni(payload):
    """Return the SNI hostname from a TLS ClientHello, or None."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # not handshake
            return None
        p = payload[5:]
        if len(p) < 38 or p[0] != 0x01:  # not ClientHello
            return None
        i = 4 + 2 + 32  # handshake header + version + random
        if i >= len(p):
            return None
        sid_len = p[i]; i += 1 + sid_len
        if i + 2 > len(p):
            return None
        cs_len = int.from_bytes(p[i:i + 2], "big"); i += 2 + cs_len
        if i + 1 > len(p):
            return None
        cm_len = p[i]; i += 1 + cm_len
        if i + 2 > len(p):
            return None
        ext_len = int.from_bytes(p[i:i + 2], "big"); i += 2
        end = min(i + ext_len, len(p))
        while i + 4 <= end:
            ext_type = int.from_bytes(p[i:i + 2], "big")
            ext_data_len = int.from_bytes(p[i + 2:i + 4], "big")
            ext_data_start = i + 4
            if ext_type == 0x0000:  # server_name
                j = ext_data_start + 2  # skip server_name_list_length
                while j + 3 < ext_data_start + ext_data_len:
                    name_type = p[j]; j += 1
                    name_len = int.from_bytes(p[j:j + 2], "big"); j += 2
                    if name_type == 0 and j + name_len <= len(p):
                        return p[j:j + name_len].decode("ascii", "replace")
                    j += name_len
            i = ext_data_start + ext_data_len
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Per-protocol payload handlers
# ---------------------------------------------------------------------------

def handle_http_request(payload, src, dst, R):
    """Parse an HTTP request payload; extract URL, headers, basic auth, form creds."""
    try:
        first_end = payload.find(b"\r\n")
        if first_end < 0:
            return
        first = payload[:first_end].decode("ascii", "replace")
        parts = first.split(" ", 2)
        if len(parts) < 3:
            return
        method, uri, _ = parts

        headers_end = payload.find(b"\r\n\r\n")
        header_text = payload[first_end + 2:headers_end if headers_end >= 0 else len(payload)]
        headers = {}
        for line in header_text.split(b"\r\n"):
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode("ascii", "replace").lower()] = v.strip().decode("latin-1", "replace")

        host = headers.get("host", "")
        ua = headers.get("user-agent", "")
        full_url = f"http://{host}{uri}" if host else uri

        R["http_requests"].append({
            "src": src, "dst": dst, "method": method,
            "url": full_url, "user_agent": ua,
        })
        if ua:
            R["user_agents"][ua] += 1

        # HTTP Basic Auth
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip(), validate=False).decode("utf-8", "replace")
                if ":" in decoded:
                    u, _, pw = decoded.partition(":")
                    R["credentials"].append({
                        "type": "http-basic",
                        "username": u, "password": pw,
                        "url": full_url, "src": src, "dst": dst,
                    })
            except Exception:
                pass

        # HTTP form POST
        if method == "POST" and headers_end >= 0:
            body = payload[headers_end + 4:]
            ctype = headers.get("content-type", "").lower()
            if "application/x-www-form-urlencoded" in ctype:
                _parse_form_creds(body, full_url, src, dst, R)
    except Exception:
        pass


def _parse_form_creds(body, url, src, dst, R):
    """If POST body has password-like fields, capture the credential pair."""
    try:
        pairs = {}
        for kv in body.split(b"&"):
            if b"=" in kv:
                k, _, v = kv.partition(b"=")
                try:
                    from urllib.parse import unquote_plus
                    key = unquote_plus(k.decode("latin-1", "replace"))
                    val = unquote_plus(v.decode("latin-1", "replace"))
                except Exception:
                    key = k.decode("latin-1", "replace")
                    val = v.decode("latin-1", "replace")
                pairs[key] = val

        pw_field = next((k for k in pairs if PASSWORD_FIELD_RE.search("_" + k + "_")), None)
        if pw_field:
            user_field = next(
                (k for k in pairs if k != pw_field and USER_FIELD_RE.search(k)),
                None,
            )
            R["credentials"].append({
                "type": "http-form",
                "username": pairs.get(user_field, "") if user_field else "",
                "password": pairs[pw_field],
                "field_user": user_field or "",
                "field_pass": pw_field,
                "url": url, "src": src, "dst": dst,
            })
    except Exception:
        pass


def handle_ftp(payload, src, dst, R):
    """FTP is line-based: USER <name> then PASS <pw>."""
    try:
        text = payload.decode("ascii", "replace")
        pending = R["_pending_ftp"]
        for line in text.splitlines():
            m = re.match(r"^USER\s+(.+)$", line, re.I)
            if m:
                pending[(src, dst)] = m.group(1).strip()
                continue
            m = re.match(r"^PASS\s+(.+)$", line, re.I)
            if m and (src, dst) in pending:
                user = pending.pop((src, dst))
                R["credentials"].append({
                    "type": "ftp", "username": user, "password": m.group(1).strip(),
                    "src": src, "dst": dst,
                })
    except Exception:
        pass


def handle_pop3(payload, src, dst, R):
    """POP3: USER <name> then PASS <pw>."""
    try:
        text = payload.decode("ascii", "replace")
        pending = R["_pending_pop3"]
        for line in text.splitlines():
            m = re.match(r"^USER\s+(.+)$", line, re.I)
            if m:
                pending[(src, dst)] = m.group(1).strip()
                continue
            m = re.match(r"^PASS\s+(.+)$", line, re.I)
            if m and (src, dst) in pending:
                user = pending.pop((src, dst))
                R["credentials"].append({
                    "type": "pop3", "username": user, "password": m.group(1).strip(),
                    "src": src, "dst": dst,
                })
    except Exception:
        pass


def handle_imap(payload, src, dst, R):
    """IMAP login is one line: '<tag> LOGIN <user> <pass>'."""
    try:
        text = payload.decode("ascii", "replace")
        for line in text.splitlines():
            m = re.match(r"^\S+\s+LOGIN\s+\"?([^\"\s]+)\"?\s+\"?([^\"\s]+)\"?", line, re.I)
            if m:
                R["credentials"].append({
                    "type": "imap", "username": m.group(1), "password": m.group(2),
                    "src": src, "dst": dst,
                })
    except Exception:
        pass


def handle_smtp(payload, src, dst, R):
    """Handle AUTH PLAIN (single b64 blob) and AUTH LOGIN (two-step b64)."""
    try:
        text = payload.decode("ascii", "replace")
        plain_state = R["_pending_smtp_plain"]
        login_state = R["_pending_smtp_login"]
        key = (src, dst)

        for line in text.splitlines():
            line = line.strip()

            m = re.match(r"^AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)$", line, re.I)
            if m:
                _emit_smtp_plain(m.group(1), src, dst, R)
                continue
            if re.match(r"^AUTH\s+PLAIN\s*$", line, re.I):
                plain_state[key] = True
                continue
            if plain_state.pop(key, False):
                if re.match(r"^[A-Za-z0-9+/=]+$", line):
                    _emit_smtp_plain(line, src, dst, R)
                    continue

            if re.match(r"^AUTH\s+LOGIN", line, re.I):
                login_state[key] = {"step": "await-user"}
                continue
            state = login_state.get(key)
            if state and re.match(r"^[A-Za-z0-9+/=]+$", line):
                try:
                    decoded = base64.b64decode(line, validate=False).decode("utf-8", "replace")
                except Exception:
                    decoded = ""
                if state["step"] == "await-user":
                    state["user"] = decoded
                    state["step"] = "await-pass"
                elif state["step"] == "await-pass":
                    R["credentials"].append({
                        "type": "smtp", "username": state.get("user", ""),
                        "password": decoded, "src": src, "dst": dst,
                    })
                    login_state.pop(key, None)
    except Exception:
        pass


def _emit_smtp_plain(b64_blob, src, dst, R):
    try:
        decoded = base64.b64decode(b64_blob, validate=False)
        parts = decoded.split(b"\x00")
        if len(parts) >= 2:
            username = parts[-2].decode("utf-8", "replace")
            password = parts[-1].decode("utf-8", "replace")
            R["credentials"].append({
                "type": "smtp", "username": username, "password": password,
                "src": src, "dst": dst,
            })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def _dns_type_name(qtype):
    return DNS_TYPES.get(qtype, str(qtype))


def _process_dns(pkt, R, src):
    dns = pkt[DNS]
    try:
        if dns.qr == 0 and dns.qd is not None:
            qd = dns.qd
            try:
                name = qd.qname.decode("ascii", "replace").rstrip(".")
                R["dns_queries"].append({
                    "src": src, "name": name, "type": _dns_type_name(qd.qtype),
                })
            except Exception:
                pass
        elif dns.qr == 1 and dns.an is not None:
            an = dns.an
            for _ in range(dns.ancount or 1):
                try:
                    name = an.rrname.decode("ascii", "replace").rstrip(".")
                    rdata = an.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("ascii", "replace").rstrip(".")
                    R["dns_responses"].append({
                        "name": name, "type": _dns_type_name(an.type),
                        "data": str(rdata),
                    })
                except Exception:
                    pass
                if hasattr(an, "payload") and isinstance(an.payload, DNSRR):
                    an = an.payload
                else:
                    break
    except Exception:
        pass


def _process_tcp_payload(payload, sport, dport, src, dst, R):
    if not payload:
        return

    if payload.startswith(HTTP_METHODS):
        handle_http_request(payload, src, dst, R)

    if payload[:1] == b"\x16" and len(payload) > 5 and payload[1] == 0x03:
        sni = extract_sni(payload)
        if sni:
            R["tls_sni"][sni] += 1

    if dport == 21 or sport == 21:
        handle_ftp(payload, src, dst, R)
    if dport == 110 or sport == 110:
        handle_pop3(payload, src, dst, R)
    if dport == 143 or sport == 143:
        handle_imap(payload, src, dst, R)
    if dport in (25, 587, 465) or sport in (25, 587, 465):
        handle_smtp(payload, src, dst, R)

    for m in EMAIL_RE.finditer(payload[:4096]):
        try:
            email = m.group(0).decode("ascii", "ignore")
            if 5 <= len(email) <= 254:
                R["emails"][email] += 1
        except Exception:
            pass


def _process_packet(pkt, R):
    src = dst = None
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    if src is None:
        return

    R["hosts"][src] += 1
    R["hosts"][dst] += 1

    if pkt.haslayer(DNS):
        _process_dns(pkt, R, src)

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        R["convs"][(src, dst, f"tcp/{dport}")] += 1
        if Raw in pkt:
            _process_tcp_payload(bytes(pkt[Raw].load), sport, dport, src, dst, R)
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        R["convs"][(src, dst, f"udp/{dport}")] += 1


def parse_pcap(path):
    R = {
        "file": path,
        "hosts": Counter(),
        "convs": Counter(),
        "dns_queries": [],
        "dns_responses": [],
        "http_requests": [],
        "tls_sni": Counter(),
        "credentials": [],
        "emails": Counter(),
        "user_agents": Counter(),
        "packet_count": 0,
        "errors": 0,
        # Internal state (stripped from output)
        "_pending_ftp": {},
        "_pending_pop3": {},
        "_pending_smtp_plain": {},
        "_pending_smtp_login": {},
    }

    with PcapReader(path) as pcap:
        for pkt in pcap:
            R["packet_count"] += 1
            try:
                _process_packet(pkt, R)
            except Exception:
                R["errors"] += 1

    for k in list(R):
        if k.startswith("_"):
            del R[k]
    return R


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _ansi(color, text, enable):
    if not enable:
        return text
    codes = {
        "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
        "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
        "bold": "\033[1m", "dim": "\033[2m", "end": "\033[0m",
        "bgred": "\033[41m\033[97m",
    }
    return f"{codes.get(color, '')}{text}{codes['end']}"


def render_text(R, color=True, creds_only=False):
    color = color and sys.stdout.isatty()
    bold = lambda s: _ansi("bold", s, color)
    dim = lambda s: _ansi("dim", s, color)
    red = lambda s: _ansi("red", s, color)
    grn = lambda s: _ansi("green", s, color)
    ylw = lambda s: _ansi("yellow", s, color)
    cyn = lambda s: _ansi("cyan", s, color)
    bgr = lambda s: _ansi("bgred", s, color)

    out = []
    out.append(bold(f"pcap-loot report: {R['file']}"))
    out.append(dim("=" * 70))
    out.append(f"Packets parsed: {R['packet_count']:,} ({R['errors']} errors)")
    out.append("")

    creds = R["credentials"]
    if creds:
        out.append(bgr(f"  CREDENTIALS RECOVERED ({len(creds)})  "))
        out.append(dim("-" * 70))
        for c in creds:
            label = red(bold(f"[{c['type']}]"))
            ctx = c.get("url") or f"{c['src']} -> {c['dst']}"
            out.append(f"  {label}  {ctx}")
            line = f"      user: {bold(c.get('username', ''))}"
            if c.get("password"):
                line += f"   pass: {bold(red(c['password']))}"
            out.append(line)
            if c.get("field_user") or c.get("field_pass"):
                out.append(dim(f"      fields: user={c.get('field_user','')} pass={c.get('field_pass','')}"))
        out.append("")
    else:
        out.append(dim("No credentials recovered."))
        out.append("")

    if creds_only:
        return "\n".join(out)

    if R["hosts"]:
        out.append(bold("Top talkers (packet count):"))
        for host, n in R["hosts"].most_common(10):
            out.append(f"  {cyn(host):<40} {n:>8,}")
        out.append("")

    if R["convs"]:
        out.append(bold(f"Top conversations ({len(R['convs'])} total):"))
        for (s, d, proto), n in R["convs"].most_common(10):
            out.append(f"  {s:>15} -> {d:<15}  {dim(proto):<14} {n:>6,} pkts")
        out.append("")

    if R["dns_queries"]:
        unique = Counter((q["name"], q["type"]) for q in R["dns_queries"])
        out.append(bold(f"DNS queries ({len(R['dns_queries'])} total, {len(unique)} unique):"))
        for (name, qtype), n in unique.most_common(25):
            out.append(f"  {grn(qtype):<8} {name}  {dim(f'x{n}') if n > 1 else ''}")
        if len(unique) > 25:
            out.append(dim(f"  ... and {len(unique) - 25} more"))
        out.append("")

    if R["tls_sni"]:
        out.append(bold(f"TLS SNI / HTTPS destinations ({len(R['tls_sni'])} unique):"))
        for sni, n in R["tls_sni"].most_common(25):
            out.append(f"  {ylw(sni):<50} {dim(f'x{n}') if n > 1 else ''}")
        if len(R["tls_sni"]) > 25:
            out.append(dim(f"  ... and {len(R['tls_sni']) - 25} more"))
        out.append("")

    if R["http_requests"]:
        out.append(bold(f"HTTP requests ({len(R['http_requests'])}):"))
        for r in R["http_requests"][:25]:
            method = grn(f"{r['method']:<5}")
            ua = dim(f"  [{r['user_agent'][:50]}]") if r["user_agent"] else ""
            out.append(f"  {method} {r['url']}{ua}")
        if len(R["http_requests"]) > 25:
            out.append(dim(f"  ... and {len(R['http_requests']) - 25} more"))
        out.append("")

    if R["user_agents"]:
        out.append(bold(f"User-Agents ({len(R['user_agents'])} unique):"))
        for ua, n in R["user_agents"].most_common(10):
            out.append(f"  {dim(f'x{n}'):>6}  {ua}")
        out.append("")

    if R["emails"]:
        out.append(bold(f"Email addresses observed ({len(R['emails'])} unique):"))
        for email, n in R["emails"].most_common(25):
            out.append(f"  {email}  {dim(f'x{n}') if n > 1 else ''}")
        out.append("")

    return "\n".join(out)


def render_json(R):
    out = {
        "file": R["file"],
        "packet_count": R["packet_count"],
        "errors": R["errors"],
        "credentials": R["credentials"],
        "hosts": dict(R["hosts"].most_common()),
        "conversations": [
            {"src": s, "dst": d, "proto": p, "packets": n}
            for (s, d, p), n in R["convs"].most_common()
        ],
        "dns_queries": R["dns_queries"],
        "dns_responses": R["dns_responses"],
        "http_requests": R["http_requests"],
        "tls_sni": dict(R["tls_sni"].most_common()),
        "user_agents": dict(R["user_agents"].most_common()),
        "emails": dict(R["emails"].most_common()),
    }
    return json.dumps(out, indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract credentials, DNS, HTTP, SNI, and other artifacts from a pcap.",
    )
    parser.add_argument("input", help="Path to .pcap or .pcapng file")
    parser.add_argument("-f", "--format", choices=["text", "json"], default="text")
    parser.add_argument("-o", "--output", help="Write to file instead of stdout")
    parser.add_argument("--creds-only", action="store_true",
                        help="Only show recovered credentials")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = parser.parse_args(argv)

    try:
        R = parse_pcap(args.input)
    except FileNotFoundError:
        sys.stderr.write(f"error: file not found: {args.input}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"error: could not read pcap: {e}\n")
        return 1

    if args.format == "json":
        out = render_json(R)
    else:
        out = render_text(R, color=not args.no_color, creds_only=args.creds_only)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
            if not out.endswith("\n"):
                f.write("\n")
        sys.stderr.write(f"wrote {args.output}\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
