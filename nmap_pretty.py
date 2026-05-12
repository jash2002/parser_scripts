#!/usr/bin/env python3
"""
Author: Jonathan Ash
Created: 12/05/2026 
nmap-pretty: Convert nmap XML output into nicely formatted reports.

USAGE
    # First, run nmap with XML output:
    nmap -sV -O -oX scan.xml 192.168.1.0/24

    # Then format it:
    python nmap_pretty.py scan.xml                       # HTML to stdout
    python nmap_pretty.py scan.xml -o report.html        # HTML to file
    python nmap_pretty.py scan.xml -f md -o report.md    # Markdown
    python nmap_pretty.py scan.xml -f txt                # Colored terminal output
    python nmap_pretty.py scan.xml -f json -o data.json  # JSON for further processing

NOTES
    - Input must be nmap XML output (the -oX flag).
    - Works with stdlib only; no pip install required.
    - Tested with nmap 7.x output formats.
"""

import argparse
import json
import re
import sys
import html as html_lib
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------------
# Severity scoring for NSE script output
# ---------------------------------------------------------------------------

CVE_RE = re.compile(r"CVE[-_ ]?\d{4}[-_ ]?\d{4,7}", re.I)
CVSS_RE = re.compile(r"CVSS(?:v?[23](?:\.[01])?)?[\s:=]+(\d+(?:\.\d+)?)", re.I)
# vulners NSE prints lines like "CVE-2016-10009    7.5    https://..."
VULNERS_SCORE_RE = re.compile(r"CVE[-_ ]?\d{4}[-_ ]?\d{4,7}\s+(\d+\.\d+)\b", re.I)
RISK_RE = re.compile(r"Risk\s*factor[\s:]+([A-Za-z]+)", re.I)
STATE_VULN_RE = re.compile(r"\bState\s*:\s*VULNERABLE\b", re.I)
SSL_GRADE_RE = re.compile(r"Least\s+strength[\s:]+([A-F])", re.I)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, None: -1}


def _score_output(text):
    """Inspect NSE script output and return (severity, max_cvss, cves).

    severity is one of: 'critical', 'high', 'medium', 'low', 'info', or None.
    """
    if not text:
        return None, 0.0, []

    cves = sorted({m.group(0).upper().replace("_", "-").replace(" ", "-")
                   for m in CVE_RE.finditer(text)})

    max_cvss = 0.0
    for m in CVSS_RE.finditer(text):
        try:
            v = float(m.group(1))
            if 0 <= v <= 10 and v > max_cvss:
                max_cvss = v
        except ValueError:
            pass
    for m in VULNERS_SCORE_RE.finditer(text):
        try:
            v = float(m.group(1))
            if 0 <= v <= 10 and v > max_cvss:
                max_cvss = v
        except ValueError:
            pass

    risk_word = None
    rm = RISK_RE.search(text)
    if rm:
        risk_word = rm.group(1).lower()

    is_vulnerable = bool(STATE_VULN_RE.search(text))

    sev = None
    if max_cvss >= 9.0:
        sev = "critical"
    elif max_cvss >= 7.0:
        sev = "high"
    elif max_cvss >= 4.0:
        sev = "medium"
    elif max_cvss > 0:
        sev = "low"
    elif risk_word == "critical":
        sev = "critical"
    elif risk_word == "high":
        sev = "high"
    elif risk_word in ("medium", "moderate"):
        sev = "medium"
    elif risk_word == "low":
        sev = "low"
    elif is_vulnerable:
        sev = "high"
    else:
        gm = SSL_GRADE_RE.search(text)
        if gm:
            grade = gm.group(1).upper()
            if grade == "F":
                sev = "high"
            elif grade in ("D", "E"):
                sev = "medium"
            elif grade == "C":
                sev = "low"
        elif cves:
            sev = "info"

    return sev, max_cvss, cves


def _collect_findings(scan):
    """Return a list of findings (from all script output) sorted worst-first."""
    findings = []
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        for p in host["ports"]:
            for s in p["scripts"]:
                sev, cvss, cves = _score_output(s["output"])
                if sev:
                    findings.append({
                        "host": addr,
                        "location": f'{p["portid"]}/{p["protocol"]}',
                        "script": s["id"],
                        "severity": sev,
                        "cvss": cvss,
                        "cves": cves,
                    })
        for s in host["scripts"]:
            sev, cvss, cves = _score_output(s["output"])
            if sev:
                findings.append({
                    "host": addr,
                    "location": "host",
                    "script": s["id"],
                    "severity": sev,
                    "cvss": cvss,
                    "cves": cves,
                })
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["cvss"], f["host"]))
    return findings


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_nmap_xml(path):
    """Parse an nmap XML file using streaming parser for robustness to truncation."""
    if path == "-":
        source = sys.stdin.buffer if hasattr(sys.stdin, 'buffer') else sys.stdin
    else:
        source = open(path, 'rb')

    scan = {
        "args": "",
        "version": "",
        "start_time": "",
        "scanner": "nmap",
        "hosts": [],
        "end_time": "",
        "elapsed": "",
        "hosts_up": 0,
        "hosts_down": 0,
        "hosts_total": 0,
    }

    try:
        for event, elem in ET.iterparse(source, events=("start", "end")):
            if event == "start" and elem.tag == "nmaprun":
                scan["args"] = elem.get("args", "")
                scan["version"] = elem.get("version", "")
                scan["start_time"] = elem.get("startstr", "")
                scan["scanner"] = elem.get("scanner", "nmap")

            elif event == "end" and elem.tag == "host":
                scan["hosts"].append(_parse_host(elem))
                elem.clear()  # free memory for huge captures

            elif event == "end" and elem.tag == "finished":
                scan["end_time"] = elem.get("timestr", "")
                scan["elapsed"] = elem.get("elapsed", "")

            elif event == "end" and elem.tag == "hosts":
                try:
                    scan["hosts_up"] = int(elem.get("up", 0))
                    scan["hosts_down"] = int(elem.get("down", 0))
                    scan["hosts_total"] = int(elem.get("total", 0))
                except ValueError:
                    pass

    except ET.ParseError as e:
        # Truncated XML is common with piped/interrupted nmap scans
        # We've already extracted what we could via streaming, so just warn
        sys.stderr.write(f"warning: XML parse error (likely truncated): {e}\n")
        sys.stderr.write(f"         but parsed {len(scan['hosts'])} hosts successfully\n")
    finally:
        if path != "-":
            source.close()

    return scan


def _parse_host(host_el):
    status_el = host_el.find("status")
    host = {
        "state": status_el.get("state") if status_el is not None else "unknown",
        "reason": status_el.get("reason") if status_el is not None else "",
        "addresses": [],
        "hostnames": [],
        "ports": [],
        "os": [],
        "scripts": [],
        "uptime": None,
    }

    for addr in host_el.findall("address"):
        host["addresses"].append({
            "addr": addr.get("addr"),
            "type": addr.get("addrtype"),
            "vendor": addr.get("vendor", ""),
        })

    for hn in host_el.findall("hostnames/hostname"):
        host["hostnames"].append({
            "name": hn.get("name"),
            "type": hn.get("type", ""),
        })

    for port in host_el.findall("ports/port"):
        state_el = port.find("state")
        service_el = port.find("service")
        info = {
            "portid": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state_el.get("state") if state_el is not None else "",
            "reason": state_el.get("reason") if state_el is not None else "",
            "service": service_el.get("name", "") if service_el is not None else "",
            "product": service_el.get("product", "") if service_el is not None else "",
            "version": service_el.get("version", "") if service_el is not None else "",
            "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
            "ostype": service_el.get("ostype", "") if service_el is not None else "",
            "scripts": [],
        }
        for script in port.findall("script"):
            info["scripts"].append({
                "id": script.get("id"),
                "output": script.get("output", ""),
            })
        host["ports"].append(info)

    for osmatch in host_el.findall("os/osmatch"):
        host["os"].append({
            "name": osmatch.get("name"),
            "accuracy": osmatch.get("accuracy"),
        })

    uptime_el = host_el.find("uptime")
    if uptime_el is not None:
        host["uptime"] = {
            "seconds": uptime_el.get("seconds"),
            "lastboot": uptime_el.get("lastboot"),
        }

    for script in host_el.findall("hostscript/script"):
        host["scripts"].append({
            "id": script.get("id"),
            "output": script.get("output", ""),
        })

    return host


def _primary_address(host):
    for kind in ("ipv4", "ipv6"):
        for addr in host["addresses"]:
            if addr["type"] == kind:
                return addr["addr"]
    return host["addresses"][0]["addr"] if host["addresses"] else "unknown"


def _mac_address(host):
    for addr in host["addresses"]:
        if addr["type"] == "mac":
            return addr
    return None


def _primary_hostname(host):
    return host["hostnames"][0]["name"] if host["hostnames"] else ""


def _version_string(p):
    parts = [p["product"], p["version"], p["extrainfo"]]
    return " ".join(x for x in parts if x).strip()


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def _parse_ip_filter(spec):
    """Parse '192.168.1.1,10.0.0.0/24,192.168.1.10-192.168.1.20' into a matcher."""
    import ipaddress
    matchers = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                matchers.append(("net", net))
            elif "-" in part:
                lo, hi = part.split("-", 1)
                lo_addr = ipaddress.ip_address(lo.strip())
                hi_addr = ipaddress.ip_address(hi.strip())
                matchers.append(("range", int(lo_addr), int(hi_addr), type(lo_addr)))
            else:
                addr = ipaddress.ip_address(part)
                matchers.append(("exact", addr))
        except ValueError:
            # Treat as hostname substring
            matchers.append(("hostname", part.lower()))

    def matches(host):
        for kind, *args in [(m[0], *m[1:]) for m in matchers]:
            if kind == "exact":
                for a in host["addresses"]:
                    try:
                        if ipaddress.ip_address(a["addr"]) == args[0]:
                            return True
                    except ValueError:
                        pass
            elif kind == "net":
                for a in host["addresses"]:
                    try:
                        if ipaddress.ip_address(a["addr"]) in args[0]:
                            return True
                    except ValueError:
                        pass
            elif kind == "range":
                lo, hi, addr_type = args
                for a in host["addresses"]:
                    try:
                        ip = ipaddress.ip_address(a["addr"])
                        if isinstance(ip, addr_type) and lo <= int(ip) <= hi:
                            return True
                    except ValueError:
                        pass
            elif kind == "hostname":
                for hn in host["hostnames"]:
                    if args[0] in hn["name"].lower():
                        return True
        return False
    return matches


def _parse_port_filter(spec):
    """'22,80,443' or '22,80-90' -> set of port ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                ports.update(range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return ports


def filter_scan(scan, ip_spec=None, port_spec=None, service=None,
                states=None, with_findings=False, min_severity=None):
    """Apply filters to a scan dict and return a new filtered scan."""
    out = dict(scan)
    out["hosts"] = []

    ip_match = _parse_ip_filter(ip_spec) if ip_spec else None
    port_set = _parse_port_filter(port_spec) if port_spec else None
    service_lc = service.lower() if service else None
    min_sev_rank = SEVERITY_ORDER.get(min_severity) if min_severity else None

    for host in scan["hosts"]:
        if ip_match and not ip_match(host):
            continue

        if port_set:
            if not any(int(p["portid"]) in port_set and p["state"] == "open"
                       for p in host["ports"]):
                continue
            # Also limit the host's port list to the requested ports
            host = dict(host)
            host["ports"] = [p for p in host["ports"] if int(p["portid"]) in port_set]

        if service_lc:
            if not any(service_lc in (p["service"] + " " + p["product"]).lower()
                       and p["state"] == "open"
                       for p in host["ports"]):
                continue

        # Filter ports by state if requested
        if states:
            host = dict(host)
            host["ports"] = [p for p in host["ports"] if p["state"] in states]

        # Findings filters
        if with_findings or min_sev_rank is not None:
            host_findings = []
            for p in host["ports"]:
                for s in p["scripts"]:
                    sev, _, _ = _score_output(s["output"])
                    if sev:
                        host_findings.append(sev)
            for s in host["scripts"]:
                sev, _, _ = _score_output(s["output"])
                if sev:
                    host_findings.append(sev)
            if with_findings and not host_findings:
                continue
            if min_sev_rank is not None:
                if not any(SEVERITY_ORDER[s] >= min_sev_rank for s in host_findings):
                    continue

        out["hosts"].append(host)

    return out


# ---------------------------------------------------------------------------
# Pentest suggestion engine
# ---------------------------------------------------------------------------

# Map service-name patterns + ports to suggested next-step commands.
# Each entry: (matcher_fn, [("label", "command_template")])  command uses {ip} and {port}
SUGGESTIONS = [
    (lambda s, p: "ssh" in s or p == 22, [
        ("SSH audit",        "ssh-audit {ip} -p {port}"),
        ("Brute force",      "hydra -L users.txt -P passwords.txt ssh://{ip}:{port}"),
        ("Check default creds", "nmap -p{port} --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt {ip}"),
    ]),
    (lambda s, p: "ftp" in s or p == 21, [
        ("Anonymous login",  "ftp {ip} {port}   # try user 'anonymous', any password"),
        ("Banner / scripts", "nmap -p{port} -sV --script 'ftp-anon,ftp-bounce,ftp-syst' {ip}"),
        ("Brute force",      "hydra -L users.txt -P passwords.txt ftp://{ip}:{port}"),
    ]),
    (lambda s, p: "http" in s and "https" not in s or p in (80, 8080, 8000, 8888), [
        ("Banner / tech",    "whatweb http://{ip}:{port}"),
        ("Directory brute",  "feroxbuster -u http://{ip}:{port}"),
        ("Vuln scan",        "nikto -h http://{ip}:{port}"),
        ("Screenshot",       "gowitness single http://{ip}:{port}"),
    ]),
    (lambda s, p: "https" in s or "ssl" in s or p in (443, 8443), [
        ("TLS audit",        "sslyze {ip}:{port}"),
        ("Banner / tech",    "whatweb https://{ip}:{port}"),
        ("Directory brute",  "feroxbuster -u https://{ip}:{port} -k"),
        ("Vuln scan",        "nikto -h https://{ip}:{port}"),
    ]),
    (lambda s, p: "smb" in s or "microsoft-ds" in s or "netbios" in s or p in (139, 445), [
        ("List shares (anon)", "smbclient -L //{ip} -N"),
        ("Enum users / shares", "enum4linux-ng -A {ip}"),
        ("Null session",      "rpcclient -U '' -N {ip}"),
        ("CME spray",         "nxc smb {ip} -u users.txt -p passwords.txt"),
    ]),
    (lambda s, p: "ldap" in s or p in (389, 636), [
        ("Anon bind",        "ldapsearch -x -H ldap://{ip} -s base"),
        ("Domain dump",      "ldapdomaindump -u 'DOMAIN\\\\user' -p 'password' {ip}"),
    ]),
    (lambda s, p: "kerberos" in s or p == 88, [
        ("User enumeration", "kerbrute userenum --dc {ip} -d DOMAIN users.txt"),
        ("AS-REP roast",     "GetNPUsers.py -dc-ip {ip} DOMAIN/ -usersfile users.txt"),
    ]),
    (lambda s, p: "dns" in s or "domain" in s or p == 53, [
        ("Zone transfer",    "dig @{ip} DOMAIN AXFR"),
        ("NSE DNS",          "nmap -p{port} --script 'dns-*' {ip}"),
    ]),
    (lambda s, p: "rdp" in s or "ms-wbt" in s or p == 3389, [
        ("Cert + protocol",  "nmap -p{port} --script 'rdp-enum-encryption,rdp-vuln-ms12-020' {ip}"),
        ("BlueKeep check",   "nmap -p{port} --script rdp-vuln-ms17-010 {ip}"),
        ("Brute force",      "ncrack -p {port} -U users.txt -P passwords.txt {ip}"),
    ]),
    (lambda s, p: "mysql" in s or p == 3306, [
        ("Default creds",    "mysql -h {ip} -P {port} -u root -p   # try blank / 'root' / 'password'"),
        ("NSE checks",       "nmap -p{port} --script 'mysql-*' {ip}"),
    ]),
    (lambda s, p: "postgres" in s or p == 5432, [
        ("Default creds",    "psql -h {ip} -p {port} -U postgres   # try blank / 'postgres'"),
        ("NSE",              "nmap -p{port} --script 'pgsql-brute' {ip}"),
    ]),
    (lambda s, p: "mssql" in s or "ms-sql" in s or p == 1433, [
        ("Connect / enum",   "mssqlclient.py -p {port} 'DOMAIN/user:password@{ip}'"),
        ("NSE",              "nmap -p{port} --script 'ms-sql-*' {ip}"),
    ]),
    (lambda s, p: "redis" in s or p == 6379, [
        ("Unauth check",     "redis-cli -h {ip} -p {port} INFO"),
    ]),
    (lambda s, p: "telnet" in s or p == 23, [
        ("Banner",           "nc -nv {ip} {port}"),
        ("Brute force",      "hydra -L users.txt -P passwords.txt telnet://{ip}:{port}"),
    ]),
    (lambda s, p: "vnc" in s or p in (5900, 5901), [
        ("Unauth screenshot","vncsnapshot {ip}::{port} out.jpg"),
        ("NSE",              "nmap -p{port} --script 'vnc-info,realvnc-auth-bypass' {ip}"),
    ]),
    (lambda s, p: "snmp" in s or p == 161, [
        ("snmpwalk (public)","snmpwalk -v2c -c public {ip}"),
        ("Community brute",  "onesixtyone -c communities.txt {ip}"),
    ]),
    (lambda s, p: "nfs" in s or "rpcbind" in s or p in (111, 2049), [
        ("List exports",     "showmount -e {ip}"),
        ("Mount + browse",   "mount -t nfs {ip}:/share /mnt/nfs -o nolock"),
    ]),
]


def suggest_for_port(service, product, port):
    """Return a list of (label, command) suggestions for a port."""
    s = (service + " " + product).lower()
    out = []
    seen = set()
    for matcher, items in SUGGESTIONS:
        if matcher(s, port):
            for label, tmpl in items:
                if label not in seen:
                    seen.add(label)
                    out.append((label, tmpl))
    return out


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{
  --bg: #f6f7f9;
  --card: #ffffff;
  --text: #1a1d21;
  --muted: #6b7280;
  --border: #e5e7eb;
  --accent: #2563eb;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --open: #16a34a;
  --closed: #6b7280;
  --filtered: #ca8a04;
  --open-bg: #dcfce7;
  --filtered-bg: #fef3c7;
  --closed-bg: #f3f4f6;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0f1115;
    --card: #1a1d21;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --border: #2a2f36;
    --accent: #60a5fa;
    --open: #4ade80;
    --closed: #9ca3af;
    --filtered: #fbbf24;
    --open-bg: #14532d;
    --filtered-bg: #713f12;
    --closed-bg: #2a2f36;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }}
header.report {{ margin-bottom: 32px; }}
h1 {{ font-size: 28px; margin: 0 0 4px; letter-spacing: -0.01em; }}
.subtitle {{ color: var(--muted); font-size: 14px; }}
.meta {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-top: 20px;
  padding: 16px 20px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
}}
.meta .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }}
.meta .value {{ font-family: var(--mono); font-size: 13px; margin-top: 2px; word-break: break-all; }}
.host {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 20px;
  overflow: hidden;
}}
.host-header {{ padding: 18px 22px; border-bottom: 1px solid var(--border); }}
.host-title {{ display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }}
.host-title .addr {{ font-family: var(--mono); font-size: 18px; font-weight: 600; color: var(--accent); }}
.host-title .hostname {{ color: var(--muted); font-size: 14px; }}
.host-attrs {{ margin-top: 8px; font-size: 13px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 16px; }}
.host-attrs .k {{ color: var(--muted); }}
.host-attrs .v {{ color: var(--text); }}
.host-attrs code {{ font-family: var(--mono); font-size: 12px; }}
table.ports {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
table.ports th, table.ports td {{
  padding: 10px 22px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}}
table.ports th {{
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  font-weight: 600;
  background: var(--bg);
}}
table.ports tr:last-child td {{ border-bottom: none; }}
table.ports td.port-cell {{ font-family: var(--mono); font-weight: 600; white-space: nowrap; }}
table.ports td.service {{ font-family: var(--mono); }}
table.ports td.version {{ color: var(--muted); font-family: var(--mono); font-size: 13px; }}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  text-transform: lowercase;
  letter-spacing: 0.02em;
}}
.badge.open {{ background: var(--open-bg); color: var(--open); }}
.badge.filtered {{ background: var(--filtered-bg); color: var(--filtered); }}
.badge.closed {{ background: var(--closed-bg); color: var(--closed); }}
.badge.critical {{ background: #fee2e2; color: #b91c1c; }}
.badge.high     {{ background: #ffedd5; color: #c2410c; }}
.badge.medium   {{ background: #fef3c7; color: #b45309; }}
.badge.low      {{ background: #dbeafe; color: #1d4ed8; }}
.badge.info     {{ background: #f3f4f6; color: #4b5563; }}
@media (prefers-color-scheme: dark) {{
  .badge.critical {{ background: #450a0a; color: #fca5a5; }}
  .badge.high     {{ background: #431407; color: #fdba74; }}
  .badge.medium   {{ background: #422006; color: #fcd34d; }}
  .badge.low      {{ background: #172554; color: #93c5fd; }}
  .badge.info     {{ background: #2a2f36; color: #d1d5db; }}
}}
.findings {{
  background: var(--card);
  border: 1px solid var(--border);
  border-left: 4px solid #dc2626;
  border-radius: 10px;
  padding: 18px 22px;
  margin-bottom: 24px;
}}
.findings h2 {{ margin: 0 0 12px; font-size: 16px; }}
.findings ul {{ list-style: none; margin: 0; padding: 0; }}
.findings li {{
  display: grid;
  grid-template-columns: 90px 1fr;
  gap: 12px;
  align-items: baseline;
  padding: 8px 0;
  border-top: 1px solid var(--border);
  font-size: 13px;
}}
.findings li:first-child {{ border-top: none; }}
.findings .f-detail {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: baseline; }}
.findings .f-host    {{ font-family: var(--mono); color: var(--accent); font-weight: 600; }}
.findings .f-loc     {{ font-family: var(--mono); color: var(--muted); }}
.findings .f-script  {{ font-family: var(--mono); }}
.findings .f-cvss    {{ font-family: var(--mono); color: var(--muted); font-size: 12px; }}
.findings .f-cves    {{ color: var(--muted); font-family: var(--mono); font-size: 12px; }}
.script.critical .script-output {{ border-left: 3px solid #dc2626; }}
.script.high     .script-output {{ border-left: 3px solid #ea580c; }}
.script.medium   .script-output {{ border-left: 3px solid #d97706; }}
.script.low      .script-output {{ border-left: 3px solid #2563eb; }}
.script-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
details.scripts {{ margin: 0; padding: 12px 22px; border-top: 1px solid var(--border); background: var(--bg); }}
details.scripts summary {{ cursor: pointer; font-size: 13px; color: var(--muted); font-weight: 500; }}
details.scripts summary:hover {{ color: var(--text); }}
.script {{ margin-top: 12px; }}
.script-id {{ font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--accent); margin-bottom: 4px; }}
.script-output {{
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 12px;
  overflow-x: auto;
  color: var(--text);
}}
.empty {{ padding: 24px 22px; color: var(--muted); font-style: italic; font-size: 14px; }}
footer {{ margin-top: 40px; text-align: center; color: var(--muted); font-size: 12px; }}
footer code {{ font-family: var(--mono); }}
@media print {{
  body {{ background: white; }}
  .host, .meta {{ break-inside: avoid; box-shadow: none; }}
  details.scripts[open] summary ~ * {{ display: block; }}
}}
</style>
</head>
<body>
<div class="wrap">
<header class="report">
  <h1>Nmap Scan Report</h1>
  <div class="subtitle">{subtitle}</div>
  <div class="meta">
    <div><div class="label">Command</div><div class="value">{cmd}</div></div>
    <div><div class="label">Started</div><div class="value">{start}</div></div>
    <div><div class="label">Finished</div><div class="value">{end}</div></div>
    <div><div class="label">Duration</div><div class="value">{elapsed}s</div></div>
    <div><div class="label">Hosts up</div><div class="value">{up} / {total}</div></div>
    <div><div class="label">Nmap version</div><div class="value">{ver}</div></div>
  </div>
</header>
{findings_html}
{hosts_html}
<footer>Generated by <code>nmap-pretty</code></footer>
</div>
</body>
</html>
"""


def render_html(scan):
    def esc(s):
        return html_lib.escape(str(s) if s is not None else "")

    def render_script(s):
        sev, cvss, cves = _score_output(s["output"])
        sev_class = f" {sev}" if sev else ""
        badge = f'<span class="badge {sev}">{sev}</span>' if sev else ""
        cvss_text = f' <span class="f-cvss">CVSS {cvss:.1f}</span>' if cvss > 0 else ""
        cve_text = (
            f' <span class="f-cves">{esc(", ".join(cves))}</span>' if cves else ""
        )
        return (
            f'<div class="script{sev_class}">'
            f'<div class="script-header">'
            f'<span class="script-id">{esc(s["id"])}</span>'
            f'{badge}{cvss_text}{cve_text}'
            f'</div>'
            f'<div class="script-output">{esc(s["output"])}</div>'
            f'</div>'
        )

    findings = _collect_findings(scan)
    findings_html = ""
    if findings:
        items = []
        for f in findings:
            cvss_text = f' &middot; <span class="f-cvss">CVSS {f["cvss"]:.1f}</span>' if f["cvss"] > 0 else ""
            cve_text = (
                f' &middot; <span class="f-cves">{esc(", ".join(f["cves"]))}</span>'
                if f["cves"] else ""
            )
            items.append(
                f'<li class="{esc(f["severity"])}">'
                f'<span><span class="badge {esc(f["severity"])}">{esc(f["severity"])}</span></span>'
                f'<span class="f-detail">'
                f'<span class="f-host">{esc(f["host"])}</span>'
                f'<span class="f-loc">{esc(f["location"])}</span>'
                f'<span class="f-script">{esc(f["script"])}</span>'
                f'{cvss_text}{cve_text}'
                f'</span>'
                f'</li>'
            )
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        count_parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev):
                count_parts.append(f'<span class="badge {sev}">{counts[sev]} {sev}</span>')
        findings_html = (
            f'<div class="findings">'
            f'<h2>&#9888; Findings &mdash; {" ".join(count_parts)}</h2>'
            f'<ul>{"".join(items)}</ul>'
            f'</div>'
        )

    host_blocks = []
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue

        addr = _primary_address(host)
        hostname = _primary_hostname(host)
        mac = _mac_address(host)

        attrs = []
        if host["os"]:
            top = host["os"][0]
            attrs.append(
                f'<span><span class="k">OS:</span> '
                f'<span class="v">{esc(top["name"])}</span> '
                f'<span class="k">({esc(top["accuracy"])}%)</span></span>'
            )
        if mac:
            mac_text = mac["addr"]
            if mac.get("vendor"):
                mac_text += f" ({mac['vendor']})"
            attrs.append(f'<span><span class="k">MAC:</span> <code>{esc(mac_text)}</code></span>')
        if host.get("uptime") and host["uptime"].get("lastboot"):
            attrs.append(
                f'<span><span class="k">Last boot:</span> '
                f'<span class="v">{esc(host["uptime"]["lastboot"])}</span></span>'
            )

        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        other_ports = [p for p in host["ports"] if p["state"] not in ("open", "closed")]
        shown = open_ports + other_ports

        if shown:
            rows = []
            for p in shown:
                rows.append(
                    f'<tr>'
                    f'<td class="port-cell">{esc(p["portid"])}/{esc(p["protocol"])}</td>'
                    f'<td><span class="badge {esc(p["state"])}">{esc(p["state"])}</span></td>'
                    f'<td class="service">{esc(p["service"]) or "&mdash;"}</td>'
                    f'<td class="version">{esc(_version_string(p)) or "&mdash;"}</td>'
                    f'</tr>'
                )
                if p["scripts"]:
                    script_items = "".join(render_script(s) for s in p["scripts"])
                    # If any script on this port is critical/high, open by default
                    worst = max(
                        (SEVERITY_ORDER[_score_output(s["output"])[0]] for s in p["scripts"]),
                        default=-1,
                    )
                    open_attr = " open" if worst >= SEVERITY_ORDER["high"] else ""
                    rows.append(
                        f'<tr><td colspan="4" style="padding:0">'
                        f'<details class="scripts"{open_attr}><summary>'
                        f'{len(p["scripts"])} script result(s) on port {esc(p["portid"])}'
                        f'</summary>{script_items}</details>'
                        f'</td></tr>'
                    )
            table = (
                '<table class="ports">'
                '<thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table>'
            )
        else:
            table = '<div class="empty">No open ports detected.</div>'

        host_scripts_html = ""
        if host["scripts"]:
            items = "".join(render_script(s) for s in host["scripts"])
            host_scripts_html = (
                f'<details class="scripts" open><summary>'
                f'Host-level script results ({len(host["scripts"])})'
                f'</summary>{items}</details>'
            )

        host_blocks.append(
            f'<section class="host">'
            f'<div class="host-header">'
            f'<div class="host-title">'
            f'<span class="addr">{esc(addr)}</span>'
            + (f'<span class="hostname">{esc(hostname)}</span>' if hostname else "")
            + f'</div>'
            + (f'<div class="host-attrs">{" ".join(attrs)}</div>' if attrs else "")
            + f'</div>'
            f'{table}'
            f'{host_scripts_html}'
            f'</section>'
        )

    up_count = sum(1 for h in scan["hosts"] if h["state"] == "up")
    subtitle = f"{up_count} host{'s' if up_count != 1 else ''} up"

    return HTML_TEMPLATE.format(
        title="Nmap Scan Report",
        subtitle=esc(subtitle),
        cmd=esc(scan["args"]) or "&mdash;",
        start=esc(scan["start_time"]) or "&mdash;",
        end=esc(scan["end_time"]) or "&mdash;",
        elapsed=esc(scan["elapsed"]) or "&mdash;",
        up=esc(scan["hosts_up"]),
        total=esc(scan["hosts_total"]),
        ver=esc(scan["version"]) or "&mdash;",
        findings_html=findings_html,
        hosts_html="".join(host_blocks) if host_blocks else '<div class="empty">No hosts up.</div>',
    )


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def render_markdown(scan):
    L = []
    L.append("# Nmap Scan Report")
    L.append("")
    L.append(f"- **Command:** `{scan['args']}`")
    L.append(f"- **Started:** {scan['start_time']}")
    if scan["end_time"]:
        L.append(f"- **Finished:** {scan['end_time']} ({scan['elapsed']}s)")
    L.append(f"- **Hosts:** {scan['hosts_up']} up / {scan['hosts_total']} total")
    L.append(f"- **Nmap version:** {scan['version']}")
    L.append("")

    findings = _collect_findings(scan)
    if findings:
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                     "low": "🔵", "info": "⚪"}
        L.append("## ⚠ Findings")
        L.append("")
        L.append("| Severity | Host | Location | Script | CVSS | CVEs |")
        L.append("|----------|------|----------|--------|------|------|")
        for f in findings:
            cvss = f"{f['cvss']:.1f}" if f["cvss"] > 0 else "—"
            cves = ", ".join(f["cves"]) if f["cves"] else "—"
            sev = f"{sev_emoji.get(f['severity'], '')} **{f['severity'].upper()}**"
            L.append(f"| {sev} | `{f['host']}` | `{f['location']}` | `{f['script']}` | {cvss} | {cves} |")
        L.append("")

    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        hostname = _primary_hostname(host)
        title = f"## {addr}"
        if hostname:
            title += f"  *({hostname})*"
        L.append(title)
        L.append("")

        if host["os"]:
            top = host["os"][0]
            L.append(f"**OS:** {top['name']} _(accuracy: {top['accuracy']}%)_")
            L.append("")
        mac = _mac_address(host)
        if mac:
            mac_text = mac["addr"]
            if mac.get("vendor"):
                mac_text += f" ({mac['vendor']})"
            L.append(f"**MAC:** `{mac_text}`")
            L.append("")

        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        other_ports = [p for p in host["ports"] if p["state"] not in ("open", "closed")]
        shown = open_ports + other_ports

        if shown:
            L.append("| Port | State | Service | Version |")
            L.append("|------|-------|---------|---------|")
            for p in shown:
                version = _version_string(p) or "—"
                service = p["service"] or "—"
                L.append(f"| `{p['portid']}/{p['protocol']}` | {p['state']} | {service} | {version} |")
            L.append("")

            for p in shown:
                if p["scripts"]:
                    L.append(f"#### Scripts on {p['portid']}/{p['protocol']}")
                    L.append("")
                    for s in p["scripts"]:
                        sev, cvss, cves = _score_output(s["output"])
                        tag = f" **[{sev.upper()}]**" if sev else ""
                        cvss_tag = f" _(CVSS {cvss:.1f})_" if cvss > 0 else ""
                        L.append(f"**{s['id']}**{tag}{cvss_tag}")
                        L.append("```")
                        L.append(s["output"].rstrip())
                        L.append("```")
                        L.append("")
        else:
            L.append("_No open ports detected._")
            L.append("")

        if host["scripts"]:
            L.append("### Host scripts")
            L.append("")
            for s in host["scripts"]:
                sev, cvss, _ = _score_output(s["output"])
                tag = f" **[{sev.upper()}]**" if sev else ""
                cvss_tag = f" _(CVSS {cvss:.1f})_" if cvss > 0 else ""
                L.append(f"**{s['id']}**{tag}{cvss_tag}")
                L.append("```")
                L.append(s["output"].rstrip())
                L.append("```")
                L.append("")

    return "\n".join(L)


# ---------------------------------------------------------------------------
# Plain text / terminal renderer (with optional ANSI color)
# ---------------------------------------------------------------------------

def render_text(scan, color=True, verbose=False):
    if color and sys.stdout.isatty():
        R, G, Y, B = "\033[91m", "\033[92m", "\033[93m", "\033[94m"
        ORANGE = "\033[38;5;208m"
        BG_RED = "\033[41m\033[97m"
        BOLD, DIM, END = "\033[1m", "\033[2m", "\033[0m"
    else:
        R = G = Y = B = ORANGE = BG_RED = BOLD = DIM = END = ""

    sev_color = {
        "critical": BG_RED,
        "high": R,
        "medium": ORANGE,
        "low": Y,
        "info": B,
    }

    out = []
    out.append(f"{BOLD}Nmap Scan Report{END}")
    out.append(f"{DIM}{'=' * 64}{END}")
    out.append(f"Command:  {scan['args']}")
    out.append(f"Started:  {scan['start_time']}")
    if scan["end_time"]:
        out.append(f"Finished: {scan['end_time']} ({scan['elapsed']}s)")
    out.append(f"Hosts:    {G}{scan['hosts_up']} up{END} / {scan['hosts_total']} total")
    out.append("")

    findings = _collect_findings(scan)
    if findings:
        out.append(f"{BOLD}{R}!! Findings{END}")
        out.append(f"{DIM}{'-' * 64}{END}")
        for f in findings:
            tag = f"{sev_color.get(f['severity'], '')}{BOLD}[{f['severity'].upper():^8}]{END}"
            cvss = f" {DIM}CVSS {f['cvss']:.1f}{END}" if f["cvss"] > 0 else ""
            cves = f" {DIM}{', '.join(f['cves'])}{END}" if f["cves"] else ""
            out.append(f"  {tag} {f['host']:<16} {f['location']:<10} {f['script']}{cvss}{cves}")
        out.append("")

    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        hostname = _primary_hostname(host)
        header = f"{BOLD}{B}{addr}{END}"
        if hostname:
            header += f" {DIM}({hostname}){END}"
        out.append(header)
        out.append(f"{DIM}{'-' * 64}{END}")

        if host["os"]:
            top = host["os"][0]
            out.append(f"OS: {top['name']} {DIM}(accuracy {top['accuracy']}%){END}")
            if verbose and len(host["os"]) > 1:
                for alt in host["os"][1:]:
                    out.append(f"    {DIM}also: {alt['name']} ({alt['accuracy']}%){END}")
        mac = _mac_address(host)
        if mac:
            tail = f" ({mac['vendor']})" if mac.get("vendor") else ""
            out.append(f"MAC: {mac['addr']}{tail}")

        open_ports = [p for p in host["ports"] if p["state"] == "open"]
        other_ports = [p for p in host["ports"] if p["state"] not in ("open", "closed")]
        if verbose:
            closed = [p for p in host["ports"] if p["state"] == "closed"]
            shown = open_ports + other_ports + closed
        else:
            shown = open_ports + other_ports

        if shown:
            out.append("")
            out.append(f"  {BOLD}{'PORT':<12}{'STATE':<11}{'SERVICE':<16}VERSION{END}")
            for p in shown:
                port_label = f"{p['portid']}/{p['protocol']}"
                if p["state"] == "open":
                    state_c = G
                elif p["state"] == "filtered":
                    state_c = Y
                else:
                    state_c = R
                version = _version_string(p)
                out.append(
                    f"  {port_label:<12}{state_c}{p['state']:<11}{END}"
                    f"{p['service']:<16}{version}"
                )
                for s in p["scripts"]:
                    sev, cvss, _ = _score_output(s["output"])
                    if sev:
                        prefix = f"{sev_color.get(sev, '')}{BOLD}[{sev.upper()}]{END}"
                        cvss_text = f" {DIM}CVSS {cvss:.1f}{END}" if cvss > 0 else ""
                        out.append(f"    {DIM}|{END} {prefix} {s['id']}{cvss_text}")
                    else:
                        out.append(f"    {DIM}| {s['id']}{END}")
                    for line in s["output"].split("\n"):
                        out.append(f"    {DIM}|{END}   {line}")
        else:
            out.append(f"  {DIM}No open ports.{END}")

        if host["scripts"]:
            out.append("")
            out.append(f"  {BOLD}Host scripts:{END}")
            for s in host["scripts"]:
                sev, cvss, _ = _score_output(s["output"])
                if sev:
                    prefix = f"{sev_color.get(sev, '')}{BOLD}[{sev.upper()}]{END}"
                    cvss_text = f" {DIM}CVSS {cvss:.1f}{END}" if cvss > 0 else ""
                    out.append(f"    {DIM}|{END} {prefix} {s['id']}{cvss_text}")
                else:
                    out.append(f"    {DIM}| {s['id']}{END}")
                for line in s["output"].split("\n"):
                    out.append(f"    {DIM}|{END}   {line}")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Pentest-focused renderers
# ---------------------------------------------------------------------------

def render_minimal(scan, color=True):
    """Compact one-line-per-port output: IP:PORT  STATE  SERVICE  VERSION."""
    if color and sys.stdout.isatty():
        G, Y, R, B, BOLD, DIM, END = "\033[92m", "\033[93m", "\033[91m", "\033[94m", "\033[1m", "\033[2m", "\033[0m"
    else:
        G = Y = R = B = BOLD = DIM = END = ""

    out = []
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        for p in host["ports"]:
            if p["state"] == "closed":
                continue
            if p["state"] == "open":
                state_c = G
            elif p["state"] == "filtered":
                state_c = Y
            else:
                state_c = R
            target = f"{addr}:{p['portid']}"
            ver = _version_string(p)
            line = (
                f"{B}{target:<22}{END}{state_c}{p['state']:<10}{END}"
                f"{p['service']:<16}{ver}"
            )
            out.append(line)
    return "\n".join(out)


def render_targets(scan):
    """ip:port lines for open ports — feed to other tools."""
    out = []
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        for p in host["ports"]:
            if p["state"] == "open":
                out.append(f"{addr}:{p['portid']}")
    return "\n".join(out)


def render_hosts(scan):
    """Just IPs of up hosts, one per line."""
    out = []
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        out.append(_primary_address(host))
    return "\n".join(out)


def render_etc_hosts(scan):
    """/etc/hosts format — useful for resolving discovered hostnames locally."""
    out = ["# Generated by nmap-pretty"]
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        if host["hostnames"]:
            names = " ".join(h["name"] for h in host["hostnames"] if h["name"])
            if names:
                out.append(f"{addr}\t{names}")
    return "\n".join(out)


def render_csv(scan):
    """CSV row per port — easy to import to spreadsheets / reports."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "hostname", "port", "protocol", "state",
                "service", "product", "version", "extrainfo",
                "severity", "cvss", "cves", "os"])
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)
        hostname = _primary_hostname(host)
        os_name = host["os"][0]["name"] if host["os"] else ""
        for p in host["ports"]:
            # Aggregate worst script severity for this port
            worst_sev, worst_cvss, all_cves = None, 0.0, set()
            for s in p["scripts"]:
                sev, cvss, cves = _score_output(s["output"])
                if sev and SEVERITY_ORDER.get(sev, -1) > SEVERITY_ORDER.get(worst_sev, -1):
                    worst_sev = sev
                if cvss > worst_cvss:
                    worst_cvss = cvss
                all_cves.update(cves)
            w.writerow([
                addr, hostname, p["portid"], p["protocol"], p["state"],
                p["service"], p["product"], p["version"], p["extrainfo"],
                worst_sev or "", f"{worst_cvss:.1f}" if worst_cvss > 0 else "",
                ",".join(sorted(all_cves)), os_name,
            ])
    return buf.getvalue()


def render_suggestions(scan, color=True):
    """Next-step pentest commands for every open port we recognize."""
    if color and sys.stdout.isatty():
        BOLD, DIM, CYAN, GREEN, END = "\033[1m", "\033[2m", "\033[96m", "\033[92m", "\033[0m"
    else:
        BOLD = DIM = CYAN = GREEN = END = ""

    out = []
    out.append(f"{BOLD}Suggested next steps{END}")
    out.append(f"{DIM}{'=' * 70}{END}")
    out.append("")

    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        addr = _primary_address(host)

        had_any = False
        for p in host["ports"]:
            if p["state"] != "open":
                continue
            sugs = suggest_for_port(p["service"], p["product"], int(p["portid"]))
            if not sugs:
                continue
            if not had_any:
                out.append(f"{BOLD}{CYAN}{addr}{END}  {DIM}({_primary_hostname(host) or '-'}){END}")
                had_any = True
            out.append(f"  {BOLD}{p['portid']}/{p['protocol']} {p['service']}{END}")
            for label, tmpl in sugs:
                cmd = tmpl.format(ip=addr, port=p["portid"])
                out.append(f"    {DIM}# {label}{END}")
                out.append(f"    {GREEN}{cmd}{END}")
        if had_any:
            out.append("")
    return "\n".join(out)


def render_stats(scan, color=True):
    """Summary statistics across the scan."""
    if color and sys.stdout.isatty():
        BOLD, DIM, END = "\033[1m", "\033[2m", "\033[0m"
    else:
        BOLD = DIM = END = ""

    from collections import Counter
    port_counter = Counter()
    service_counter = Counter()
    os_counter = Counter()
    state_counter = Counter()
    sev_counter = Counter()

    up = 0
    for host in scan["hosts"]:
        if host["state"] != "up":
            continue
        up += 1
        if host["os"]:
            os_counter[host["os"][0]["name"]] += 1
        for p in host["ports"]:
            state_counter[p["state"]] += 1
            if p["state"] == "open":
                port_counter[f"{p['portid']}/{p['protocol']}"] += 1
                if p["service"]:
                    service_counter[p["service"]] += 1
            for s in p["scripts"]:
                sev, _, _ = _score_output(s["output"])
                if sev:
                    sev_counter[sev] += 1

    out = [f"{BOLD}Scan statistics{END}", f"{DIM}{'=' * 70}{END}", ""]
    out.append(f"Hosts up:      {up}")
    out.append(f"Open ports:    {state_counter.get('open', 0)}")
    out.append(f"Filtered:      {state_counter.get('filtered', 0)}")
    out.append("")

    if port_counter:
        out.append(f"{BOLD}Most common open ports:{END}")
        for port, n in port_counter.most_common(15):
            bar = "#" * min(n, 40)
            out.append(f"  {port:<10} {n:>4}  {DIM}{bar}{END}")
        out.append("")

    if service_counter:
        out.append(f"{BOLD}Top services:{END}")
        for svc, n in service_counter.most_common(15):
            out.append(f"  {svc:<20} {n:>4}")
        out.append("")

    if os_counter:
        out.append(f"{BOLD}Operating systems:{END}")
        for os_name, n in os_counter.most_common(10):
            out.append(f"  {os_name:<40} {n:>4}")
        out.append("")

    if sev_counter:
        out.append(f"{BOLD}Findings by severity:{END}")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_counter.get(sev):
                out.append(f"  {sev.upper():<10} {sev_counter[sev]:>4}")
        out.append("")

    return "\n".join(out)




def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Format nmap XML scan output into HTML, Markdown, JSON, CSV, or pentest-friendly target lists.",
        epilog="Tip: run `nmap -sV -O -sC -oX scan.xml <target>` first to produce input.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="Path to nmap XML file, or '-' for stdin")

    # Verbosity
    vgroup = parser.add_mutually_exclusive_group()
    vgroup.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose: show closed ports, full script output, all OS guesses")
    vgroup.add_argument("-q", "--quiet", "--minimal", dest="quiet", action="store_true",
                        help="Minimal: one-line-per-port (host:port  state  service  version)")

    # Output format
    parser.add_argument(
        "-f", "--format",
        choices=["html", "md", "txt", "json", "csv", "targets", "hosts", "etc-hosts"],
        default="html",
        help=("Output format. html=styled report, md=markdown, txt=colored terminal, "
              "json=full data, csv=spreadsheet, targets=ip:port lines, "
              "hosts=just IPs, etc-hosts=/etc/hosts entries"),
    )
    parser.add_argument("-o", "--output", help="Write to file instead of stdout")

    # Filtering
    fgroup = parser.add_argument_group("filtering")
    fgroup.add_argument("--hosts-filter", "--ip", dest="ip_filter", metavar="SPEC",
                        help="Filter by IP: '192.168.1.1', '192.168.1.0/24', '10.0.0.1-10.0.0.50', "
                             "or comma-separated combo. Substrings match hostnames.")
    fgroup.add_argument("-p", "--port", dest="port_filter", metavar="PORTS",
                        help="Only hosts with these ports open: '80,443' or '20-25,80'")
    fgroup.add_argument("-s", "--service", metavar="NAME",
                        help="Only hosts running a service whose name/product contains NAME (e.g. 'ssh', 'apache')")
    fgroup.add_argument("--state", default="open,filtered",
                        help="Port states to include (comma-separated; default: open,filtered)")
    fgroup.add_argument("--with-findings", action="store_true",
                        help="Only hosts with at least one security finding")
    fgroup.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"],
                        help="Only hosts with a finding at this severity or higher")

    # Pentest helpers
    pgroup = parser.add_argument_group("pentest helpers")
    pgroup.add_argument("--suggest", action="store_true",
                        help="Output suggested next-step commands per open service")
    pgroup.add_argument("--stats", action="store_true",
                        help="Show summary statistics (port distribution, top services, OS counts)")

    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors in terminal output")

    args = parser.parse_args(argv)

    try:
        scan = parse_nmap_xml(args.input)
    except FileNotFoundError:
        sys.stderr.write(f"error: file not found: {args.input}\n")
        return 1

    # Apply filters
    states = None
    if args.state:
        states = {s.strip() for s in args.state.split(",") if s.strip()}
        if "all" in states:
            states = None
    if args.verbose:
        states = None  # show everything in verbose mode

    if any([args.ip_filter, args.port_filter, args.service, states,
            args.with_findings, args.min_severity]):
        scan = filter_scan(
            scan,
            ip_spec=args.ip_filter,
            port_spec=args.port_filter,
            service=args.service,
            states=states,
            with_findings=args.with_findings,
            min_severity=args.min_severity,
        )

    color = not args.no_color

    # Pentest-helper modes are content-only; they bypass the format flag
    if args.stats:
        print(render_stats(scan, color=color))
        if not args.suggest and not args.quiet:
            print()
    if args.suggest:
        print(render_suggestions(scan, color=color))
        if args.stats or args.quiet:
            return 0

    # Main output
    if args.quiet:
        out = render_minimal(scan, color=color)
    elif args.format == "html":
        out = render_html(scan)
    elif args.format == "md":
        out = render_markdown(scan)
    elif args.format == "json":
        out = render_json_compatible(scan)
    elif args.format == "csv":
        out = render_csv(scan)
    elif args.format == "targets":
        out = render_targets(scan)
    elif args.format == "hosts":
        out = render_hosts(scan)
    elif args.format == "etc-hosts":
        out = render_etc_hosts(scan)
    else:
        out = render_text(scan, color=color, verbose=args.verbose)

    if args.suggest or args.stats:
        # already printed above; only emit main output if not using a redirect-only mode
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
                if not out.endswith("\n"):
                    f.write("\n")
            sys.stderr.write(f"wrote {args.output}\n")
        return 0

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
            if not out.endswith("\n"):
                f.write("\n")
        sys.stderr.write(f"wrote {args.output}\n")
    else:
        print(out)

    return 0


def render_json_compatible(scan):
    """JSON output (was inline before)."""
    return json.dumps(scan, indent=2)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Silently exit when piped output is cut off (e.g. `| head`)
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
