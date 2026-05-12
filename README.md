<!-- 
Author: Jonathan Ash
Created: 12/05/2026 
-->

## Parsers 

Two Simple Parsers for PCAP loot and NMAP XML scans

## nmap-pretty

### Filtering
- `--ip 192.168.1.0/24` — IP filter accepts single IPs, CIDR, ranges (`10.0.0.1-10.0.0.50`), comma-separated combos, or hostname substrings
- `-p 80,443` or `-p 20-25` — only hosts with these ports open, and limits output to those ports
- `-s ssh` — substring match on service name/product
- `--state open,filtered` — which port states to include (default omits closed)
- `--with-findings` — only hosts with at least one detected vuln
- `--min-severity high` — only hosts with a finding at this severity or higher

### Verbosity 
- `-q` / `--quiet` / `--minimal` — one line per port: `192.168.1.1:22 open ssh OpenSSH 7.2p2`
- (default) — current behaviour
- `-v` / `--verbose` — adds closed ports and all alternate OS guesses

### Output
 `-f targets` — bare `ip:port` lines, perfect for piping into `hydra`, `ffuf`, `feroxbuster`, etc.
- `-f hosts` — just IPs, one per line — feed to `nmap -iL`, `nuclei -l`, mass scanners
- `-f etc-hosts` — `/etc/hosts` format with hostname → IP entries
- `-f csv` — full CSV with severity, CVSS, and CVE columns for client reports

### Suggestor 
WIP

## PCAP Looter 
Read helper if required
