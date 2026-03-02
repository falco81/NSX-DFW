# NSX-T DFW Log Analyzer

A Python toolkit for analyzing VMware NSX-T Distributed Firewall (DFW) logs. Extracts, deduplicates, and filters flow records from Log Insight / Aria Operations for Logs exports, producing CSV reports or fully interactive HTML dashboards — all completely offline.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## The Problem

NSX-T DFW log exports from Log Insight can contain tens of millions of raw syslog rows across dozens of CSV files packed in a tar.gz archive. Manually sifting through these to identify unique flows, blocked traffic, or suspicious connections is impractical. You need a way to deduplicate, filter, enrich (DNS, service names), and visualize the data — ideally without uploading anything to external services.

This toolkit solves that with two scripts:

| Script | Purpose |
|---|---|
| `nsxt_fw_analyzer.py` | Main analyzer — extract, deduplicate, filter, and report DFW flows |
| `dns_cache_update.py` | Helper — bulk DNS PTR cache management, pre-population, and maintenance |

## Features

- **Extract & deduplicate** — reads tar.gz archives with CSVs, deduplicates flows by `(src_ip, dst_ip, dst_port, protocol)`
- **IP class filtering** — filter by private (RFC 1918), public, multicast, or show all
- **Flexible exclusions** — exclude specific IPs/ports via CLI flags or file lists
- **DNS PTR resolution** — reverse DNS against up to 2 custom DNS servers with persistent file cache and automatic retry of failed lookups
- **Port-to-service translation** — maps port numbers to service names (built-in ~270 ports or optional full IANA database with ~6,000 entries)
- **Protocol descriptions** — human-readable labels for non-TCP/UDP protocols (ICMP, GRE, OSPF, etc.)
- **Interactive HTML report** — self-contained, offline-capable dark-themed dashboard with sorting, filtering, drag-and-drop column management, and clickable Top Talkers
- **Bulk DNS helper** — standalone script for pre-populating, refreshing, and exporting the DNS cache
- **Performance** — handles tens of millions of rows with IP classification cache and set-based deduplication
- **Zero dependencies** — core functionality works with Python standard library only; `dnspython` optional for custom DNS servers

## Installation

```bash
# Clone and use directly — no installation needed
git clone https://github.com/youruser/nsxt-fw-analyzer.git
cd nsxt-fw-analyzer

# Optional: install dnspython for custom DNS server support
pip install dnspython
```

> On RHEL/Fedora without internet pip access: `dnf install python3-dns`

### File Layout

```
nsxt-fw-analyzer/
├── nsxt_fw_analyzer.py      # Main analyzer script
├── dns_cache_update.py      # DNS cache management helper
├── .dns_ptr_cache.json      # Auto-generated DNS cache (gitignored)
├── services-db.csv          # Optional IANA port database
└── README.md
```

## Quick Start

```bash
# Basic analysis — private IPs only (default)
python3 nsxt_fw_analyzer.py export.tar.gz

# All IPs with interactive HTML report
python3 nsxt_fw_analyzer.py export.tar.gz -m all --html

# Full analysis with DNS resolution
python3 nsxt_fw_analyzer.py export.tar.gz -m all --resolve-dns --html -o report.html
```

---

# nsxt_fw_analyzer.py

## Input Format

The script expects a `.tar.gz` archive containing CSV files exported from VMware Log Insight / Aria Operations for Logs. Each CSV should contain DFW syslog records with columns for timestamp, hostname, text (the raw syslog message), and optional vSphere metadata (cluster, datacenter).

## IP Class Modes

| Mode | Description |
|---|---|
| `private` | Both src and dst must be RFC 1918 (10.x, 172.16-31.x, 192.168.x) — **default** |
| `public` | At least one IP is publicly routable |
| `multicast` | At least one IP is in 224.0.0.0/4 |
| `all` | No IP class filtering |

## CLI Reference

```
python3 nsxt_fw_analyzer.py INPUT [OPTIONS]
```

### Required

| Argument | Description |
|---|---|
| `INPUT` | Path to `.tar.gz` archive with CSV files |

### Output Options

| Flag | Description |
|---|---|
| `-o, --output FILE` | Output file path. Default: `<archive>_<mode>_unique.csv` |
| `--html` | Generate interactive HTML report instead of CSV |
| `--sort-by {src_ip,dst_ip,dst_port}` | Sort order (default: `src_ip`) |
| `--stats` | Print top-talker statistics to stderr |
| `--no-translate` | Disable port-to-service and protocol description columns |

### Filtering Options

| Flag | Description |
|---|---|
| `-m, --mode {private,public,multicast,all}` | IP class filter (default: `private`) |
| `--action {PASS,DROP,REJECT}` | Show only matching firewall action |
| `--direction {IN,OUT}` | Show only matching flow direction |
| `--exclude-ips IP1,IP2,...` | Comma-separated IPs to exclude |
| `--exclude-ports PORT1,PORT2,...` | Comma-separated ports to exclude |
| `--exclude-ips-file FILE` | File with IPs to exclude (one per line, `#` comments) |
| `--exclude-ports-file FILE` | File with ports to exclude (one per line, `#` comments) |

### DNS Options

| Flag | Description |
|---|---|
| `--resolve-dns` | Enable PTR lookups (results cached to `.dns_ptr_cache.json`) |
| `--dns-server IP` | Primary DNS server for PTR queries |
| `--dns-server2 IP` | Secondary DNS server (fallback if primary fails) |
| `--dns-cache-file PATH` | Custom cache file path |

## Usage Examples

### Basic Analysis

```bash
# Private traffic only (default)
python3 nsxt_fw_analyzer.py logs_export.tar.gz

# All traffic
python3 nsxt_fw_analyzer.py logs_export.tar.gz -m all

# Public traffic only
python3 nsxt_fw_analyzer.py logs_export.tar.gz -m public
```

### Filtering

```bash
# Dropped traffic only
python3 nsxt_fw_analyzer.py logs_export.tar.gz -m all --action DROP

# Outbound traffic, excluding management IPs
python3 nsxt_fw_analyzer.py logs_export.tar.gz \
    --direction OUT --exclude-ips 10.0.0.1,10.0.0.2

# Exclude using files
python3 nsxt_fw_analyzer.py logs_export.tar.gz \
    --exclude-ips-file skip_ips.txt --exclude-ports-file skip_ports.txt
```

Example `skip_ips.txt`:
```
# Management IPs
10.0.0.1
10.0.0.2
# Monitoring
10.0.10.50
```

### DNS Resolution

```bash
# With custom DNS servers
python3 nsxt_fw_analyzer.py logs_export.tar.gz --resolve-dns \
    --dns-server 10.0.0.53 --dns-server2 10.0.1.53

# Reuses cached results from previous runs automatically
python3 nsxt_fw_analyzer.py logs_export.tar.gz --resolve-dns
```

### HTML Report

```bash
# Interactive HTML dashboard
python3 nsxt_fw_analyzer.py logs_export.tar.gz -m all --html

# Full analysis with HTML output
python3 nsxt_fw_analyzer.py logs_export.tar.gz \
    -m all --resolve-dns --html --stats -o report.html
```

### Complete Analysis

```bash
python3 nsxt_fw_analyzer.py logs_export.tar.gz \
    -m all --resolve-dns \
    --dns-server 10.0.0.53 --dns-server2 10.0.1.53 \
    --exclude-ips-file skip_ips.txt --exclude-ports 53,67,68 \
    --action PASS --direction IN --sort-by dst_ip --stats \
    -o full_analysis.csv
```

## Output

### CSV

Standard comma-separated output with all columns. Importable into Excel, Google Sheets, or any SIEM.

### CLI

```
┌─ NSX-T DFW Log Analyzer ─────────────────────┐
│ Input:    logs_export.tar.gz
│ Output:   report.html
│ Format:   HTML
│ Mode:     all
│ DNS:      True
│ DNS srv:  10.0.0.53, 10.0.1.53
│ Sort:     src_ip
└──────────────────────────────────────────────┘

[1/4] Extracting CSVs...
  Found 15 CSV files

[2/4] Processing & deduplicating...
  [export1.csv] 2,586 rows
  [export2.csv] 4,831 rows
  ...
─────────────────────────────────────────────
  Total rows:          26,726
  Filtered out:         2,397
  Duplicates:          23,953
  Unique flows:           376
─────────────────────────────────────────────

[3/4] DNS PTR resolution...
[DNS] dnspython -> 10.0.0.53, 10.0.1.53
  Resolving 142 unique IPs...  [142/142]

[4/4] Writing output...

[OUTPUT] 376 records -> report.html (HTML)

Done in 8.3s
```

## Output Columns

| Column | Description | Condition |
|---|---|---|
| `src_ip` | Source IP address | Always |
| `src_dns` | PTR hostname for source IP | `--resolve-dns` |
| `src_port` | Source port | Always |
| `dst_ip` | Destination IP address | Always |
| `dst_dns` | PTR hostname for destination IP | `--resolve-dns` |
| `dst_port` | Destination port number | Always |
| `dst_service` | Service name (e.g. `https`, `ssh`, `rdp`) | Default (disable: `--no-translate`) |
| `protocol` | Protocol (TCP, UDP, or number) | Always |
| `protocol_desc` | Short label for non-TCP/UDP (e.g. `ICMP (1)`) | Default (disable: `--no-translate`) |
| `action` | Firewall action: PASS, DROP, or REJECT | Always |
| `direction` | Flow direction: IN or OUT | Always |
| `rule_name` | DFW rule name | Always |
| `hostname` | ESXi host name | Always |
| `cluster` | vSphere cluster name | Always |
| `datacenter` | vSphere datacenter name | Always |
| `first_seen` | First occurrence timestamp | Always |

## Interactive HTML Report

The `--html` flag generates a fully self-contained HTML file that works offline in any browser. No external CSS, JavaScript, or font dependencies.

### Dashboard

- **Statistics cards** — total unique flows, PASS/DROP/REJECT counts with percentages, protocol breakdown, unique port count
- **Top Talkers** — expandable panel showing top 10 source IPs, top 10 destination IPs, and top 15 destination ports with bar charts

### Table Features

| Feature | Description |
|---|---|
| **Global search** | Fulltext search across all columns with match highlighting |
| **Column sorting** | Click column header popup → Sort Ascending / Sort Descending |
| **Per-column filters** | Click any column header for a filter popup (see Filter Syntax below) |
| **Negation filters** | Prefix `!` to exclude matches: `!DROP`, `!10.0.*` |
| **Multi-column filters** | Multiple column filters combine as AND |
| **Drag & drop columns** | Reorder columns by dragging headers |
| **Show/hide columns** | "Columns" button toggles visibility (Host, Cluster, DC hidden by default) |
| **Interactive Top Talkers** | Click any IP or port in Top Talkers to instantly filter the table; click again to remove |
| **Pagination** | Configurable 50/100/250/500/1000 rows per page |
| **CSV export** | Exports currently filtered and visible columns |
| **Print layout** | Optimized for printing (controls hidden) |
| **Reset** | Restores all defaults (column order, visibility, filters, sort) |

### Filter Syntax

Filters are entered in the per-column popup (click any column header). All three modes support negation with `!` prefix.

| Syntax | Type | Example | Matches |
|---|---|---|---|
| `text` | Substring (case-insensitive) | `DROP` | Any cell containing "DROP" |
| `*pattern*` | Wildcard (`*` = any, `?` = one char) | `10.0.1.*` | All IPs in 10.0.1.x |
| `/regex/i` | Regular expression | `/^10\.0\./` | IPs starting with 10.0. |
| `!pattern` | Negation (any type) | `!DROP` | Everything except DROP |

**Combined filter examples:**

| Column | Filter | Result |
|---|---|---|
| Src IP | `10.0.1.*` | All flows from 10.0.1.x subnet |
| Action | `!DROP` | Everything except DROP |
| Dst Port | `443` | HTTPS traffic |
| Rule | `!*-PROD-*` | Exclude rules containing "-PROD-" |
| Dst IP | `/^10\.0\./` | Regex: all IPs starting with 10.0. |

## Port-to-Service Database

The `dst_service` column maps port numbers to service names using a tiered system:

| Priority | Source | Coverage |
|---|---|---|
| 1 | `services-db.csv` (IANA CSV file) | ~6,000 port mappings |
| 2 | Built-in dictionary | ~270 common ports |

The built-in dictionary covers all well-known services (SSH, HTTP, HTTPS, RDP, DNS, SMTP, MySQL, PostgreSQL, Kubernetes API, Elasticsearch, MongoDB, etc.) and works completely offline.

For comprehensive coverage, download the IANA registry once:

```bash
wget -O services-db.csv \
  'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
```

## DNS Resolution

DNS results are persisted in `.dns_ptr_cache.json` next to the script:

```json
{
  "10.0.1.5": "web01.example.com",
  "10.0.2.10": "db-master.internal",
  "203.0.113.50": ""
}
```

**Resolution flow for each IP:**

```
1. Query PRIMARY DNS server
   ├── PTR found → use hostname, DONE (skip secondary)
   └── NXDOMAIN / timeout → continue
2. Query SECONDARY DNS server
   ├── PTR found → use hostname, DONE
   └── NXDOMAIN / timeout → store ""
```

This ensures both servers are always consulted when needed — important when different DNS servers are authoritative for different zones.

**Cache behavior:**

- **Non-empty entries** — reused without re-querying
- **Empty entries** (`""`) — automatically retried on each run (DNS records may have been added since last attempt)
- Delete the file for a complete fresh start

---

# dns_cache_update.py

Standalone helper for bulk DNS PTR cache management. Place it in the same directory as `nsxt_fw_analyzer.py` — both scripts share the same `.dns_ptr_cache.json` file.

## Requirements

- `dnspython` — `pip install dnspython` (or `dnf install python3-dns` on RHEL/Fedora)

## CLI Reference

```
python3 dns_cache_update.py [OPTIONS]
```

### Connection Options

| Flag | Description | Default |
|---|---|---|
| `--dns-server IP` | Primary DNS server | Configured in script |
| `--dns-server2 IP` | Secondary DNS server (fallback) | Configured in script |
| `--timeout SECONDS` | DNS query timeout per server | `2` |
| `--cache-file PATH` | Path to cache file | `.dns_ptr_cache.json` |

### Actions

| Flag | Description |
|---|---|
| *(no flags)* | Retry all empty (failed) entries in cache |
| `--retry-all` | Re-resolve ALL entries (full refresh) |
| `--add IP [IP ...]` | Add and resolve IPs or subnets (e.g. `10.0.1.0/24`) |
| `--add-file FILE` | Add and resolve IPs from a text file |
| `--stats` | Show cache statistics and top domains |
| `--remove-empty` | Delete all unresolved entries from cache |
| `--export FILE` | Export resolved entries as hosts file (`IP\thostname`) |
| `--dry-run` | Preview what would be resolved without making DNS queries |

## Usage Examples

### Retry Failed Lookups

```bash
python3 dns_cache_update.py
```

```
[LOAD] 450 entries (312 resolved, 138 empty) from .dns_ptr_cache.json
[DNS] Servers: 10.0.0.53, 10.0.1.53
[RETRY] Resolving 138 IPs against 10.0.0.53, 10.0.1.53...
  + 10.0.1.15         -> app-server01.example.com  [10.0.0.53]
  + 10.0.2.30         -> db-replica.internal        [10.0.1.53]
  ...
[RETRY] Done: 45 resolved, 93 empty (12.3s)
[SAVE] 450 records -> .dns_ptr_cache.json
```

### Full Refresh

```bash
python3 dns_cache_update.py --retry-all
```

### Add Subnets

```bash
# Single subnet
python3 dns_cache_update.py --add 10.0.1.0/24

# Multiple subnets and individual IPs
python3 dns_cache_update.py --add 10.0.1.0/24 10.0.2.0/24 172.16.0.5

# Large subnet — preview first
python3 dns_cache_update.py --add 10.0.0.0/16 --dry-run
```

### Add from File

```bash
python3 dns_cache_update.py --add-file targets.txt
```

Example `targets.txt`:
```
# Web servers
10.0.1.0/24

# Database subnet
10.0.2.0/24

# Individual hosts
172.16.0.5
172.16.0.6
```

### Cache Statistics

```bash
python3 dns_cache_update.py --stats
```

```
==================================================
  DNS PTR Cache Statistics
==================================================
  Total entries:         450
  Resolved (PTR):        357  (79%)
  Empty (no PTR):         93  (20%)

  Top 10 domains:
    example.com                           185
    internal.local                         98
    cloud.provider.net                     42
    corp.company.com                       32
==================================================
```

### Export & Cleanup

```bash
# Export resolved entries as hosts file
python3 dns_cache_update.py --export hosts.txt

# Remove permanently failed entries
python3 dns_cache_update.py --remove-empty
```

## Workflow Examples

### Pre-populate Cache Before Analysis

```bash
# 1. Resolve all IPs in advance
python3 dns_cache_update.py --add 10.0.0.0/16 10.1.0.0/16

# 2. Run analyzer — DNS lookups will be instant from cache
python3 nsxt_fw_analyzer.py export.tar.gz -m all --resolve-dns --html
```

### Periodic Cache Maintenance

```bash
# Weekly: retry failed lookups (DNS records may have been added)
python3 dns_cache_update.py

# Monthly: full refresh (catch hostname changes)
python3 dns_cache_update.py --retry-all

# Quarterly: clean up permanent failures
python3 dns_cache_update.py --remove-empty
```

---

## Configuration

Default DNS servers and timeouts are configured at the top of each script. Edit these to match your environment:

```python
# In nsxt_fw_analyzer.py and dns_cache_update.py:
DNS_SERVER   = "10.0.0.53"     # Primary DNS for PTR lookups
DNS_SERVER2  = "10.0.1.53"     # Secondary DNS for PTR lookups
DNS_TIMEOUT  = 2               # Seconds per query per server
```

## Performance

| Metric | Value |
|---|---|
| 27,000 input rows → 376 unique flows | ~0.6 seconds |
| HTML report generation | ~0.2 seconds |
| DNS resolution (per IP, cached) | instant |
| DNS resolution (per IP, uncached) | 0.1–4 seconds |

The script uses IP classification caching, set-based deduplication, and streaming CSV processing to handle large datasets efficiently.

## Troubleshooting

| Issue | Solution |
|---|---|
| `tarfile` RuntimeWarning on RHEL 9 | Handled automatically (CVE-2007-4559 mitigation) |
| DNS resolution slow for many IPs | Pre-populate cache with `dns_cache_update.py --add` |
| Missing service names for ports | Download IANA CSV: `wget -O services-db.csv 'https://...'` |
| `--dns-server` has no effect | Install `dnspython` — without it, system resolver is used |
| `dnspython` not in dnf repos | Try `dnf install python3-dns` (RHEL/Fedora package name) |

## Requirements

- Python 3.8+
- No external dependencies for core functionality (CSV output, HTML report, port translation)
- `dnspython` for custom DNS server support (`pip install dnspython` or `dnf install python3-dns`)
- `openpyxl` NOT required (this tool works with CSV/tar.gz only)

## License

MIT
