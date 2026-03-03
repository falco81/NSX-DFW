# NSX-T DFW Log Analyzer

A Python toolkit for analyzing VMware NSX-T Distributed Firewall (DFW) logs. Connects to tar.gz exports from Log Insight / Aria Operations for Logs, extracts and deduplicates flow records, enriches them with DNS and service names, and produces CSV reports or fully interactive HTML dashboards — all completely offline.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## The Problem

NSX-T DFW log exports from Log Insight can contain **tens of millions** of raw syslog rows spread across dozens of CSV files packed in a tar.gz archive. Manually sifting through these to identify unique flows, blocked traffic, or suspicious connections is impractical. You need a way to deduplicate, filter, enrich (DNS PTR, service names), and visualize the data — ideally without uploading anything to external services.

This toolkit solves that with three scripts:

| Script | Purpose |
|---|---|
| `nsxt_fw_analyzer.py` | Main analyzer — extract, deduplicate, filter, and report DFW flows |
| `dns_cache_update.py` | Helper — bulk DNS PTR cache management, pre-population, and maintenance |
| `nsx_dfw_doc.py` | DFW documentation — fetch policies/rules/groups from NSX API and generate interactive HTML reference |

## Features

- **Extract & deduplicate** — reads tar.gz archives with CSVs, deduplicates flows by `(src_ip, dst_ip, dst_port, protocol)`
- **IP class filtering** — filter by private (RFC 1918 + CGNAT 100.64/10), public, multicast, or show all
- **Load Balancer detection** — identifies NSX LB traffic via 100.64.0.0/10 SNAT addresses, with dedicated badge, stats card, and one-click toggle filter
- **GeoIP country flags** — offline SVG flag icons next to public IPs using the free DB-IP Lite database; interactive stats card lets you click any flag to filter by country
- **Flexible exclusions** — exclude specific IPs/ports via CLI flags or file lists
- **DNS PTR resolution** — reverse DNS against up to 2 custom DNS servers with persistent file cache and automatic retry of failed lookups
- **Port-to-service translation** — maps port numbers to service names (built-in ~270 ports or optional full IANA database with ~6,000 entries)
- **Protocol descriptions** — human-readable labels for non-TCP/UDP protocols (ICMP, GRE, OSPF, etc.)
- **Interactive HTML report** — self-contained, offline-capable dark-themed dashboard with sorting, filtering, drag-and-drop column management, and clickable Top Talkers
- **Auto-download** — built-in `--download-geoip`, `--download-services`, and `--download-all` flags to fetch optional databases without manual wget commands
- **Bulk DNS helper** — standalone script for pre-populating, refreshing, and exporting the DNS cache
- **Performance** — handles tens of millions of rows with IP classification cache and set-based deduplication

## Installation

```bash
# Clone and use directly — no installation needed
git clone https://github.com/youruser/nsxt-fw-analyzer.git
cd nsxt-fw-analyzer

# Optional: install dnspython for custom DNS server support
pip install dnspython
```

> On RHEL/Fedora without pip access: `dnf install python3-dns`

### File Layout

```
nsxt-fw-analyzer/
├── nsxt_fw_analyzer.py      # Main analyzer script
├── dns_cache_update.py      # DNS cache management helper
├── nsx_dfw_doc.py           # DFW documentation generator
├── .dns_ptr_cache.json      # Auto-generated DNS cache (gitignored)
├── services-db.csv          # Optional IANA port database (--download-services)
├── geoip-country.csv        # Optional GeoIP country database (--download-geoip)
└── README.md
```

## Quick Start

```bash
# Download optional databases (IANA services + GeoIP country)
python3 nsxt_fw_analyzer.py --download-all

# Basic analysis — private IPs only (default)
python3 nsxt_fw_analyzer.py export.tar.gz

# All IPs with interactive HTML report
python3 nsxt_fw_analyzer.py export.tar.gz -m all --html

# Public IPs with DNS + GeoIP country flags
python3 nsxt_fw_analyzer.py export.tar.gz -m public --resolve-dns --html -o report.html
```

---

# nsxt_fw_analyzer.py

## Input Format

The script expects a `.tar.gz` archive containing CSV files exported from VMware Log Insight / Aria Operations for Logs. Each CSV should contain DFW syslog records with columns for timestamp, hostname, text (the raw syslog message), and optional vSphere metadata (cluster, datacenter).

## IP Class Modes

| Mode | Description |
|---|---|
| `private` | Both src and dst must be RFC 1918 (10.x, 172.16-31.x, 192.168.x) or CGNAT (100.64.0.0/10) — **default** |
| `public` | At least one IP is publicly routable |
| `multicast` | At least one IP is in 224.0.0.0/4 |
| `all` | No IP class filtering |

The 100.64.0.0/10 range (Shared Address Space / CGNAT) is classified as private because NSX-T Load Balancers use these addresses for SNAT. Flows involving these IPs are automatically tagged with an `LB` badge in the HTML report.

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

### Database Download

| Flag | Description |
|---|---|
| `--download-services` | Download IANA port-to-service database (~580 KB) |
| `--download-geoip` | Download DB-IP Country Lite GeoIP database (~24 MB, auto-detects current month) |
| `--download-all` | Download both databases at once |

These flags require no positional argument — they download the file next to the script and exit. If the current month's GeoIP release is not available yet, the previous month is used automatically.

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

```text
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

### Download Optional Databases

```bash
# Download IANA services database (~580 KB, ~6,000 port mappings)
python3 nsxt_fw_analyzer.py --download-services

# Download GeoIP country database (~24 MB, auto-detects current month)
python3 nsxt_fw_analyzer.py --download-geoip

# Download both at once
python3 nsxt_fw_analyzer.py --download-all
```

## Output

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
  [export_001.csv] 2,586 rows
  [export_002.csv] 4,831 rows
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

### CSV

Standard comma-separated output with all columns. Importable into Excel, Google Sheets, or any SIEM.

### HTML

Fully self-contained interactive report — see [Interactive HTML Report](#interactive-html-report) below.

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

- **Statistics cards** — total unique flows, PASS/DROP/REJECT counts with percentages, protocol breakdown, Load Balancer flow count (100.64/10)
- **GeoIP card** — when GeoIP database is present, shows country count with clickable SVG flag icons; click any flag to filter the table by that country
- **Top Talkers** — expandable panels showing top 10 source IPs, top 10 destination IPs, and top 15 destination ports with bar charts

### Table Features

| Feature | Description |
|---|---|
| **Global search** | Fulltext search across all columns with match highlighting |
| **Column sorting** | Click column header popup → Sort Ascending / Sort Descending |
| **Per-column filters** | Wildcard, regex, and negation filters per column (see [Filter Syntax](#filter-syntax)) |
| **LB toggle** | `LB` button next to search — one-click filter to show only Load Balancer flows (100.64.0.0/10) |
| **LB badge** | Rows involving NSX LB SNAT IPs display a small blue `LB` tag in the first visible column |
| **GeoIP flags** | Inline SVG country flags next to public IP addresses (offline, no CDN); fallback to 2-letter code for unknown countries |
| **GeoIP filter** | Click any flag in the GeoIP stats card to filter the table by country; click again to deselect |
| **Top Talker click** | Click any value in Top Talkers to set it as a column filter (click again to unset) |
| **Active filter tags** | Colored tags above the table showing all active filters — click ✕ to remove individual filters |
| **Drag-and-drop columns** | Reorder columns by dragging headers |
| **Column visibility** | Show/hide columns via the Columns panel |
| **Export CSV** | Export the currently visible (filtered) data as CSV |
| **Pagination** | 100 rows per page with page navigation |
| **Print layout** | Optimized for printing (controls hidden automatically) |
| **Reset** | Restores all defaults (column order, visibility, filters, sort, LB toggle, GeoIP filter) |
| **Print layout** | Optimized for printing (controls hidden automatically) |
| **Reset** | Restores all defaults (column order, visibility, filters, sort) |

### Filter Syntax

Filters are entered in the per-column popup (click any column header). All modes support negation with `!` prefix.

| Syntax | Type | Example | Matches |
|---|---|---|---|
| `text` | Substring (case-insensitive) | `DROP` | Any cell containing "DROP" |
| `*`, `?` | Wildcard (`*` = any chars, `?` = one char) | `10.0.1.*` | All IPs in 10.0.1.x |
| `/regex/i` | Regular expression | `/^10\.0\./` | IPs starting with 10.0. |
| `!pattern` | Negation (any of the above) | `!DROP` | Everything except DROP |

**Combined filter examples (filters across columns act as AND):**

| Column | Filter | Result |
|---|---|---|
| Src IP | `10.0.1.*` | Flows from 10.0.1.x subnet only |
| Action | `!DROP` | Exclude all DROPs |
| Dst Port | `443` | HTTPS traffic only |
| Rule | `!*-PROD-*` | Exclude rules containing "-PROD-" |
| Dst IP | `/^10\.0\./` | Destinations starting with 10.0. |

## Port-to-Service Database

The `dst_service` column maps port numbers to service names using a tiered system:

| Priority | Source | Coverage |
|---|---|---|
| 1 | `services-db.csv` (IANA CSV file next to script) | ~6,000 port mappings |
| 2 | Built-in dictionary (no file needed) | ~270 common ports |

The built-in dictionary covers all well-known services (SSH, HTTP, HTTPS, RDP, DNS, SMTP, MySQL, PostgreSQL, Kubernetes API, Elasticsearch, MongoDB, etc.) and works completely offline.

For comprehensive coverage, download the IANA registry:

```bash
python3 nsxt_fw_analyzer.py --download-services
```

## GeoIP Country Database

When a `geoip-country.csv` file is present next to the script, the HTML report displays inline SVG country flags next to public IP addresses. Private IPs never show flags. The database is the free [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) (CC BY 4.0 license).

```bash
python3 nsxt_fw_analyzer.py --download-geoip
```

This auto-detects the current month and downloads the correct file (~24 MB). If the current month's release is not published yet, the previous month is used as fallback.

The HTML report includes ~70 built-in SVG flag definitions covering most countries. For any country without a built-in SVG, a 2-letter country code badge is shown instead. All flags are embedded as base64 data URIs — fully offline, no CDN or internet needed at report viewing time.

If the file is missing, geolocation is silently skipped — no errors, no flags.

---

# dns_cache_update.py

Standalone helper for bulk DNS PTR cache management. Place it in the same directory as `nsxt_fw_analyzer.py` — both scripts share the same `.dns_ptr_cache.json` file.

> **Requires:** `pip install dnspython` (or `dnf install python3-dns` on RHEL/Fedora)

## Commands Executed

| Action | Command | Description |
|---|---|---|
| Retry empty | `python3 dns_cache_update.py` | Re-resolve all failed lookups |
| Full refresh | `python3 dns_cache_update.py --retry-all` | Re-resolve ALL entries from scratch |
| Add subnet | `python3 dns_cache_update.py --add 10.0.1.0/24` | Resolve entire subnet, skip already cached |
| Add from file | `python3 dns_cache_update.py --add-file ips.txt` | Bulk add IPs/subnets from text file |
| Statistics | `python3 dns_cache_update.py --stats` | Show resolution rates and top domains |
| Cleanup | `python3 dns_cache_update.py --remove-empty` | Delete all unresolved entries |
| Export | `python3 dns_cache_update.py --export hosts.txt` | Export as `/etc/hosts` format |
| Preview | `python3 dns_cache_update.py --add 10.0.0.0/16 --dry-run` | Show what would happen |

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
| `--dry-run` | Preview what would be resolved |

## Output

### Retry

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

### Statistics

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

## Usage Examples

### Add from File

```bash
python3 dns_cache_update.py --add-file targets.txt
```

Example `targets.txt`:

```text
# Web servers
10.0.1.0/24

# Database subnet
10.0.2.0/24

# Individual hosts
172.16.0.5
172.16.0.6
```

### Pre-populate Cache Before Analysis

```bash
# 1. Resolve all IPs in advance
python3 dns_cache_update.py --add 10.0.0.0/16 10.1.0.0/16

# 2. Run analyzer — DNS lookups will be instant from cache
python3 nsxt_fw_analyzer.py export.tar.gz -m all --resolve-dns --html
```

### Periodic Maintenance

```bash
# Weekly: retry failed lookups (DNS records may have been added)
python3 dns_cache_update.py

# Monthly: full refresh (catch hostname changes)
python3 dns_cache_update.py --retry-all

# Quarterly: clean up permanent failures
python3 dns_cache_update.py --remove-empty
```

---

# nsx_dfw_doc.py

Interactive HTML documentation generator for NSX-T Distributed Firewall configuration. Connects to the NSX Manager Policy API to fetch all security policies, rules, groups, services, and context profiles, then renders a self-contained dark-themed HTML reference with sidebar navigation, enriched object details, and cross-linking between rules and inventory.

Can also work fully offline from a previously exported JSON file.

> **Requires:** `pip install requests` (only for `fetch` mode — offline JSON mode has no dependencies)

## How It Works

The script operates in two stages:

1. **Fetch** — connects to NSX Manager via the Policy API (`/policy/api/v1/infra`) and exports DFW domains, security policies, rules, groups, user-defined services, and context profiles into a single JSON file. System-owned objects (built-in NSX services) are excluded from the export but their display names are preserved when referenced by nested service entries.

2. **Generate** — parses the JSON and produces a fully self-contained HTML document. All CSS, JavaScript, and data are embedded — no external dependencies, works offline in any browser.

## Features

- **Live fetch or offline JSON** — pull directly from NSX Manager or generate from a previously saved JSON export
- **Category-based layout** — policies grouped by DFW processing order (Ethernet → Emergency → Infrastructure → Environment → Application), sorted by `internal_sequence_number` from the API
- **Dynamic color palette** — category colors assigned automatically from a 10-color palette, no hardcoded assumptions about category names
- **Sidebar navigation** — auto-width sidebar listing all policies per category with rule counts; click to jump directly to any policy
- **Full-text search** — search box filters policies, rules, groups, and services across the entire document
- **Toggle filters** — one-click buttons to hide auto-generated (system-owned) policies and disabled rules
- **Enriched groups** — rules display group members inline: IP addresses, tag conditions, VM names (truncated UUIDs for ExternalIDExpression), nested expressions with full condition trees, and clickable cross-references to other groups
- **Enriched services** — nested service entries (e.g. Microsoft Active Directory V2) are resolved to their constituent service names instead of showing raw `NestedServiceServiceEntry` types
- **Clickable cross-links** — group names in rules link to the Groups inventory; service names link to the Services inventory
- **Rule metadata** — displays rule tags / log labels, logging status, enabled/disabled state, direction, IP protocol, and scope
- **Groups inventory** — full table of all groups with member types, member details, and rule reference counts; unused groups visually dimmed
- **Services inventory** — all user-defined services with protocol/port details and rule reference counts
- **`--filter` option** — generate documentation for a specific project or segment by matching against policy names, group names, and rule tags
- **Fully dynamic** — no hardcoded NSX object names, category names, prefixes, or detection strings; works with any NSX-T environment

## CLI Reference

```
nsx_dfw_doc.py fetch [output.json] [output.html] [--filter TEXT]
nsx_dfw_doc.py <input.json> [output.html] [--filter TEXT]
```

### Modes

| Mode | Description |
|---|---|
| `fetch` | Connect to NSX Manager API, export JSON, then generate HTML |
| `<input.json>` | Generate HTML from a previously exported JSON file |

### Options

| Flag | Description |
|---|---|
| `--filter TEXT` | Only include policies matching TEXT (case-insensitive) in policy name, source/destination group names, or rule tags |

### Output Files

| File | When | Default Name |
|---|---|---|
| JSON export | `fetch` mode | `dfw_objects.json` |
| HTML report | Always | `<json_basename>_documentation.html` |
| Filtered report | `--filter` used | `<json_basename>_<filter>_documentation.html` |

Filenames can be overridden by passing `.json` and/or `.html` paths as positional arguments.

## Usage Examples

### Fetch and Generate

```bash
# Interactive — prompts for NSX host, username, password
python3 nsx_dfw_doc.py fetch

# With custom output filenames
python3 nsx_dfw_doc.py fetch dfw_export.json dfw_report.html

# Fetch and filter in one step
python3 nsx_dfw_doc.py fetch --filter PROJ-A
```

### Generate from Existing JSON

```bash
# Full documentation
python3 nsx_dfw_doc.py dfw_objects.json

# Custom output path
python3 nsx_dfw_doc.py dfw_objects.json /tmp/dfw_report.html

# Filtered — only policies related to PROJ-A
python3 nsx_dfw_doc.py dfw_objects.json --filter PROJ-A

# Filtered — only policies related to PROJ-B
python3 nsx_dfw_doc.py dfw_objects.json --filter PROJ-B
```

### Filter Logic

The `--filter` flag performs case-insensitive matching. A policy is included if any of these conditions are met:

| Condition | Behavior |
|---|---|
| Policy name contains filter text | All rules of that policy are included |
| Any rule has source/destination groups whose name contains filter text | Only matching rules are included |
| Any rule has a tag containing filter text | Only matching rules are included |

This means infrastructure policies that reference project-specific groups are automatically included with the relevant rules, even if the policy name itself does not match.

## Output

### CLI

```
Loading JSON: dfw_objects.json
  Found 60 policies, 316 rules
  2862 groups, 110 services, 2 profiles
  Categories: Ethernet, Emergency, Infrastructure, Environment, Application
HTML documentation written to: dfw_objects_documentation.html
```

With `--filter`:

```
Loading JSON: dfw_objects.json
  Found 60 policies, 316 rules
  2862 groups, 110 services, 2 profiles
  Categories: Ethernet, Emergency, Infrastructure, Environment, Application
  Filter 'PROJ-A': 3 policies, 27 rules matched
HTML documentation written to: dfw_objects_PROJ-A_documentation.html
```

### HTML Report Structure

The generated HTML document contains these sections:

| Section | Content |
|---|---|
| **Sidebar** | Category headers with color indicators, policy names with rule counts, click-to-navigate |
| **Header** | Title, filter indicator (if active), global stats (policies, rules, categories) |
| **Filter bar** | Full-text search, toggle buttons for auto-generated policies and disabled rules |
| **Policies** | One card per policy: metadata row (category badge, enabled/disabled, scope, rule count), then a rules table |
| **Rules table** | Columns: Seq, Name, Source, Destination, Services, Profiles, Action, Direction, IP Protocol, Flags |
| **Groups inventory** | All groups with ID, display name, member types, member details, rule reference count |
| **Services inventory** | All user-defined services with protocol/port details and rule reference count |

### Rule Display Details

Each rule row shows:

| Element | Description |
|---|---|
| **Source / Destination** | Group display names with clickable links to inventory; inline member detail (IPs, tags, conditions) |
| **Services** | Service names with clickable links; protocol/port shown on hover; nested services resolved to constituent names |
| **Action badge** | Color-coded: green (ALLOW), red (DROP), orange (REJECT) |
| **Flags** | Logging status with tag label, enabled/disabled state, auto-generated badge for system-owned policies |

### Group Member Display

Groups are rendered with full member detail depending on expression type:

| Expression Type | Display |
|---|---|
| IPAddressExpression | Comma-separated IP addresses |
| Condition | `MemberType Key OPERATOR value` (e.g. `VirtualMachine Tag EQUALS web-tier`) |
| NestedExpression | Recursive condition tree with AND/OR operators in brackets |
| PathExpression (groups) | Clickable links to referenced groups |
| PathExpression (segments) | Segment path names |
| ExternalIDExpression | Truncated VM UUIDs with count |
| ConjunctionOperator | `AND` / `OR` between conditions |

### Nested Service Resolution

Services of type `NestedServiceServiceEntry` (e.g. Microsoft Active Directory V2, which bundles 16 sub-services) are resolved to their constituent service display names. If the referenced service exists in the export, its protocol/port details are shown in parentheses. Otherwise, the service display name is shown as-is.

## Configuration

Default connection settings are configured at the top of the script:

```python
DEFAULT_NSX_HOST = 'nsx.example.local'    # NSX Manager hostname
DEFAULT_USERNAME = 'audit'                 # Default username (prompted interactively)
DEFAULT_JSON_OUTPUT = 'dfw_objects.json'   # Default JSON export filename
```

The `fetch` command prompts interactively for hostname, username, and password. Defaults can be accepted by pressing Enter.

## API Endpoints

The script fetches from three NSX Policy API endpoints:

| Endpoint | Objects |
|---|---|
| `/policy/api/v1/infra?filter=Type-Service` | User-defined services (system-owned excluded) |
| `/policy/api/v1/infra?filter=Type-PolicyContextProfile` | User-defined context profiles |
| `/policy/api/v1/infra?filter=Type-Domain\|Group\|SecurityPolicy\|Rule` | Domains, groups, security policies, rules |

All three responses are merged into a single JSON file. TLS certificate verification is disabled (`verify=False`) to support self-signed certificates common in lab and production NSX deployments.

## Requirements

- Python 3.8+
- `requests` for fetch mode (`pip install requests`)
- No dependencies for offline JSON-to-HTML generation

---

## DNS Resolution Logic

Both `nsxt_fw_analyzer.py` and `dns_cache_update.py` share the same resolution flow for each IP:

```
1. Query PRIMARY DNS server
   ├── PTR found → use hostname, DONE (skip secondary)
   └── NXDOMAIN / timeout → continue
2. Query SECONDARY DNS server
   ├── PTR found → use hostname, DONE
   └── NXDOMAIN / timeout → store ""
```

This ensures both servers are always consulted when needed — important when different DNS servers are authoritative for different reverse zones.

### Cache File

DNS results are persisted in `.dns_ptr_cache.json` next to the scripts:

```json
{
  "10.0.1.5": "web01.example.com",
  "10.0.2.10": "db-master.internal",
  "203.0.113.50": ""
}
```

| Value | Meaning | On next run |
|---|---|---|
| `"hostname"` | Successfully resolved PTR | Reused from cache |
| `""` | Lookup attempted, no PTR found | Automatically retried |
| *(missing)* | Never queried | Resolved on first encounter |

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
| /24 subnet pre-population (254 IPs) | 1–17 minutes |

## Troubleshooting

| Issue | Solution |
|---|---|
| `tarfile` RuntimeWarning on Python 3.12+ | Handled automatically (CVE-2007-4559 mitigation with fallback) |
| DNS resolution slow for many IPs | Pre-populate cache with `dns_cache_update.py --add` |
| Missing service names for uncommon ports | Run `python3 nsxt_fw_analyzer.py --download-services` |
| No country flags in HTML report | Run `python3 nsxt_fw_analyzer.py --download-geoip` |
| GeoIP download: "404 Not Found" for current month | Automatic fallback to previous month; or wait for DB-IP monthly release |
| Flags show as 2-letter codes, not images | Country not in built-in SVG set (~70 countries); this is expected for rare countries |
| `--dns-server` has no effect | Install `dnspython` — without it, system resolver is used |
| `dnspython` package not found in dnf | Package name is `python3-dns` on RHEL/Fedora |

## Requirements

- Python 3.8+
- No external dependencies for core functionality (CSV output, HTML report, port translation)
- `dnspython` for custom DNS server support (`pip install dnspython` or `dnf install python3-dns`)

## License

MIT
