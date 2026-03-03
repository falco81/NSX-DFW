#!/usr/bin/env python3
"""
NSX-T Firewall Log Analyzer
============================
Extracts, deduplicates, and filters DFW flow records from VMware NSX-T
log exports (tar.gz with CSVs from Log Insight / Aria Operations for Logs).

Features:
  - Extracts all CSVs from tar.gz archive
  - Filters by IP class: private (default), public, multicast, or all
  - Deduplicates by (src_ip, dst_ip, dst_port, protocol)
  - Exclude specific IPs or ports via CLI or files
  - Optional PTR DNS lookup against 1 or 2 DNS servers with persistent file cache
  - Port-to-service name translation (e.g. 443 -> https, 22 -> ssh)
  - Protocol number/name translation for non-TCP/UDP (e.g. 1 -> ICMP, 47 -> GRE)
  - Optimized for tens of millions of rows (IP classification cache, set-based dedup)
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

DNS_SERVER     = "10.12.254.11"    # Primary DNS for PTR lookups
DNS_SERVER2    = "10.12.255.101"   # Secondary DNS for PTR lookups
DNS_TIMEOUT    = 2
DNS_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".dns_ptr_cache.json"
)

# Port-to-service database file (IANA CSV format).
# Auto-download:  python3 nsxt_fw_analyzer.py --download-services
# Place next to this script. If missing, the built-in dictionary is used.
SERVICES_DB_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "services-db.csv"
)
SERVICES_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

# GeoIP country database (DB-IP lite CSV).
# Download page:  https://db-ip.com/db/download/ip-to-country-lite
# Auto-download:  python3 nsxt_fw_analyzer.py --download-geoip
# Place next to this script. If missing, geolocation is silently skipped.
GEOIP_DB_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "geoip-country.csv"
)
GEOIP_URL_TEMPLATE = "https://download.db-ip.com/free/dbip-country-lite-{ym}.csv.gz"

PROGRESS_EVERY = 500_000

# =============================================================================
# Well-known protocol numbers -> human-readable name
# =============================================================================

PROTOCOL_MAP = {
    "0":   ("HOPOPT",    "IPv6 Hop-by-Hop Option"),
    "1":   ("ICMP",      "Internet Control Message Protocol"),
    "2":   ("IGMP",      "Internet Group Management Protocol"),
    "3":   ("GGP",       "Gateway-to-Gateway Protocol"),
    "4":   ("IP-in-IP",  "IP in IP encapsulation"),
    "5":   ("ST",        "Internet Stream Protocol"),
    "6":   ("TCP",       "Transmission Control Protocol"),
    "7":   ("CBT",       "Core-Based Trees"),
    "8":   ("EGP",       "Exterior Gateway Protocol"),
    "9":   ("IGP",       "Interior Gateway Protocol (IGRP)"),
    "17":  ("UDP",       "User Datagram Protocol"),
    "27":  ("RDP",       "Reliable Data Protocol"),
    "41":  ("IPv6",      "IPv6 Encapsulation (6in4/6to4)"),
    "43":  ("IPv6-Route","Routing Header for IPv6"),
    "44":  ("IPv6-Frag", "Fragment Header for IPv6"),
    "46":  ("RSVP",      "Resource Reservation Protocol"),
    "47":  ("GRE",       "Generic Routing Encapsulation"),
    "50":  ("ESP",       "Encapsulating Security Payload (IPsec)"),
    "51":  ("AH",        "Authentication Header (IPsec)"),
    "58":  ("ICMPv6",    "ICMP for IPv6"),
    "59":  ("IPv6-NoNxt","No Next Header for IPv6"),
    "60":  ("IPv6-Opts", "Destination Options for IPv6"),
    "88":  ("EIGRP",     "Enhanced Interior Gateway Routing Protocol"),
    "89":  ("OSPF",      "Open Shortest Path First"),
    "103": ("PIM",       "Protocol Independent Multicast"),
    "112": ("VRRP",      "Virtual Router Redundancy Protocol"),
    "115": ("L2TP",      "Layer 2 Tunnelling Protocol"),
    "132": ("SCTP",      "Stream Control Transmission Protocol"),
    "137": ("MPLS-in-IP","MPLS in IP"),
}


def get_protocol_description(proto_str: str) -> str:
    """Return short protocol label. Empty for TCP/UDP.
    Handles NSX-T 'PROTO N' format, plain numbers, and names."""
    up = proto_str.strip().upper()
    if up in ("TCP", "UDP", "6", "17"):
        return ""
    raw = proto_str.strip()
    m = re.match(r'(?:PROTO\s+)?(\d+)', raw, re.IGNORECASE)
    if m:
        num = m.group(1)
        if num in PROTOCOL_MAP:
            name, _ = PROTOCOL_MAP[num]
            return f"{name} ({num})"
        return f"proto {num}"
    if raw in PROTOCOL_MAP:
        name, _ = PROTOCOL_MAP[raw]
        return name
    for num, (name, _) in PROTOCOL_MAP.items():
        if name.upper() == up:
            return f"{name} ({num})"
    return f"proto {proto_str}" if proto_str else ""


def get_service_name(port_str: str, protocol: str = "tcp") -> str:
    """Translate a port number to a well-known service name.
    Uses local IANA CSV (services-db.csv) if available, otherwise built-in dict."""
    if not port_str or not port_str.isdigit():
        return ""
    _load_services_db()
    port_num = int(port_str)
    if port_num <= 0 or port_num > 65535:
        return ""
    return _services_db.get(port_num, "")


# Built-in port-to-service dictionary (used when IANA CSV is not available)
BUILTIN_SERVICES = {
    1:"tcpmux",5:"rje",7:"echo",9:"discard",11:"systat",13:"daytime",
    17:"qotd",19:"chargen",20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",
    25:"smtp",37:"time",42:"nameserver",43:"whois",49:"tacacs",53:"dns",
    67:"dhcp-server",68:"dhcp-client",69:"tftp",70:"gopher",79:"finger",
    80:"http",81:"http-alt",88:"kerberos",102:"iso-tsap",109:"pop2",
    110:"pop3",111:"sunrpc",113:"ident",119:"nntp",123:"ntp",135:"msrpc",
    137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",143:"imap",
    161:"snmp",162:"snmptrap",179:"bgp",194:"irc",220:"imap3",
    389:"ldap",443:"https",445:"microsoft-ds",464:"kpasswd",465:"smtps",
    500:"isakmp",502:"modbus",512:"rexec",513:"rlogin",514:"syslog",
    515:"printer",520:"rip",523:"ibm-db2",524:"ncp",530:"courier",
    540:"uucp",543:"klogin",544:"kshell",546:"dhcpv6-client",
    547:"dhcpv6-server",548:"afp",554:"rtsp",563:"nntps",
    587:"submission",593:"http-rpc-epmap",631:"ipp",636:"ldaps",
    639:"msdp",646:"ldp",660:"mac-srvr-admin",666:"doom",
    691:"msexch-routing",694:"ha-cluster",749:"kerberos-adm",
    860:"iscsi",873:"rsync",902:"vmware-auth",953:"rndc",
    989:"ftps-data",990:"ftps",992:"telnets",993:"imaps",995:"pop3s",
    1080:"socks",1099:"rmi-registry",1194:"openvpn",1241:"nessus",
    1311:"rxmon",1433:"ms-sql-s",1434:"ms-sql-m",1521:"oracle",
    1701:"l2tp",1723:"pptp",1755:"wms",1801:"msmq",1812:"radius",
    1813:"radius-acct",1863:"msnp",1900:"upnp",1935:"rtmp",
    1985:"hsrp",2000:"cisco-sccp",2049:"nfs",2082:"cpanel",
    2083:"cpanel-ssl",2086:"whm",2087:"whm-ssl",2121:"ftp-proxy",
    2179:"vmrdp",2181:"zookeeper",2222:"directadmin",2302:"halo",
    2375:"docker",2376:"docker-ssl",2379:"etcd-client",
    2380:"etcd-server",2427:"mgcp-gateway",2483:"oracle-tls",
    2525:"smtp-alt",2598:"citrix-ica",2601:"zebra",2638:"sybase",
    2809:"corbaloc",2947:"gpsd",3000:"grafana",3050:"gds-db",
    3128:"squid-http",3260:"iscsi-target",3268:"msft-gc",
    3269:"msft-gc-ssl",3306:"mysql",3389:"ms-wbt-server",
    3478:"stun",3544:"teredo",3632:"distccd",3689:"daap",
    3690:"svn",3784:"bfd-control",3868:"diameter",4000:"remoteanything",
    4243:"docker-alt",4369:"epmd",4443:"pharos",4500:"ipsec-nat-t",
    4506:"salt-master",4567:"tram",4662:"edonkey",4789:"vxlan",
    4840:"opcua-tcp",4848:"appserv-http",4949:"munin",
    5000:"upnp",5001:"commplex-link",5003:"filemaker",
    5060:"sip",5061:"sip-tls",5190:"aim",5222:"xmpp-client",
    5269:"xmpp-server",5280:"xmpp-bosh",5349:"stuns",
    5353:"mdns",5355:"llmnr",5357:"wsd",5432:"postgresql",
    5500:"vnc-http",5555:"freeciv",5631:"pcanywheredata",
    5666:"nrpe",5667:"nsca",5672:"amqp",5683:"coap",
    5800:"vnc-http-alt",5900:"vnc",5901:"vnc-1",5938:"teamviewer",
    5984:"couchdb",5985:"wsman",5986:"wsmans",6000:"x11",
    6112:"dtspc",6129:"dameware",6379:"redis",6432:"pgbouncer",
    6443:"kubernetes-api",6514:"syslog-tls",6660:"irc-alt",
    6667:"irc",6697:"ircs-u",6881:"bittorrent",
    7000:"afs3-fileserver",7001:"afs3-callback",7070:"realserver",
    7443:"oracleas-https",7474:"neo4j",7547:"cwmp",7687:"neo4j-bolt",
    7777:"cbt",7900:"mevent",8000:"http-alt",8008:"http-alt-2",
    8009:"ajp13",8020:"hdfs-namenode",8042:"yarn-nodemanager",
    8060:"palo-ctrl",8080:"http-proxy",8081:"blackice-icecap",
    8088:"radan-http",8089:"splunk-mgmt",8090:"opsmessaging",
    8112:"deluge-web",8139:"puppet",8140:"puppet-ssl",
    8161:"activemq-web",8200:"trivnet1",8291:"mikrotik-winbox",
    8300:"consul",8332:"bitcoin-rpc",8333:"bitcoin",
    8443:"https-alt",8500:"fmtp",8530:"wsus-http",
    8545:"ganache-rpc",8649:"ganglia-gmond",8834:"nessus-xmlrpc",
    8880:"cddbp-alt",8883:"mqtt-ssl",8888:"sun-answerbook",
    8983:"solr",9000:"cslistener",9001:"tor-orport",
    9042:"cassandra-native",9050:"tor-socks",9080:"glrpc",
    9090:"websm",9092:"kafka",9100:"jetdirect",9160:"cassandra",
    9200:"elasticsearch",9300:"elasticsearch-transport",
    9389:"adws",9418:"git",9443:"tungsten-https",
    9600:"logstash",9876:"sd",9999:"distinct",
    10000:"ndmp",10050:"zabbix-agent",10051:"zabbix-trapper",
    10389:"openldap",11211:"memcached",11371:"hkp",
    15672:"rabbitmq-mgmt",16010:"hbase-master",
    20000:"dnp",25565:"minecraft",27017:"mongodb",
    27018:"mongodb-shard",27019:"mongodb-config",28015:"rethinkdb",
    32400:"plex",44818:"ethernet-ip",47808:"bacnet",
    50000:"ibm-db2",50070:"hdfs-http",61616:"activemq-openwire",
}

# Runtime service lookup dict
_services_db: dict = {}
_services_loaded = False


def _load_services_db():
    """Load port-to-service mapping. Priority: IANA CSV file > built-in dict."""
    global _services_db, _services_loaded
    if _services_loaded:
        return
    _services_loaded = True

    if os.path.isfile(SERVICES_DB_FILE):
        count = 0
        try:
            with open(SERVICES_DB_FILE, encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header:
                    for row in reader:
                        if len(row) < 3:
                            continue
                        name = row[0].strip()
                        port_str = row[1].strip()
                        if not name or not port_str or not port_str.isdigit():
                            continue
                        port = int(port_str)
                        if port not in _services_db and name:
                            _services_db[port] = name
                            count += 1
            print(f"[SERVICES] Loaded {count} port mappings from {SERVICES_DB_FILE}",
                  file=sys.stderr)
        except Exception as e:
            print(f"[SERVICES] Error reading {SERVICES_DB_FILE}: {e}, using built-in DB",
                  file=sys.stderr)
            _services_db = dict(BUILTIN_SERVICES)
    else:
        _services_db = dict(BUILTIN_SERVICES)
        print(f"[SERVICES] Using built-in database ({len(_services_db)} ports)", file=sys.stderr)
        print(f"[SERVICES] For ~6000 ports:  python3 nsxt_fw_analyzer.py --download-services",
              file=sys.stderr)


# =============================================================================
# NSX-T Log Insight CSV column mapping
# =============================================================================

COL_SRC_IP     = "vmw_nsxt_firewall_src"
COL_DST_IP     = "vmw_nsxt_firewall_dst"
COL_SRC_PORT   = "vmw_nsxt_firewall_src_port"
COL_DST_PORT   = "vmw_nsxt_firewall_dst_port"
COL_PROTOCOL   = "vmw_nsxt_firewall_protocol"
COL_ACTION     = "vmw_nsxt_firewall_action"
COL_HOSTNAME   = "hostname"
COL_CLUSTER    = "vmw_cluster"
COL_DATACENTER = "vmw_datacenter"
COL_TIME       = "time"
COL_TEXT       = "text"

RE_ACTION    = re.compile(r'INET\s+(?:match|TERM)\s+(PASS|DROP|REJECT)\s+')
RE_DIRECTION = re.compile(r'(?:PASS|DROP|REJECT)\s+\d+\s+(IN|OUT)\s+')
RE_RULENAME  = re.compile(r'\s([A-Za-z][\w-]*(?:-[\w]+)+)\s*$')


# =============================================================================
# IP classification
# =============================================================================

_PRIVATE = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),     # Shared/CGNAT – NSX LB SNAT
]
_CGNAT      = ipaddress.IPv4Network("100.64.0.0/10")   # LB detection
_MULTICAST  = ipaddress.IPv4Network("224.0.0.0/4")
_LINKLOCAL  = ipaddress.IPv4Network("169.254.0.0/16")
_LOOPBACK   = ipaddress.IPv4Network("127.0.0.0/8")

_ip_obj_cache: dict[str, "ipaddress.IPv4Address | None"] = {}
_ip_cls_cache: dict[str, str] = {}


def _parse_ip(s: str) -> "ipaddress.IPv4Address | None":
    r = _ip_obj_cache.get(s)
    if r is not None or s in _ip_obj_cache:
        return r
    try:
        a = ipaddress.IPv4Address(s.strip())
    except (ipaddress.AddressValueError, ValueError):
        a = None
    _ip_obj_cache[s] = a
    return a


def classify_ip(s: str) -> str:
    r = _ip_cls_cache.get(s)
    if r:
        return r
    a = _parse_ip(s)
    if a is None:
        c = "other"
    elif any(a in n for n in _PRIVATE):
        c = "private"
    elif a in _MULTICAST:
        c = "multicast"
    elif a in _LINKLOCAL or a in _LOOPBACK:
        c = "other"
    else:
        c = "public"
    _ip_cls_cache[s] = c
    return c


def ip_ok(src: str, dst: str, mode: str) -> bool:
    if mode == "all":
        return True
    if mode == "private":
        return classify_ip(src) == "private" and classify_ip(dst) == "private"
    if mode == "public":
        return classify_ip(src) == "public" or classify_ip(dst) == "public"
    if mode == "multicast":
        return classify_ip(src) == "multicast" or classify_ip(dst) == "multicast"
    return True


def is_lb_ip(s: str) -> bool:
    """Check if IP is in 100.64.0.0/10 (NSX Load Balancer SNAT range)."""
    a = _parse_ip(s)
    return a is not None and a in _CGNAT


# =============================================================================
# GeoIP country lookup (DB-IP lite CSV)
# =============================================================================

_geoip_db: list = []       # sorted list of (start_int, end_int, country_code)
_geoip_loaded = False
_geoip_cache: dict[str, str] = {}


def _ip_to_int(s: str) -> int:
    """Convert IPv4 string to integer."""
    parts = s.strip().split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def load_geoip(path: str = GEOIP_DB_FILE) -> bool:
    """Load DB-IP lite CSV. Returns True if loaded successfully.
    Supports DB-IP Lite Country CSV format:
      - 7 cols: start_ip, end_ip, continent, continent_name, CC, eu, country_name
      - 3 cols: start_ip, end_ip, CC  (legacy/simplified)
    """
    global _geoip_db, _geoip_loaded
    if not os.path.isfile(path):
        return False
    try:
        entries = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                start_s = parts[0].strip().strip('"')
                end_s   = parts[1].strip().strip('"')
                # Skip IPv6 entries
                if ":" in start_s:
                    continue
                # Country code: column 4 for 7-col format, column 2 for 3-col
                cc_idx = 4 if len(parts) >= 7 else 2
                cc = parts[cc_idx].strip().strip('"').upper()
                if len(cc) != 2:
                    continue
                try:
                    entries.append((_ip_to_int(start_s), _ip_to_int(end_s), cc))
                except (ValueError, IndexError):
                    continue
        entries.sort(key=lambda x: x[0])
        _geoip_db = entries
        _geoip_loaded = True
        print(f"[GEO] Loaded {len(entries):,} IPv4 ranges from {path}",
              file=sys.stderr)
        return True
    except Exception as e:
        print(f"[GEO] Failed to load {path}: {e}", file=sys.stderr)
        return False


def geoip_lookup(ip_str: str) -> str:
    """Return 2-letter country code for an IP, or '' if not found."""
    if not _geoip_loaded:
        return ""
    cached = _geoip_cache.get(ip_str)
    if cached is not None:
        return cached
    try:
        ip_int = _ip_to_int(ip_str)
    except (ValueError, IndexError):
        _geoip_cache[ip_str] = ""
        return ""
    # Binary search
    lo, hi = 0, len(_geoip_db) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e, cc = _geoip_db[mid]
        if ip_int < s:
            hi = mid - 1
        elif ip_int > e:
            lo = mid + 1
        else:
            _geoip_cache[ip_str] = cc
            return cc
    _geoip_cache[ip_str] = ""
    return ""


def cc_to_flag(cc: str) -> str:
    """Convert 2-letter country code to Unicode flag emoji (fallback)."""
    if len(cc) != 2:
        return ""
    return chr(0x1F1E6 + ord(cc[0]) - ord('A')) + chr(0x1F1E6 + ord(cc[1]) - ord('A'))


# ─── Compact SVG flag definitions ───
# Only the SVG inner content (without the xmlns wrapper).
# Helpers generate common flag patterns.

def _h3(a, b, c):
    return f'<rect width="6" height="1.4" fill="{a}"/><rect y="1.3" width="6" height="1.4" fill="{b}"/><rect y="2.6" width="6" height="1.4" fill="{c}"/>'

def _v3(a, b, c):
    return f'<rect width="2" height="4" fill="{a}"/><rect x="2" width="2" height="4" fill="{b}"/><rect x="4" width="2" height="4" fill="{c}"/>'

def _h2(a, b):
    return f'<rect width="6" height="2" fill="{a}"/><rect y="2" width="6" height="2" fill="{b}"/>'

_FLAG_SVG_INNER: dict[str, str] = {}

def _build_flags():
    """Build flag SVG inner content dict. Called once."""
    f = _FLAG_SVG_INNER
    # ─ Horizontal tricolors ─
    f["DE"] = _h3("#000","#D00","#FC0")
    f["AT"] = _h3("#ED2939","#FFF","#ED2939")
    f["HU"] = _h3("#CE2939","#FFF","#477050")
    f["BG"] = _h3("#FFF","#00966E","#D62612")
    f["LU"] = _h3("#00A1DE","#FFF","#EF3340")
    f["NL"] = _h3("#AE1C28","#FFF","#21468B")
    f["RU"] = _h3("#FFF","#0039A6","#D52B1E")
    f["EE"] = _h3("#0072CE","#000","#FFF")
    f["LT"] = _h3("#FDB913","#006A44","#C1272D")
    f["LV"] = _h3("#9E3039","#FFF","#9E3039")
    f["HR"] = _h3("#FF0000","#FFF","#171796")
    f["SI"] = _h3("#FFF","#003DA5","#ED1C24")
    f["SL"] = _h3("#009739","#FFF","#0072C6")
    f["YE"] = _h3("#CE1126","#FFF","#000")
    f["GA"] = _h3("#009E60","#FCD116","#3A75C4")
    f["BO"] = _h3("#D52B1E","#F9E300","#007934")
    f["AM"] = _h3("#D90012","#0033A0","#F2A800")
    f["CO"] = '<rect width="6" height="2" fill="#FCD116"/><rect y="2" width="6" height="1" fill="#003893"/><rect y="3" width="6" height="1" fill="#CE1126"/>'
    # ─ Vertical tricolors ─
    f["FR"] = _v3("#002395","#FFF","#ED2939")
    f["IT"] = _v3("#009246","#FFF","#CE2B37")
    f["IE"] = _v3("#169B62","#FFF","#FF883E")
    f["BE"] = _v3("#000","#FDE300","#FF0000")
    f["RO"] = _v3("#002B7F","#FCD116","#CE1126")
    f["MD"] = _v3("#003DA5","#FCD116","#CC092F")
    f["CI"] = _v3("#F77F00","#FFF","#009E60")
    f["ML"] = _v3("#14B53A","#FCD116","#CE1126")
    f["NG"] = _v3("#008751","#FFF","#008751")
    f["MX"] = _v3("#006847","#FFF","#CE1126")
    f["PE"] = _v3("#D91023","#FFF","#D91023")
    f["CA"] = '<rect width="1.5" height="4" fill="#FF0000"/><rect x="1.5" width="3" height="4" fill="#FFF"/><rect x="4.5" width="1.5" height="4" fill="#FF0000"/>'
    # ─ Bicolors ─
    f["UA"] = _h2("#005BBB","#FFD500")
    f["PL"] = _h2("#FFF","#DC143C")
    f["MC"] = _h2("#CE1126","#FFF")
    f["ID"] = _h2("#FF0000","#FFF")
    f["SG"] = _h2("#EF3340","#FFF")
    # ─ Nordic crosses ─
    _nc = '<rect width="6" height="4" fill="{bg}"/><rect x="1.7" width="0.8" height="4" fill="{cr}"/><rect y="1.6" width="6" height="0.8" fill="{cr}"/>'
    _nci = '<rect width="6" height="4" fill="{bg}"/><rect x="1.55" width="1.1" height="4" fill="{cr}"/><rect y="1.45" width="6" height="1.1" fill="{cr}"/><rect x="1.7" width="0.8" height="4" fill="{inner}"/><rect y="1.6" width="6" height="0.8" fill="{inner}"/>'
    f["SE"] = _nc.format(bg="#006AA7", cr="#FECC00")
    f["DK"] = _nc.format(bg="#C60C30", cr="#FFF")
    f["FI"] = _nc.format(bg="#FFF", cr="#003580")
    f["NO"] = _nci.format(bg="#EF2B2D", cr="#FFF", inner="#002868")
    f["IS"] = _nci.format(bg="#003897", cr="#FFF", inner="#D72828")
    # ─ Special flags ─
    f["JP"] = '<rect width="6" height="4" fill="#FFF"/><circle cx="3" cy="2" r="1.1" fill="#BC002D"/>'
    f["BD"] = '<rect width="6" height="4" fill="#006A4E"/><circle cx="2.7" cy="2" r="1.1" fill="#F42A41"/>'
    f["GB"] = '<rect width="6" height="4" fill="#012169"/><line x1="0" y1="0" x2="6" y2="4" stroke="#FFF" stroke-width=".7"/><line x1="6" y1="0" x2="0" y2="4" stroke="#FFF" stroke-width=".7"/><line x1="0" y1="0" x2="6" y2="4" stroke="#C8102E" stroke-width=".35"/><line x1="6" y1="0" x2="0" y2="4" stroke="#C8102E" stroke-width=".35"/><rect x="2.3" width="1.4" height="4" fill="#FFF"/><rect y="1.3" width="6" height="1.4" fill="#FFF"/><rect x="2.5" width="1" height="4" fill="#C8102E"/><rect y="1.5" width="6" height="1" fill="#C8102E"/>'
    f["US"] = '<rect width="6" height="4" fill="#B22234"/><rect y=".62" width="6" height=".31" fill="#FFF"/><rect y="1.23" width="6" height=".31" fill="#FFF"/><rect y="1.85" width="6" height=".31" fill="#FFF"/><rect y="2.46" width="6" height=".31" fill="#FFF"/><rect y="3.08" width="6" height=".31" fill="#FFF"/><rect y="3.69" width="6" height=".31" fill="#FFF"/><rect width="2.4" height="2.15" fill="#3C3B6E"/>'
    f["AU"] = '<rect width="6" height="4" fill="#00008B"/><rect width="2.4" height="2" fill="#012169"/><line x1="0" y1="0" x2="2.4" y2="2" stroke="#FFF" stroke-width=".35"/><line x1="2.4" y1="0" x2="0" y2="2" stroke="#FFF" stroke-width=".35"/><rect x=".8" width=".8" height="2" fill="#FFF"/><rect y=".7" width="2.4" height=".6" fill="#FFF"/><rect x=".9" width=".6" height="2" fill="#C8102E"/><rect y=".8" width="2.4" height=".4" fill="#C8102E"/>'
    f["NZ"] = f["AU"]  # simplified
    f["CN"] = '<rect width="6" height="4" fill="#DE2910"/><circle cx=".9" cy="1" r=".55" fill="#FFDE00"/>'
    f["KR"] = '<rect width="6" height="4" fill="#FFF"/><circle cx="3" cy="2" r="1.1" fill="#C60C30"/><path d="M3,2 a.55,.55 0 0,1 0-1.1 a.55,.55 0 0,0 0,1.1" fill="#003478"/>'
    f["IN"] = '<rect width="6" height="1.33" fill="#FF9933"/><rect y="1.33" width="6" height="1.33" fill="#FFF"/><rect y="2.67" width="6" height="1.33" fill="#138808"/><circle cx="3" cy="2" r=".45" fill="#000080" fill-opacity=".2"/>'
    f["BR"] = '<rect width="6" height="4" fill="#009B3A"/><polygon points="3,.4 5.7,2 3,3.6 .3,2" fill="#FEDF00"/><circle cx="3" cy="2" r=".85" fill="#002776"/>'
    f["ZA"] = '<rect width="6" height="4" fill="#007A4D"/><polygon points="0,0 2.4,2 0,4" fill="#000"/><polygon points="0,.3 2,2 0,3.7" fill="#FFB612"/><rect y="0" width="6" height="1.3" fill="#DE3831"/><rect y="2.7" width="6" height="1.3" fill="#002395"/><rect x="2.5" y="0" width="3.5" height=".3" fill="#FFF"/><rect x="2.5" y="3.7" width="3.5" height=".3" fill="#FFF"/>'
    f["IL"] = '<rect width="6" height="4" fill="#FFF"/><rect y=".4" width="6" height=".5" fill="#0038B8"/><rect y="3.1" width="6" height=".5" fill="#0038B8"/>'
    f["TR"] = '<rect width="6" height="4" fill="#E30A17"/><circle cx="2.3" cy="2" r="1" fill="#FFF"/><circle cx="2.6" cy="2" r=".8" fill="#E30A17"/>'
    f["SA"] = '<rect width="6" height="4" fill="#006C35"/>'
    f["AE"] = '<rect width="6" height="4" fill="#FFF"/><rect width="6" height="1.33" fill="#00732F"/><rect y="2.67" width="6" height="1.33" fill="#000"/><rect width="1.5" height="4" fill="#FF0000"/>'
    f["TH"] = '<rect width="6" height="4" fill="#FFF"/><rect width="6" height=".67" fill="#A51931"/><rect y="3.33" width="6" height=".67" fill="#A51931"/><rect y="1" width="6" height="2" fill="#2D2A4A"/>'
    f["VN"] = '<rect width="6" height="4" fill="#DA251D"/><polygon points="3,0.7 3.4,1.9 2.1,1.2 3.9,1.2 2.6,1.9" fill="#FFFF00"/>'
    f["PH"] = '<rect width="6" height="2" fill="#0038A8"/><rect y="2" width="6" height="2" fill="#CE1126"/><polygon points="0,0 2.4,2 0,4" fill="#FFF"/>'
    f["MY"] = '<rect width="6" height="4" fill="#FFF"/><rect width="6" height=".57" fill="#CC0001"/><rect y="1.14" width="6" height=".57" fill="#CC0001"/><rect y="2.29" width="6" height=".57" fill="#CC0001"/><rect y="3.43" width="6" height=".57" fill="#CC0001"/><rect width="3" height="2.3" fill="#010066"/>'
    f["PK"] = '<rect width="6" height="4" fill="#01411C"/><rect width="1.5" height="4" fill="#FFF"/>'
    f["CL"] = '<rect width="6" height="2" fill="#FFF"/><rect y="2" width="6" height="2" fill="#D52B1E"/><rect width="2" height="2" fill="#0039A6"/>'
    f["AR"] = _h3("#74ACDF","#FFF","#74ACDF")
    f["EG"] = _h3("#CE1126","#FFF","#000")
    f["GR"] = '<rect width="6" height="4" fill="#0D5EAF"/><rect y=".44" width="6" height=".44" fill="#FFF"/><rect y="1.33" width="6" height=".44" fill="#FFF"/><rect y="2.22" width="6" height=".44" fill="#FFF"/><rect y="3.11" width="6" height=".44" fill="#FFF"/><rect width="2.2" height="2.22" fill="#0D5EAF"/><rect x=".72" width=".67" height="2.22" fill="#FFF"/><rect y=".78" width="2.2" height=".67" fill="#FFF"/>'
    f["PT"] = '<rect width="2.4" height="4" fill="#006600"/><rect x="2.4" width="3.6" height="4" fill="#FF0000"/>'
    f["ES"] = '<rect width="6" height="4" fill="#AA151B"/><rect y="1" width="6" height="2" fill="#F1BF00"/>'
    f["CH"] = '<rect width="6" height="4" fill="#D52B1E" rx=".2"/><rect x="2.5" y=".8" width="1" height="2.4" fill="#FFF"/><rect x="1.8" y="1.5" width="2.4" height="1" fill="#FFF"/>'
    f["CZ"] = '<rect width="6" height="2" fill="#FFF"/><rect y="2" width="6" height="2" fill="#D7141A"/><polygon points="0,0 3,2 0,4" fill="#11457E"/>'
    f["SK"] = _h3("#FFF","#0B4EA2","#EE1C25")
    f["RS"] = _h3("#C6363C","#0C4076","#FFF")
    f["FI"] = _nc.format(bg="#FFF", cr="#003580")
    f["GE"] = '<rect width="6" height="4" fill="#FFF"/><rect x="2.5" width="1" height="4" fill="#FF0000"/><rect y="1.5" width="6" height="1" fill="#FF0000"/>'
    f["KZ"] = '<rect width="6" height="4" fill="#00AFCA"/><circle cx="3" cy="2" r="1" fill="#FEC50C"/>'
    f["TW"] = '<rect width="6" height="4" fill="#FE0000"/><rect width="3" height="2" fill="#000095"/>'
    f["HK"] = '<rect width="6" height="4" fill="#DE2910"/>'
    f["KE"] = '<rect width="6" height="4" fill="#FFF"/><rect width="6" height="1.2" fill="#000"/><rect y="2.8" width="6" height="1.2" fill="#006600"/><rect y="1.3" width="6" height="1.4" fill="#BB0000"/>'
    f["DZ"] = '<rect width="3" height="4" fill="#006233"/><rect x="3" width="3" height="4" fill="#FFF"/>'
    f["MA"] = '<rect width="6" height="4" fill="#C1272D"/>'
    f["TN"] = '<rect width="6" height="4" fill="#E70013"/><circle cx="3" cy="2" r="1.1" fill="#FFF"/><circle cx="3.25" cy="2" r=".9" fill="#E70013"/>'
    f["QA"] = '<rect width="2" height="4" fill="#FFF"/><polygon points="2,0 3.2,.5 2,1 3.2,1.5 2,2 3.2,2.5 2,3 3.2,3.5 2,4 6,4 6,0" fill="#8A1538"/>'

_build_flags()


def flag_svg_data_uri(cc: str) -> str:
    """Return data URI for a flag SVG, or '' if not available."""
    inner = _FLAG_SVG_INNER.get(cc.upper(), "")
    if not inner:
        return ""
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 6 4">{inner}</svg>'
    import base64
    b64 = base64.b64encode(svg.encode()).decode()
    return f"data:image/svg+xml;base64,{b64}"


# =============================================================================
# DNS PTR cache - supports 2 DNS servers
# =============================================================================

class DnsCache:
    def __init__(self, path=DNS_CACHE_FILE, server=DNS_SERVER,
                 server2="", timeout=DNS_TIMEOUT):
        self.path = path
        self.servers = [s for s in [server, server2] if s]
        self.timeout = timeout
        self.cache: dict[str, str] = {}
        self._dnspy = False
        self._resolvers: list = []
        self._retried = 0
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.cache = json.load(f)
                empty = sum(1 for v in self.cache.values() if v == "")
                total = len(self.cache)
                print(f"[DNS] Loaded {total} cached records ({empty} empty, will retry)",
                      file=sys.stderr)
            except Exception:
                pass

    def save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self.cache, f, indent=2, sort_keys=True)
            msg = f"[DNS] Saved {len(self.cache)} records -> {self.path}"
            if self._retried:
                msg += f" ({self._retried} previously empty retried)"
            print(msg, file=sys.stderr)
        except IOError as e:
            print(f"[DNS] Cannot save cache: {e}", file=sys.stderr)

    def setup(self):
        try:
            import dns.resolver
            for srv in self.servers:
                r = dns.resolver.Resolver()
                r.nameservers = [srv]
                r.timeout = self.timeout
                r.lifetime = self.timeout
                self._resolvers.append((srv, r))
            self._dnspy = True
            srv_list = ", ".join(self.servers)
            print(f"[DNS] dnspython -> {srv_list}", file=sys.stderr)
        except ImportError:
            print("[DNS] Using system resolver (install dnspython for custom DNS)",
                  file=sys.stderr)

    def _resolve_dnspy(self, ip: str) -> str:
        """Try PTR resolution against all configured resolvers, return first hit."""
        rev = ipaddress.ip_address(ip).reverse_pointer
        for srv_name, resolver in self._resolvers:
            try:
                ans = resolver.resolve(rev, "PTR")
                if ans:
                    return str(ans[0]).rstrip(".")
            except Exception:
                continue
        return ""

    def _resolve_system(self, ip: str) -> str:
        """Fallback system resolver."""
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            try:
                return socket.gethostbyaddr(ip)[0]
            finally:
                socket.setdefaulttimeout(old)
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""

    def resolve(self, ip: str) -> str:
        # If cached AND non-empty -> use cache
        if ip in self.cache and self.cache[ip] != "":
            return self.cache[ip]
        # Empty or missing -> (re)try resolution
        is_retry = ip in self.cache and self.cache[ip] == ""
        h = ""
        if self._dnspy and self._resolvers:
            h = self._resolve_dnspy(ip)
        else:
            h = self._resolve_system(ip)
        if h and is_retry:
            self._retried += 1
        self.cache[ip] = h
        return h


# =============================================================================
# Text field parsing
# =============================================================================

def parse_text(text: str) -> tuple:
    """Return (action, direction, rule_name) from syslog text."""
    action = direction = rule_name = ""
    m = RE_ACTION.search(text)
    if m:
        action = m.group(1)
    m = RE_DIRECTION.search(text)
    if m:
        direction = m.group(1)
    m = RE_RULENAME.search(text)
    if m:
        rule_name = m.group(1)
    return action, direction, rule_name


# =============================================================================
# Archive extraction
# =============================================================================

def extract_csvs(path: str, tmpdir: str) -> list:
    out = []
    with tarfile.open(path, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.lower().endswith(".csv") and m.isfile():
                try:
                    tar.extract(m, path=tmpdir, filter='data')
                except TypeError:
                    # Python < 3.12 doesn't support filter=
                    tar.extract(m, path=tmpdir)
                out.append(os.path.join(tmpdir, m.name))
    return sorted(out)


# =============================================================================
# Core processing
# =============================================================================

def process(csv_files, mode, ex_ips, ex_ports, act_filter, dir_filter):
    recs = {}
    all_ips = set()
    total = skip = dupes = 0

    for csv_file in csv_files:
        fn = os.path.basename(csv_file)
        frows = 0
        with open(csv_file, "r", encoding="utf-8", errors="replace") as fh:
            rd = csv.DictReader(fh)
            if not rd.fieldnames or COL_SRC_IP not in rd.fieldnames:
                print(f"  [SKIP] {fn}: missing required columns", file=sys.stderr)
                continue

            for row in rd:
                total += 1; frows += 1

                src  = (row.get(COL_SRC_IP) or "").strip()
                dst  = (row.get(COL_DST_IP) or "").strip()
                sp   = (row.get(COL_SRC_PORT) or "").strip()
                dp   = (row.get(COL_DST_PORT) or "").strip()
                prot = (row.get(COL_PROTOCOL) or "").strip().upper()
                act  = (row.get(COL_ACTION) or "").strip().upper()
                text = (row.get(COL_TEXT) or "")

                if not src or not dst or _parse_ip(src) is None or _parse_ip(dst) is None:
                    skip += 1; continue
                if not ip_ok(src, dst, mode):
                    skip += 1; continue
                if src in ex_ips or dst in ex_ips:
                    skip += 1; continue
                if dp in ex_ports or sp in ex_ports:
                    skip += 1; continue

                t_act, t_dir, t_rule = parse_text(text)
                if not act:
                    act = t_act
                direction = t_dir
                rule_name = t_rule

                if act_filter and act != act_filter:
                    skip += 1; continue
                if dir_filter and direction != dir_filter:
                    skip += 1; continue

                key = (src, dst, dp, prot)
                if key in recs:
                    dupes += 1; continue

                recs[key] = {
                    "src_ip": src, "src_port": sp,
                    "dst_ip": dst, "dst_port": dp,
                    "protocol": prot, "action": act,
                    "direction": direction, "rule_name": rule_name,
                    "hostname":   (row.get(COL_HOSTNAME) or "").strip(),
                    "cluster":    (row.get(COL_CLUSTER) or "").strip(),
                    "datacenter": (row.get(COL_DATACENTER) or "").strip(),
                    "first_seen": (row.get(COL_TIME) or "").strip(),
                }
                all_ips.add(src); all_ips.add(dst)

                if total % PROGRESS_EVERY == 0:
                    print(f"  ... {total:,} rows, {len(recs):,} unique", file=sys.stderr)

        print(f"  [{fn}] {frows:,} rows", file=sys.stderr)

    print(f"\n{'─'*45}", file=sys.stderr)
    print(f"  Total rows:    {total:>12,}", file=sys.stderr)
    print(f"  Filtered out:  {skip:>12,}", file=sys.stderr)
    print(f"  Duplicates:    {dupes:>12,}", file=sys.stderr)
    print(f"  Unique flows:  {len(recs):>12,}", file=sys.stderr)
    print(f"{'─'*45}", file=sys.stderr)
    return recs, all_ips


def resolve_all(ips, dc):
    dc.setup()
    n = len(ips)
    ok = fail = 0
    print(f"\n[DNS] Resolving {n} unique IPs...", file=sys.stderr)
    out = {}
    for i, ip in enumerate(sorted(ips), 1):
        h = dc.resolve(ip)
        out[ip] = h
        if h: ok += 1
        else:  fail += 1
        if i % 100 == 0 or i == n:
            print(f"  {i}/{n} ({ok} ok, {fail} fail)", file=sys.stderr)
    dc.save()
    return out


def write_csv(recs, path, dns_map=None, sort_by="src_ip", translate=True):
    cols, rows = _prepare_rows(recs, dns_map, sort_by, translate)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})
    print(f"\n[OUTPUT] {len(rows):,} records -> {path}", file=sys.stderr)


def stats(recs):
    sc, dc, pc, prc, ac = Counter(), Counter(), Counter(), Counter(), Counter()
    for r in recs.values():
        sc[r["src_ip"]] += 1;  dc[r["dst_ip"]] += 1
        pc[r["dst_port"]] += 1; prc[r["protocol"]] += 1; ac[r["action"]] += 1
    print(f"\n{'='*55}\n STATISTICS  ({len(recs):,} unique flows)\n{'='*55}", file=sys.stderr)
    print(f"\n Protocols:", file=sys.stderr)
    for x, c in prc.most_common(): print(f"   {x:10s} {c:>8,}", file=sys.stderr)
    print(f"\n Actions:", file=sys.stderr)
    for x, c in ac.most_common():  print(f"   {x:10s} {c:>8,}", file=sys.stderr)
    print(f"\n Top 15 Source IPs:", file=sys.stderr)
    for x, c in sc.most_common(15): print(f"   {x:20s} {c:>8,} flows", file=sys.stderr)
    print(f"\n Top 15 Destination IPs:", file=sys.stderr)
    for x, c in dc.most_common(15): print(f"   {x:20s} {c:>8,} flows", file=sys.stderr)
    print(f"\n Top 20 Destination Ports:", file=sys.stderr)
    for x, c in pc.most_common(20):
        svc = get_service_name(x)
        svc_str = f" ({svc})" if svc else ""
        print(f"   {x:>10s}{svc_str:16s} {c:>8,} flows", file=sys.stderr)
    print(f"{'='*55}", file=sys.stderr)


# =============================================================================
# HTML Report Generator
# =============================================================================

HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NSX-T DFW Flow Analysis</title>
<style>
:root {
  --bg0:#0a0e17;--bg1:#111827;--bg2:#161f31;--bg2h:#1c2740;--bgi:#0d1321;
  --brd:#1e2d4a;--bf:#3b82f6;--t1:#e2e8f0;--t2:#8892a8;--tm:#4a5568;
  --ab:#3b82f6;--ac:#06b6d4;--ag:#10b981;--ar:#ef4444;--ao:#f59e0b;--ap:#8b5cf6;
  --r:8px;--rl:12px;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg0);color:var(--t1);font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:linear-gradient(rgba(59,130,246,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,.02) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.ctr{max-width:100%;padding:24px;position:relative;z-index:1}
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--brd)}
.hdr-l{display:flex;align-items:center;gap:16px}
.logo{width:42px;height:42px;background:linear-gradient(135deg,var(--ab),var(--ac));border-radius:var(--r);display:flex;align-items:center;justify-content:center;font-family:'Consolas','Liberation Mono','Courier New',monospace;font-weight:700;font-size:15px;color:#fff;box-shadow:0 0 20px rgba(59,130,246,.15)}
.hdr h1{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:22px;font-weight:600;background:linear-gradient(135deg,var(--t1),var(--ac));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hdr-m{font-size:12px;color:var(--tm);font-family:'Consolas','Liberation Mono','Courier New',monospace}
.hdr-r{display:flex;gap:10px}
.btn{padding:8px 16px;border-radius:var(--r);border:1px solid var(--brd);background:var(--bg2);color:var(--t1);font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
.btn:hover{background:var(--bg2h);border-color:var(--ab)}
.btn svg{width:15px;height:15px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:22px}
.sc{background:var(--bg2);border:1px solid var(--brd);border-radius:var(--rl);padding:18px 20px;position:relative;overflow:hidden;transition:all .25s}
.sc:hover{border-color:var(--ab);box-shadow:0 0 20px rgba(59,130,246,.15);transform:translateY(-1px)}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--ab),var(--ac));opacity:0;transition:opacity .25s}
.sc:hover::before{opacity:1}
.sl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--tm);margin-bottom:6px}
.sv{font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:26px;font-weight:700;color:var(--t1)}
.sd{font-size:12px;color:var(--t2);margin-top:6px;font-family:'Consolas','Liberation Mono','Courier New',monospace}
.sv.g{color:var(--ag)}.sv.r{color:var(--ar)}.sv.c{color:var(--ac)}.sv.p{color:var(--ap)}
.tb{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;align-items:center}
.sb{flex:1;min-width:250px;position:relative}
.sb svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:16px;height:16px;color:var(--tm)}
.sb input{width:100%;padding:9px 14px 9px 38px;background:var(--bgi);border:1px solid var(--brd);border-radius:var(--r);color:var(--t1);font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:13px;transition:all .2s;outline:none}
.sb input::placeholder{color:var(--tm)}
.sb input:focus{border-color:var(--ab);box-shadow:0 0 20px rgba(59,130,246,.15)}
.rc{font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;color:var(--tm);white-space:nowrap;padding:9px 0}
.rc b{color:var(--ac)}
.tw{border:1px solid var(--brd);border-radius:var(--rl);overflow:hidden;background:var(--bg1)}
.ts{overflow-x:auto;max-height:calc(100vh - 360px);overflow-y:auto;min-height:340px}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{position:sticky;top:0;z-index:10}
thead th{background:var(--bg2);padding:0;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--t2);border-bottom:2px solid var(--brd);user-select:none;white-space:nowrap;transition:color .15s;position:relative}
thead th:hover{color:var(--ac)}
thead th.so{color:var(--ac)}
thead th .sa{display:inline-block;margin-left:3px;font-size:10px;opacity:.3;transition:opacity .15s}
thead th.so .sa{opacity:1;color:var(--ac)}
/* th inner layout: draggable label area */
thead th .th-inner{display:flex;align-items:center;padding:11px 14px;cursor:pointer;gap:4px}
thead th .th-label{flex:1}
/* filter indicator dot */
thead th .filt-dot{width:6px;height:6px;border-radius:50%;background:var(--ao);display:none;flex-shrink:0}
thead th.has-filter .filt-dot{display:block}
/* drag state */
thead th.dragging{opacity:.4}
thead th.drag-over{border-left:2px solid var(--ac)}
tbody tr{border-bottom:1px solid rgba(30,45,74,.5);transition:background .12s}
tbody tr:hover{background:var(--bg2h)}
tbody td{padding:8px 14px;font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;white-space:nowrap;color:var(--t1)}
td.ip{color:var(--ac)}td.port{color:var(--ap)}td.svc{color:var(--t2);font-style:italic}
td.ip.has-geo{display:flex;align-items:center;gap:6px}
td.pdesc{color:var(--t2);font-size:11px}td.dns{color:var(--ag);font-size:11px}
td.hn{color:var(--t2);font-size:11px}td.tm{color:var(--tm);font-size:11px}
td.rule{color:var(--ao);font-size:11px}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.5px;font-family:'Consolas','Liberation Mono','Courier New',monospace}
.b-pass{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);color:var(--ag)}
.b-drop{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);color:var(--ar)}
.b-rej{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);color:var(--ao)}
.b-in{background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.25);color:var(--ap)}
.b-out{background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.25);color:var(--ac)}
.lb-tag{display:inline-block;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.5px;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);color:#60a5fa;margin-right:5px;vertical-align:middle;line-height:1.4}
.btn-lb{font-size:11px;padding:4px 10px;border-radius:var(--r);border:1px solid rgba(96,165,250,.3);background:rgba(96,165,250,.06);color:#60a5fa;cursor:pointer;font-weight:600;transition:all .15s;margin-left:8px}
.btn-lb:hover{background:rgba(96,165,250,.15)}
.btn-lb.active{background:rgba(96,165,250,.2);border-color:#60a5fa;box-shadow:0 0 6px rgba(96,165,250,.3)}
.geo-flag{margin-left:5px;vertical-align:middle;display:inline-block}
.geo-flag-img{width:18px;height:12px;vertical-align:middle;border:.5px solid rgba(255,255,255,.15);border-radius:1px}
.geo-cc{font-size:9px;padding:0 3px;border-radius:2px;background:rgba(167,139,250,.15);color:#a78bfa;font-weight:700;letter-spacing:.5px;vertical-align:middle}
.geo-click{cursor:pointer;display:inline-block;padding:2px;border-radius:3px;border:1.5px solid transparent;transition:all .15s;vertical-align:middle}
.geo-click:hover{border-color:rgba(167,139,250,.5);background:rgba(167,139,250,.1)}
.geo-click.geo-active{border-color:#a78bfa;background:rgba(167,139,250,.2);box-shadow:0 0 6px rgba(167,139,250,.3)}
.geo-click.geo-dim{opacity:.3}
.geo-reset{font-size:11px;color:#a78bfa;cursor:pointer;margin-left:8px;opacity:.7;transition:opacity .15s}
.geo-reset:hover{opacity:1}
mark{background:rgba(245,158,11,.3);color:inherit;border-radius:2px;padding:0 1px}
.pg{display:flex;align-items:center;justify-content:center;gap:6px;padding:14px;border-top:1px solid var(--brd);background:var(--bg2)}
.pg button{padding:5px 12px;border-radius:var(--r);border:1px solid var(--brd);background:var(--bgi);color:var(--t2);font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;cursor:pointer;transition:all .15s}
.pg button:hover:not(:disabled){border-color:var(--ab);color:var(--t1)}
.pg button:disabled{opacity:.3;cursor:default}
.pg button.act{background:var(--ab);border-color:var(--ab);color:#fff}
.pg .pi{font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;color:var(--tm);margin:0 8px}
.pss{padding:5px 8px;background:var(--bgi);border:1px solid var(--brd);border-radius:var(--r);color:var(--t2);font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;margin-left:12px;cursor:pointer;outline:none}
.nr{text-align:center;padding:60px 20px;color:var(--tm);font-size:15px}
.nr .ico{font-size:40px;margin-bottom:12px;opacity:.4}
.tt{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:22px}
.tc{background:var(--bg2);border:1px solid var(--brd);border-radius:var(--rl);padding:16px 18px}
.tc h3{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--tm);margin-bottom:10px}
.tr_{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px}
.tr_.tr-click{cursor:pointer;padding:4px 6px;margin:0 -6px;border-radius:4px;transition:background .15s}
.tr_.tr-click:hover{background:var(--bg2h)}
.tr_.tr-click.active{background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);margin:-1px -7px}
.tr_ .ip{color:var(--ac)}.tr_ .port{color:var(--ap)}.tr_ .cnt{color:var(--tm)}
.tbar{height:3px;background:var(--brd);border-radius:2px;margin-top:2px;margin-bottom:4px;overflow:hidden}
.tbf{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--ab),var(--ac))}
.ct{background:none;border:none;color:var(--t2);font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;font-weight:500;cursor:pointer;display:flex;align-items:center;gap:6px;padding:8px 0;margin-bottom:8px}
.ct:hover{color:var(--ac)}
.ct .ar{transition:transform .2s}
.ct.open .ar{transform:rotate(90deg)}

/* ─── Column popup ─── */
.col-popup{position:absolute;top:100%;left:0;min-width:220px;background:var(--bg2);border:1px solid var(--brd);border-radius:var(--rl);box-shadow:0 8px 32px rgba(0,0,0,.5);z-index:100;padding:8px 0;display:none}
.col-popup.open{display:block}
.col-popup .cp-row{display:flex;align-items:center;padding:6px 14px;gap:8px;cursor:pointer;font-size:12px;color:var(--t2);transition:background .1s}
.col-popup .cp-row:hover{background:var(--bg2h);color:var(--t1)}
.col-popup .cp-row svg{width:14px;height:14px;flex-shrink:0}
.col-popup .cp-row.active{color:var(--ac)}
.col-popup .cp-sep{height:1px;background:var(--brd);margin:4px 0}
.col-popup .cp-filter{padding:6px 10px}
.col-popup .cp-filter input{width:100%;padding:6px 10px;background:var(--bgi);border:1px solid var(--brd);border-radius:var(--r);color:var(--t1);font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:12px;outline:none;transition:border-color .2s}
.col-popup .cp-filter input:focus{border-color:var(--ab)}
.col-popup .cp-filter input::placeholder{color:var(--tm)}
.col-popup .cp-hint{padding:2px 10px 6px;font-size:10px;color:var(--tm);font-family:'Consolas','Liberation Mono','Courier New',monospace;line-height:1.4}
.col-popup .cp-clear{padding:6px 14px;cursor:pointer;font-size:11px;color:var(--ar);transition:background .1s}
.col-popup .cp-clear:hover{background:var(--bg2h)}

/* ─── Column visibility panel ─── */
.col-panel{position:relative;display:inline-block}
.col-panel-dropdown{position:absolute;top:100%;right:0;min-width:200px;max-height:400px;overflow-y:auto;background:var(--bg2);border:1px solid var(--brd);border-radius:var(--rl);box-shadow:0 8px 32px rgba(0,0,0,.5);z-index:100;padding:8px 0;display:none;margin-top:4px}
.col-panel-dropdown.open{display:block}
.col-panel-dropdown label{display:flex;align-items:center;gap:8px;padding:5px 14px;font-size:12px;color:var(--t2);cursor:pointer;transition:background .1s;font-family:'Consolas','Liberation Mono','Courier New',monospace}
.col-panel-dropdown label:hover{background:var(--bg2h);color:var(--t1)}
.col-panel-dropdown input[type=checkbox]{accent-color:var(--ab);width:14px;height:14px;cursor:pointer}
.col-panel-dropdown .cp-sep{height:1px;background:var(--brd);margin:4px 0}
.col-panel-dropdown .cp-actions{display:flex;gap:6px;padding:6px 14px}
.col-panel-dropdown .cp-actions button{flex:1;padding:4px 8px;border:1px solid var(--brd);border-radius:var(--r);background:var(--bgi);color:var(--t2);font-size:11px;cursor:pointer;transition:all .15s;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.col-panel-dropdown .cp-actions button:hover{border-color:var(--ab);color:var(--t1)}

/* Active filters indicator bar */
.active-filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;min-height:0}
.af-tag{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:20px;font-family:'Consolas','Liberation Mono','Courier New',monospace;font-size:11px;color:var(--ao)}
.af-tag .af-col{color:var(--t2);margin-right:2px}
.af-tag .af-x{cursor:pointer;color:var(--ar);font-weight:700;margin-left:4px;font-size:13px;line-height:1}
.af-tag .af-x:hover{color:#fff}

@media(max-width:768px){.ctr{padding:12px}.hdr{flex-direction:column;gap:12px;align-items:flex-start}.sg{grid-template-columns:repeat(2,1fr)}.tb{flex-direction:column}.sb{min-width:100%}}
@media print{body::before{display:none}.tb,.pg,.btn,.hdr-r,.ct,.col-popup,.col-panel-dropdown,.active-filters{display:none!important}.ts{max-height:none!important;overflow:visible!important}.sc{break-inside:avoid}}
</style>
</head>
<body>
<div class="ctr">
<div class="hdr">
 <div class="hdr-l">
  <div class="logo">DFW</div>
  <div><h1>NSX-T Firewall Flow Analysis</h1><div class="hdr-m">%%META%%</div></div>
 </div>
 <div class="hdr-r">
  <div class="col-panel">
   <button class="btn" onclick="toggleColPanel(this)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Columns</button>
   <div class="col-panel-dropdown" id="colPanel"></div>
  </div>
  <button class="btn" onclick="resetAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 109-9"/><polyline points="3 3 3 9 9 9"/></svg>Reset</button>
  <button class="btn" onclick="exportCSV()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Export CSV</button>
  <button class="btn" onclick="window.print()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>Print</button>
 </div>
</div>
<div class="sg">%%STATS%%</div>
<button class="ct" onclick="toggleS('ttDiv',this)"><span class="ar">&#9654;</span> Top Talkers &amp; Ports</button>
<div id="ttDiv" style="display:none"><div class="tt">%%TALKERS%%</div></div>
<div class="tb">
 <div class="sb"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input type="text" id="sI" placeholder="Search all columns..." oninput="af()"></div>
 <button class="btn-lb" id="lbBtn" onclick="toggleLB()" title="Show Load Balancer flows (100.64.0.0/10)">LB</button>
 <span class="rc" id="rc"></span>
</div>
<div class="active-filters" id="afTags"></div>
<div class="tw"><div class="ts" id="tS"><table><thead><tr id="hR"></tr></thead><tbody id="tB"></tbody></table><div class="nr" id="nR" style="display:none"><div class="ico">&#128269;</div>No records match the current filter.</div></div><div class="pg" id="pg"></div></div>
</div>
<script>
// ─── DATA ───
const D=%%DATA%%,C=%%COLS%%,CC=%%CCLS%%,CL=%%CLABELS%%;
const LBI=C.length; // LB flag index (appended after all columns)
const SGI=C.length+1,DGI=C.length+2; // src/dst geo country code indices
const srcCI=C.indexOf('src_ip'),dstCI=C.indexOf('dst_ip');
// ─── STATE ───
let F=[...D],sC=-1,sA=true,pg=0,ps=100;
let lbFilter=false;
let geoFilterCC='';
let colOrder=C.map((_,i)=>i);            // display order (indices into C)
const defVis=%%COLVIS%%;
const FL=%%FLAGS%%;
let colVisible=[...defVis];           // visibility
let colFilters={};                        // {origColIdx: filterString}
let openPopup=null;                       // currently open popup col idx
let dragSrc=null;                         // drag source col idx

// ─── FILTER MATCHING ───
function matchFilter(val,pattern){
  val=String(val);
  if(!pattern)return true;
  // negation: !pattern -> invert result
  if(pattern.startsWith('!')){
    const inner=pattern.slice(1);
    if(!inner)return true;
    return !matchFilter(val,inner);
  }
  // regex: /pattern/ or /pattern/i
  if(pattern.startsWith('/')){
    const m=pattern.match(/^\/(.+)\/([gimsuy]*)$/);
    if(m){try{return new RegExp(m[1],m[2].includes('i')?'i':'').test(val)}catch(e){return false}}
  }
  // wildcard: contains * or ?
  if(pattern.includes('*')||pattern.includes('?')){
    let re='^'+pattern.replace(/([.+^${}()|[\]\\])/g,'\\$1').replace(/\*/g,'.*').replace(/\?/g,'.')+'$';
    try{return new RegExp(re,'i').test(val)}catch(e){return false}
  }
  // plain substring (case-insensitive)
  return val.toLowerCase().includes(pattern.toLowerCase());
}

// ─── SORTING ───
function doSort(origCI){
  if(sC===origCI)sA=!sA;else{sC=origCI;sA=true}
  doSortApply();
}
function doSortApply(){
  F.sort((a,b)=>{
    let va=a[sC],vb=b[sC];
    const na=Number(va),nb=Number(vb);
    if(!isNaN(na)&&!isNaN(nb)&&va!==''&&vb!=='')return sA?na-nb:nb-na;
    if(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(va)&&/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(vb)){
      const ia=va.split('.').map(Number),ib=vb.split('.').map(Number);
      for(let k=0;k<4;k++){if(ia[k]!==ib[k])return sA?ia[k]-ib[k]:ib[k]-ia[k]}return 0;
    }
    va=String(va).toLowerCase();vb=String(vb).toLowerCase();
    return va<vb?(sA?-1:1):va>vb?(sA?1:-1):0;
  });
  pg=0;render();
}

// ─── FILTERING ───
function af(){
  const q=document.getElementById('sI').value.toLowerCase().trim();
  F=D.filter(r=>{
    if(lbFilter&&!r[LBI])return false;
    if(geoFilterCC&&r[SGI]!==geoFilterCC&&r[DGI]!==geoFilterCC)return false;
    for(const[ci,pat]of Object.entries(colFilters)){
      if(!matchFilter(r[parseInt(ci)],pat))return false;
    }
    if(q)return r.some((c,i)=>i<LBI&&String(c).toLowerCase().includes(q));
    return true;
  });
  if(sC>=0){doSortApply();return}
  pg=0;render();
}

// ─── RENDER ───
function eH(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function ccFlag(cc){if(!cc||cc.length!==2)return'';const uri=FL[cc.toUpperCase()];if(uri)return'<img src="'+uri+'" class="geo-flag-img" title="'+cc+'">';return'<span class="geo-cc" title="'+cc+'">'+cc+'</span>'}
function hM(t,q){if(!q)return eH(t);const e=eH(t);const re=new RegExp('('+q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+')','gi');return e.replace(re,'<mark>$1</mark>')}

function fC(v,origCI,q){
  const cls=CC[origCI]||'';const col=C[origCI];let ct=hM(v,q);
  if(col==='action'){const u=String(v).toUpperCase();const b=u==='PASS'?'b-pass':u==='DROP'?'b-drop':'b-rej';ct='<span class="badge '+b+'">'+ct+'</span>'}
  else if(col==='direction'){const u=String(v).toUpperCase();if(u==='IN'||u==='OUT')ct='<span class="badge '+(u==='IN'?'b-in':'b-out')+'">'+ct+'</span>'}
  return'<td class="'+cls+'">'+ct+'</td>';
}

function buildHeader(){
  const tr=document.getElementById('hR');
  tr.innerHTML='';
  const visCols=colOrder.filter(i=>colVisible[i]);
  for(const ci of visCols){
    const th=document.createElement('th');
    th.dataset.ci=ci;
    if(sC===ci)th.classList.add('so');
    if(colFilters[ci])th.classList.add('has-filter');
    // draggable
    th.draggable=true;
    th.addEventListener('dragstart',onDragStart);
    th.addEventListener('dragover',onDragOver);
    th.addEventListener('dragleave',onDragLeave);
    th.addEventListener('drop',onDrop);
    th.addEventListener('dragend',onDragEnd);
    // inner
    const inner=document.createElement('div');
    inner.className='th-inner';
    inner.addEventListener('click',function(e){e.stopPropagation();togglePopup(ci,th)});
    const lbl=document.createElement('span');
    lbl.className='th-label';
    lbl.textContent=CL[ci]||C[ci];
    inner.appendChild(lbl);
    const dot=document.createElement('span');
    dot.className='filt-dot';
    inner.appendChild(dot);
    const arrow=document.createElement('span');
    arrow.className='sa';
    arrow.textContent=sC===ci?(sA?'\u25B2':'\u25BC'):'\u25B2';
    inner.appendChild(arrow);
    th.appendChild(inner);
    // popup container
    const popup=document.createElement('div');
    popup.className='col-popup';
    popup.id='cp-'+ci;
    popup.addEventListener('click',function(e){e.stopPropagation()});
    th.appendChild(popup);
    tr.appendChild(th);
  }
}

function render(){
  const q=document.getElementById('sI').value.toLowerCase().trim();
  const tp=Math.max(1,Math.ceil(F.length/ps));
  if(pg>=tp)pg=tp-1;if(pg<0)pg=0;
  const st=pg*ps;const sl=F.slice(st,st+ps);

  buildHeader();

  const visCols=colOrder.filter(i=>colVisible[i]);
  const tb=document.getElementById('tB');
  if(sl.length===0){
    tb.innerHTML='';document.getElementById('nR').style.display='block';
  }else{
    document.getElementById('nR').style.display='none';
    let h='';
    for(const r of sl){
      const isLB=r[LBI];
      const srcGeo=r[SGI]||'';
      const dstGeo=r[DGI]||'';
      h+='<tr>';
      let first=true;
      for(const ci of visCols){
        let cell=fC(r[ci],ci,q);
        if(first&&isLB){cell=cell.replace('>','><span class="lb-tag">LB</span>');first=false}
        else{first=false}
        // Inject country flag into IP cells
        const geo=(ci===srcCI)?srcGeo:(ci===dstCI)?dstGeo:'';
        if(geo){cell=cell.replace('class="ip"','class="ip has-geo"');cell=cell.replace('</td>','<span class="geo-flag">'+ccFlag(geo)+'</span></td>');}
        h+=cell;
      }
      h+='</tr>';
    }
    tb.innerHTML=h;
  }
  document.getElementById('rc').innerHTML='<b>'+F.length.toLocaleString()+'</b> / '+D.length.toLocaleString()+' records';
  rPg(tp);
  renderFilterTags();
  syncTTHighlight();
}

function rPg(tp){
  const d=document.getElementById('pg');if(tp<=1){d.innerHTML='';return}
  let h='<button onclick="gP(0)"'+(pg===0?' disabled':'')+'>&laquo;</button><button onclick="gP('+(pg-1)+')"'+(pg===0?' disabled':'')+'>&lsaquo;</button>';
  let s=Math.max(0,pg-3),e=Math.min(tp-1,pg+3);
  if(s>0)h+='<button disabled>...</button>';
  for(let i=s;i<=e;i++)h+='<button onclick="gP('+i+')" class="'+(i===pg?'act':'')+'">'+(i+1)+'</button>';
  if(e<tp-1)h+='<button disabled>...</button>';
  h+='<button onclick="gP('+(pg+1)+')"'+(pg>=tp-1?' disabled':'')+'>&rsaquo;</button><button onclick="gP('+(tp-1)+')"'+(pg>=tp-1?' disabled':'')+'>&raquo;</button>';
  h+='<span class="pi">'+(pg+1)+' / '+tp+'</span>';
  h+='<select class="pss" onchange="cPs(this.value)">';
  for(const sz of[50,100,250,500,1000])h+='<option value="'+sz+'"'+(sz===ps?' selected':'')+'>'+sz+' / page</option>';
  h+='</select>';d.innerHTML=h;
}
function gP(p){pg=p;render();document.getElementById('tS').scrollTop=0}
function cPs(v){ps=parseInt(v);pg=0;render()}

// ─── FILTER TAGS BAR ───
function renderFilterTags(){
  const div=document.getElementById('afTags');
  let h='';
  for(const[ci,pat]of Object.entries(colFilters)){
    const label=CL[parseInt(ci)]||C[parseInt(ci)];
    h+='<span class="af-tag"><span class="af-col">'+eH(label)+':</span> '+eH(pat)+' <span class="af-x" onclick="clearColFilter('+ci+')">&times;</span></span>';
  }
  div.innerHTML=h;
}
function clearColFilter(ci){delete colFilters[ci];af()}

// ─── SYNC TOP TALKERS HIGHLIGHT WITH ACTIVE FILTERS ───
function syncTTHighlight(){
  document.querySelectorAll('.tr-click').forEach(el=>{el.classList.remove('active')});
  for(const[fci,fval]of Object.entries(colFilters)){
    document.querySelectorAll('.tr-click').forEach(el=>{
      const onclick=el.getAttribute('onclick')||'';
      if(onclick.includes("'"+C[parseInt(fci)]+"'")&&onclick.includes("'"+fval+"'"))
        el.classList.add('active');
    });
  }
}

// ─── COLUMN POPUP ───
function togglePopup(ci,thEl){
  // Close any other
  closeAllPopups();
  const popup=document.getElementById('cp-'+ci);
  if(!popup)return;
  // Build popup content
  let h='';
  h+='<div class="cp-row'+(sC===ci&&sA?' active':'')+'" onclick="sC='+ci+';sA=true;doSortApply();closeAllPopups()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 19V5m-7 7l7-7 7 7"/></svg> Sort Ascending</div>';
  h+='<div class="cp-row'+(sC===ci&&!sA?' active':'')+'" onclick="sC='+ci+';sA=false;doSortApply();closeAllPopups()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14m-7-7l7 7 7-7"/></svg> Sort Descending</div>';
  h+='<div class="cp-sep"></div>';
  h+='<div class="cp-filter"><input type="text" id="cpf-'+ci+'" placeholder="Filter: text, *, /regex/" value="'+eH(colFilters[ci]||'')+'" onkeydown="if(event.key===\'Enter\'){applyPopupFilter('+ci+');closeAllPopups()}"></div>';
  h+='<div class="cp-hint">* = any &nbsp; ? = one char &nbsp; ! = exclude<br>/regex/i &nbsp; Examples: !DROP &nbsp; !10.0.* &nbsp; !/^PASS$/</div>';
  if(colFilters[ci]){
    h+='<div class="cp-clear" onclick="clearColFilter('+ci+');closeAllPopups()">&#10005; Clear filter</div>';
  }
  h+='<div class="cp-sep"></div>';
  h+='<div class="cp-row" onclick="hideColumn('+ci+');closeAllPopups()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg> Hide column</div>';
  popup.innerHTML=h;
  popup.classList.add('open');
  openPopup=ci;
  // Focus filter input
  setTimeout(()=>{const inp=document.getElementById('cpf-'+ci);if(inp)inp.focus()},50);
}
function closeAllPopups(){
  document.querySelectorAll('.col-popup.open').forEach(p=>p.classList.remove('open'));
  openPopup=null;
}
function applyPopupFilter(ci){
  const inp=document.getElementById('cpf-'+ci);
  if(!inp)return;
  const v=inp.value.trim();
  if(v)colFilters[ci]=v;else delete colFilters[ci];
  af();
}
function hideColumn(ci){colVisible[ci]=false;renderColPanel();af()}

// ─── COLUMN VISIBILITY PANEL ───
function toggleColPanel(btn){
  const dd=document.getElementById('colPanel');
  const isOpen=dd.classList.contains('open');
  closeAllPopups();
  if(isOpen){dd.classList.remove('open');return}
  renderColPanel();
  dd.classList.add('open');
}
function renderColPanel(){
  const dd=document.getElementById('colPanel');
  let h='<div class="cp-actions"><button onclick="allColsVis(true)">Show all</button><button onclick="allColsVis(false)">Hide all</button></div><div class="cp-sep"></div>';
  for(const ci of colOrder){
    const label=CL[ci]||C[ci];
    h+='<label><input type="checkbox" '+(colVisible[ci]?'checked':'')+' onchange="colVisible['+ci+']=this.checked;af()"> '+eH(label)+'</label>';
  }
  dd.innerHTML=h;
}
function allColsVis(v){colVisible=C.map(()=>v);renderColPanel();af()}

// ─── DRAG & DROP COLUMNS ───
function onDragStart(e){
  dragSrc=parseInt(this.dataset.ci);
  this.classList.add('dragging');
  e.dataTransfer.effectAllowed='move';
  e.dataTransfer.setData('text/plain',dragSrc);
}
function onDragOver(e){
  e.preventDefault();e.dataTransfer.dropEffect='move';
  this.classList.add('drag-over');
}
function onDragLeave(e){this.classList.remove('drag-over')}
function onDrop(e){
  e.preventDefault();this.classList.remove('drag-over');
  const tgt=parseInt(this.dataset.ci);
  if(dragSrc===null||dragSrc===tgt)return;
  // Reorder: move dragSrc to position of tgt in colOrder
  const fromIdx=colOrder.indexOf(dragSrc);
  const toIdx=colOrder.indexOf(tgt);
  colOrder.splice(fromIdx,1);
  colOrder.splice(toIdx,0,dragSrc);
  render();
}
function onDragEnd(e){
  dragSrc=null;
  document.querySelectorAll('thead th').forEach(th=>{th.classList.remove('dragging','drag-over')});
}

// ─── RESET ALL ───
function resetAll(){
  colOrder=C.map((_,i)=>i);
  colVisible=[...defVis];
  colFilters={};
  sC=-1;sA=true;pg=0;
  lbFilter=false;document.getElementById('lbBtn').classList.remove('active');
  geoFilterCC='';document.querySelectorAll('.geo-click').forEach(el=>{el.classList.remove('geo-active','geo-dim')});
  const rb=document.getElementById('geoReset');if(rb)rb.style.display='none';
  document.getElementById('sI').value='';
  af();
}

// ─── EXPORT ───
function exportCSV(){
  const visCols=colOrder.filter(i=>colVisible[i]);
  let c=visCols.map(i=>'"'+(CL[i]||C[i])+'"').join(',')+'\n';
  for(const r of F)c+=visCols.map(i=>'"'+String(r[i]).replace(/"/g,'""')+'"').join(',')+'\n';
  const b=new Blob(['\ufeff'+c],{type:'text/csv;charset=utf-8;'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='nsxt_dfw_export.csv';a.click();URL.revokeObjectURL(a.href);
}

// ─── MISC ───
function toggleS(id,btn){const el=document.getElementById(id);const o=el.style.display!=='none';el.style.display=o?'none':'block';btn.classList.toggle('open',!o)}

// ─── LB FILTER TOGGLE ───
function toggleLB(){lbFilter=!lbFilter;document.getElementById('lbBtn').classList.toggle('active',lbFilter);af()}

// ─── GEO FILTER ───
function geoFilter(cc){
  geoFilterCC=(geoFilterCC===cc)?'':cc;
  document.querySelectorAll('.geo-click').forEach(el=>{
    el.classList.remove('geo-active','geo-dim');
    if(geoFilterCC){
      if(el.dataset.cc===geoFilterCC)el.classList.add('geo-active');
      else el.classList.add('geo-dim');
    }
  });
  const rb=document.getElementById('geoReset');
  if(rb)rb.style.display=geoFilterCC?'inline':'none';
  af();
}

// ─── TOP TALKERS CLICK-TO-FILTER ───
function ttFilter(colName,val){
  const ci=C.indexOf(colName);
  if(ci<0)return;
  if(colFilters[ci]===val){delete colFilters[ci]}
  else{colFilters[ci]=val}
  af();
}

// Close popups on outside click
document.addEventListener('click',function(e){
  if(!e.target.closest('.col-popup')&&!e.target.closest('.th-inner')){
    if(openPopup!==null){
      applyPopupFilter(openPopup);
      closeAllPopups();
      af();
    }
  }
  if(!e.target.closest('.col-panel')){
    document.getElementById('colPanel').classList.remove('open');
  }
});

render();
</script>
</body>
</html>
'''


def _prepare_rows(recs, dns_map, sort_by, translate):
    """Prepare sorted list of row-dicts with all computed columns."""
    cols = _get_columns(translate, dns_map is not None)

    zero = ipaddress.IPv4Address("0.0.0.0")
    def sk(r):
        s = _parse_ip(r["src_ip"]) or zero
        d = _parse_ip(r["dst_ip"]) or zero
        p = int(r["dst_port"]) if r["dst_port"].isdigit() else 0
        if sort_by == "dst_ip":   return (d, s, p)
        if sort_by == "dst_port": return (p, s, d)
        return (s, d, p)

    rows = sorted(recs.values(), key=sk)
    out = []
    for r in rows:
        o = dict(r)
        if translate:
            o["dst_service"] = get_service_name(r["dst_port"], r.get("protocol", "tcp"))
            o["protocol_desc"] = get_protocol_description(r["protocol"])
        if dns_map is not None:
            o["src_dns"] = dns_map.get(r["src_ip"], "")
            o["dst_dns"] = dns_map.get(r["dst_ip"], "")
        out.append(o)
    return cols, out


def _get_columns(translate, has_dns):
    if translate:
        cols = ["src_ip", "src_port", "dst_ip", "dst_port", "dst_service",
                "protocol", "protocol_desc",
                "action", "direction", "rule_name",
                "hostname", "cluster", "datacenter", "first_seen"]
    else:
        cols = ["src_ip", "src_port", "dst_ip", "dst_port",
                "protocol",
                "action", "direction", "rule_name",
                "hostname", "cluster", "datacenter", "first_seen"]
    if has_dns:
        cols.insert(cols.index("src_port"), "src_dns")
        cols.insert(cols.index("dst_port"), "dst_dns")
    return cols


# CSS class map for table cell styling
_COL_CSS = {
    "src_ip": "ip", "dst_ip": "ip",
    "src_port": "port", "dst_port": "port",
    "dst_service": "svc", "protocol_desc": "pdesc",
    "src_dns": "dns", "dst_dns": "dns",
    "hostname": "hn", "cluster": "hn", "datacenter": "hn",
    "first_seen": "tm", "rule_name": "rule",
}

# Column display names
_COL_LABELS = {
    "src_ip": "Src IP", "src_dns": "Src DNS", "src_port": "Src Port",
    "dst_ip": "Dst IP", "dst_dns": "Dst DNS", "dst_port": "Dst Port",
    "dst_service": "Service", "protocol": "Proto", "protocol_desc": "Proto Desc",
    "action": "Action", "direction": "Dir", "rule_name": "Rule",
    "hostname": "Host", "cluster": "Cluster", "datacenter": "DC",
    "first_seen": "First Seen",
}


def write_html(recs, path, dns_map=None, sort_by="src_ip", translate=True):
    import html as html_mod

    cols, rows = _prepare_rows(recs, dns_map, sort_by, translate)

    # JSON data for JS
    has_geo = _geoip_loaded
    json_rows = []
    for r in rows:
        row_data = [r.get(c, "") for c in cols]
        # Append LB flag (1 if src or dst in 100.64.0.0/10, else 0)
        lb = 1 if (is_lb_ip(r.get("src_ip", "")) or is_lb_ip(r.get("dst_ip", ""))) else 0
        row_data.append(lb)
        # Append geo country codes (only for public IPs, empty if no DB)
        src_ip = r.get("src_ip", "")
        dst_ip = r.get("dst_ip", "")
        src_cc = geoip_lookup(src_ip) if has_geo and classify_ip(src_ip) == "public" else ""
        dst_cc = geoip_lookup(dst_ip) if has_geo and classify_ip(dst_ip) == "public" else ""
        row_data.append(src_cc)
        row_data.append(dst_cc)
        json_rows.append(row_data)
    col_classes = [_COL_CSS.get(c, "") for c in cols]
    col_labels = [_COL_LABELS.get(c, c) for c in cols]

    # Stats
    sc, dc, pc, prc, ac = Counter(), Counter(), Counter(), Counter(), Counter()
    lb_count = 0
    geo_countries: set = set()
    for r in recs.values():
        sc[r["src_ip"]] += 1;  dc[r["dst_ip"]] += 1
        pc[r["dst_port"]] += 1; prc[r["protocol"]] += 1; ac[r["action"]] += 1
        if is_lb_ip(r["src_ip"]) or is_lb_ip(r["dst_ip"]):
            lb_count += 1
        if has_geo:
            for ip in (r["src_ip"], r["dst_ip"]):
                if classify_ip(ip) == "public":
                    cc = geoip_lookup(ip)
                    if cc:
                        geo_countries.add(cc)

    n = len(recs)
    pass_n = ac.get("PASS", 0)
    drop_n = ac.get("DROP", 0)
    rej_n  = ac.get("REJECT", 0)
    proto_detail = ", ".join(f"{p} {c}" for p, c in prc.most_common(5))

    stats_html = f'''
    <div class="sc"><div class="sl">Unique Flows</div><div class="sv c">{n:,}</div><div class="sd">{len(sc)} src &rarr; {len(dc)} dst IPs</div></div>
    <div class="sc"><div class="sl">PASS</div><div class="sv g">{pass_n:,}</div><div class="sd">{pass_n*100//max(n,1)}% of total</div></div>
    <div class="sc"><div class="sl">DROP</div><div class="sv r">{drop_n:,}</div><div class="sd">{drop_n*100//max(n,1)}% of total</div></div>
    <div class="sc"><div class="sl">REJECT</div><div class="sv" style="color:var(--ao)">{rej_n:,}</div><div class="sd">{rej_n*100//max(n,1)}% of total</div></div>
    <div class="sc"><div class="sl">Protocols</div><div class="sv p">{len(prc)}</div><div class="sd">{html_mod.escape(proto_detail)}</div></div>
    <div class="sc"><div class="sl">Load Balancer</div><div class="sv" style="color:#60a5fa">{lb_count:,}</div><div class="sd">flows via 100.64/10</div></div>
    '''
    if has_geo and geo_countries:
        flag_imgs = []
        for cc in sorted(geo_countries):
            uri = flag_svg_data_uri(cc)
            if uri:
                flag_imgs.append(
                    f'<span class="geo-click" data-cc="{cc}" onclick="geoFilter(\'{cc}\')" title="{cc}">'
                    f'<img src="{uri}" class="geo-flag-img">'
                    f'</span>')
            else:
                flag_imgs.append(
                    f'<span class="geo-click geo-cc" data-cc="{cc}" onclick="geoFilter(\'{cc}\')" title="{cc}">'
                    f'{cc}</span>')
        top_flags = " ".join(flag_imgs)
        stats_html += f'''
    <div class="sc" style="grid-column:1/-1"><div class="sl">GeoIP <span class="geo-reset" id="geoReset" style="display:none" onclick="geoFilter(\'\')">&times; reset</span></div><div class="sv" style="color:#a78bfa;font-size:18px">{len(geo_countries)} countries</div><div class="sd">{top_flags}</div></div>
    '''

    # Top talkers
    def talker_card(title, counter, top_n, css_class, col_name):
        items = counter.most_common(top_n)
        if not items:
            return ""
        mx = items[0][1]
        h = f'<div class="tc"><h3>{html_mod.escape(title)}</h3>'
        for val, cnt in items:
            pct = cnt * 100 // max(mx, 1)
            v = html_mod.escape(str(val))
            svc = ""
            if css_class == "port":
                svc_name = get_service_name(val)
                if svc_name:
                    svc = f' <span style="color:var(--t2);font-size:11px">({svc_name})</span>'
            h += f'<div class="tr_ tr-click" onclick="ttFilter(\'{col_name}\',\'{v}\')" title="Click to filter"><span class="{css_class}">{v}{svc}</span><span class="cnt">{cnt:,}</span></div>'
            h += f'<div class="tbar"><div class="tbf" style="width:{pct}%"></div></div>'
        h += '</div>'
        return h

    talkers_html = (
        talker_card("Top Source IPs", sc, 10, "ip", "src_ip") +
        talker_card("Top Destination IPs", dc, 10, "ip", "dst_ip") +
        talker_card("Top Destination Ports", pc, 15, "port", "dst_port")
    )

    # Meta
    from datetime import datetime
    meta = f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | {n:,} unique flows | Sort: {sort_by}"

    # Fill template
    output = HTML_TEMPLATE
    output = output.replace("%%META%%", html_mod.escape(meta))
    output = output.replace("%%STATS%%", stats_html)
    output = output.replace("%%TALKERS%%", talkers_html)
    output = output.replace("%%DATA%%", json.dumps(json_rows, ensure_ascii=False))
    output = output.replace("%%COLS%%", json.dumps(cols))
    output = output.replace("%%CCLS%%", json.dumps(col_classes))
    output = output.replace("%%CLABELS%%", json.dumps(col_labels))
    # Hide hostname, cluster, datacenter by default
    _hidden_default = {"hostname", "cluster", "datacenter"}
    col_vis = [c not in _hidden_default for c in cols]
    output = output.replace("%%COLVIS%%", json.dumps(col_vis))

    # Build flag data-URI map for all country codes found in data
    flag_map: dict[str, str] = {}
    if has_geo:
        used_ccs = set()
        for r in json_rows:
            src_cc, dst_cc = r[-2], r[-1]
            if src_cc:
                used_ccs.add(src_cc)
            if dst_cc:
                used_ccs.add(dst_cc)
        for cc in used_ccs:
            uri = flag_svg_data_uri(cc)
            if uri:
                flag_map[cc] = uri
    output = output.replace("%%FLAGS%%", json.dumps(flag_map))

    with open(path, "w", encoding="utf-8") as f:
        f.write(output)
    print(f"\n[OUTPUT] {len(rows):,} records -> {path} (HTML)", file=sys.stderr)


# =============================================================================
# GeoIP database download helper
# =============================================================================

def download_geoip(target_path: str = GEOIP_DB_FILE) -> bool:
    """Download current month's DB-IP Country Lite CSV."""
    import datetime
    import gzip
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError

    ym = datetime.date.today().strftime("%Y-%m")
    url = GEOIP_URL_TEMPLATE.format(ym=ym)

    print(f"[GEO] Downloading DB-IP Country Lite ({ym})...", file=sys.stderr)
    print(f"[GEO] URL: {url}", file=sys.stderr)

    try:
        req = Request(url, headers={"User-Agent": "nsxt_fw_analyzer/1.0"})
        with urlopen(req, timeout=30) as resp:
            gz_data = resp.read()
    except HTTPError as e:
        if e.code == 404:
            # Current month not published yet, try previous month
            d = datetime.date.today().replace(day=1) - datetime.timedelta(days=1)
            ym_prev = d.strftime("%Y-%m")
            url_prev = GEOIP_URL_TEMPLATE.format(ym=ym_prev)
            print(f"[GEO] {ym} not available yet, trying {ym_prev}...",
                  file=sys.stderr)
            try:
                req2 = Request(url_prev,
                               headers={"User-Agent": "nsxt_fw_analyzer/1.0"})
                with urlopen(req2, timeout=30) as resp2:
                    gz_data = resp2.read()
                url = url_prev
                ym = ym_prev
            except Exception as e2:
                print(f"[GEO] Download failed: {e2}", file=sys.stderr)
                return False
        else:
            print(f"[GEO] HTTP error: {e}", file=sys.stderr)
            return False
    except (URLError, OSError) as e:
        print(f"[GEO] Download failed: {e}", file=sys.stderr)
        return False

    print(f"[GEO] Downloaded {len(gz_data):,} bytes, decompressing...",
          file=sys.stderr)
    try:
        csv_data = gzip.decompress(gz_data)
    except Exception as e:
        print(f"[GEO] Decompression failed: {e}", file=sys.stderr)
        return False

    with open(target_path, "wb") as f:
        f.write(csv_data)

    size_mb = len(csv_data) / 1_048_576
    lines = csv_data.count(b"\n")
    print(f"[GEO] Saved {target_path}  ({size_mb:.1f} MB, ~{lines:,} rows)",
          file=sys.stderr)
    return True


def download_services(target_path: str = SERVICES_DB_FILE) -> bool:
    """Download IANA Service Name and Transport Protocol Port Number Registry."""
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError

    print(f"[SVC] Downloading IANA services database...", file=sys.stderr)
    print(f"[SVC] URL: {SERVICES_URL}", file=sys.stderr)

    try:
        req = Request(SERVICES_URL,
                      headers={"User-Agent": "nsxt_fw_analyzer/1.0"})
        with urlopen(req, timeout=30) as resp:
            data = resp.read()
    except (HTTPError, URLError, OSError) as e:
        print(f"[SVC] Download failed: {e}", file=sys.stderr)
        return False

    with open(target_path, "wb") as f:
        f.write(data)

    size_kb = len(data) / 1024
    lines = data.count(b"\n")
    print(f"[SVC] Saved {target_path}  ({size_kb:.0f} KB, ~{lines:,} rows)",
          file=sys.stderr)
    return True


# =============================================================================
# CLI
# =============================================================================

USAGE_TEXT = r"""
================================================================================
                     NSX-T DFW Log Analyzer  -  USAGE
================================================================================

DESCRIPTION:
  Analyzer for VMware NSX-T Distributed Firewall (DFW) logs.
  Reads a tar.gz archive exported from Log Insight / Aria Operations for Logs,
  extracts CSV files, deduplicates flow records and saves the result.

  Additional output columns:
    dst_service   - service name for destination port (e.g. 443 -> https)
    protocol_desc - protocol description for non-TCP/UDP (e.g. 1 -> ICMP)
    src_dns       - DNS PTR name for source IP      (only with --resolve-dns)
    dst_dns       - DNS PTR name for destination IP  (only with --resolve-dns)

  Output format: CSV (default) or interactive HTML (--html).

================================================================================
 REQUIRED ARGUMENT
================================================================================

  input                 Path to tar.gz archive with CSV files from Log Insight.

================================================================================
 OPTIONAL ARGUMENTS
================================================================================

  -o, --output FILE     Output file (CSV or HTML).
                         Default: <archive_name>_<mode>_unique.csv (.html with --html)

  -m, --mode {private,public,multicast,all}
                         IP address class filter (default: private).
                           private   - BOTH IPs must be RFC1918 (10/172.16/192.168)
                                       or shared address space (100.64/10, NSX LB)
                           public    - AT LEAST ONE IP is publicly routable
                           multicast - AT LEAST ONE IP is 224.0.0.0/4
                           all       - no IP class filter

================================================================================
 FILTERING
================================================================================

  --exclude-ips IP1,IP2,...
                         Comma-separated list of IPs to exclude.
                         Excludes rows where src OR dst matches.

  --exclude-ports PORT1,PORT2,...
                         Comma-separated list of ports to exclude.
                         Excludes rows where src_port OR dst_port matches.

  --exclude-ips-file FILE
                         Text file with IPs to exclude (one IP per line).
                         Lines starting with # are treated as comments.

  --exclude-ports-file FILE
                         Text file with ports to exclude (one port per line).
                         Lines starting with # are treated as comments.

  --action {PASS,DROP,REJECT}
                         Show only records with the given firewall action.

  --direction {IN,OUT}
                         Show only records with the given flow direction.

================================================================================
 DNS RESOLUTION (PTR)
================================================================================

  --resolve-dns          Enable reverse DNS (PTR) lookups for IP addresses.
                         Results are saved to a file cache (.dns_ptr_cache.json).
                         Adds src_dns and dst_dns columns to the output.
                         Empty entries in cache are automatically retried.

  --dns-server IP        Primary DNS server for PTR queries.
                         Default: 10.12.254.11

  --dns-server2 IP       Secondary DNS server for PTR queries.
                         PTR query is first tried on the primary server;
                         if it fails, the secondary server is used.
                         Default: 10.12.255.101

  --dns-cache-file PATH  Path to the DNS cache file.
                         Default: .dns_ptr_cache.json (next to the script)

================================================================================
 OUTPUT & SORTING
================================================================================

  --sort-by {src_ip,dst_ip,dst_port}
                         Sort order (default: src_ip).
                           src_ip   - by source IP -> destination IP -> port
                           dst_ip   - by destination IP -> source IP -> port
                           dst_port - by destination port -> source IP

  --stats                Print top-talker statistics to stderr.

  --no-translate         Disable port-to-service and protocol description.
                         Columns dst_service and protocol_desc are omitted.

  --html                 Generate interactive HTML report instead of CSV.
                         Features: dashboard, top talkers, fulltext search,
                         dropdown filters, column sorting, pagination,
                         color-coded actions, CSV export, print layout.
                         Self-contained file (zero dependencies).

================================================================================
 PORT-TO-SERVICE DATABASE
================================================================================

  The dst_service column translates port numbers to service names.
  Sources (in priority order):

    1) IANA CSV file (services-db.csv) next to this script.
       Most comprehensive mapping (~6000 services). Download:

         python3 nsxt_fw_analyzer.py --download-services

    2) Built-in dictionary (~500 common ports) when no CSV file is found.
       Works fully offline, no external files needed.

  The script runs completely offline (except for DNS PTR lookups).

================================================================================
 GEOIP COUNTRY DATABASE (optional)
================================================================================

  When a GeoIP database is present, the HTML report shows country flags
  next to public IP addresses. Download the free DB-IP lite CSV:

    python3 nsxt_fw_analyzer.py --download-geoip

  This auto-detects the current month, downloads and decompresses the
  database (~24 MB) to geoip-country.csv next to the script.
  If the current month is not published yet, previous month is used.

  If the file is missing, geolocation is silently skipped.
  The database is updated monthly — re-run --download-geoip to refresh.

================================================================================
 DOWNLOAD ALL OPTIONAL DATABASES AT ONCE
================================================================================

    python3 nsxt_fw_analyzer.py --download-all

================================================================================
 EXAMPLES
================================================================================

  1) Basic analysis - private IPs only (default mode):

     python3 nsxt_fw_analyzer.py export.tar.gz

  2) Public IP analysis with DNS resolution:

     python3 nsxt_fw_analyzer.py export.tar.gz -m public --resolve-dns

  3) DNS resolution with TWO DNS servers (primary + secondary):

     python3 nsxt_fw_analyzer.py export.tar.gz --resolve-dns \
         --dns-server 10.12.254.11 --dns-server2 10.12.255.101

  4) Exclude specific IPs and ports:

     python3 nsxt_fw_analyzer.py export.tar.gz \
         --exclude-ips 10.0.0.1,10.0.0.2 --exclude-ports 22,3389

  5) Exclude using files (one entry per line, # = comment):

     python3 nsxt_fw_analyzer.py export.tar.gz \
         --exclude-ips-file skip_ips.txt --exclude-ports-file skip_ports.txt

  6) DROP actions only, direction OUT, with statistics:

     python3 nsxt_fw_analyzer.py export.tar.gz \
         -m all --action DROP --direction OUT -o dropped.csv --stats

  7) Sort by destination port:

     python3 nsxt_fw_analyzer.py export.tar.gz --sort-by dst_port -o by_port.csv

  8) Complete analysis - everything at once:

     python3 nsxt_fw_analyzer.py export.tar.gz \
         -m all --resolve-dns \
         --dns-server 10.12.254.11 --dns-server2 10.12.255.101 \
         --exclude-ips-file skip_ips.txt --exclude-ports 53,67,68 \
         --action PASS --direction IN --sort-by dst_ip --stats \
         -o full_analysis.csv

  9) Without port/protocol translation (raw numeric values):

     python3 nsxt_fw_analyzer.py export.tar.gz --no-translate

 10) Interactive HTML report:

     python3 nsxt_fw_analyzer.py export.tar.gz -m all --html

 11) HTML report with DNS and statistics:

     python3 nsxt_fw_analyzer.py export.tar.gz --html --resolve-dns \
         -m all --stats -o report.html

 12) Download IANA services database for richer port translation:

     python3 nsxt_fw_analyzer.py --download-services

 13) Download GeoIP database for country flags in HTML reports:

     python3 nsxt_fw_analyzer.py --download-geoip

 14) Download all optional databases at once:

     python3 nsxt_fw_analyzer.py --download-all

================================================================================
 OUTPUT CSV COLUMNS
================================================================================

  src_ip        - source IP address
  src_dns       - DNS PTR name for source IP     (only with --resolve-dns)
  src_port      - source port
  dst_ip        - destination IP address
  dst_dns       - DNS PTR name for dest IP       (only with --resolve-dns)
  dst_port      - destination port (number)
  dst_service   - service name for dest port      (e.g. https, ssh, rdp)
  protocol      - protocol (TCP/UDP/number)
  protocol_desc - protocol description            (only for non-TCP/UDP)
  action        - firewall action (PASS/DROP/REJECT)
  direction     - direction (IN/OUT)
  rule_name     - DFW rule name
  hostname      - ESXi host hostname
  cluster       - vSphere cluster
  datacenter    - vSphere datacenter
  first_seen    - first occurrence timestamp

================================================================================
 NOTES
================================================================================

  * For DNS resolution via custom servers: pip install dnspython
    Without dnspython, system resolver is used (--dns-server is ignored).
  * DNS cache persists across runs. Empty entries (failed lookups) are
    automatically retried on the next run. Delete the file for fresh start.
  * Port-to-service uses services-db.csv (IANA) if present, otherwise
    built-in dictionary (~500 common ports).
  * protocol_desc is non-empty ONLY for non-TCP/UDP protocols.
"""


def main():
    if len(sys.argv) == 1:
        print(USAGE_TEXT)
        sys.exit(0)

    # Handle --download-* early (no positional arg needed)
    if "--download-geoip" in sys.argv or "--download-services" in sys.argv \
            or "--download-all" in sys.argv:
        ok = True
        if "--download-geoip" in sys.argv or "--download-all" in sys.argv:
            ok = download_geoip() and ok
        if "--download-services" in sys.argv or "--download-all" in sys.argv:
            ok = download_services() and ok
        sys.exit(0 if ok else 1)

    p = argparse.ArgumentParser(
        description="NSX-T DFW Log Analyzer - extract, filter, deduplicate flows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_TEXT)
    p.add_argument("input", help="tar.gz archive with CSV files")
    p.add_argument("-o", "--output", help="Output CSV (default: auto)")
    p.add_argument("-m", "--mode", choices=["private", "public", "multicast", "all"],
                   default="private", help="IP filter mode (default: private)")
    g = p.add_argument_group("Filtering")
    g.add_argument("--exclude-ips", default="", help="Comma-separated IPs to exclude")
    g.add_argument("--exclude-ports", default="", help="Comma-separated ports to exclude")
    g.add_argument("--exclude-ips-file", help="File: IPs to exclude (one/line, # comments)")
    g.add_argument("--exclude-ports-file", help="File: ports to exclude (one/line)")
    g.add_argument("--action", choices=["PASS", "DROP", "REJECT"], help="Filter by action")
    g.add_argument("--direction", choices=["IN", "OUT"], help="Filter by direction")
    d = p.add_argument_group("DNS")
    d.add_argument("--resolve-dns", action="store_true",
                   help="PTR lookup (cached to file)")
    d.add_argument("--dns-server", default=DNS_SERVER,
                   help=f"Primary DNS server (default: {DNS_SERVER})")
    d.add_argument("--dns-server2", default=DNS_SERVER2,
                   help=f"Secondary DNS server (default: {DNS_SERVER2})")
    d.add_argument("--dns-cache-file", default=DNS_CACHE_FILE,
                   help="Cache file path")
    o = p.add_argument_group("Output")
    o.add_argument("--sort-by", choices=["src_ip", "dst_ip", "dst_port"],
                   default="src_ip")
    o.add_argument("--stats", action="store_true",
                   help="Print top-talker statistics")
    o.add_argument("--no-translate", action="store_true",
                   help="Disable port-to-service and protocol description translation")
    o.add_argument("--html", action="store_true",
                   help="Generate interactive HTML report instead of CSV")
    args = p.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: {args.input} not found", file=sys.stderr); sys.exit(1)

    ex_ips = set()
    if args.exclude_ips:
        ex_ips.update(x.strip() for x in args.exclude_ips.split(",") if x.strip())
    if args.exclude_ips_file and os.path.isfile(args.exclude_ips_file):
        with open(args.exclude_ips_file) as f:
            ex_ips.update(l.strip() for l in f if l.strip() and not l.startswith("#"))
    ex_ports = set()
    if args.exclude_ports:
        ex_ports.update(x.strip() for x in args.exclude_ports.split(",") if x.strip())
    if args.exclude_ports_file and os.path.isfile(args.exclude_ports_file):
        with open(args.exclude_ports_file) as f:
            ex_ports.update(l.strip() for l in f if l.strip() and not l.startswith("#"))

    if not args.output:
        base = Path(args.input).stem.replace(".tar", "").replace(".csv", "")
        ext = ".html" if args.html else ".csv"
        args.output = f"{base}_{args.mode}_unique{ext}"

    dns_srv_display = args.dns_server
    if args.dns_server2:
        dns_srv_display += f", {args.dns_server2}"

    fmt_label = "HTML" if args.html else "CSV"
    print(f"\n┌─ NSX-T DFW Log Analyzer ─────────────────────┐", file=sys.stderr)
    print(f"│ Input:    {args.input}", file=sys.stderr)
    print(f"│ Output:   {args.output}", file=sys.stderr)
    print(f"│ Format:   {fmt_label}", file=sys.stderr)
    print(f"│ Mode:     {args.mode}", file=sys.stderr)
    if ex_ips:    print(f"│ Excl IPs: {len(ex_ips)}", file=sys.stderr)
    if ex_ports:  print(f"│ Excl prt: {len(ex_ports)}", file=sys.stderr)
    if args.action:    print(f"│ Action:   {args.action}", file=sys.stderr)
    if args.direction: print(f"│ Dir:      {args.direction}", file=sys.stderr)
    print(f"│ DNS:      {args.resolve_dns}", file=sys.stderr)
    if args.resolve_dns:
        print(f"│ DNS srv:  {dns_srv_display}", file=sys.stderr)
    print(f"│ Sort:     {args.sort_by}", file=sys.stderr)
    if args.no_translate:
        print(f"│ Transl:   disabled", file=sys.stderr)
    print(f"└──────────────────────────────────────────────┘\n", file=sys.stderr)

    t0 = time.time()
    # Load GeoIP database if available (optional, for HTML country flags)
    load_geoip()
    with tempfile.TemporaryDirectory(prefix="nsxt_") as tmp:
        print("[1/4] Extracting CSVs...", file=sys.stderr)
        csvs = extract_csvs(args.input, tmp)
        print(f"  Found {len(csvs)} CSV files\n", file=sys.stderr)
        if not csvs:
            print("Error: No CSVs in archive!", file=sys.stderr); sys.exit(1)

        print("[2/4] Processing & deduplicating...", file=sys.stderr)
        recs, ips = process(csvs, args.mode, ex_ips, ex_ports,
                            args.action.upper() if args.action else None,
                            args.direction.upper() if args.direction else None)
        if not recs:
            print("\nNo records match.", file=sys.stderr); sys.exit(0)

        dns_map = None
        if args.resolve_dns:
            print("\n[3/4] DNS PTR resolution...", file=sys.stderr)
            dc = DnsCache(args.dns_cache_file, args.dns_server,
                          args.dns_server2)
            dns_map = resolve_all(ips, dc)
        else:
            print("\n[3/4] DNS skipped (--resolve-dns to enable)", file=sys.stderr)

        print(f"\n[4/4] Writing output...", file=sys.stderr)
        translate = not args.no_translate
        if args.html:
            write_html(recs, args.output, dns_map, args.sort_by,
                       translate=translate)
        else:
            write_csv(recs, args.output, dns_map, args.sort_by,
                      translate=translate)
        if args.stats:
            stats(recs)

    print(f"\nDone in {time.time()-t0:.1f}s", file=sys.stderr)

if __name__ == "__main__":
    main()
