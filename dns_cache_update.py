#!/usr/bin/env python3
"""
DNS PTR Cache Updater
======================
Standalone helper for managing the .dns_ptr_cache.json file used by
nsxt_fw_analyzer.py. Retries empty entries, adds new IPs, shows stats.

Requires: pip install dnspython

Usage:
  python3 dns_cache_update.py                  # retry all empty entries
  python3 dns_cache_update.py --retry-all      # re-resolve ALL entries (full refresh)
  python3 dns_cache_update.py --add 10.1.1.0/24  # add & resolve a subnet
  python3 dns_cache_update.py --add-file ips.txt  # add & resolve IPs from file
  python3 dns_cache_update.py --stats          # show cache statistics
  python3 dns_cache_update.py --remove-empty   # delete all empty entries from cache
  python3 dns_cache_update.py --export hosts.txt  # export as hosts file format
"""

import argparse
import ipaddress
import json
import os
import sys
import time

DNS_SERVER   = "1.1.1.1"
DNS_SERVER2  = "2.2.2.2"
DNS_SERVER3  = "3.3.3.3"
DNS_TIMEOUT  = 2
DNS_CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".dns_ptr_cache.json"
)

def load_cache(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Cannot read {path}: {e}", file=sys.stderr)
    return {}

def save_cache(cache, path):
    try:
        with open(path, "w") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        print(f"[SAVE] {len(cache)} records -> {path}")
    except IOError as e:
        print(f"[ERROR] Cannot save: {e}", file=sys.stderr)

def setup_resolvers(servers, timeout):
    try:
        import dns.resolver
    except ImportError:
        print("[ERROR] dnspython is required: pip install dnspython", file=sys.stderr)
        sys.exit(1)
    resolvers = []
    for srv in servers:
        if not srv:
            continue
        r = dns.resolver.Resolver()
        r.nameservers = [srv]
        r.timeout = timeout
        r.lifetime = timeout
        resolvers.append((srv, r))
    return resolvers

def resolve_ip(ip, resolvers):
    """Try PTR on each resolver, return first hit."""
    rev = ipaddress.ip_address(ip).reverse_pointer
    for srv_name, resolver in resolvers:
        try:
            ans = resolver.resolve(rev, "PTR")
            if ans:
                return str(ans[0]).rstrip("."), srv_name
        except Exception:
            continue
    return "", None

def print_stats(cache):
    total = len(cache)
    resolved = sum(1 for v in cache.values() if v)
    empty = total - resolved
    print(f"\n{'='*50}")
    print(f"  DNS PTR Cache Statistics")
    print(f"{'='*50}")
    print(f"  Total entries:    {total:>8,}")
    print(f"  Resolved (PTR):   {resolved:>8,}  ({resolved*100//max(total,1)}%)")
    print(f"  Empty (no PTR):   {empty:>8,}  ({empty*100//max(total,1)}%)")
    if resolved:
        from collections import Counter
        domains = Counter()
        for v in cache.values():
            if v:
                parts = v.split(".")
                if len(parts) >= 2:
                    domains[".".join(parts[-2:])] += 1
                else:
                    domains[v] += 1
        print(f"\n  Top 10 domains:")
        for dom, cnt in domains.most_common(10):
            print(f"    {dom:30s} {cnt:>6,}")
    print(f"{'='*50}\n")

def expand_targets(targets):
    ips = set()
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"):
            continue
        if "/" in t:
            try:
                net = ipaddress.IPv4Network(t, strict=False)
                for ip in net.hosts():
                    ips.add(str(ip))
            except ValueError:
                print(f"[WARN] Invalid subnet: {t}", file=sys.stderr)
        else:
            try:
                ipaddress.IPv4Address(t)
                ips.add(t)
            except ValueError:
                print(f"[WARN] Invalid IP: {t}", file=sys.stderr)
    return sorted(ips)

def do_resolve(cache, ips_to_resolve, resolvers, label=""):
    n = len(ips_to_resolve)
    if n == 0:
        print(f"[{label}] Nothing to resolve.")
        return 0, 0
    ok = fail = 0
    t0 = time.time()
    srv_names = ", ".join(s for s, _ in resolvers)
    print(f"[{label}] Resolving {n} IPs against {srv_names}...")
    for i, ip in enumerate(ips_to_resolve, 1):
        hostname, srv = resolve_ip(ip, resolvers)
        old = cache.get(ip, "")
        cache[ip] = hostname
        if hostname:
            ok += 1
            marker = "+" if not old else "~"
            print(f"  {marker} {ip:>18s} -> {hostname}  [{srv}]")
        else:
            fail += 1
        if i % 100 == 0:
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed > 0 else 0
            eta = (n - i) / rate if rate > 0 else 0
            print(f"  ... {i}/{n}  ({ok} ok, {fail} fail)  "
                  f"ETA {eta:.0f}s", file=sys.stderr)
    elapsed = time.time() - t0
    print(f"[{label}] Done: {ok} resolved, {fail} empty ({elapsed:.1f}s)")
    return ok, fail

def main():
    p = argparse.ArgumentParser(
        description="DNS PTR Cache Updater - manage .dns_ptr_cache.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--cache-file", default=DNS_CACHE_FILE,
                   help=f"Cache file path (default: {DNS_CACHE_FILE})")
    p.add_argument("--dns-server", default=DNS_SERVER,
                   help=f"Primary DNS (default: {DNS_SERVER})")
    p.add_argument("--dns-server2", default=DNS_SERVER2,
                   help=f"Secondary DNS (default: {DNS_SERVER2})")
    p.add_argument("--dns-server3", default=DNS_SERVER3,
                   help=f"Tertiary DNS (default: {DNS_SERVER3 or 'none'})")
    p.add_argument("--timeout", type=int, default=DNS_TIMEOUT,
                   help=f"DNS timeout in seconds (default: {DNS_TIMEOUT})")
    g = p.add_argument_group("Actions")
    g.add_argument("--retry-all", action="store_true",
                   help="Re-resolve ALL entries (full refresh)")
    g.add_argument("--add", nargs="+", metavar="IP_OR_SUBNET",
                   help="Add & resolve IPs or subnets (e.g. 10.1.1.0/24 10.2.0.5)")
    g.add_argument("--add-file", metavar="FILE",
                   help="Add & resolve IPs from file (one IP/subnet per line)")
    g.add_argument("--stats", action="store_true",
                   help="Show cache statistics")
    g.add_argument("--remove-empty", action="store_true",
                   help="Delete all empty (unresolved) entries from cache")
    g.add_argument("--export", metavar="FILE",
                   help="Export resolved entries as hosts file (IP hostname)")
    g.add_argument("--dry-run", action="store_true",
                   help="Show what would be resolved without doing it")
    args = p.parse_args()
    cache = load_cache(args.cache_file)
    total = len(cache)
    empty = sum(1 for v in cache.values() if v == "")
    resolved = total - empty
    print(f"[LOAD] {total} entries ({resolved} resolved, {empty} empty) "
          f"from {args.cache_file}")
    if args.stats:
        print_stats(cache)
        return
    if args.remove_empty:
        before = len(cache)
        cache = {k: v for k, v in cache.items() if v}
        removed = before - len(cache)
        print(f"[CLEAN] Removed {removed} empty entries")
        save_cache(cache, args.cache_file)
        return
    if args.export:
        count = 0
        with open(args.export, "w") as f:
            for ip in sorted(cache.keys(),
                             key=lambda x: ipaddress.IPv4Address(x)):
                hostname = cache[ip]
                if hostname:
                    f.write(f"{ip}\t{hostname}\n")
                    count += 1
        print(f"[EXPORT] {count} entries -> {args.export}")
        return
    resolvers = setup_resolvers(
        [args.dns_server, args.dns_server2, args.dns_server3], args.timeout)
    print(f"[DNS] Servers: {', '.join(s for s,_ in resolvers)}")
    modified = False
    if args.add or args.add_file:
        targets = list(args.add or [])
        if args.add_file:
            if not os.path.isfile(args.add_file):
                print(f"[ERROR] File not found: {args.add_file}", file=sys.stderr)
                sys.exit(1)
            with open(args.add_file) as f:
                targets.extend(l.strip() for l in f
                               if l.strip() and not l.startswith("#"))
        new_ips = expand_targets(targets)
        to_resolve = [ip for ip in new_ips
                      if ip not in cache or cache.get(ip) == ""]
        already = len(new_ips) - len(to_resolve)
        if already:
            print(f"[ADD] {already} IPs already resolved in cache, skipping")
        if args.dry_run:
            print(f"[DRY-RUN] Would resolve {len(to_resolve)} new IPs")
            for ip in to_resolve[:20]:
                print(f"  {ip}")
            if len(to_resolve) > 20:
                print(f"  ... and {len(to_resolve)-20} more")
            return
        if to_resolve:
            do_resolve(cache, to_resolve, resolvers, "ADD")
            modified = True
    if not args.add and not args.add_file:
        if args.retry_all:
            to_resolve = sorted(cache.keys(),
                                key=lambda x: ipaddress.IPv4Address(x))
            label = "REFRESH"
        else:
            to_resolve = sorted(
                [ip for ip, v in cache.items() if v == ""],
                key=lambda x: ipaddress.IPv4Address(x))
            label = "RETRY"
        if args.dry_run:
            print(f"[DRY-RUN] Would resolve {len(to_resolve)} IPs")
            for ip in to_resolve[:20]:
                cur = cache.get(ip, "")
                print(f"  {ip:>18s}  (current: {cur or '(empty)'})")
            if len(to_resolve) > 20:
                print(f"  ... and {len(to_resolve)-20} more")
            return
        if to_resolve:
            do_resolve(cache, to_resolve, resolvers, label)
            modified = True
        else:
            print("[OK] No empty entries to retry. Use --retry-all for full refresh.")
    if modified:
        save_cache(cache, args.cache_file)
        print_stats(cache)

if __name__ == "__main__":
    main()
