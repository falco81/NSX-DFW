#!/usr/bin/env python3
"""
NSX Distributed Firewall Documentation Generator

Modes:
  nsx_dfw_doc.py fetch [output.json] [output.html]
      Fetch DFW objects from NSX Manager API and generate HTML documentation.

  nsx_dfw_doc.py <input.json> [output.html] [--filter TEXT] [--filter-tag TAG]
      Generate HTML documentation from previously fetched JSON.

  --filter TEXT        Match policy names, group names, condition values,
                       effective VM names, rule tags. Case-insensitive.
  --filter-tag TAG     Match NSX tag scope/value. Colon for AND logic:
                       --filter-tag Z00:Prod
"""

import os
import sys
import json
import html as html_mod
import getpass
from datetime import datetime
from collections import defaultdict, OrderedDict

# ─── Configuration ───────────────────────────────────────────────────────────
DEFAULT_NSX_HOST = 'nsx.example.local'
DEFAULT_USERNAME = 'audit'
DEFAULT_JSON_OUTPUT = 'dfw_objects.json'

# ─── Category order per NSX DFW processing ───
CATEGORY_ORDER = [
    "Ethernet",
    "Emergency",
    "Infrastructure",
    "Environment",
    "Application",
]


# ─── Helpers ───

def _esc(text):
    return html_mod.escape(str(text))


def extract_name_from_path(path):
    if not path or path == "ANY":
        return "ANY"
    parts = path.split("/")
    return parts[-1] if parts else path


def parse_timestamp(ts):
    if not ts:
        return ""
    try:
        ts = int(ts)
        return datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M")
    except:
        return str(ts)


def safe_int(val, default=0):
    try:
        return int(val)
    except:
        return default


# ─── NSX API fetch ───


def _get_inner_object(child):
    resource_type = child.get("resource_type", "")
    if resource_type.startswith("Child"):
        inner_key = resource_type[len("Child"):]
        if inner_key in child:
            return inner_key, child[inner_key]
    for key, value in child.items():
        if isinstance(value, dict) and "_system_owned" in value:
            return key, value
    return None, None


def fetch_nsx_objects(nsx_host=None, username=None, password=None, output_file=None):
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        print("ERROR: 'requests' module is required for fetch mode.")
        print("  Install it with: pip install requests")
        sys.exit(1)

    if nsx_host is None:
        nsx_host = input(f"NSX Manager hostname [{DEFAULT_NSX_HOST}]: ").strip() or DEFAULT_NSX_HOST
    if username is None:
        username = input(f"Username [{DEFAULT_USERNAME}]: ").strip() or DEFAULT_USERNAME
    if password is None:
        password = getpass.getpass(f"Password for {username}@{nsx_host}: ")
    if output_file is None:
        output_file = DEFAULT_JSON_OUTPUT

    nsx_mgr = f"https://{nsx_host}"
    session = requests.Session()
    session.verify = False
    session.auth = (username, password)

    print(f"Connecting to {nsx_mgr} ...")

    print("  Fetching services ...")
    resp = session.get(nsx_mgr + '/policy/api/v1/infra?filter=Type-Service')
    if resp.status_code != 200:
        print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
        sys.exit(1)
    services_json = resp.json()
    print(f"    -> {len(services_json.get('children', []))} children received")
    user_defined_services = []
    for child in services_json.get("children", []):
        inner_key, inner_obj = _get_inner_object(child)
        if inner_obj is None:
            continue
        if inner_obj.get("_system_owned") == False:
            inner_obj.pop("children", None)
            user_defined_services.append(child)

    print("  Fetching profiles ...")
    resp = session.get(nsx_mgr + '/policy/api/v1/infra?filter=Type-PolicyContextProfile')
    if resp.status_code != 200:
        print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
        sys.exit(1)
    profiles_json = resp.json()
    print(f"    -> {len(profiles_json.get('children', []))} children received")
    user_defined_profiles = []
    for child in profiles_json.get("children", []):
        inner_key, inner_obj = _get_inner_object(child)
        if inner_obj is None:
            continue
        if inner_obj.get("_system_owned") == False:
            user_defined_profiles.append(child)

    print("  Fetching DFW configuration ...")
    resp = session.get(nsx_mgr + '/policy/api/v1/infra?filter=Type-Domain|Group|SecurityPolicy|Rule')
    if resp.status_code != 200:
        print(f"  ERROR: HTTP {resp.status_code} - {resp.text[:200]}")
        sys.exit(1)
    dfw_json = resp.json()
    print(f"    -> {len(dfw_json.get('children', []))} children received")
    dfw_json["children"] = dfw_json["children"] + user_defined_services + user_defined_profiles

    # Fetch VM inventory (paginated)
    print("  Fetching virtual machines inventory ...")
    vm_results = []
    vm_cursor = None
    while True:
        vm_url = nsx_mgr + '/api/v1/fabric/virtual-machines?page_size=500'
        if vm_cursor:
            vm_url += f'&cursor={vm_cursor}'
        resp = session.get(vm_url)
        if resp.status_code != 200:
            print(f"    WARNING: VM inventory fetch failed (HTTP {resp.status_code}), skipping")
            break
        vm_data = resp.json()
        vm_results.extend(vm_data.get('results', []))
        vm_cursor = vm_data.get('cursor')
        if not vm_cursor:
            break
    print(f"    -> {len(vm_results)} VMs")

    # Store VM inventory alongside infra data
    export_data = {
        "infra": dfw_json,
        "virtual_machines": vm_results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4)

    print(f"  Export complete: {len(user_defined_services)} services, "
          f"{len(user_defined_profiles)} profiles, "
          f"{len(vm_results)} VMs, "
          f"{len(dfw_json['children'])} total children")
    print(f"  Written to: {output_file}")
    return output_file


# ─── JSON parsing ───

def parse_json(filepath):
    """Parse the NSX JSON export into policies, rules, groups, services, profiles."""
    print(f"Loading JSON: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Support both formats: new wrapper {"infra":..., "virtual_machines":...}
    # and legacy direct infra export {"children": [...]}
    if "infra" in raw:
        data = raw["infra"]
        vm_list = raw.get("virtual_machines", [])
    else:
        data = raw
        vm_list = []

    # Build VM database: external_id -> {display_name, tags, power_state}
    vm_db = {}
    for vm in vm_list:
        eid = vm.get("external_id", "")
        if eid:
            vm_db[eid] = {
                "display_name": vm.get("display_name", ""),
                "tags": vm.get("tags", []),
                "power_state": vm.get("power_state", ""),
                "host_id": vm.get("host_id", ""),
            }

    policies = []      # flat list of policy dicts (normalized)
    rules_by_policy = defaultdict(list)  # policy_path -> [rule_dicts]
    groups = {}        # path -> group info
    services = {}      # path -> service info
    profiles = {}      # path -> profile info

    for child in data.get("children", []):
        for ctype, obj in child.items():
            if ctype == "Service":
                _parse_service(obj, services)
            elif ctype == "PolicyContextProfile":
                p_path = obj.get("path", "")
                profiles[p_path] = {
                    "id": obj.get("id", ""),
                    "display_name": obj.get("display_name", ""),
                    "path": p_path,
                }
            elif ctype == "Domain":
                _parse_domain(obj, policies, rules_by_policy, groups)

    # Build policy tree by category
    policy_map = {}
    cat_policies = defaultdict(list)
    for p in policies:
        path = p["path"]
        policy_map[path] = p
        cat = p.get("category", "Application")
        cat_policies[cat].append(p)

    for cat in cat_policies:
        cat_policies[cat].sort(key=lambda p: safe_int(p.get("sequence_number", 0)))

    for path in rules_by_policy:
        rules_by_policy[path].sort(key=lambda r: safe_int(r.get("sequence_number", 0)))

    ordered = OrderedDict()
    for cat in CATEGORY_ORDER:
        if cat in cat_policies:
            ordered[cat] = cat_policies[cat]

    total_rules = sum(len(v) for v in rules_by_policy.values())
    print(f"  Found {len(policies)} policies, {total_rules} rules")
    if vm_db:
        print(f"  {len(groups)} groups, {len(services)} services, {len(profiles)} profiles, {len(vm_db)} VMs")
    else:
        print(f"  {len(groups)} groups, {len(services)} services, {len(profiles)} profiles")
    print(f"  Categories: {', '.join(ordered.keys())}")

    # Resolve nested service references
    for svc in services.values():
        for entry in svc["entries"]:
            if entry.get("type") == "nested_svc":
                ref_path = entry.get("nested_service_path", "")
                if ref_path in services:
                    entry["resolved_entries"] = services[ref_path]["entries"]

    return ordered, rules_by_policy, policy_map, groups, services, profiles, vm_db


def _parse_domain(domain_obj, policies, rules_by_policy, groups):
    domain_id = domain_obj.get("id", "")
    for dc in domain_obj.get("children", []):
        if "Group" in dc:
            g = dc["Group"]
            g_path = g.get("path", "")
            groups[g_path] = {
                "id": g.get("id", ""),
                "display_name": g.get("display_name", ""),
                "path": g_path,
                "description": g.get("description", ""),
                "domain": domain_id,
                "members": _extract_group_members(g),
                "tags": g.get("tags", []),
            }
        elif "SecurityPolicy" in dc:
            sp = dc["SecurityPolicy"]
            sp_path = sp.get("path", "")
            policies.append({
                "path": sp_path,
                "display_name": sp.get("display_name", ""),
                "category": sp.get("category", "Application"),
                "sequence_number": sp.get("sequence_number", 0),
                "stateful": sp.get("stateful", False),
                "tcp_strict": sp.get("tcp_strict", False),
                "locked": sp.get("locked", False),
                "is_default": sp.get("is_default", False),
                "scope": sp.get("scope", ["ANY"]),
                "_create_user": sp.get("_create_user", ""),
                "_create_time": sp.get("_create_time", ""),
                "_last_modified_user": sp.get("_last_modified_user", ""),
                "_last_modified_time": sp.get("_last_modified_time", ""),
            })
            for rc in sp.get("children", []):
                if "Rule" in rc:
                    r = rc["Rule"]
                    rules_by_policy[sp_path].append({
                        "display_name": r.get("display_name", ""),
                        "action": r.get("action", ""),
                        "sequence_number": r.get("sequence_number", 0),
                        "source_groups": r.get("source_groups", ["ANY"]),
                        "destination_groups": r.get("destination_groups", ["ANY"]),
                        "services": r.get("services", ["ANY"]),
                        "direction": r.get("direction", "IN_OUT"),
                        "logged": r.get("logged", False),
                        "disabled": r.get("disabled", False),
                        "ip_protocol": r.get("ip_protocol", "IPV4_IPV6"),
                        "scope": r.get("scope", []),
                        "notes": r.get("notes", ""),
                        "tag": r.get("tag", ""),
                        "log_label": r.get("log_label", ""),
                        "profiles": r.get("profiles", ["ANY"]),
                    })


def _parse_service(obj, services):
    svc_path = obj.get("path", "")
    entries = []
    for se in obj.get("service_entries", []):
        rt = se.get("resource_type", "")
        if rt == "L4PortSetServiceEntry":
            entries.append({
                "type": "L4",
                "protocol": se.get("l4_protocol", ""),
                "dst_ports": se.get("destination_ports", []),
                "src_ports": se.get("source_ports", []),
            })
        elif rt == "ICMPTypeServiceEntry":
            entries.append({
                "type": "ICMP",
                "protocol": se.get("protocol", "ICMPv4"),
                "icmp_type": se.get("icmp_type"),
                "icmp_code": se.get("icmp_code"),
            })
        elif rt == "IGMPTypeServiceEntry":
            entries.append({"type": "IGMP"})
        elif rt == "ALGTypeServiceEntry":
            entries.append({
                "type": "ALG",
                "alg": se.get("alg", ""),
                "dst_ports": se.get("destination_ports", []),
            })
        elif rt == "NestedServiceServiceEntry":
            entries.append({
                "type": "nested_svc",
                "display_name": se.get("display_name", ""),
                "nested_service_path": se.get("nested_service_path", ""),
            })
        else:
            entries.append({"type": rt})

    for sc in obj.get("children", []):
        if "ServiceEntry" in sc:
            se = sc["ServiceEntry"]
            if se.get("resource_type") == "L4PortSetServiceEntry":
                entries.append({
                    "type": "L4",
                    "protocol": se.get("l4_protocol", ""),
                    "dst_ports": se.get("destination_ports", []),
                    "src_ports": se.get("source_ports", []),
                })

    services[svc_path] = {
        "id": obj.get("id", ""),
        "display_name": obj.get("display_name", ""),
        "path": svc_path,
        "entries": entries,
    }


def _extract_group_members(group_obj):
    members = []
    for expr in group_obj.get("expression", []):
        rt = expr.get("resource_type", "")
        if rt == "IPAddressExpression":
            members.append({"type": "ip", "addresses": expr.get("ip_addresses", [])})
        elif rt == "Condition":
            members.append({
                "type": "condition",
                "member_type": expr.get("member_type", ""),
                "key": expr.get("key", ""),
                "operator": expr.get("operator", ""),
                "value": expr.get("value", ""),
            })
        elif rt == "PathExpression":
            members.append({"type": "path", "paths": expr.get("paths", [])})
        elif rt == "ExternalIDExpression":
            eids = expr.get("external_ids", [])
            members.append({
                "type": "external_id",
                "member_type": expr.get("member_type", ""),
                "external_ids": eids,
                "count": len(eids),
            })
        elif rt == "ConjunctionOperator":
            members.append({"type": "conjunction", "operator": expr.get("conjunction_operator", "OR")})
        elif rt == "NestedExpression":
            nested_items = []
            for ne in expr.get("expressions", []):
                nrt = ne.get("resource_type", "")
                if nrt == "Condition":
                    nested_items.append({
                        "type": "condition",
                        "member_type": ne.get("member_type", ""),
                        "key": ne.get("key", ""),
                        "operator": ne.get("operator", ""),
                        "value": ne.get("value", ""),
                    })
                elif nrt == "ConjunctionOperator":
                    nested_items.append({"type": "conjunction", "operator": ne.get("conjunction_operator", "OR")})
            members.append({"type": "nested", "expressions": nested_items})
    return members


# ─── Formatting helpers ───

def get_action_class(action):
    action = action.upper()
    if action == "ALLOW":
        return "action-allow"
    elif action == "DROP":
        return "action-drop"
    elif action == "REJECT":
        return "action-reject"
    return "action-other"


def render_group_members_html(members, vm_db=None):
    if vm_db is None:
        vm_db = {}
    if not members:
        return '<span class="detail-empty">No members defined</span>'
    parts = []
    for m in members:
        if m["type"] == "ip":
            addrs = m["addresses"]
            if len(addrs) <= 6:
                parts.append(", ".join(_esc(a) for a in addrs))
            else:
                shown = ", ".join(_esc(a) for a in addrs[:5])
                parts.append(f'{shown} <span class="more-count">+{len(addrs)-5}</span>')
        elif m["type"] == "condition":
            parts.append(f'<span class="cond-badge">{_esc(m["member_type"])} {_esc(m["key"])} {_esc(m["operator"])} {_esc(m["value"])}</span>')
        elif m["type"] == "path":
            for p in m["paths"][:4]:
                seg = p.split("/")[-1]
                parts.append(f'<span class="path-ref">{_esc(seg)}</span>')
            if len(m["paths"]) > 4:
                parts.append(f'<span class="more-count">+{len(m["paths"])-4}</span>')
        elif m["type"] == "external_id":
            eids = m.get("external_ids", [])
            if eids and vm_db:
                vm_names = []
                for eid in eids[:5]:
                    if eid in vm_db:
                        vm_names.append(f'<a href="#vm-{_esc(eid)}" class="vm-link" title="{_esc(eid)}">{_esc(vm_db[eid]["display_name"])}</a>')
                    else:
                        vm_names.append(f'<span class="vm-name" title="{_esc(eid)}">{_esc(eid[:13])}\u2026</span>')
                shown = ", ".join(vm_names)
                if len(eids) > 5:
                    shown += f' <span class="more-count">+{len(eids)-5}</span>'
                parts.append(shown)
            else:
                parts.append(f'{_esc(m["member_type"])} &times;{m["count"]}')
        elif m["type"] == "conjunction":
            parts.append(f'<span class="conj-op">{_esc(m["operator"])}</span>')
        elif m["type"] == "nested":
            nested_exprs = m.get("expressions", [])
            if nested_exprs:
                inner_parts = []
                for ne in nested_exprs:
                    if ne["type"] == "condition":
                        inner_parts.append(f'<span class="cond-badge">{_esc(ne["member_type"])} {_esc(ne["key"])} {_esc(ne["operator"])} {_esc(ne["value"])}</span>')
                    elif ne["type"] == "conjunction":
                        inner_parts.append(f'<span class="conj-op">{_esc(ne["operator"])}</span>')
                parts.append("[" + " ".join(inner_parts) + "]")
            else:
                parts.append('<span class="cond-badge">Nested</span>')
    return " ".join(parts)


def format_groups(group_paths, groups_db, vm_db=None):
    """Format list of group paths into HTML."""
    if not group_paths or group_paths == ["ANY"]:
        return '<span class="any-badge">ANY</span>'
    parts = []
    for path in group_paths:
        if path == "ANY":
            parts.append('<span class="any-badge">ANY</span>')
            continue
        name = extract_name_from_path(path)
        if path in groups_db:
            g = groups_db[path]
            display = g.get("display_name", name)
            detail = render_group_members_html(g["members"], vm_db=vm_db)
            parts.append(
                f'<span class="group-enriched" data-group-path="{_esc(path)}">'
                f'<a href="#grp-{_esc(g["id"])}" class="group-link">{_esc(display)}</a>'
                f'<span class="group-detail">{detail}</span>'
                f'</span>'
            )
        else:
            parts.append(f'<span class="group-name">{_esc(name)}</span>')
    return " ".join(parts)


def format_services(svc_paths, services_db):
    """Format list of service paths into HTML."""
    if not svc_paths or svc_paths == ["ANY"]:
        return '<span class="any-badge">ANY</span>'
    parts = []
    for path in svc_paths:
        if path == "ANY":
            parts.append('<span class="any-badge">ANY</span>')
            continue
        seg = path.split("/")[-1] if "/" in path else path
        if path in services_db:
            svc = services_db[path]
            port_str = _format_service_entries_compact(svc["entries"])
            display = svc.get("display_name", seg)
            svc_id = svc.get("id", seg)
            parts.append(
                f'<span class="svc-enriched" title="{_esc(port_str)}">'
                f'<a href="#svc-{_esc(svc_id)}" class="svc-link">{_esc(display)}</a>'
                f'<span class="svc-ports">{_esc(port_str)}</span>'
                f'</span>'
            )
        else:
            parts.append(f'<span class="svc-name">{_esc(seg)}</span>')
    return " ".join(parts)


def _format_service_entries_compact(entries):
    parts = []
    for e in entries:
        if e["type"] == "L4":
            proto = e.get("protocol", "")
            ports = e.get("dst_ports", [])
            if ports:
                parts.append(f'{proto}/{",".join(ports)}')
            else:
                parts.append(proto)
        elif e["type"] == "ICMP":
            p = e.get("protocol", "ICMP")
            t = e.get("icmp_type")
            parts.append(f'{p}' + (f' type={t}' if t else ''))
        elif e["type"] == "ALG":
            parts.append(f'ALG:{e.get("alg","")}')
        elif e["type"] == "IGMP":
            parts.append("IGMP")
        elif e["type"] == "nested_svc":
            name = e.get("display_name", "")
            resolved = e.get("resolved_entries")
            if resolved:
                parts.append(f'{name}({_format_service_entries_compact(resolved)})')
            else:
                parts.append(name)
        else:
            parts.append(e["type"])
    return ", ".join(parts) if parts else ""


# ─── HTML generation ───

def _build_vm_section(vm_db, groups_db, is_filtered=False, total_vms=0):
    """Build HTML for VM inventory section."""
    if not vm_db:
        return ""
    tagged_vms = {eid: vm for eid, vm in vm_db.items() if vm.get("tags")}
    vm_to_groups = defaultdict(list)
    for g_path, g in groups_db.items():
        for m in g.get("members", []):
            if m.get("type") == "external_id":
                for eid in m.get("external_ids", []):
                    vm_to_groups[eid].append(g)
    lines = []
    lines.append('<div class="category-section" id="vm-inventory">')
    lines.append('  <div class="category-header" style="--cat-color: #93c5fd">')
    lines.append('    <span class="cat-dot" style="background: #93c5fd"></span>')
    lines.append(f'    <h2>Virtual Machines</h2>')
    if is_filtered:
        lines.append(f'    <span class="cat-count">{len(vm_db)} VMs (filtered from {total_vms} total)</span>')
    else:
        lines.append(f'    <span class="cat-count">{len(vm_db)} VMs ({len(tagged_vms)} tagged)</span>')
    lines.append('  </div>')
    lines.append('  <div class="filter-bar">')
    lines.append('    <input type="text" id="vmSearchInput" placeholder="Filter VMs..." oninput="filterVMs()" />')
    lines.append('  </div>')
    lines.append('  <div class="rules-table-wrap">')
    lines.append('  <table class="rules-table" id="vmTable">')
    lines.append('    <thead><tr><th>VM Name</th><th>Power</th><th>Tags</th><th>Groups</th></tr></thead>')
    lines.append('    <tbody>')
    for eid in sorted(vm_db.keys(), key=lambda e: vm_db[e]["display_name"].lower()):
        vm = vm_db[eid]
        tags = vm.get("tags", [])
        power = vm.get("power_state", "")
        power_cls = "action-allow" if power == "VM_RUNNING" else "action-drop" if power == "VM_STOPPED" else ""
        power_short = power.replace("VM_", "").lower() if power else "\u2014"
        if tags:
            tag_parts = []
            for t in tags:
                scope = t.get("scope", "")
                tag_val = t.get("tag", "")
                display = f'{scope}|{tag_val}' if scope else tag_val
                tag_parts.append(f'<span class="cond-badge" title="{_esc(display)}">{_esc(display)}</span>')
            tag_html = " ".join(tag_parts)
        else:
            tag_html = '<span class="detail-empty">\u2014</span>'
        grps = vm_to_groups.get(eid, [])
        if grps:
            grp_parts = []
            for g in grps[:5]:
                grp_parts.append(f'<a href="#grp-{_esc(g["id"])}" class="group-link">{_esc(g["display_name"])}</a>')
            grp_html = ", ".join(grp_parts)
            if len(grps) > 5:
                grp_html += f' <span class="more-count">+{len(grps)-5}</span>'
        else:
            grp_html = '<span class="detail-empty">\u2014</span>'
        unused_cls = "" if tags or grps else "group-unused"
        lines.append(f'    <tr class="{unused_cls}" id="vm-{_esc(eid)}">')
        lines.append(f'      <td class="col-name"><a href="#vm-{_esc(eid)}" class="vm-link" title="{_esc(eid)}">{_esc(vm["display_name"])}</a></td>')
        lines.append(f'      <td><span class="{power_cls}">{_esc(power_short)}</span></td>')
        lines.append(f'      <td>{tag_html}</td>')
        lines.append(f'      <td>{grp_html}</td>')
        lines.append(f'    </tr>')
    lines.append('    </tbody></table></div></div>')
    return "\n".join(lines) + "\n"


def generate_html(ordered_categories, rules_by_policy, policy_map, output_path,
                  groups_db, services_db, profiles_db, vm_db=None, filter_text=None, filter_tag=None):

    total_policies = sum(len(v) for v in ordered_categories.values())
    total_rules = sum(len(v) for v in rules_by_policy.values())
    total_allow = sum(1 for rlist in rules_by_policy.values() for r in rlist if r.get("action", "").upper() == "ALLOW")
    total_drop = sum(1 for rlist in rules_by_policy.values() for r in rlist if r.get("action", "").upper() == "DROP")
    total_reject = sum(1 for rlist in rules_by_policy.values() for r in rlist if r.get("action", "").upper() == "REJECT")
    disabled_rules = sum(1 for rlist in rules_by_policy.values() for r in rlist if r.get("disabled") == True)
    user_policies = sum(1 for p in sum(ordered_categories.values(), [])
                        if not p.get("is_default")
                        and "wcp-cluster-user" not in p.get("_create_user", ""))

    category_colors = {
        "Ethernet": "#6366f1", "Emergency": "#ef4444", "Infrastructure": "#f59e0b",
        "Environment": "#10b981", "Application": "#3b82f6",
    }

    # Collect referenced groups/services
    referenced_groups = set()
    referenced_services = set()
    for rlist in rules_by_policy.values():
        for r in rlist:
            for path in r.get("source_groups", []):
                if path != "ANY":
                    referenced_groups.add(path)
            for path in r.get("destination_groups", []):
                if path != "ANY":
                    referenced_groups.add(path)
            for path in r.get("scope", []):
                if path != "ANY":
                    referenced_groups.add(path)
            for path in r.get("services", []):
                if path != "ANY":
                    referenced_services.add(path)
    # Also from policy scope
    for p in sum(ordered_categories.values(), []):
        for path in p.get("scope", []):
            if path != "ANY":
                referenced_groups.add(path)

    # Resolve nested references for complete dependency graph
    # Groups: follow path members to include nested groups
    def _resolve_nested_groups(seeds, gdb):
        resolved = set(seeds)
        queue = list(seeds)
        while queue:
            gpath = queue.pop()
            g = gdb.get(gpath)
            if not g:
                continue
            for m in g.get("members", []):
                if m.get("type") == "path":
                    for p in m.get("paths", []):
                        if p not in resolved and p in gdb:
                            resolved.add(p)
                            queue.append(p)
        return resolved

    # Services: follow nested_svc entries
    def _resolve_nested_services(seeds, sdb):
        resolved = set(seeds)
        queue = list(seeds)
        while queue:
            spath = queue.pop()
            svc = sdb.get(spath)
            if not svc:
                continue
            for entry in svc.get("entries", []):
                if entry.get("type") == "nested_svc":
                    npath = entry.get("nested_service_path", "")
                    if npath and npath not in resolved and npath in sdb:
                        resolved.add(npath)
                        queue.append(npath)
        return resolved

    referenced_groups = _resolve_nested_groups(referenced_groups, groups_db)
    referenced_services = _resolve_nested_services(referenced_services, services_db)

    # Collect referenced VMs (from groups that are in the filtered set)
    referenced_vms = set()
    if filter_text and vm_db:
        for gpath in referenced_groups:
            g = groups_db.get(gpath)
            if not g:
                continue
            for m in g.get("members", []):
                if m.get("type") == "external_id":
                    referenced_vms.update(m.get("external_ids", []))
            # Also evaluate conditions to find dynamically matching VMs
            effective = _get_group_effective_vm_eids(g, vm_db)
            referenced_vms.update(effective)

    # ─── Build sidebar + content ───
    nav_html = ""
    content_html = ""
    policy_idx = 0

    for cat, cat_policies in ordered_categories.items():
        color = category_colors.get(cat, "#8b5cf6")
        nav_html += f'<div class="nav-category" style="--cat-color: {color}">\n'
        nav_html += f'  <div class="nav-cat-label">{cat}</div>\n'

        content_html += f'<div class="category-section" id="cat-{cat}">\n'
        content_html += f'  <div class="category-header" style="--cat-color: {color}">\n'
        content_html += f'    <span class="cat-dot" style="background: {color}"></span>\n'
        content_html += f'    <h2>{cat}</h2>\n'
        content_html += f'    <span class="cat-count">{len(cat_policies)} policies</span>\n'
        content_html += f'  </div>\n'

        for p in cat_policies:
            path = p["path"]
            display_name = p["display_name"]
            policy_id = f"policy-{policy_idx}"
            is_wcp = "wcp-cluster-user" in p.get("_create_user", "")
            policy_rules = rules_by_policy.get(path, [])
            rule_count = len(policy_rules)
            short_name = extract_name_from_path(display_name)

            nav_html += f'  <a class="nav-policy" href="#{policy_id}" title="{_esc(display_name)}">'
            nav_html += f'<span>{_esc(short_name)}</span>'
            nav_html += f'<span class="nav-rule-count">{rule_count}</span></a>\n'

            card_cls = "policy-card"
            if is_wcp:
                card_cls += " wcp-policy"
            if p.get("is_default"):
                card_cls += " default-policy"

            content_html += f'<div class="{card_cls}" id="{policy_id}">\n'
            content_html += f'  <div class="policy-header">\n'
            content_html += f'    <div class="policy-title-row">\n'
            content_html += f'      <h3>{_esc(display_name)}</h3>\n'
            content_html += f'      <div class="policy-badges">\n'
            if p.get("stateful"):
                content_html += '        <span class="badge badge-stateful">Stateful</span>\n'
            if p.get("tcp_strict"):
                content_html += '        <span class="badge badge-strict">TCP Strict</span>\n'
            if p.get("locked"):
                content_html += '        <span class="badge badge-locked">Locked</span>\n'
            if p.get("is_default"):
                content_html += '        <span class="badge badge-default">Default</span>\n'
            if is_wcp:
                content_html += '        <span class="badge badge-wcp">Kubernetes</span>\n'
            content_html += '      </div>\n'
            content_html += '    </div>\n'

            content_html += '    <div class="policy-meta">\n'
            created_by = p.get("_create_user", "")
            if created_by:
                content_html += f'      <span class="meta-item"><strong>Created by:</strong> {_esc(created_by)}</span>\n'
            ct = parse_timestamp(p.get("_create_time"))
            if ct:
                content_html += f'      <span class="meta-item"><strong>Created:</strong> {ct}</span>\n'
            mt = parse_timestamp(p.get("_last_modified_time"))
            if mt:
                content_html += f'      <span class="meta-item"><strong>Modified:</strong> {mt}</span>\n'
            scope = p.get("scope", ["ANY"])
            if scope and scope != ["ANY"]:
                content_html += f'      <span class="meta-item"><strong>Scope:</strong> {format_groups(scope, groups_db)}</span>\n'
            content_html += '    </div>\n'
            content_html += '  </div>\n'

            if policy_rules:
                content_html += '  <div class="rules-table-wrap">\n'
                content_html += '  <table class="rules-table">\n'
                content_html += '    <thead><tr>\n'
                content_html += '      <th>Seq</th><th>Name</th><th>Action</th><th>Source</th><th>Destination</th><th>Services</th><th>Dir</th><th>Flags</th><th>Log Prefix</th>\n'
                content_html += '    </tr></thead>\n'
                content_html += '    <tbody>\n'

                for r in policy_rules:
                    action = r.get("action", "")
                    r_name = r.get("display_name", "")
                    seq = r.get("sequence_number", "")
                    disabled = r.get("disabled", False)
                    logged = r.get("logged", False)
                    ip_proto = r.get("ip_protocol", "IPV4_IPV6")

                    action_cls = get_action_class(action)
                    row_cls = "rule-disabled" if disabled else ""

                    flags = []
                    if disabled:
                        flags.append('<span class="flag flag-disabled">Disabled</span>')
                    if logged:
                        flags.append('<span class="flag flag-logged">Log</span>')
                    if ip_proto and ip_proto != "IPV4_IPV6":
                        flags.append(f'<span class="flag flag-proto">{_esc(ip_proto)}</span>')

                    content_html += f'    <tr class="{row_cls}">\n'
                    content_html += f'      <td class="col-seq">{_esc(str(seq))}</td>\n'
                    content_html += f'      <td class="col-name" title="{_esc(r_name)}">{_esc(r_name)}</td>\n'
                    content_html += f'      <td class="col-action"><span class="action-badge {action_cls}">{_esc(action)}</span></td>\n'
                    content_html += f'      <td class="col-src">{format_groups(r.get("source_groups", ["ANY"]), groups_db, vm_db)}</td>\n'
                    content_html += f'      <td class="col-dst">{format_groups(r.get("destination_groups", ["ANY"]), groups_db, vm_db)}</td>\n'
                    content_html += f'      <td class="col-svc">{format_services(r.get("services", ["ANY"]), services_db)}</td>\n'
                    content_html += f'      <td class="col-dir">{_esc(r.get("direction", ""))}</td>\n'
                    content_html += f'      <td class="col-flags">{"".join(flags)}</td>\n'
                    log_prefix = r.get("tag", "") or r.get("log_label", "")
                    if log_prefix:
                        content_html += f'      <td class="col-logprefix"><span class="log-prefix">{_esc(log_prefix)}</span></td>\n'
                    else:
                        content_html += f'      <td class="col-logprefix"><span class="detail-empty">\u2014</span></td>\n'
                    content_html += f'    </tr>\n'

                content_html += '    </tbody></table></div>\n'
            else:
                content_html += '  <div class="no-rules">No rules</div>\n'

            content_html += '</div>\n'
            policy_idx += 1

        nav_html += '</div>\n'
        content_html += '</div>\n'

    # ─── Groups Inventory ───
    groups_section = ""
    groups_nav = ""
    default_groups = {p: g for p, g in groups_db.items() if g.get("domain") == "default"}
    ref_groups = {p: g for p, g in default_groups.items() if p in referenced_groups}

    # When filter is active, only show referenced groups (with nested deps)
    if filter_text:
        display_groups = ref_groups
    else:
        display_groups = default_groups

    # Pre-calculate display_services for nav counts
    ref_svc_count = len(referenced_services & set(services_db.keys()))
    if filter_text:
        display_services = {p: s for p, s in services_db.items() if p in referenced_services}
    else:
        display_services = services_db

    # Pre-calculate display_vm_db for nav counts
    if filter_text and vm_db and referenced_vms:
        display_vm_db = {eid: vm for eid, vm in vm_db.items() if eid in referenced_vms}
    else:
        display_vm_db = vm_db if vm_db else {}

    # When filter_tag is active, further restrict VMs to only those matching the tag
    if filter_tag and vm_db:
        tag_parts = [p.lower() for p in filter_tag.split(":")]
        display_vm_db = {eid: vm for eid, vm in display_vm_db.items()
                         if _vm_tag_matches(vm, tag_parts)}

    groups_nav += '<div class="nav-category" style="--cat-color: #a78bfa">\n'
    groups_nav += '  <div class="nav-cat-label">Inventory</div>\n'
    groups_nav += f'  <a class="nav-policy" href="#groups-inventory">Groups ({len(display_groups)})</a>\n'
    groups_nav += f'  <a class="nav-policy" href="#services-inventory">Services ({len(display_services)})</a>\n'
    if vm_db:
        if filter_text or filter_tag:
            groups_nav += f'  <a class="nav-policy" href="#vm-inventory">VMs ({len(display_vm_db)} filtered)</a>\n'
        else:
            tagged_vm_count = sum(1 for vm in vm_db.values() if vm.get("tags"))
            groups_nav += f'  <a class="nav-policy" href="#vm-inventory">VMs ({len(vm_db)}, {tagged_vm_count} tagged)</a>\n'
    groups_nav += '</div>\n'

    groups_section += '<div class="category-section" id="groups-inventory">\n'
    groups_section += '  <div class="category-header" style="--cat-color: #a78bfa">\n'
    groups_section += '    <span class="cat-dot" style="background: #a78bfa"></span>\n'
    groups_section += f'    <h2>Groups</h2>\n'
    if filter_text:
        groups_section += f'    <span class="cat-count">{len(display_groups)} groups (filtered from {len(default_groups)} total)</span>\n'
    else:
        groups_section += f'    <span class="cat-count">{len(default_groups)} groups ({len(ref_groups)} used in rules)</span>\n'
    groups_section += '  </div>\n'
    groups_section += '  <div class="filter-bar">\n'
    groups_section += '    <input type="text" id="groupSearchInput" placeholder="Filter groups..." oninput="filterGroups()" />\n'
    groups_section += '    <button class="filter-btn" id="btnShowUnused" onclick="toggleUnused(this)">Hide unused</button>\n'
    groups_section += '  </div>\n'
    groups_section += '  <div class="rules-table-wrap">\n'
    groups_section += '  <table class="rules-table groups-table" id="groupsTable">\n'
    groups_section += '    <thead><tr><th>Name</th><th>Type</th><th>Members</th><th>Rules</th></tr></thead>\n'
    groups_section += '    <tbody>\n'

    for g_path in sorted(display_groups.keys(), key=lambda p: display_groups[p]["display_name"].lower()):
        g = display_groups[g_path]
        is_used = g_path in referenced_groups
        used_cls = "" if is_used else "group-unused"
        members = g["members"]
        detail_html = render_group_members_html(members, vm_db=vm_db)

        mtypes = set()
        for m in members:
            if m["type"] == "ip": mtypes.add("IP")
            elif m["type"] == "condition": mtypes.add("Tag")
            elif m["type"] == "path": mtypes.add("Segment")
            elif m["type"] == "external_id": mtypes.add("VM")
        mtype_str = ", ".join(sorted(mtypes)) if mtypes else "\u2014"

        rule_ref_count = 0
        for rlist in rules_by_policy.values():
            for r in rlist:
                if g_path in r.get("source_groups", []) or g_path in r.get("destination_groups", []):
                    rule_ref_count += 1

        groups_section += f'    <tr class="{used_cls}" id="grp-{_esc(g["id"])}">\n'
        groups_section += f'      <td class="col-name">{_esc(g["display_name"])}</td>\n'
        groups_section += f'      <td>{_esc(mtype_str)}</td>\n'
        groups_section += f'      <td class="group-members-cell">{detail_html}</td>\n'
        groups_section += f'      <td class="col-seq">{rule_ref_count}</td>\n'
        groups_section += f'    </tr>\n'

    groups_section += '    </tbody></table></div></div>\n'

    # ─── Services Inventory ───
    services_section = ""
    services_section += '<div class="category-section" id="services-inventory">\n'
    services_section += '  <div class="category-header" style="--cat-color: #a78bfa">\n'
    services_section += '    <span class="cat-dot" style="background: #a78bfa"></span>\n'
    services_section += f'    <h2>Services</h2>\n'
    if filter_text:
        services_section += f'    <span class="cat-count">{len(display_services)} services (filtered from {len(services_db)} total)</span>\n'
    else:
        services_section += f'    <span class="cat-count">{len(services_db)} services ({ref_svc_count} used in rules)</span>\n'
    services_section += '  </div>\n'
    services_section += '  <div class="filter-bar">\n'
    services_section += '    <input type="text" id="svcSearchInput" placeholder="Filter services..." oninput="filterServices()" />\n'
    services_section += '  </div>\n'
    services_section += '  <div class="rules-table-wrap">\n'
    services_section += '  <table class="rules-table" id="servicesTable">\n'
    services_section += '    <thead><tr><th>Name</th><th>Protocol / Ports</th><th>Rules</th></tr></thead>\n'
    services_section += '    <tbody>\n'

    for s_path in sorted(display_services.keys(), key=lambda p: display_services[p]["display_name"].lower()):
        svc = display_services[s_path]
        port_str = _format_service_entries_compact(svc["entries"])
        is_used = s_path in referenced_services
        used_cls = "" if is_used else "group-unused"
        ref_count = sum(1 for rlist in rules_by_policy.values() for r in rlist if s_path in r.get("services", []))

        svc_id = _esc(svc["id"])
        svc_id = _esc(svc["id"])
        services_section += f'    <tr class="{used_cls}" id="svc-{svc_id}">\n'
        services_section += f'      <td class="col-name"><span class="svc-name">{_esc(svc["display_name"])}</span></td>\n'
        services_section += f'      <td><code>{_esc(port_str)}</code></td>\n'
        services_section += f'      <td class="col-seq">{ref_count}</td>\n'
        services_section += f'    </tr>\n'

    services_section += '    </tbody></table></div></div>\n'

    vm_section = _build_vm_section(display_vm_db, groups_db, is_filtered=bool(filter_text or filter_tag), total_vms=len(vm_db) if vm_db else 0)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NSX DFW \u2013 Firewall Rules Documentation</title>
<style>
:root {{
  --bg: #0f1117; --bg-card: #181b24; --bg-card-hover: #1e2230;
  --bg-table-head: #12141c; --bg-table-row: #181b24; --bg-table-alt: #1a1e28;
  --border: #2a2e3a; --border-light: #353a4a;
  --text: #e2e4ea; --text-dim: #8b90a0; --text-bright: #ffffff;
  --accent: #60a5fa; --green: #34d399; --red: #f87171; --amber: #fbbf24; --purple: #a78bfa;
  --nav-min: 220px;
  --nav-max: 480px;
}}
*,*::before,*::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{ font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; display: flex; min-height: 100vh; }}

.sidebar {{ min-width: var(--nav-min); max-width: var(--nav-max); width: max-content; background: #13151d; border-right: 1px solid var(--border); position: fixed; top:0;left:0;bottom:0; overflow-y: auto; z-index: 100; padding: 20px 0; }}
.sidebar::-webkit-scrollbar {{ width: 4px; }}
.sidebar::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}
.sidebar-title {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 13px; font-weight: 600; color: var(--accent); padding: 0 16px 16px; border-bottom: 1px solid var(--border); margin-bottom: 12px; letter-spacing: 1px; text-transform: uppercase; }}
.nav-category {{ margin-bottom: 8px; }}
.nav-cat-label {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: var(--cat-color, var(--text-dim)); padding: 8px 16px 4px; }}
.nav-policy {{ display: flex; align-items: center; justify-content: space-between; padding: 4px 16px 4px 24px; font-size: 12px; color: var(--text-dim); text-decoration: none; transition: all 0.15s;  }}
.nav-policy:hover {{ color: var(--text); background: rgba(255,255,255,0.03); }}
.nav-rule-count {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 8px; flex-shrink: 0; margin-left: 6px; }}

.main {{ margin-left: var(--nav-max); flex: 1; padding: 32px 40px 80px; max-width: 1440px; }}
.page-header {{ margin-bottom: 36px; }}
.page-header h1 {{ font-size: 28px; font-weight: 700; color: var(--text-bright); margin-bottom: 4px; }}
.page-header .subtitle {{ font-size: 13px; color: var(--text-dim); font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; }}

.stats-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 36px; }}
.stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; text-align: center; }}
.stat-value {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 28px; font-weight: 700; color: var(--text-bright); }}
.stat-value.green {{ color: var(--green); }}
.stat-value.red {{ color: var(--red); }}
.stat-value.amber {{ color: var(--amber); }}
.stat-value.purple {{ color: var(--purple); }}
.stat-value.blue {{ color: var(--accent); }}
.stat-label {{ font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

.category-section {{ margin-bottom: 40px; }}
.category-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }}
.cat-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
.category-header h2 {{ font-size: 18px; font-weight: 700; color: var(--text-bright); }}
.cat-count {{ font-size: 12px; color: var(--text-dim); font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; }}

.policy-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; transition: border-color 0.2s; }}
.policy-card:hover {{ border-color: var(--border-light); }}
.policy-card.wcp-policy {{ opacity: 0.7; }}
.policy-card.default-policy {{ border-left: 3px solid var(--text-dim); }}
.policy-header {{ padding: 16px 20px 12px; border-bottom: 1px solid var(--border); }}
.policy-title-row {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
.policy-title-row h3 {{ font-size: 15px; font-weight: 600; color: var(--text-bright); word-break: break-all; }}
.policy-badges {{ display: flex; gap: 4px; flex-shrink: 0; flex-wrap: wrap; }}
.badge {{ font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
.badge-stateful {{ background: rgba(52,211,153,0.12); color: var(--green); }}
.badge-strict {{ background: rgba(251,191,36,0.12); color: var(--amber); }}
.badge-locked {{ background: rgba(248,113,113,0.12); color: var(--red); }}
.badge-default {{ background: rgba(139,144,160,0.15); color: var(--text-dim); }}
.badge-wcp {{ background: rgba(96,165,250,0.12); color: var(--accent); }}
.policy-meta {{ display: flex; gap: 16px; margin-top: 8px; flex-wrap: wrap; }}
.meta-item {{ font-size: 11px; color: var(--text-dim); }}
.meta-item strong {{ color: var(--text); font-weight: 500; }}

.rules-table-wrap {{ overflow-x: auto; }}
.rules-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
.rules-table thead {{ background: var(--bg-table-head); }}
.rules-table th {{ padding: 8px 12px; text-align: left; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); border-bottom: 1px solid var(--border); white-space: nowrap; }}
.rules-table td {{ padding: 8px 12px; border-bottom: 1px solid rgba(42,46,58,0.5); vertical-align: top; }}
.rules-table tbody tr:nth-child(even) {{ background: var(--bg-table-alt); }}
.rules-table tbody tr:hover {{ background: var(--bg-card-hover); }}
.rules-table tbody tr.rule-disabled {{ opacity: 0.45; }}

.col-seq {{ width: 40px; text-align: center; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; color: var(--text-dim); }}
.col-name {{ min-width: 140px; max-width: 220px; font-weight: 500; color: var(--text-bright); word-break: break-word; }}
.col-action {{ width: 70px; text-align: center; }}
.col-src, .col-dst {{ min-width: 120px; max-width: 300px; word-break: break-word; }}
.col-svc {{ min-width: 100px; max-width: 280px; word-break: break-word; }}
.col-dir {{ width: 60px; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; color: var(--text-dim); }}
.col-flags {{ width: 100px; }}
.col-logprefix {{ min-width: 80px; max-width: 200px; word-break: break-word; }}
.log-prefix {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; color: var(--text-dim); background: rgba(139,144,160,0.08); padding: 1px 5px; border-radius: 3px; }}

.action-badge {{ display: inline-block; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }}
.action-allow {{ background: rgba(52,211,153,0.15); color: #34d399; }}
.action-drop {{ background: rgba(248,113,113,0.15); color: #f87171; }}
.action-reject {{ background: rgba(251,146,60,0.15); color: #fb923c; }}
.action-other {{ background: rgba(139,144,160,0.15); color: var(--text-dim); }}

.group-name {{ display: inline; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: var(--text); }}
.svc-name {{ display: inline; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: var(--purple); }}
.any-badge {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; color: var(--text-dim); background: rgba(139,144,160,0.1); padding: 1px 6px; border-radius: 3px; }}
.flag {{ display: inline-block; font-size: 9px; font-weight: 600; padding: 1px 5px; border-radius: 3px; margin-right: 3px; text-transform: uppercase; }}
.flag-disabled {{ background: rgba(248,113,113,0.12); color: var(--red); }}
.flag-logged {{ background: rgba(96,165,250,0.12); color: var(--accent); }}
.flag-proto {{ background: rgba(251,191,36,0.1); color: var(--amber); }}
.no-rules {{ padding: 20px; text-align: center; color: var(--text-dim); font-size: 13px; }}

.group-enriched {{ display: inline-block; margin: 2px 0; }}
.group-link {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: var(--accent); text-decoration: none; border-bottom: 1px dotted rgba(96,165,250,0.4); cursor: pointer; }}
.group-link:hover {{ color: var(--text-bright); border-bottom-color: var(--text-bright); }}
.svc-link {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: var(--purple); text-decoration: none; border-bottom: 1px dotted rgba(167,139,250,0.4); cursor: pointer; }}
.svc-link:hover {{ color: var(--text-bright); border-bottom-color: var(--text-bright); }}
.group-detail {{ display: block; font-size: 10px; color: var(--text-dim); font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; max-width: 300px; line-height: 1.6; margin-top: 1px; }}
.group-detail .more-count {{ color: var(--accent); font-size: 9px; }}
.group-detail .cond-badge {{ background: rgba(251,191,36,0.1); color: var(--amber); padding: 1px 4px; border-radius: 3px; font-size: 9px; }}
.group-detail .path-ref {{ color: var(--green); font-size: 10px; }}
.group-detail .conj-op {{ color: var(--text-dim); font-size: 9px; font-weight: 600; }}
.detail-empty {{ color: var(--text-dim); font-size: 10px; font-style: italic; }}
.vm-name {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: #93c5fd; }}
.vm-link {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; color: #93c5fd; text-decoration: none; border-bottom: 1px dotted rgba(147,197,253,0.4); cursor: pointer; }}
.vm-link:hover {{ color: var(--text-bright); border-bottom-color: var(--text-bright); }}

.svc-enriched {{ display: inline-block; margin: 2px 0; }}
.svc-ports {{ display: block; font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 10px; color: var(--green); line-height: 1.4; }}

.groups-table td {{ max-width: 400px; }}
.group-members-cell {{ font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace; font-size: 11px; line-height: 1.6; max-width: 500px; word-break: break-word; }}
tr.group-unused {{ opacity: 0.4; }}
tr.group-unused:hover {{ opacity: 0.8; }}

.filter-bar {{ display: flex; gap: 10px; margin-bottom: 24px; flex-wrap: wrap; align-items: center; }}
.filter-bar input {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 8px 14px; font-size: 13px; color: var(--text); font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; width: 300px; outline: none; transition: border-color 0.2s; }}
.filter-bar input:focus {{ border-color: var(--accent); }}
.filter-bar input::placeholder {{ color: var(--text-dim); }}
.filter-btn {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 8px 14px; font-size: 12px; color: var(--text-dim); cursor: pointer; font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; transition: all 0.15s; }}
.filter-btn:hover, .filter-btn.active {{ border-color: var(--accent); color: var(--accent); }}

@media (max-width: 900px) {{ .sidebar {{ display: none; }} .main {{ margin-left: 0; padding: 20px; }} }}
@media print {{ .sidebar {{ display: none; }} .main {{ margin-left: 0; }} .filter-bar {{ display: none; }} .policy-card {{ break-inside: avoid; }} }}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-title">NSX DFW{'  –  ' + _esc(filter_text) if filter_text else ''}</div>
  {nav_html}
  {groups_nav}
</nav>

<main class="main">
  <div class="page-header">
    <h1>NSX Distributed Firewall \u2013 Documentation</h1>
    <div class="subtitle">Generated: {now}</div>
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="stat-value blue">{total_policies}</div><div class="stat-label">Policies</div></div>
    <div class="stat-card"><div class="stat-value">{total_rules}</div><div class="stat-label">Total Rules</div></div>
    <div class="stat-card"><div class="stat-value green">{total_allow}</div><div class="stat-label">Allow</div></div>
    <div class="stat-card"><div class="stat-value red">{total_drop}</div><div class="stat-label">Drop</div></div>
    <div class="stat-card"><div class="stat-value amber">{total_reject}</div><div class="stat-label">Reject</div></div>
    <div class="stat-card"><div class="stat-value purple">{disabled_rules}</div><div class="stat-label">Disabled</div></div>
    <div class="stat-card"><div class="stat-value">{user_policies}</div><div class="stat-label">User policies</div></div>
    <div class="stat-card"><div class="stat-value purple">{len(display_groups)}</div><div class="stat-label">Groups</div></div>
    <div class="stat-card"><div class="stat-value purple">{len(display_services)}</div><div class="stat-label">Services</div></div>
    <div class="stat-card"><div class="stat-value blue">{len(display_vm_db)}</div><div class="stat-label">VMs</div></div>
  </div>

  <div class="filter-bar">
    <input type="text" id="searchInput" placeholder="Search rules, policies, groups..." oninput="filterContent()" />
    <button class="filter-btn" onclick="toggleWcp(this)">Hide Kubernetes</button>
    <button class="filter-btn" onclick="toggleDisabled(this)">Hide disabled</button>
  </div>

  {content_html}
  {groups_section}
  {services_section}
  {vm_section}
</main>

<script>
(function(){{
  var sb=document.querySelector('.sidebar');
  var mn=document.querySelector('.main');
  function adj(){{
    if(sb&&mn&&window.innerWidth>900){{mn.style.marginLeft=sb.offsetWidth+'px';}}
    else if(mn){{mn.style.marginLeft='0';}}
  }}
  adj();
  new ResizeObserver(adj).observe(sb);
  window.addEventListener('resize',adj);
}})();
let hideWcp=false, hideDisabled=false, hideUnused=false;
function filterContent() {{
  const q=document.getElementById('searchInput').value.toLowerCase();
  document.querySelectorAll('.policy-card').forEach(card=>{{
    const text=card.textContent.toLowerCase();
    const matchesSearch=!q||text.includes(q);
    const isWcp=card.classList.contains('wcp-policy');
    const show=matchesSearch&&!(hideWcp&&isWcp);
    card.style.display=show?'':'none';
    if(show&&hideDisabled) card.querySelectorAll('tr.rule-disabled').forEach(r=>r.style.display='none');
    else if(show) card.querySelectorAll('tr.rule-disabled').forEach(r=>r.style.display='');
  }});
}}
function toggleWcp(btn) {{ hideWcp=!hideWcp; btn.classList.toggle('active',hideWcp); filterContent(); }}
function toggleDisabled(btn) {{ hideDisabled=!hideDisabled; btn.classList.toggle('active',hideDisabled); filterContent(); }}
function filterGroups() {{
  const q=(document.getElementById('groupSearchInput')||{{}}).value||'';
  const ql=q.toLowerCase();
  const table=document.getElementById('groupsTable');
  if(!table)return;
  table.querySelectorAll('tbody tr').forEach(row=>{{
    const text=row.textContent.toLowerCase();
    const isUnused=row.classList.contains('group-unused');
    row.style.display=(!ql||text.includes(ql))&&!(hideUnused&&isUnused)?'':'none';
  }});
}}
function toggleUnused(btn) {{ hideUnused=!hideUnused; btn.classList.toggle('active',hideUnused); filterGroups(); }}
function filterVMs(){{
  var q=document.getElementById('vmSearchInput').value.toLowerCase();
  document.querySelectorAll('#vmTable tbody tr').forEach(function(tr){{
    tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';
  }});
}}
function filterServices() {{
  const q=(document.getElementById('svcSearchInput')||{{}}).value||'';
  const ql=q.toLowerCase();
  const table=document.getElementById('servicesTable');
  if(!table)return;
  table.querySelectorAll('tbody tr').forEach(row=>{{
    row.style.display=(!ql||row.textContent.toLowerCase().includes(ql))?'':'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"HTML documentation written to: {output_path}")


# ─── Main ───


# ─── Condition evaluation helpers ───

def _vm_matches_condition(vm, member_type, key, operator, value):
    """Evaluate a single NSX Condition against a VM from vm_db."""
    mt = member_type.lower()
    if mt != "virtualmachine":
        return False
    k = key.lower()
    op = operator.upper()
    val = value.lower()
    if k == "name":
        target = vm.get("display_name", "").lower()
    elif k == "tag":
        for t in vm.get("tags", []):
            ts = ((t.get("scope", "") or "") + "|" + (t.get("tag", "") or "")).lower()
            tv = (t.get("tag", "") or "").lower()
            if op == "EQUALS" and (ts == val or tv == val):
                return True
            elif op == "NOTEQUALS" and ts != val and tv != val:
                return True
            elif op == "CONTAINS" and val in ts:
                return True
            elif op == "STARTSWITH" and (ts.startswith(val) or tv.startswith(val)):
                return True
            elif op == "ENDSWITH" and (ts.endswith(val) or tv.endswith(val)):
                return True
        return False
    elif k == "computername":
        target = vm.get("display_name", "").lower()
    else:
        return False
    if op == "EQUALS":
        return target == val
    elif op == "NOTEQUALS":
        return target != val
    elif op == "CONTAINS":
        return val in target
    elif op == "STARTSWITH":
        return target.startswith(val)
    elif op == "ENDSWITH":
        return target.endswith(val)
    return False


def _get_group_effective_vm_eids(group, vm_db):
    """Evaluate group conditions against vm_db, return set of matching eids."""
    if not vm_db:
        return set()
    members = group.get("members", [])
    # Collect condition blocks with conjunction operators between them
    condition_blocks = []  # list of (kind, inner_op, conds)
    conjunctions = []      # conjunction ops BETWEEN blocks
    current_block = []
    for m in members:
        if m.get("type") == "condition":
            current_block.append(m)
        elif m.get("type") == "nested":
            nc = [ne for ne in m.get("expressions", []) if ne.get("type") == "condition"]
            nj = [ne for ne in m.get("expressions", []) if ne.get("type") == "conjunction"]
            if nc:
                if current_block:
                    condition_blocks.append(("simple", None, current_block))
                    current_block = []
                nop = nj[0].get("operator", "AND").upper() if nj else "AND"
                condition_blocks.append(("nested", nop, nc))
        elif m.get("type") == "conjunction":
            if current_block:
                condition_blocks.append(("simple", None, current_block))
                current_block = []
            conjunctions.append(m.get("operator", "OR").upper())
        elif m.get("type") == "external_id":
            return set(m.get("external_ids", []))
    if current_block:
        condition_blocks.append(("simple", None, current_block))
    if not condition_blocks:
        return set()
    result = None
    for i, (kind, op, conds) in enumerate(condition_blocks):
        block_eids = set()
        for eid, vm in vm_db.items():
            check = any if (kind == "nested" and op == "OR") else all
            if check(_vm_matches_condition(vm, c.get("member_type", ""), c.get("key", ""),
                     c.get("operator", ""), c.get("value", "")) for c in conds):
                block_eids.add(eid)
        if result is None:
            result = block_eids
        else:
            conj = conjunctions[i - 1] if i - 1 < len(conjunctions) else "AND"
            if conj == "OR":
                result = result | block_eids
            else:
                result = result & block_eids
    return result or set()


def _vm_tag_matches(vm, filter_parts):
    """Check if VM tags match all filter_tag parts (AND logic)."""
    tags = vm.get("tags", [])
    if not tags:
        return False
    tag_strings = []
    for t in tags:
        s = (t.get("scope", "") or "").lower()
        v = (t.get("tag", "") or "").lower()
        tag_strings.extend([s + "|" + v, s, v])
    for part in filter_parts:
        if not any(part in ts for ts in tag_strings):
            return False
    return True


def filter_policies(ordered_categories, rules_by_policy, policy_map, groups_db,
                    filter_text=None, filter_tag=None, vm_db=None):
    if vm_db is None:
        vm_db = {}
    ft = filter_text.lower() if filter_text else None
    tag_parts = [p.lower() for p in filter_tag.split(":")] if filter_tag else []
    _effective_cache = {}
    def _get_effective(path):
        if path not in _effective_cache:
            g = groups_db.get(path)
            _effective_cache[path] = _get_group_effective_vm_eids(g, vm_db) if g else set()
        return _effective_cache[path]
    filtered_ordered = OrderedDict()
    filtered_rules = {}
    filtered_pmap = {}
    def group_matches_text(path, text):
        if not path or path == "ANY":
            return False
        name = path.split("/")[-1].lower()
        if text in name:
            return True
        if path not in groups_db:
            return False
        g = groups_db[path]
        if text in g.get("display_name", "").lower():
            return True
        for m in g.get("members", []):
            if m.get("type") == "condition":
                if text in m.get("value", "").lower():
                    return True
            elif m.get("type") == "nested":
                for ne in m.get("expressions", []):
                    if ne.get("type") == "condition":
                        if text in ne.get("value", "").lower():
                            return True
            elif m.get("type") == "external_id":
                for eid in m.get("external_ids", []):
                    if eid in vm_db:
                        if text in vm_db[eid].get("display_name", "").lower():
                            return True
                        for t in vm_db[eid].get("tags", []):
                            tag_str = ((t.get("scope","") or "") + "|" + (t.get("tag","") or "")).lower()
                            if text in tag_str:
                                return True
        effective = _get_effective(path)
        for eid in effective:
            if eid in vm_db and text in vm_db[eid].get("display_name", "").lower():
                return True
        return False
    def group_matches_tag(path, parts):
        if not path or path == "ANY" or path not in groups_db:
            return False
        g = groups_db[path]
        for m in g.get("members", []):
            if m.get("type") == "condition" and m.get("key", "").lower() == "tag":
                val = m.get("value", "").lower()
                if all(p in val for p in parts):
                    return True
            elif m.get("type") == "nested":
                for ne in m.get("expressions", []):
                    if ne.get("type") == "condition" and ne.get("key", "").lower() == "tag":
                        val = ne.get("value", "").lower()
                        if all(p in val for p in parts):
                            return True
            elif m.get("type") == "external_id":
                for eid in m.get("external_ids", []):
                    if eid in vm_db and _vm_tag_matches(vm_db[eid], parts):
                        return True
        effective = _get_effective(path)
        for eid in effective:
            if eid in vm_db and _vm_tag_matches(vm_db[eid], parts):
                return True
        return False
    def group_path_matches(path):
        if not path or path == "ANY":
            return False
        text_ok = group_matches_text(path, ft) if ft else True
        tag_ok = group_matches_tag(path, tag_parts) if tag_parts else True
        if ft and tag_parts:
            return text_ok or tag_ok
        return text_ok and tag_ok
    for cat, policies in ordered_categories.items():
        matching = []
        for p in policies:
            path = p["path"]
            policy_rules = rules_by_policy.get(path, [])
            policy_name_hit = ft and ft in p.get("display_name", "").lower()
            if policy_name_hit and not tag_parts:
                matching.append(p)
                filtered_rules[path] = policy_rules
                filtered_pmap[path] = p
                continue
            matched_rules = []
            for r in policy_rules:
                hit = False
                if ft and ft in r.get("tag", "").lower():
                    hit = True
                if not hit:
                    for field in ("source_groups", "destination_groups", "scope"):
                        for gpath in r.get(field, []):
                            if group_path_matches(gpath):
                                hit = True
                                break
                        if hit:
                            break
                if not hit and policy_name_hit and tag_parts:
                    for field in ("source_groups", "destination_groups", "scope"):
                        for gpath in r.get(field, []):
                            if group_matches_tag(gpath, tag_parts):
                                hit = True
                                break
                        if hit:
                            break
                if hit:
                    matched_rules.append(r)
            if matched_rules:
                matching.append(p)
                filtered_rules[path] = matched_rules
                filtered_pmap[path] = p
        if matching:
            filtered_ordered[cat] = matching
    tp = sum(len(v) for v in filtered_ordered.values())
    tr = sum(len(v) for v in filtered_rules.values())
    parts_desc = []
    if filter_text:
        parts_desc.append(f"text=\'{filter_text}\'")
    if filter_tag:
        parts_desc.append(f"tag=\'{filter_tag}\'")
    print(f"  Filter {', '.join(parts_desc)}: {tp} policies, {tr} rules matched")
    return filtered_ordered, filtered_rules, filtered_pmap


def print_usage():
    print("""NSX DFW Documentation Generator

Usage:
  nsx_dfw_doc.py fetch [output.json] [output.html] [--filter TEXT] [--filter-tag TAG]
      Fetch DFW objects + VM inventory and generate HTML.

  nsx_dfw_doc.py <input.json> [output.html] [--filter TEXT] [--filter-tag TAG]
      Generate HTML from previously fetched JSON.

  --filter TEXT        Match policy names, group names, condition values,
                       effective VM names (STARTSWITH/ENDSWITH/etc.), rule tags.
  --filter-tag TAG     Match NSX tag scope/value (colon = AND logic):
                         --filter-tag Z00:Prod
  Both filters can be combined. Case-insensitive.

Examples:
  nsx_dfw_doc.py fetch
  nsx_dfw_doc.py dfw_objects.json
  nsx_dfw_doc.py dfw_objects.json --filter Z00
  nsx_dfw_doc.py dfw_objects.json --filter-tag Z00
  nsx_dfw_doc.py dfw_objects.json --filter-tag Z00:Prod
  nsx_dfw_doc.py dfw_objects.json --filter xdc --filter-tag Z00
  nsx_dfw_doc.py fetch --filter WSA04""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    args = sys.argv[1:]

    # Extract --filter and --filter-tag arguments
    filter_text = None
    filter_tag = None
    clean_args = []
    i = 0
    while i < len(args):
        if args[i] == "--filter" and i + 1 < len(args):
            filter_text = args[i + 1]
            i += 2
        elif args[i] == "--filter-tag" and i + 1 < len(args):
            filter_tag = args[i + 1]
            i += 2
        else:
            clean_args.append(args[i])
            i += 1
    args = clean_args
    if not args:
        print_usage()
        sys.exit(1)

    if args[0].lower() == "fetch":
        remaining = args[1:]
        json_output = None
        html_output = None
        for arg in remaining:
            low = arg.lower()
            if low.endswith(".html") or low.endswith(".htm"):
                html_output = arg
            elif low.endswith(".json"):
                json_output = arg

        json_file = fetch_nsx_objects(output_file=json_output)

    else:
        json_file = args[0]
        html_output = None
        for arg in args[1:]:
            low = arg.lower()
            if low.endswith(".html") or low.endswith(".htm"):
                html_output = arg

    if html_output is None:
        base = os.path.splitext(os.path.basename(json_file))[0]
        suffix_parts = []
        if filter_text:
            suffix_parts.append(filter_text)
        if filter_tag:
            suffix_parts.append("tag-" + filter_tag.replace(":", "-"))
        if suffix_parts:
            html_output = base + "_" + "_".join(suffix_parts) + "_documentation.html"
        else:
            html_output = base + "_documentation.html"

    ordered, rules_by_policy, policy_map, groups_db, services_db, profiles_db, vm_db = parse_json(json_file)

    if filter_text or filter_tag:
        ordered, rules_by_policy, policy_map = filter_policies(
            ordered, rules_by_policy, policy_map, groups_db,
            filter_text=filter_text, filter_tag=filter_tag, vm_db=vm_db)

    filter_label = None
    if filter_text and filter_tag:
        filter_label = f"{filter_text} + tag:{filter_tag}"
    elif filter_text:
        filter_label = filter_text
    elif filter_tag:
        filter_label = f"tag:{filter_tag}"

    generate_html(ordered, rules_by_policy, policy_map, html_output, groups_db, services_db, profiles_db, vm_db=vm_db, filter_text=filter_label, filter_tag=filter_tag)


if __name__ == "__main__":
    main()
