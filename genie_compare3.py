import re
import argparse
import sys
import os
from genie.utils.diff import Diff

def parse_config_to_dict(config_text):
    """Parses NX-OS config into a logical dictionary for comparison."""
    config_text = config_text.replace('\r\n', '\n')
    parsed = {
        "features": set(),
        "vlans": {},
        "vrfs": {},
        "vpc": {},
        "interfaces": {},
        "bgp": {},
        "prefix_lists": {},
        "route_maps": {}
    }

    # 1. Features
    parsed["features"] = set(re.findall(r"^feature\s+(\S+)", config_text, re.M))

    # 2. Route-Map Parser (Logical grouping by Name and Sequence)
    rm_blocks = re.finditer(r"^route-map (?P<name>\S+) (?P<action>permit|deny) (?P<seq>\d+)\n(?P<content>(?:  .*\n?)*)", config_text, re.M)
    for match in rm_blocks:
        name, seq, action = match.group('name'), match.group('seq'), match.group('action')
        content = match.group('content')
        if name not in parsed["route_maps"]: parsed["route_maps"][name] = {}
        parsed["route_maps"][name][seq] = {
            "action": action,
            "match_statements": re.findall(r"match (\S+ .*)", content),
            "set_statements": re.findall(r"set (\S+ .*)", content)
        }

    # 3. vPC Domain
    vpc_m = re.search(r"^vpc domain (?P<id>\d+)\n(?P<content>(?:  .*\n?)*)", config_text, re.M)
    if vpc_m:
        d_id, content = vpc_m.group('id'), vpc_m.group('content')
        parsed["vpc"][d_id] = {
            "peer_switch": "peer-switch" in content,
            "peer_gateway": "peer-gateway" in content,
            "auto_recovery": "auto-recovery" in content,
            "keepalive_dest": re.search(r"peer-keepalive destination (\S+)", content),
            "keepalive_vrf": re.search(r"vrf (\S+)", content)
        }
        for k in ["keepalive_dest", "keepalive_vrf"]:
            if parsed["vpc"][d_id][k]: parsed["vpc"][d_id][k] = parsed["vpc"][d_id][k].group(1)

    # 4. Hierarchical BGP
    bgp_m = re.search(r"^router\s+bgp\s+(?P<as>\d+)\n(?P<content>(?:  .*\n?)*)", config_text, re.M)
    if bgp_m:
        bgp_content = bgp_m.group('content')
        parsed["bgp"] = {"as_number": bgp_m.group('as'), "neighbors": {}}
        n_matches = re.finditer(r"^\s{2}neighbor\s+(?P<ip>\S+)\n(?P<n_content>(?:    .*\n?)*)", bgp_content, re.M)
        for n_m in n_matches:
            ip, n_content = n_m.group('ip'), n_m.group('n_content')
            parsed["bgp"]["neighbors"][ip] = {"remote_as": re.search(r"remote-as\s+(\d+)", n_content), "address_families": {}}
            if parsed["bgp"]["neighbors"][ip]["remote_as"]:
                parsed["bgp"]["neighbors"][ip]["remote_as"] = parsed["bgp"]["neighbors"][ip]["remote_as"].group(1)
            
            af_matches = re.finditer(r"^\s{4}address-family\s+(?P<af_name>.*)\n(?P<af_content>(?:      .*\n?)*)", n_content, re.M)
            for af_m in af_matches:
                name, af_content = af_m.group('af_name').strip(), af_m.group('af_content')
                parsed["bgp"]["neighbors"][ip]["address_families"][name] = {
                    "prefix_list_out": re.search(r"prefix-list\s+(\S+)\s+out", af_content),
                    "route_map_out": re.search(r"route-map\s+(\S+)\s+out", af_content)
                }
                for k in ["prefix_list_out", "route_map_out"]:
                    if parsed["bgp"]["neighbors"][ip]["address_families"][name][k]:
                        parsed["bgp"]["neighbors"][ip]["address_families"][name][k] = \
                            parsed["bgp"]["neighbors"][ip]["address_families"][name][k].group(1)

    # 5. Prefix-Lists
    pl_pat = r"^\s*ip\s+prefix-list\s+(?P<name>\S+)\s+seq\s+(?P<seq>\d+)\s+(?P<action>permit|deny)\s+(?P<prefix>\S+)(?P<extra>.*)"
    for m in re.finditer(pl_pat, config_text, re.M):
        name, seq = m.group('name'), m.group('seq')
        if name not in parsed["prefix_lists"]: parsed["prefix_lists"][name] = {}
        parsed["prefix_lists"][name][seq] = {
            "action": m.group('action'), "prefix": m.group('prefix'),
            "range": m.group('extra').strip() if m.group('extra').strip() else "exact"
        }

    # 6. Interfaces
    for m in re.finditer(r"^interface (\S+)\n((?:  .*\n?)*)", config_text, re.M):
        name, block = m.group(1), m.group(2)
        parsed["interfaces"][name] = {
            "vrf": re.search(r"vrf member (\S+)", block),
            "ip": re.search(r"ip address (\S+)", block),
            "anycast": "anycast-gateway" in block,
        }
        for k in ["vrf", "ip"]:
            if parsed["interfaces"][name][k]:
                parsed["interfaces"][name][k] = parsed["interfaces"][name][k].group(1)

    return parsed

def colorize_diff(diff_text):
    lines = diff_text.splitlines()
    colorized_lines = []
    for line in lines:
        if line.strip().startswith('-'):
            colorized_lines.append(f'<div class="removed">{line}</div>')
        elif line.strip().startswith('+'):
            colorized_lines.append(f'<div class="added">{line}</div>')
        else:
            colorized_lines.append(f'<div>{line}</div>')
    return "".join(colorized_lines)

def generate_html(diff_text, base_name, new_name):
    colorized_content = colorize_diff(diff_text)
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Audit: {base_name} vs {new_name}</title>
        <style>
            body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 40px; background-color: #ffffff; color: #24292e; }}
            .container {{ max-width: 1100px; margin: auto; }}
            h1 {{ font-size: 24px; border-bottom: 1px solid #eaecef; padding-bottom: 10px; }}
            .diff-box {{ border: 1px solid #e1e4e8; border-radius: 6px; font-family: monospace; font-size: 13px; line-height: 1.5; background-color: #ffffff; }}
            .added {{ background-color: #e6ffed; color: #22863a; border-left: 4px solid #28a745; padding-left: 10px; }}
            .removed {{ background-color: #ffeef0; color: #b31d28; border-left: 4px solid #d73a49; padding-left: 10px; }}
            .diff-box div {{ padding-right: 10px; min-height: 20px; }}
            div:not(.added):not(.removed) {{ padding-left: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Logical Config Audit Report</h1>
            <div class="diff-box">{colorized_content}</div>
        </div>
    </body>
    </html>
    """

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("new")
    parser.add_argument("-ho", "--html")
    args = parser.parse_args()

    with open(args.base, 'r') as f: d1 = parse_config_to_dict(f.read())
    with open(args.new, 'r') as f: d2 = parse_config_to_dict(f.read())

    dd = Diff(d1, d2)
    dd.findDiff()

    output_text = str(dd) if dd.diffs else "✅ SUCCESS: No logical differences found."
    print(output_text)

    if args.html:
        with open(args.html, 'w') as hf:
            hf.write(generate_html(output_text, args.base, args.new))
        print(f"\n✨ HTML report saved: {os.path.abspath(args.html)}")

if __name__ == "__main__":
    main()