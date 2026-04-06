#!/usr/bin/env python3
"""
Updates README.md with current rule statistics.
Run manually or via GitHub Actions on merge to main.
"""

import os
import re
from pathlib import Path
from collections import Counter

RULES_DIR = "sigma_rules"
README_PATH = "README.md"


def count_rules():
    """Count rules by platform and category."""
    rules_path = Path(RULES_DIR)

    if not rules_path.exists():
        print(f"Error: {RULES_DIR} directory not found")
        return None

    rule_files = list(rules_path.glob("*.yml"))
    total = len(rule_files)

    # Count by platform
    windows = sum(1 for f in rule_files if "_win_" in f.name or f.name.startswith("reg_"))
    linux = sum(1 for f in rule_files if "_lnx_" in f.name)
    m365 = sum(1 for f in rule_files if f.name.startswith("m365_"))
    web = sum(1 for f in rule_files if f.name.startswith("web_"))
    security = sum(1 for f in rule_files if f.name.startswith("security_"))

    # Cloud/other = m365 + web + security
    cloud = m365 + web + security

    # Count by category (first two parts of filename)
    categories = Counter()
    for f in rule_files:
        parts = f.stem.split("_")
        if len(parts) >= 2:
            # Handle special cases
            if parts[0] == "m365":
                cat = "m365_*"
            elif parts[0] == "web":
                cat = f"{parts[0]}_{parts[1]}"
            elif parts[0] == "security":
                cat = "security_*"
            else:
                cat = f"{parts[0]}_{parts[1]}"
            categories[cat] += 1

    return {
        "total": total,
        "windows": windows,
        "linux": linux,
        "cloud": cloud,
        "categories": categories
    }


def update_readme(stats):
    """Update README.md with new statistics."""
    readme_path = Path(README_PATH)

    if not readme_path.exists():
        print(f"Error: {README_PATH} not found")
        return False

    content = readme_path.read_text(encoding='utf-8')

    # Update overview table
    overview_pattern = r'(\| \*\*Total Rules\*\* \| )\d+( \|)'
    content = re.sub(overview_pattern, rf'\g<1>{stats["total"]}\2', content)

    overview_pattern = r'(\| \*\*Windows Rules\*\* \| )\d+( \|)'
    content = re.sub(overview_pattern, rf'\g<1>{stats["windows"]}\2', content)

    overview_pattern = r'(\| \*\*Linux Rules\*\* \| )\d+( \|)'
    content = re.sub(overview_pattern, rf'\g<1>{stats["linux"]}\2', content)

    overview_pattern = r'(\| \*\*M365/Cloud Rules\*\* \| )\d+( \|)'
    content = re.sub(overview_pattern, rf'\g<1>{stats["cloud"]}\2', content)

    # Build new categories table
    category_descriptions = {
        "proc_creation": "Process creation events",
        "file_event": "File system activity",
        "file_creation": "File creation events",
        "reg_set": "Registry modifications",
        "registry_set": "Registry modifications",
        "net_connection": "Network connections",
        "dns_query": "DNS query anomalies",
        "web_sharepoint": "SharePoint web activity",
        "wmi_event": "WMI event subscription monitoring",
        "posh_ps": "PowerShell script block logging",
        "powershell_base64": "Base64-encoded PowerShell detection",
        "bitsadmin_mal": "Malicious BITSAdmin activity",
        "m365_*": "Microsoft 365 audit logs",
        "azure_network": "Azure network firewall changes",
        "azure_firewall": "Azure firewall modifications",
        "azure_application": "Azure application security changes",
        "security_*": "Windows Security event logs",
        "sysmon_lockbitv3": "LockBit 3.0 ransomware detection (Sysmon)",
        "sysmon_ALPHVblackcat": "ALPHV BlackCat ransomware detection (Sysmon)",
        "sysmon_medusa": "Medusa ransomware detection (Sysmon)",
        "sysmon_netconnect": "Suspicious network connections (Sysmon)",
        "sysmon_RAS": "Remote access software detection (Sysmon)",
    }

    # Sort categories by count descending
    sorted_cats = sorted(stats["categories"].items(), key=lambda x: -x[1])

    new_table_rows = []
    for cat, count in sorted_cats:
        desc = category_descriptions.get(cat, "Other events")
        new_table_rows.append(f"| `{cat}` | {desc} | {count} |")

    # Replace categories table
    cat_table_pattern = r'(### Rule Categories\n\n\| Category \| Description \| Count \|\n\|----------|-------------|-------\|\n)((?:\| .+ \| .+ \| \d+ \|\n)+)'
    new_table = "\n".join(new_table_rows) + "\n"
    content = re.sub(cat_table_pattern, rf'\1{new_table}', content)

    readme_path.write_text(content, encoding='utf-8')
    return True


def main():
    print("Counting rules...")
    stats = count_rules()

    if not stats:
        return 1

    print(f"Found {stats['total']} total rules:")
    print(f"  - Windows: {stats['windows']}")
    print(f"  - Linux: {stats['linux']}")
    print(f"  - M365/Cloud: {stats['cloud']}")
    print(f"\nCategories:")
    for cat, count in sorted(stats['categories'].items(), key=lambda x: -x[1]):
        print(f"  - {cat}: {count}")

    print(f"\nUpdating {README_PATH}...")
    if update_readme(stats):
        print("README.md updated successfully")
        return 0
    else:
        print("Failed to update README.md")
        return 1


if __name__ == "__main__":
    exit(main())
