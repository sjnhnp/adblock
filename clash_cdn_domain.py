import requests
import yaml
import os

SOURCE_URL = "https://raw.githubusercontent.com/pmkol/easymosdns/rules/cdn_domain_list.txt"
OUTPUT_FILE = "cdn_domain_clash.yaml"

def fetch_rules():
    print(f"Fetching rules from {SOURCE_URL}...")
    try:
        response = requests.get(SOURCE_URL)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"Error fetching rules: {e}")
        return []

def convert_to_clash_yaml(rules):
    payload = []
    for line in rules:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Convert MosDNS prefixes to Clash types
        if line.startswith("regexp:"):
            # regexp:pattern -> DOMAIN-REGEX,pattern
            payload.append(f"DOMAIN-REGEX,{line[7:]}")
        elif line.startswith("full:"):
            # full:domain -> DOMAIN,domain
            payload.append(f"DOMAIN,{line[5:]}")
        elif line.startswith("domain:"):
            # domain:domain -> DOMAIN-SUFFIX,domain
            payload.append(f"DOMAIN-SUFFIX,{line[7:]}")
        elif line.startswith("keyword:"):
            # keyword:key -> DOMAIN-KEYWORD,key
            payload.append(f"DOMAIN-KEYWORD,{line[8:]}")
        else:
            # Default to DOMAIN-SUFFIX for lines without known prefix
            # Assuming lines are domains.
            payload.append(f"DOMAIN-SUFFIX,{line}")
    
    return {
        "payload": payload
    }

def main():
    rules = fetch_rules()
    if not rules:
        print("No rules found or failed to fetch.")
        return

    clash_data = convert_to_clash_yaml(rules)
    
    print(f"Writing {len(clash_data['payload'])} rules to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for line in clash_data['payload']:
            f.write(f"  - '{line}'\n")

    print("Done.")

if __name__ == "__main__":
    main()
