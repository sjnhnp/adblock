import requests
from datetime import datetime, timedelta, timezone
import re
import asyncio
import aiodns
import json
import os
import logging

# --- Configuration ---
LOG_FILE = "filter_script.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

CUSTOM_DNS_SERVERS = [
    '223.5.5.5', '223.6.6.6', '119.29.29.29', '208.67.222.2',
    '8.8.4.4', '9.9.9.10', '1.1.1.1', '1.0.0.1'
]

CACHE_FILE = "domain_cache.json"
CACHE_EXPIRY_DAYS = 7

SOURCES = {
    'a': 'https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt',
    'b': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt',
    'c': 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt'
}

OUTPUT_FILES = {
    'a1': {'title': 'X dns - A1 Unique Rules (Validated)', 'source': 'a', 'exclude': ['b', 'c']},
    'b1': {'title': 'X dns - B1 Unique Rules (Validated)', 'source': 'b', 'exclude': ['c']},
    'a1b1': {'title': 'X dns - Combined A1+B1 (Validated)', 'combine': ['a1', 'b1']}
}

DNS_TIMEOUT = 5
DNS_RETRIES = 2
CONCURRENT_CHECK_LIMIT = 200
HOMEPAGE_URL = 'https://github.com/sjnhnp/adblock'

# --- Core Functions ---

def fetch_rules(url):
    logging.info(f"Fetching rules from: {url}")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('!')]
        logging.info(f"Fetched {len(lines)} rules from {url}")
        return lines
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return []

def extract_domain(rule):
    if rule.startswith('@@||'): rule = rule[4:]
    elif rule.startswith('||'): rule = rule[2:]
    elif rule.startswith('@@|'): rule = rule[3:]
    elif rule.startswith('|'): rule = rule[1:]
    
    rule = rule.split('^')[0].split('$')[0].split('/')[0].split(':')[0].strip('*')
    if re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$', rule):
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', rule):
            return rule.lower()
    return None

async def check_domain_is_nxdomain(domain, resolver, retries=DNS_RETRIES):
    nxdomain_code = aiodns.error.ARES_ENOTFOUND
    a_is_nxdomain = False
    aaaa_is_nxdomain = False

    async def perform_query(qtype):
        nonlocal a_is_nxdomain, aaaa_is_nxdomain
        try:
            await resolver.query(domain, qtype)
            return False
        except aiodns.error.DNSError as e:
            if e.args[0] == nxdomain_code:
                if qtype == 'A': a_is_nxdomain = True
                if qtype == 'AAAA': aaaa_is_nxdomain = True
                return True
            elif e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED]:
                raise
            return False

    for attempt in range(retries + 1):
        a_is_nxdomain = False
        aaaa_is_nxdomain = False
        try:
            if not await perform_query('A'): return False
            if a_is_nxdomain and not await perform_query('AAAA'): return False
            if a_is_nxdomain and aaaa_is_nxdomain: return True
        except aiodns.error.DNSError as e:
            if e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED] and attempt < retries:
                await asyncio.sleep(1 + attempt)
                continue
            return False
    return False

def load_invalid_domain_cache():
    if not os.path.exists(CACHE_FILE):
        logging.info("Cache file not found. Starting with an empty cache.")
        return {}
        
    try:
        with open(CACHE_FILE, 'r') as f:
            cache_data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Error reading or parsing cache file {CACHE_FILE}: {e}. Starting with an empty cache.")
        return {}

    utc8_tz = timezone(timedelta(hours=8))
    now = datetime.now(utc8_tz)
    valid_cache = {}
    expiry_limit = now - timedelta(days=CACHE_EXPIRY_DAYS)
    loaded_count = 0
    expired_count = 0

    for domain, entry in cache_data.items():
        loaded_count += 1
        timestamp_str = None
        is_invalid = False

        if isinstance(entry, dict) and 'timestamp' in entry:
            timestamp_str = entry.get('timestamp')
            is_invalid = entry.get('invalid', False)
        
        if is_invalid and timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc).astimezone(utc8_tz)
                if timestamp > expiry_limit:
                    valid_cache[domain] = True
                else:
                    expired_count += 1
            except ValueError:
                logging.warning(f"Invalid timestamp format in cache for domain: {domain}. Ignoring entry.")
    
    logging.info(f"Loaded {len(valid_cache)} non-expired invalid domains from cache ({loaded_count} total entries, {expired_count} expired or ignored).")
    return valid_cache

def save_invalid_domain_cache(invalid_domains):
    cache_data = {}
    utc8_tz = timezone(timedelta(hours=8))
    now_iso = datetime.now(utc8_tz).isoformat()
    for domain in invalid_domains:
        cache_data[domain] = {"invalid": True, "timestamp": now_iso}
        
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logging.info(f"Saved {len(invalid_domains)} confirmed invalid domains to cache.")
    except IOError as e:
        logging.error(f"Error writing cache file {CACHE_FILE}: {e}")

async def filter_rules_async(rules, force_refresh=False):
    invalid_domain_cache = load_invalid_domain_cache()
    resolver = aiodns.DNSResolver(nameservers=CUSTOM_DNS_SERVERS, timeout=DNS_TIMEOUT, tries=(1 + DNS_RETRIES))

    domains_map = {}
    rules_without_domain = []
    original_rule_order = {}
    rule_index = 0
    for rule in rules:
        if rule not in original_rule_order:
            original_rule_order[rule] = rule_index
            rule_index += 1
        domain = extract_domain(rule)
        if domain:
            domains_map.setdefault(domain, []).append(rule)
        else:
            rules_without_domain.append(rule)

    domains_to_check = list(domains_map.keys()) if force_refresh else [d for d in domains_map if d not in invalid_domain_cache]
    confirmed_invalid_domains = set(invalid_domain_cache.keys())
    newly_confirmed_invalid = set()
    domains_resolved_valid = set()

    if domains_to_check:
        semaphore = asyncio.Semaphore(CONCURRENT_CHECK_LIMIT)
        async def check_and_update(domain):
            async with semaphore:
                if await check_domain_is_nxdomain(domain, resolver):
                    newly_confirmed_invalid.add(domain)
                else:
                    domains_resolved_valid.add(domain)

        await asyncio.gather(*[asyncio.create_task(check_and_update(d)) for d in domains_to_check], return_exceptions=True)

    confirmed_invalid_domains.update(newly_confirmed_invalid)
    confirmed_invalid_domains.difference_update(confirmed_invalid_domains.intersection(domains_resolved_valid))
    save_invalid_domain_cache(confirmed_invalid_domains)

    final_valid_rules = [(rule, original_rule_order.get(rule, float('inf'))) for rule in rules_without_domain]
    processed_rules = set(rules_without_domain)
    for domain, rules_list in domains_map.items():
        if domain not in confirmed_invalid_domains:
            for rule in rules_list:
                if rule not in processed_rules:
                    final_valid_rules.append((rule, original_rule_order.get(rule, float('inf'))))
                    processed_rules.add(rule)
    
    final_valid_rules.sort(key=lambda x: x[1])
    result_rules = [rule for rule, _ in final_valid_rules]
    logging.info(f"Original rules: {len(rules)}, Filtered rules: {len(result_rules)}. Removed {len(rules) - len(result_rules)} rules.")
    return result_rules

def generate_unique_rules(source_rules, *other_rule_lists):
    source_set = set(source_rules)
    exclude_set = set().union(*other_rule_lists)
    unique = [rule for rule in source_rules if rule in source_set and rule not in exclude_set]
    logging.info(f"Generated {len(unique)} unique rules from {len(source_rules)} initial rules.")
    return unique

def generate_header(title, rule_count):
    utc8_tz = timezone(timedelta(hours=8))
    current_time_str = datetime.now(utc8_tz).strftime('%Y/%m/%d %H:%M:%S %Z')
    return [
        '[X Adguard Dns]', f'! Title: {title}', '! Expires: 1 day',
        f'! Last modified: {current_time_str}', f'! Homepage: {HOMEPAGE_URL}',
        f'! Total count: {rule_count}'
    ]

def split_rules(rules):
    return [rule for rule in rules if rule.startswith('@@')] + [rule for rule in rules if not rule.startswith('@@')]

def write_rules_file(filename, title, rules):
    processed_rules = split_rules(rules)
    header = generate_header(title, len(processed_rules))
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n' + '\n'.join(processed_rules) + '\n')
        logging.info(f"Successfully wrote {len(processed_rules)} rules to {filename}")
    except IOError as e:
        logging.error(f"Error writing file {filename}: {e}")

async def main_async():
    logging.info("Starting adblock list processing...")
    fetched_rules = {key: fetch_rules(url) for key, url in SOURCES.items()}
    
    intermediate_rules = {
        'a1': generate_unique_rules(fetched_rules['a'], fetched_rules['b'], fetched_rules['c']),
        'b1': generate_unique_rules(fetched_rules['b'], fetched_rules['c'])
    }
    
    all_rules_to_validate = list(dict.fromkeys(intermediate_rules['a1'] + intermediate_rules['b1']))
    valid_rules_after_filter = await filter_rules_async(all_rules_to_validate, force_refresh=False)
    valid_rules_set = set(valid_rules_after_filter)
    
    final_rules = {
        'a1': [r for r in intermediate_rules['a1'] if r in valid_rules_set],
        'b1': [r for r in intermediate_rules['b1'] if r in valid_rules_set]
    }
    final_rules['a1b1'] = list(dict.fromkeys(final_rules['a1'] + final_rules['b1']))
    
    for key, definition in OUTPUT_FILES.items():
        rules = final_rules[key] if 'combine' in definition else final_rules[key]
        write_rules_file(f"{key}.txt", definition['title'], rules)
    
    logging.info("Adblock list processing finished successfully.")

if __name__ == '__main__':
    try:
        asyncio.run(main_async())
    except Exception as e:
        logging.exception(f"An unhandled error occurred: {e}")
