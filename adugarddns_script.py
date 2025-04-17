import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple, Any

import aiodns
import aiohttp

# --- Compiled Regular Expressions ---
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

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

CACHE_FILE = "domain_cache1.json"
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
HTTP_TIMEOUT = 60  # seconds

# --- Core Functions ---

async def fetch_rules(url: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch rules from a URL asynchronously using aiohttp."""
    logging.info(f"Fetching rules from: {url}")
    try:
        async with session.get(url, timeout=HTTP_TIMEOUT) as response:
            if response.status != 200:
                logging.error(f"Error fetching {url}: HTTP {response.status}")
                return []
            
            text = await response.text()
            lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith('!')]
            logging.info(f"Fetched {len(lines)} rules from {url}")
            return lines
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.error(f"Error fetching {url}: {e}")
        return []

def extract_domain(rule: str) -> Optional[str]:
    """Extract and validate domain from a rule."""
    if rule.startswith('@@||'): rule = rule[4:]
    elif rule.startswith('||'): rule = rule[2:]
    elif rule.startswith('@@|'): rule = rule[3:]
    elif rule.startswith('|'): rule = rule[1:]
    
    rule = rule.split('^')[0].split('$')[0].split('/')[0].split(':')[0].strip('*')
    if DOMAIN_REGEX.match(rule):
        if not IP_REGEX.match(rule):
            return rule.lower()
    return None

async def check_domain_is_nxdomain(domain: str, resolver: aiodns.DNSResolver, retries: int = DNS_RETRIES) -> bool:
    """Check if a domain returns NXDOMAIN for both A and AAAA records."""
    nxdomain_code = aiodns.error.ARES_ENOTFOUND
    a_is_nxdomain = False
    aaaa_is_nxdomain = False

    async def perform_query(qtype: str) -> bool:
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

def load_invalid_domain_cache() -> Dict[str, bool]:
    """Load and filter the invalid domain cache, removing expired entries."""
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

def save_invalid_domain_cache(invalid_domains: Set[str]) -> None:
    """Save the set of invalid domains to cache with timestamps."""
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

async def validate_domains_async(domains: Set[str], force_refresh: bool = False) -> Set[str]:
    """Validate domains by checking if they return NXDOMAIN."""
    invalid_domain_cache = load_invalid_domain_cache()
    resolver = aiodns.DNSResolver(nameservers=CUSTOM_DNS_SERVERS, timeout=DNS_TIMEOUT, tries=(1 + DNS_RETRIES))

    domains_to_check = list(domains) if force_refresh else [d for d in domains if d not in invalid_domain_cache]
    confirmed_invalid_domains = set(invalid_domain_cache.keys())
    newly_confirmed_invalid = set()
    domains_resolved_valid = set()

    if domains_to_check:
        logging.info(f"Validating {len(domains_to_check)} domains (skipping {len(domains) - len(domains_to_check)} cached domains)")
        semaphore = asyncio.Semaphore(CONCURRENT_CHECK_LIMIT)
        
        async def check_and_update(domain: str) -> None:
            async with semaphore:
                if await check_domain_is_nxdomain(domain, resolver):
                    logging.debug(f"Domain {domain} confirmed NXDOMAIN")
                    newly_confirmed_invalid.add(domain)
                else:
                    logging.debug(f"Domain {domain} resolved successfully")
                    domains_resolved_valid.add(domain)

        tasks = [asyncio.create_task(check_and_update(d)) for d in domains_to_check]
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.info(f"Found {len(newly_confirmed_invalid)} newly invalid domains")

    # Update the set of confirmed invalid domains
    confirmed_invalid_domains.update(newly_confirmed_invalid)
    # Remove any domains that were previously thought invalid but now resolve
    confirmed_invalid_domains.difference_update(domains_resolved_valid)
    
    save_invalid_domain_cache(confirmed_invalid_domains)
    return confirmed_invalid_domains

def filter_rules_by_invalid_domains(rules: List[str], invalid_domains: Set[str]) -> List[str]:
    """Filter out rules that point to invalid domains."""
    valid_rules = []
    for rule in rules:
        domain = extract_domain(rule)
        if domain is None or domain not in invalid_domains:
            valid_rules.append(rule)
    
    logging.info(f"Filtered {len(rules) - len(valid_rules)} rules with invalid domains from {len(rules)} total rules")
    return valid_rules

def generate_unique_rules(source_rules: List[str], *other_rule_lists: List[str]) -> List[str]:
    """Generate a list of rules unique to the source list."""
    source_set = set(source_rules)
    exclude_set = set().union(*other_rule_lists)
    unique = [rule for rule in source_rules if rule in source_set and rule not in exclude_set]
    logging.info(f"Generated {len(unique)} unique rules from {len(source_rules)} initial rules.")
    return unique

def generate_header(title: str, rule_count: int) -> List[str]:
    """Generate the header for the output file."""
    utc8_tz = timezone(timedelta(hours=8))
    current_time_str = datetime.now(utc8_tz).strftime('%Y/%m/%d %H:%M:%S %Z')
    return [
        '[X Adguard Dns]', f'! Title: {title}', '! Expires: 1 day',
        f'! Last modified: {current_time_str}', f'! Homepage: {HOMEPAGE_URL}',
        f'! Total count: {rule_count}'
    ]

def split_rules(rules: List[str]) -> List[str]:
    """Split rules into allow and block lists, with allow rules first."""
    return [rule for rule in rules if rule.startswith('@@')] + [rule for rule in rules if not rule.startswith('@@')]

def write_rules_file(filename: str, title: str, rules: List[str]) -> None:
    """Write rules to a file with proper header and formatting."""
    processed_rules = split_rules(rules)
    header = generate_header(title, len(processed_rules))
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n' + '\n'.join(processed_rules) + '\n')
        logging.info(f"Successfully wrote {len(processed_rules)} rules to {filename}")
    except IOError as e:
        logging.error(f"Error writing file {filename}: {e}")

async def main_async() -> None:
    """Main async function to process adblock lists."""
    logging.info("Starting adblock list processing...")
    
    # Fetch all rules concurrently
    async with aiohttp.ClientSession() as session:
        fetch_tasks = {key: fetch_rules(url, session) for key, url in SOURCES.items()}
        fetched_rules = {}
        for key, task in fetch_tasks.items():
            fetched_rules[key] = await task
    
    # Extract all unique domains from all rules for validation
    all_domains = set()
    for rules_list in fetched_rules.values():
        for rule in rules_list:
            domain = extract_domain(rule)
            if domain:
                all_domains.add(domain)
    
    logging.info(f"Extracted {len(all_domains)} unique domains from all rules")
    
    # Validate all domains at once
    invalid_domains = await validate_domains_async(all_domains)
    
    # Filter each rule list to remove rules with invalid domains
    filtered_rules = {
        key: filter_rules_by_invalid_domains(rules, invalid_domains)
        for key, rules in fetched_rules.items()
    }
    
    # Generate intermediate rule lists
    intermediate_rules = {
        'a1': generate_unique_rules(filtered_rules['a'], filtered_rules['b'], filtered_rules['c']),
        'b1': generate_unique_rules(filtered_rules['b'], filtered_rules['c'])
    }
    
    # Combine rules for the final output
    final_rules = {
        'a1': intermediate_rules['a1'],
        'b1': intermediate_rules['b1'],
        'a1b1': list(dict.fromkeys(intermediate_rules['a1'] + intermediate_rules['b1']))
    }
    
    # Write output files
    for key, definition in OUTPUT_FILES.items():
        rules = final_rules[key]
        write_rules_file(f"{key}.txt", definition['title'], rules)
    
    logging.info("Adblock list processing finished successfully.")

if __name__ == '__main__':
    try:
        asyncio.run(main_async())
    except Exception as e:
        logging.exception(f"An unhandled error occurred: {e}")
