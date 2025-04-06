import requests
from datetime import datetime, timedelta, timezone
import re
import asyncio
import aiodns
import json
import os
import logging

# --- Configuration ---

# --- Configuration ---
LOG_FILE = "filter_script.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),  # 写入日志文件
        logging.StreamHandler()  # 同时输出到控制台，便于调试
    ]
)

# Custom DNS servers (add more reliable ones as needed)
CUSTOM_DNS_SERVERS = [
    '223.5.5.5',      # AliDNS
    '223.6.6.6',      # AliDNS Backup
    '119.29.29.29',   # DNSPod
    '208.67.222.2',   # BaiduDNS
    '8.8.4.4',        # Google Public DNS
    '9.9.9.10',        # Google Public DNS Backup
    '1.1.1.1',        # Cloudflare DNS
    '1.0.0.1'         # Cloudflare DNS Backup
]

# Cache file path and expiry duration
CACHE_FILE = "domain_cache.json"
CACHE_EXPIRY_DAYS = 7 # Cache confirmed invalid domains for 7 days

# Adblock list sources
SOURCES = {
    'a': 'https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt',
    'b': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt',
    'c': 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt'
}

# Output file definitions
OUTPUT_FILES = {
    'a1': {
        'title': 'X dns - A1 Unique Rules (Validated)',
        'source': 'a',
        'exclude': ['b', 'c']
    },
    'b1': {
        'title': 'X dns - B1 Unique Rules (Validated)',
        'source': 'b',
        'exclude': ['c'] # Only exclude C from B for b1
    },
    'a1b1': {
        'title': 'X dns - Combined A1+B1 (Validated)',
        'combine': ['a1', 'b1'] # Indicates this file combines others
    }
}

# Concurrency settings
DNS_TIMEOUT = 5 # Timeout for each DNS query in seconds
DNS_RETRIES = 2 # Number of retries for DNS queries (total attempts = 1 + retries)
CONCURRENT_CHECK_LIMIT = 200 # Max number of domains to check concurrently

# GitHub Repo URL (Replace with your actual repo URL)
HOMEPAGE_URL = 'https://github.com/sjnhnp/adblock' 

# --- Core Functions ---

def fetch_rules(url):
    """Fetches rules from a URL, handling potential errors."""
    logging.info(f"Fetching rules from: {url}")
    try:
        # Use a reasonable timeout
        response = requests.get(url, timeout=60) 
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        # Process lines: strip whitespace, ignore empty lines and comments starting with '!'
        lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('!')]
        logging.info(f"Fetched {len(lines)} rules from {url}")
        return lines
    except requests.exceptions.Timeout:
        logging.error(f"Timeout error fetching {url}")
        return []
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return [] # Return empty list on error to prevent script failure

def extract_domain(rule):
    """Extracts a potential domain name from an adblock rule."""
    # Remove @@ prefix (whitelist marker) and common domain prefixes like ||, |
    if rule.startswith('@@||'): rule = rule[4:]
    elif rule.startswith('||'): rule = rule[2:]
    elif rule.startswith('@@|'): rule = rule[3:]
    elif rule.startswith('|'): rule = rule[1:]
    
    # Remove common Adblock Plus syntax (^, $, ~, /, :, *) that might be attached
    # Split by common separators and take the first part
    rule = rule.split('^')[0].split('$')[0].split('/')[0].split(':')[0].strip('*')
    
    # Basic domain format check (allows internationalized domains via Punycode)
    # Checks for sequences of letters, numbers, hyphens separated by dots
    # Does not guarantee validity, just format. DNS check is the real validation.
    # Updated regex to be slightly more robust.
    if re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$', rule):
        # Exclude simple IP addresses (more complex patterns could exist)
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', rule):
             # Normalize to lowercase
            return rule.lower()
    return None

async def check_domain_is_nxdomain(domain, resolver, retries=DNS_RETRIES):
    """
    Checks if a domain is definitively NXDOMAIN for both A and AAAA records.
    Returns True only if both A and AAAA queries explicitly return NXDOMAIN.
    Returns False if either query succeeds, fails with a non-NXDOMAIN error, or times out after retries.
    """
    nxdomain_code = aiodns.error.ARES_ENOTFOUND
    a_is_nxdomain = False
    aaaa_is_nxdomain = False

    async def perform_query(qtype):
        nonlocal a_is_nxdomain, aaaa_is_nxdomain
        try:
            logging.debug(f"Querying {qtype} record for '{domain}'")
            await resolver.query(domain, qtype)
            logging.debug(f"{qtype} query for '{domain}' succeeded. Domain exists or state uncertain.")
            return False # Query succeeded (even if no records returned, not NXDOMAIN)
        except aiodns.error.DNSError as e:
            if e.args[0] == nxdomain_code:
                logging.debug(f"{qtype} query for '{domain}' resulted in NXDOMAIN.")
                if qtype == 'A': a_is_nxdomain = True
                if qtype == 'AAAA': aaaa_is_nxdomain = True
                return True # Explicit NXDOMAIN
            elif e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED]:
                logging.warning(f"{qtype} query for '{domain}' failed (non-NXDOMAIN error: {e.args[0]}).")
                raise # Re-throw retryable errors
            else:
                logging.error(f"{qtype} query for '{domain}' failed with unexpected DNS error {e.args[0]}. Assuming non-NXDOMAIN.")
                return False # Treat other DNS errors as non-NXDOMAIN conservatively
        except Exception as e:
            logging.error(f"Unexpected error checking {qtype} record for '{domain}': {e}. Assuming non-NXDOMAIN.")
            return False # Treat other exceptions as non-NXDOMAIN conservatively

    for attempt in range(retries + 1):
        a_is_nxdomain = False # Reset status for each attempt
        aaaa_is_nxdomain = False
        try:
            # 1. Check A Record
            a_result_is_nx = await perform_query('A')
            if not a_result_is_nx: # A record exists or status uncertain
                logging.debug(f"Assuming '{domain}' is valid based on A record check.")
                return False # Not confirmed NXDOMAIN

            # If A was NXDOMAIN, proceed to check AAAA
            if a_is_nxdomain:
                # 2. Check AAAA Record
                aaaa_result_is_nx = await perform_query('AAAA')
                if not aaaa_result_is_nx: # AAAA record exists or status uncertain
                     logging.debug(f"Assuming '{domain}' is valid based on AAAA check (A was NXDOMAIN).")
                     return False # Not confirmed NXDOMAIN (possibly IPv6 only)
                
                # If both A and AAAA explicitly returned NXDOMAIN in this attempt
                if aaaa_is_nxdomain: 
                    logging.info(f"Confirmed NXDOMAIN for '{domain}' (both A and AAAA).")
                    return True # Confirmed Invalid

        except aiodns.error.DNSError as e:
             # Catch retryable errors re-thrown by perform_query
            if e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED]:
                if attempt < retries:
                    logging.warning(f"Retrying ({attempt+1}/{retries}) domain check for '{domain}' due to {e.args[0]}")
                    await asyncio.sleep(1 + attempt) # Exponential backoff might be better
                    continue # Go to next retry attempt
                else:
                    logging.error(f"Domain check for '{domain}' failed after {retries+1} attempts due to persistent non-NXDOMAIN errors. Assuming valid.")
                    return False # Retries exhausted, assume valid conservatively
            else:
                 logging.error(f"Caught unexpected DNSError during check for '{domain}': {e}. Assuming valid.")
                 return False # Assume valid for unexpected DNS errors
        except Exception as e:
            logging.error(f"Caught unexpected Exception during check for '{domain}': {e}. Assuming valid.")
            return False # Assume valid for other exceptions

    # If loop finishes without returning (e.g., exhausted retries on non-NXDOMAIN errors)
    logging.warning(f"Domain check for '{domain}' inconclusive after all retries. Assuming valid.")
    return False # Final conservative fallback


def load_invalid_domain_cache():
    """Loads non-expired confirmed invalid domains from the cache file."""
    if not os.path.exists(CACHE_FILE):
        logging.info("Cache file not found. Starting with an empty cache.")
        return {}
        
    try:
        with open(CACHE_FILE, 'r') as f:
            cache_data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Error reading or parsing cache file {CACHE_FILE}: {e}. Starting with an empty cache.")
        return {}

    now = datetime.now(timezone.utc)
    valid_cache = {}
    expiry_limit = now - timedelta(days=CACHE_EXPIRY_DAYS)
    loaded_count = 0
    expired_count = 0

    for domain, entry in cache_data.items():
        loaded_count += 1
        timestamp_str = None
        is_invalid = False

        # Check cache entry format (new format preferred)
        if isinstance(entry, dict) and 'timestamp' in entry:
            timestamp_str = entry.get('timestamp')
            is_invalid = entry.get('invalid', False) # Explicit 'invalid: true' flag
        # Add compatibility for older format if needed, otherwise ignore malformed entries
        # elif ...

        if is_invalid and timestamp_str:
            try:
                # Ensure timestamp is timezone-aware (UTC)
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc) # Assume UTC if no tzinfo
                
                if timestamp > expiry_limit:
                    valid_cache[domain] = True # Value True means confirmed invalid and not expired
                else:
                    expired_count += 1
            except ValueError:
                logging.warning(f"Invalid timestamp format in cache for domain: {domain}. Ignoring entry.")
        # Silently ignore entries not marked as invalid or without timestamp

    logging.info(f"Loaded {len(valid_cache)} non-expired invalid domains from cache ({loaded_count} total entries, {expired_count} expired or ignored).")
    return valid_cache


def save_invalid_domain_cache(invalid_domains):
    """Saves the set of confirmed invalid domains to the cache file."""
    cache_data = {}
    now_iso = datetime.now(timezone.utc).isoformat()
    for domain in invalid_domains:
        # Use the new format for clarity
        cache_data[domain] = {"invalid": True, "timestamp": now_iso} 
        
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logging.info(f"Saved {len(invalid_domains)} confirmed invalid domains to cache.")
    except IOError as e:
        logging.error(f"Error writing cache file {CACHE_FILE}: {e}")


async def filter_rules_async(rules, force_refresh=False):
    """Filters a list of rules, removing those associated with confirmed invalid domains."""
    # Load existing non-expired invalid domains
    invalid_domain_cache = load_invalid_domain_cache()

    # Initialize DNS resolver
    resolver = aiodns.DNSResolver(
        nameservers=CUSTOM_DNS_SERVERS, 
        timeout=DNS_TIMEOUT, 
        tries=(1 + DNS_RETRIES) # aiodns tries = total attempts
    )

    # Map domains to their rules and collect non-domain rules
    domains_map = {} # {domain: [rule1, rule2, ...]}
    rules_without_domain = []
    original_rule_order = {} # Store original index for sorting later
    rule_index = 0
    for rule in rules:
        if rule not in original_rule_order: # Keep first occurrence order
             original_rule_order[rule] = rule_index
             rule_index += 1

        domain = extract_domain(rule)
        if domain:
            if domain not in domains_map:
                domains_map[domain] = []
            domains_map[domain].append(rule)
        else:
            # Preserve rules that don't contain extractable domains
            rules_without_domain.append(rule) 

    # Determine which domains actually need checking
    domains_to_check = []
    if force_refresh:
        domains_to_check = list(domains_map.keys())
        logging.info("Force refresh enabled. Checking all domains.")
    else:
        domains_to_check = [d for d in domains_map.keys() if d not in invalid_domain_cache]
        skipped_count = len(domains_map) - len(domains_to_check)
        logging.info(f"Checking {len(domains_to_check)} domains. ({skipped_count} domains skipped via cache).")

    # Perform DNS checks concurrently
    confirmed_invalid_domains = set(invalid_domain_cache.keys()) # Start with cached invalid domains
    newly_confirmed_invalid = set()
    domains_resolved_valid = set() # Track domains that resolved successfully this run

    if domains_to_check:
        semaphore = asyncio.Semaphore(CONCURRENT_CHECK_LIMIT)
        tasks = []

        async def check_and_update(domain):
            async with semaphore:
                is_nxdomain = await check_domain_is_nxdomain(domain, resolver)
                if is_nxdomain:
                    newly_confirmed_invalid.add(domain)
                else:
                    # Domain resolved or status uncertain, mark as potentially valid this run
                    domains_resolved_valid.add(domain)

        for domain in domains_to_check:
             tasks.append(asyncio.create_task(check_and_update(domain)))

        # Wait for all checks to complete
        await asyncio.gather(*tasks, return_exceptions=True) # Handle potential exceptions during gather

    # Update the set of confirmed invalid domains
    confirmed_invalid_domains.update(newly_confirmed_invalid)
    # Remove domains from the invalid set if they resolved successfully this run
    # This handles cases where a previously invalid domain becomes valid again
    domains_to_remove_from_invalid = confirmed_invalid_domains.intersection(domains_resolved_valid)
    if domains_to_remove_from_invalid:
        logging.info(f"Removing {len(domains_to_remove_from_invalid)} domains from invalid cache as they resolved successfully now.")
        confirmed_invalid_domains.difference_update(domains_to_remove_from_invalid)

    # Save the final set of confirmed invalid domains to cache
    save_invalid_domain_cache(confirmed_invalid_domains)

    # Assemble the final list of valid rules, preserving order
    final_valid_rules = []
    processed_rules = set() # Avoid duplicates if a rule appears in multiple source lists mapped here

    # Add non-domain rules first
    for rule in rules_without_domain:
        if rule not in processed_rules:
            final_valid_rules.append((rule, original_rule_order.get(rule, float('inf'))))
            processed_rules.add(rule)

    # Add rules associated with valid or uncertain domains
    for domain, associated_rules in domains_map.items():
        if domain not in confirmed_invalid_domains:
            for rule in associated_rules:
                 if rule not in processed_rules:
                     final_valid_rules.append((rule, original_rule_order.get(rule, float('inf'))))
                     processed_rules.add(rule)
    
    # Sort based on original appearance order
    final_valid_rules.sort(key=lambda x: x[1])
    
    # Extract just the rule strings
    result_rules = [rule for rule, order in final_valid_rules]

    logging.info(f"Original rules input to filter: {len(rules)}, Filtered rules output: {len(result_rules)}. Removed {len(rules) - len(result_rules)} rules.")
    return result_rules


def generate_unique_rules(source_rules, *other_rule_lists):
    """Returns rules from source_rules that are not present in any other_rule_lists."""
    source_set = set(source_rules)
    exclude_set = set()
    for lst in other_rule_lists:
        exclude_set.update(lst)
    
    # Keep rules from source only if they are not in the exclude set
    unique = [rule for rule in source_rules if rule in source_set and rule not in exclude_set]
    logging.info(f"Generated {len(unique)} unique rules for source (had {len(source_rules)} rules initially).")
    return unique

def generate_header(title, rule_count):
    """Generates the adblock list header."""
    # Get current UTC time and format it for UTC+8
    utc_now = datetime.now(timezone.utc)
    utc8_tz = timezone(timedelta(hours=8))
    utc8_now = utc_now.astimezone(utc8_tz)
    # Format: YYYY/MM/DD HH:MM:SS TIMEZONE
    current_time_str = utc8_now.strftime('%Y/%m/%d %H:%M:%S %Z') 

    return [
        '[X Adguard Dns]', # Common header format
        f'! Title: {title}',
        f'! Expires: 1 day', # Standard expiry suggestion
        f'! Last modified: {current_time_str}',
        f'! Homepage: {HOMEPAGE_URL}', # Use configured homepage
        f'! Total count: {rule_count}'
    ]

def split_rules(rules):
    """Separates whitelist (@@) and blacklist rules, putting whitelist first."""
    whitelist = [rule for rule in rules if rule.startswith('@@')]
    blacklist = [rule for rule in rules if not rule.startswith('@@')]
    return whitelist + blacklist

def write_rules_file(filename, title, rules):
    """Writes the rules to a file with the generated header."""
    # Split rules into whitelist/blacklist before counting and writing
    processed_rules = split_rules(rules)
    header = generate_header(title, len(processed_rules))
    
    logging.info(f"Writing {len(processed_rules)} rules to {filename}...")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n') # Header followed by blank line
            f.write('\n'.join(processed_rules) + '\n') # Rules, ensuring trailing newline
        logging.info(f"Successfully wrote {filename}")
    except IOError as e:
        logging.error(f"Error writing file {filename}: {e}")

# --- Main Execution Logic ---

async def main_async():
    """Main asynchronous function orchestrating the process."""
    logging.info("Starting adblock list processing...")
    
    # --- 1. Fetch all source rules ---
    fetched_rules = {}
    for key, url in SOURCES.items():
        # Fetching is blocking, run in executor or keep as is for simplicity in Actions
        fetched_rules[key] = fetch_rules(url)

    # --- 2. Calculate intermediate rule lists (before filtering) ---
    intermediate_rules = {}
    # a1: A - (B U C)
    intermediate_rules['a1'] = generate_unique_rules(
        fetched_rules['a'], 
        fetched_rules['b'], fetched_rules['c']
    )
    # b1: B - C
    intermediate_rules['b1'] = generate_unique_rules(
        fetched_rules['b'], 
        fetched_rules['c']
    )

    # --- 3. Combine all rules needing validation and filter them ---
    # Use dict.fromkeys to preserve order while getting unique rules
    all_rules_to_validate = list(dict.fromkeys(
        intermediate_rules['a1'] + intermediate_rules['b1']
    ))
    logging.info(f"Total unique rules across a1_raw & b1_raw to validate: {len(all_rules_to_validate)}")
    
    # Filter the combined list (utilizes cache for efficiency)
    # Set force_refresh=True if you want to ignore cache for this run
    valid_rules_after_filter = await filter_rules_async(all_rules_to_validate, force_refresh=False)
    valid_rules_set = set(valid_rules_after_filter) # Use set for fast lookups

    # --- 4. Generate final rule lists based on filtered results ---
    final_rules = {}
    final_rules['a1'] = [rule for rule in intermediate_rules['a1'] if rule in valid_rules_set]
    final_rules['b1'] = [rule for rule in intermediate_rules['b1'] if rule in valid_rules_set]
    
    # Combine a1 and b1 for the combined list
    # Use dict.fromkeys again for efficient combination and deduplication
    final_rules['a1b1'] = list(dict.fromkeys(final_rules['a1'] + final_rules['b1']))

    # --- 5. Write output files ---
    for key, definition in OUTPUT_FILES.items():
        if 'combine' in definition:
             # Handle combined files (already calculated)
             write_rules_file(f"{key}.txt", definition['title'], final_rules[key])
        else:
             # Handle files based on directly filtered intermediate results
             write_rules_file(f"{key}.txt", definition['title'], final_rules[key])
             
    logging.info("Adblock list processing finished successfully.")

if __name__ == '__main__':
    # Ensure the script runs the main asynchronous function
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    except Exception as e:
        logging.exception(f"An unhandled error occurred: {e}") # Log traceback
