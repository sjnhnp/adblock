import requests
from datetime import datetime, timedelta
import re
import asyncio
import aiodns
import json
import os
import socket

# 缓存文件路径
CACHE_FILE = "domain_cache.json"
CACHE_EXPIRY_HOURS = 24  # 缓存过期时间设为24小时

# 获取规则文件内容并保持原始顺序
def fetch_rules(url):
    response = requests.get(url)
    response.raise_for_status()
    lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('!')]
    return lines

# 从规则中提取域名
def extract_domain(rule):
    rule = rule.strip().replace('@@', '').replace('||', '').split('^')[0].split('/')[0]
    rule = re.sub(r'[\*\|\[\]]', '', rule)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-\.]*\.[a-zA-Z]{2,}$', rule):
        return rule
    return None

# 异步检查域名有效性
async def check_domain(domain, resolver):
    try:
        await resolver.gethostbyname(domain, socket.AF_INET)
        return True
    except Exception:
        return False

# 加载缓存并检查过期
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
            now = datetime.now()
            # 过滤掉过期的数据
            valid_cache = {}
            for domain, data in cache.items():
                timestamp = datetime.fromisoformat(data['timestamp'])
                if (now - timestamp).total_seconds() < CACHE_EXPIRY_HOURS * 3600:
                    valid_cache[domain] = data['result']
            return valid_cache
    return {}

# 保存缓存，记录验证时间
def save_cache(cache):
    now = datetime.now().isoformat()
    updated_cache = {domain: {"result": result, "timestamp": now} 
                     for domain, result in cache.items()}
    with open(CACHE_FILE, 'w') as f:
        json.dump(updated_cache, f, indent=2)  # 添加 indent 以便阅读

# 异步批量验证域名并过滤无效规则，支持失效检测
async def filter_valid_rules_async(rules, force_refresh=False):
    cache = load_cache()
    resolver = aiodns.DNSResolver(timeout=5)  # 设置 5 秒超时
    domains_to_check = {extract_domain(rule): rule for rule in rules if extract_domain(rule)}
    
    # 如果 force_refresh 为 True，强制重新验证所有域名
    if force_refresh:
        domains_to_validate = domains_to_check.keys()
    else:
        # 只验证不在缓存中或已过期的域名
        domains_to_validate = [domain for domain in domains_to_check.keys() if domain not in cache]
    
    if domains_to_validate:
        tasks = [check_domain(domain, resolver) for domain in domains_to_validate]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 更新缓存
        for domain, is_valid in zip(domains_to_validate, results):
            if not isinstance(is_valid, Exception):
                cache[domain] = is_valid
    
    # 过滤有效规则
    valid_rules = [domains_to_check[domain] for domain in domains_to_check if cache.get(domain, False)]
    save_cache(cache)
    return valid_rules

# 去重并生成新规则，保持原始顺序
def generate_unique_rules(source, *others):
    source_list = source.copy()
    result = source_list
    for other in others:
        common = set(source).intersection(set(other))  # 分别移除与每个规则集的共有规则
        result = [rule for rule in result if rule not in common]
    return result

# 生成头部信息（UTC+8）
def generate_header(title, rule_count):
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
    return [
        '[X adguard dns]',
        f'! Title: {title}',
        '! Expires: 24 Hours',  # 更新头部信息，与缓存一致
        f'! Last modified: {current_time}',
        f'! Total count: {rule_count}'
    ]

# 分离白名单和黑名单，保持原始顺序
def split_rules(rules):
    whitelist = [rule for rule in rules if rule.startswith('@@')]
    blacklist = [rule for rule in rules if not rule.startswith('@@')]
    return whitelist + blacklist

# 写入文件
def write_rules_file(filename, title, rules):
    processed_rules = split_rules(rules)
    header = generate_header(title, len(processed_rules))
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header) + '\n')
        f.write('\n'.join(processed_rules) + '\n')

# 主逻辑
def main():
    # 获取规则
    a_url = 'https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt'
    b_url = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt'
    c_url = 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt'
    
    rules_a = fetch_rules(a_url)
    rules_b = fetch_rules(b_url)
    rules_c = fetch_rules(c_url)

    # 生成 a1.txt（从 rules_a 中移除 rules_a ∩ rules_b 和 rules_a ∩ rules_c，并验证域名）
    a1_rules_raw = generate_unique_rules(rules_a, rules_b, rules_c)
    a1_rules = asyncio.run(filter_valid_rules_async(a1_rules_raw))
    write_rules_file('a1.txt', 'X dns - A1 Unique Rules (Validated)', a1_rules)

    # 生成 b1.txt（从 rules_b 中移除 rules_b ∩ rules_a 和 rules_b ∩ rules_c，并验证域名）
    b1_rules_raw = generate_unique_rules(rules_b, rules_a, rules_c)
    b1_rules = asyncio.run(filter_valid_rules_async(b1_rules_raw))
    write_rules_file('b1.txt', 'X dns - B1 Unique Rules (Validated)', b1_rules)

    # 合并 a1.txt 和 b1.txt 的规则，保持首次出现的顺序
    combined_rules_dict = {}
    for rule in a1_rules + b1_rules:
        if rule not in combined_rules_dict:
            combined_rules_dict[rule] = None
    combined_rules = list(combined_rules_dict.keys())
    write_rules_file('a1b1.txt', 'X dns (Validated)', combined_rules)

if __name__ == '__main__':
    main()
