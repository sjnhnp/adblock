import requests
from datetime import datetime, timedelta
import re
import asyncio
import aiodns
import json
import os
import socket

# 自定义 DNS 服务器列表（Google 和 Cloudflare）
CUSTOM_DNS_SERVERS = [
    '8.8.8.8',  # Google Public DNS
    '1.1.1.1'   # Cloudflare DNS
]

# 缓存文件路径和过期时间
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

# 异步检查域名是否明确失效
async def check_domain(domain, resolver, retries=2):
    for attempt in range(retries):
        try:
            # 检查 A、AAAA、CNAME 记录
            for qtype in ('A', 'AAAA', 'CNAME'):
                try:
                    result = await resolver.query(domain, qtype)
                    if result:  # 存在任何记录则认为有效
                        return True
                except aiodns.error.DNSError as e:
                    if e.args[0] == 1:  # NXDOMAIN (域名不存在)
                        return False
                    # 其他错误（超时等）继续尝试其他记录类型
            # 如果没有任何记录，返回 False
            return False
        except Exception as e:
            if attempt == retries - 1:  # 最后一次尝试仍失败
                return False  # 多次超时且无记录，认为是明确失效
            await asyncio.sleep(1)  # 重试前等待1秒
    return False

# 加载缓存并检查过期
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
            now = datetime.now()
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
        json.dump(updated_cache, f, indent=2)

# 异步过滤规则，只移除明确失效的域名
async def filter_valid_rules_async(rules, force_refresh=False):
    cache = load_cache()  # 缓存中记录的是“明确失效”的域名（result=False）
    # 使用自定义 DNS 服务器初始化 resolver
    resolver = aiodns.DNSResolver(nameservers=CUSTOM_DNS_SERVERS, timeout=10)
    domains_to_check = {extract_domain(rule): rule for rule in rules if extract_domain(rule)}
    
    # 只验证不在缓存中或需要刷新的域名
    domains_to_validate = [d for d in domains_to_check.keys() if d not in cache or force_refresh]
    
    if domains_to_validate:
        tasks = [check_domain(domain, resolver) for domain in domains_to_validate]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 更新缓存，只记录明确失效的域名
        for domain, is_valid in zip(domains_to_validate, results):
            if not isinstance(is_valid, Exception):  # 避免异常影响判断
                if not is_valid:  # 明确失效
                    cache[domain] = False
    
    # 默认保留所有规则，除非缓存明确标记为失效
    valid_rules = [rule for rule in rules if (
        extract_domain(rule) is None or  # 非域名规则直接保留
        extract_domain(rule) not in cache or  # 未验证的保留
        cache.get(extract_domain(rule), True)  # 缓存中标记为 True 或未标记的保留
    )]
    save_cache(cache)
    return valid_rules

# 去重并生成新规则，保持原始顺序
def generate_unique_rules(source, *others):
    source_list = source.copy()
    result = source_list
    for other in others:
        common = set(source).intersection(set(other))
        result = [rule for rule in result if rule not in common]
    return result

# 生成头部信息（UTC+8）
def generate_header(title, rule_count):
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
    return [
        '[X adguard dns]',
        f'! Title: {title}',
        '! Expires: 24 Hours',
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
    a_url = 'https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt'
    b_url = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt'
    c_url = 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt'
    
    rules_a = fetch_rules(a_url)
    rules_b = fetch_rules(b_url)
    rules_c = fetch_rules(c_url)

    # 生成 a1.txt
    a1_rules_raw = generate_unique_rules(rules_a, rules_b, rules_c)
    a1_rules = asyncio.run(filter_valid_rules_async(a1_rules_raw))
    write_rules_file('a1.txt', 'X dns - A1 Unique Rules (Validated)', a1_rules)

    # 生成 b1.txt
    b1_rules_raw = generate_unique_rules(rules_b, rules_a, rules_c)
    b1_rules = asyncio.run(filter_valid_rules_async(b1_rules_raw))
    write_rules_file('b1.txt', 'X dns - B1 Unique Rules (Validated)', b1_rules)

    # 合并 a1 和 b1
    combined_rules_dict = {}
    for rule in a1_rules + b1_rules:
        if rule not in combined_rules_dict:
            combined_rules_dict[rule] = None
    combined_rules = list(combined_rules_dict.keys())
    write_rules_file('a1b1.txt', 'X dns (Validated)', combined_rules)

if __name__ == '__main__':
    main()
