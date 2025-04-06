import requests
from datetime import datetime, timedelta, timezone
import re
import asyncio
import aiodns
import json
import os
import logging

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 自定义 DNS 服务器列表 (可以添加更多备用)
CUSTOM_DNS_SERVERS = [
    '223.5.5.5',      # AliDNS
    '223.6.6.6',      # AliDNS Backup
    '119.29.29.29',   # DNSPod
    '9.9.9.9',   
    '8.8.8.8',        # Google Public DNS
    '8.8.4.4',        # Google Public DNS Backup
    '1.1.1.1',        # Cloudflare DNS
    '1.0.0.1'         # Cloudflare DNS Backup
]

# 缓存文件路径和过期时间
CACHE_FILE = "domain_cache.json"
CACHE_EXPIRY_DAYS = 7 # 缓存有效期延长至 7 天，减少重复查询

# 获取规则文件内容并保持原始顺序
def fetch_rules(url):
    logging.info(f"Fetching rules from: {url}")
    try:
        response = requests.get(url, timeout=60) # 增加超时时间
        response.raise_for_status()
        lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('!')]
        logging.info(f"Fetched {len(lines)} rules from {url}")
        return lines
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return [] # 返回空列表，避免后续出错

# 从规则中提取域名 (保持不变)
def extract_domain(rule):
    # 移除 @@ 前缀（白名单标记）和 || 或 | 域名前缀
    if rule.startswith('@@||'):
        rule = rule[4:]
    elif rule.startswith('||'):
        rule = rule[2:]
    elif rule.startswith('@@|'):
         rule = rule[3:]
    elif rule.startswith('|'):
         rule = rule[1:]
    
    # 移除可能存在的路径、参数、端口和 Adblock Plus 选项 (^, $, ~ 等)
    rule = rule.split('^')[0].split('$')[0].split('/')[0].split(':')[0].strip('*')
    
    # 基础域名有效性检查（允许国际化域名 Punycode）
    # 这个正则表达式比之前的更宽松一点，避免过滤掉一些特殊但有效的格式
    # 但主要依赖 DNS 查询来确认
    if re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$', rule):
        # 排除纯 IP 地址 (简单检查)
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', rule):
            return rule.lower() # 统一小写处理
    return None

# 异步检查域名是否明确失效 (检查 A 和 AAAA)
async def check_domain_is_nxdomain(domain, resolver, retries=1):
    """
    检查域名是否明确返回 NXDOMAIN (对 A 和 AAAA 记录)。
    返回 True 表示确认无效 (A 和 AAAA 均为 NXDOMAIN)，
    返回 False 表示有效、仅 IPv6/IPv4 或状态不确定。
    """
    nxdomain_code = aiodns.error.ARES_ENOTFOUND
    a_is_nxdomain = False
    aaaa_is_nxdomain = False

    # --- 内部辅助函数，用于执行单次查询并处理结果 ---
    async def perform_query(qtype):
        nonlocal a_is_nxdomain, aaaa_is_nxdomain
        try:
            logging.debug(f"Querying {qtype} record for '{domain}'")
            await resolver.query(domain, qtype)
            # 查询成功 (即使无记录，但非 NXDOMAIN 异常)
            logging.debug(f"{qtype} query for '{domain}' succeeded. Domain exists or state uncertain.")
            return False # 明确不是 NXDOMAIN

        except aiodns.error.DNSError as e:
            if e.args[0] == nxdomain_code:
                logging.debug(f"{qtype} query for '{domain}' resulted in NXDOMAIN.")
                if qtype == 'A': a_is_nxdomain = True
                if qtype == 'AAAA': aaaa_is_nxdomain = True
                return True # 明确是 NXDOMAIN
            elif e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED]:
                # 超时、服务器失败等暂时性错误
                logging.warning(f"{qtype} query for '{domain}' failed (non-NXDOMAIN error: {e.args[0]}).")
                raise # 重新抛出，由外层重试逻辑处理
            else:
                # 其他 DNS 错误
                logging.error(f"{qtype} query for '{domain}' failed with unexpected DNS error {e.args[0]}. Assuming non-NXDOMAIN.")
                return False # 保守处理，视为非 NXDOMAIN
        except Exception as e:
            # 其他网络等异常
            logging.error(f"Unexpected error checking {qtype} record for '{domain}': {e}. Assuming non-NXDOMAIN.")
            return False # 保守处理，视为非 NXDOMAIN

    # --- 重试循环 ---
    for attempt in range(retries + 1):
        a_is_nxdomain = False # 重置状态
        aaaa_is_nxdomain = False

        try:
            # 1. 检查 A 记录
            a_result_is_nx = await perform_query('A')

            if a_result_is_nx is False: # A 记录存在或状态不确定
                 logging.debug(f"Assuming '{domain}' is valid based on A record check result.")
                 return False # 直接判定为非确认无效

            # A 记录是 NXDOMAIN，继续检查 AAAA
            if a_is_nxdomain:
                # 2. 检查 AAAA 记录
                aaaa_result_is_nx = await perform_query('AAAA')

                if aaaa_result_is_nx is False: # AAAA 记录存在或状态不确定
                    logging.debug(f"Assuming '{domain}' is valid based on AAAA record check result (A was NXDOMAIN).")
                    return False # 判定为非确认无效 (可能是 IPv6 only)
                
                # A 和 AAAA 都明确是 NXDOMAIN
                if aaaa_is_nxdomain: # 双重确认
                     logging.info(f"Confirmed NXDOMAIN for '{domain}' (both A and AAAA).")
                     return True # 确认无效
            
            # 如果代码能执行到这里，说明 A 查询是 NXDOMAIN，但 AAAA 查询因为某种原因没有完成或结果不确定
            # 但外层循环会处理重试，这里不需要额外操作

        except aiodns.error.DNSError as e:
             # 捕获 perform_query 抛出的可重试错误
            if e.args[0] in [aiodns.error.ARES_ETIMEOUT, aiodns.error.ARES_ESERVFAIL, aiodns.error.ARES_EREFUSED]:
                if attempt < retries:
                    logging.warning(f"Retrying ({attempt+1}/{retries}) domain check for '{domain}' due to {e.args[0]}")
                    await asyncio.sleep(1 + attempt) # 退避等待
                    continue # 进入下一次重试
                else:
                    logging.error(f"Domain check for '{domain}' failed after {retries+1} attempts due to persistent non-NXDOMAIN errors. Assuming valid.")
                    return False # 重试耗尽，保守处理，视为非确认无效
            else:
                 # 捕获 perform_query 可能漏掉的其他 DNSError (理论上不应发生)
                 logging.error(f"Caught unexpected DNSError during check for '{domain}': {e}. Assuming valid.")
                 return False

        except Exception as e:
            # 捕获其他意外错误
            logging.error(f"Caught unexpected Exception during check for '{domain}': {e}. Assuming valid.")
            return False # 保守处理

        # 如果 perform_query 返回了 True (NXDOMAIN) 但条件判断未覆盖 (理论上不应发生)
        # 或者 A 记录非 NXDOMAIN 且 AAAA 未检查等情况 (逻辑上应已被处理)
        # 安全起见，如果循环正常结束一次而未返回，也视为非确认无效
        logging.debug(f"Attempt {attempt+1} for '{domain}' completed without definitive result, proceeding if retries remain.")


    # 如果所有重试都完成仍无定论 (理论上不太可能，除非全是可重试错误且耗尽重试次数)
    logging.warning(f"Domain check for '{domain}' inconclusive after all retries. Assuming valid.")
    return False # 最终的保守处理
    
# 加载缓存 (缓存现在存储的是确认无效的域名)
def load_invalid_domain_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                cache_data = json.load(f)
            now = datetime.now(timezone.utc)
            valid_cache = {}
            expiry_limit = now - timedelta(days=CACHE_EXPIRY_DAYS)
            
            # 兼容旧格式，并过滤过期条目
            for domain, entry in cache_data.items():
                timestamp_str = None
                is_invalid = False
                
                if isinstance(entry, dict) and 'timestamp' in entry: # 新格式 {"invalid": true, "timestamp": "..."} 或旧格式 {"result": false, "timestamp": "..."}
                   timestamp_str = entry.get('timestamp')
                   # 检查是否明确标记为无效 (新格式优先，兼容旧格式 result=False)
                   is_invalid = entry.get('invalid', entry.get('result') == False) 
                elif isinstance(entry, bool) and not entry : # 非常旧的格式，只存了 False
                    is_invalid = True
                    # 没有时间戳，可能需要重新检查，或者直接视为不过期？为安全起见，视为需要检查
                    continue # 跳过没有时间戳的旧格式

                if is_invalid and timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc) # 确保是 UTC
                        if timestamp > expiry_limit:
                            valid_cache[domain] = True # 值为 True 表示确认无效且未过期
                        else:
                             logging.info(f"Cache expired for invalid domain: {domain}")
                    except ValueError:
                         logging.warning(f"Invalid timestamp format in cache for domain: {domain}")
                         
            logging.info(f"Loaded {len(valid_cache)} non-expired invalid domains from cache.")
            return valid_cache
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Error loading cache file {CACHE_FILE}: {e}")
            return {}
    return {}

# 保存缓存 (只保存确认无效的域名)
def save_invalid_domain_cache(invalid_domains):
    cache_data = {}
    now_iso = datetime.now(timezone.utc).isoformat()
    for domain in invalid_domains:
        cache_data[domain] = {"invalid": True, "timestamp": now_iso} # 新格式
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logging.info(f"Saved {len(invalid_domains)} confirmed invalid domains to cache.")
    except IOError as e:
        logging.error(f"Error saving cache file {CACHE_FILE}: {e}")


# 异步过滤规则，只移除明确失效(NXDOMAIN)的域名
async def filter_rules_async(rules, force_refresh=False):
    invalid_domain_cache = load_invalid_domain_cache()
    resolver = aiodns.DNSResolver(nameservers=CUSTOM_DNS_SERVERS, timeout=5, tries=2) # aiodns内部的尝试次数

    domains_map = {} # {domain: [rule1, rule2, ...]}
    rules_without_domain = []
    for rule in rules:
        domain = extract_domain(rule)
        if domain:
            if domain not in domains_map:
                domains_map[domain] = []
            domains_map[domain].append(rule)
        else:
            rules_without_domain.append(rule) # 保留非域名规则

    # 确定需要实际检查的域名
    domains_to_check = []
    if force_refresh:
        domains_to_check = list(domains_map.keys())
        logging.info("Force refresh requested, checking all domains.")
    else:
        domains_to_check = [d for d in domains_map.keys() if d not in invalid_domain_cache]
        logging.info(f"Checking {len(domains_to_check)} domains not in valid cache.")
        # 添加一些日志显示被缓存跳过的数量
        skipped_count = len(domains_map) - len(domains_to_check)
        if skipped_count > 0:
            logging.info(f"Skipping {skipped_count} domains found in invalid domain cache.")


    # 执行检查
    confirmed_invalid_domains = set(invalid_domain_cache.keys()) # 从缓存初始化
    
    if domains_to_check:
        tasks = {domain: asyncio.create_task(check_domain_is_nxdomain(domain, resolver)) for domain in domains_to_check}
        
        batch_size = 200 # 同时处理的并发任务数量，根据 Actions Runner 性能调整
        newly_confirmed_invalid = set()

        domain_list = list(tasks.keys())
        for i in range(0, len(domain_list), batch_size):
            batch_domains = domain_list[i:i+batch_size]
            batch_tasks = [tasks[d] for d in batch_domains]
            results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for domain, result in zip(batch_domains, results):
                if isinstance(result, Exception):
                    logging.error(f"Error during DNS check for {domain}: {result}")
                    # 出错时，保守处理，不认为它是无效的
                    if domain in confirmed_invalid_domains:
                         # 如果之前缓存是无效，但现在检查出错，暂时移除无效标记
                         confirmed_invalid_domains.remove(domain)
                elif result is True: # check_domain_is_nxdomain 返回 True 表示确认 NXDOMAIN
                    newly_confirmed_invalid.add(domain)
                elif domain in confirmed_invalid_domains:
                    # 如果检查结果不是 True (即不是 NXDOMAIN 或出错)，
                    # 且之前在缓存中是无效的，说明域名可能恢复了，从无效集合中移除
                    logging.info(f"Domain {domain} previously cached as invalid, now resolved or status uncertain. Removing from invalid set.")
                    confirmed_invalid_domains.remove(domain)
            
            logging.info(f"Processed batch {i//batch_size + 1}/{(len(domain_list) + batch_size - 1)//batch_size}. Confirmed {len(newly_confirmed_invalid)} new invalid domains so far.")
            await asyncio.sleep(0.5) # 短暂休息，避免过于频繁请求

        confirmed_invalid_domains.update(newly_confirmed_invalid)


    # 保存更新后的无效域名缓存
    save_invalid_domain_cache(confirmed_invalid_domains)

    # 构建最终的有效规则列表 (保持原始顺序)
    final_valid_rules = []
    processed_rules = set() # 用于处理同一个 rule 字符串出现在不同 list 的情况

    # 优先添加非域名规则
    for rule in rules_without_domain:
         if rule not in processed_rules:
              final_valid_rules.append(rule)
              processed_rules.add(rule)

    # 添加有效域名的规则
    original_rule_order = {rule: i for i, rule in enumerate(rules)} # 记录原始顺序

    valid_domain_rules = []
    for domain, associated_rules in domains_map.items():
        if domain not in confirmed_invalid_domains:
            for rule in associated_rules:
                 if rule not in processed_rules:
                     valid_domain_rules.append((rule, original_rule_order.get(rule, float('inf'))))
                     processed_rules.add(rule) # 标记已处理

    # 按原始顺序排序有效域名的规则
    valid_domain_rules.sort(key=lambda x: x[1])
    
    # 合并结果
    final_valid_rules.extend([rule for rule, order in valid_domain_rules])


    logging.info(f"Original rules: {len(rules)}, Filtered rules: {len(final_valid_rules)}. Removed {len(rules) - len(final_valid_rules)} rules associated with confirmed invalid domains.")
    return final_valid_rules


# 去重并生成新规则，保持原始顺序 (修改以适应需求)
def generate_unique_rules(source_rules, *other_rule_lists):
    """
    返回在 source_rules 中存在，但在所有 other_rule_lists 中都不存在的规则。
    保持 source_rules 的原始相对顺序。
    """
    source_set = set(source_rules)
    exclude_set = set()
    for lst in other_rule_lists:
        exclude_set.update(lst)
    
    unique = [rule for rule in source_rules if rule in source_set and rule not in exclude_set]
    logging.info(f"Generated {len(unique)} unique rules from source ({len(source_rules)}) excluding rules from {len(other_rule_lists)} other lists.")
    return unique

# 生成头部信息（UTC+8）(保持不变)
def generate_header(title, rule_count):
    # 获取当前的 UTC 时间
    utc_now = datetime.now(timezone.utc)
    # 转换为 UTC+8 时区
    utc8_tz = timezone(timedelta(hours=8))
    utc8_now = utc_now.astimezone(utc8_tz)
    current_time_str = utc8_now.strftime('%Y/%m/%d %H:%M:%S %Z') # 添加时区信息

    return [
        '[Adblock Plus 2.0]', # 更通用的 Header
        '! Title: {}'.format(title),
        '! Expires: 1 day', # Adblock 规范建议用天数
        '! Last modified: {}'.format(current_time_str),
        '! Homepage: https://github.com/your-repo-path', # 建议添加你的仓库地址
        '! Total count: {}'.format(rule_count)
    ]

# 分离白名单和黑名单，保持原始顺序 (保持不变)
def split_rules(rules):
    whitelist = [rule for rule in rules if rule.startswith('@@')]
    blacklist = [rule for rule in rules if not rule.startswith('@@')]
    # 通常白名单优先，所以放前面
    return whitelist + blacklist

# 写入文件 (保持不变)
def write_rules_file(filename, title, rules):
    # 先分离白名单和黑名单，再生成头部 (因为头部需要最终规则数量)
    processed_rules = split_rules(rules)
    header = generate_header(title, len(processed_rules))
    
    logging.info(f"Writing {len(processed_rules)} rules to {filename}...")
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n') # Header 后空一行
            f.write('\n'.join(processed_rules) + '\n') # 文件末尾也加换行
        logging.info(f"Successfully wrote {filename}")
    except IOError as e:
        logging.error(f"Error writing file {filename}: {e}")


# 主逻辑 (添加异步运行和日志)
async def main_async():
    a_url = 'https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt'
    b_url = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt'
    c_url = 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt'

    # --- 1. 获取所有原始规则 ---
    # 注意：fetch_rules 是同步的，可以在异步函数外执行，或者用 asyncio.to_thread 包装
    # 为简单起见，这里直接调用
    rules_a = fetch_rules(a_url)
    rules_b = fetch_rules(b_url)
    rules_c = fetch_rules(c_url)

    if not rules_a and not rules_b and not rules_c:
         logging.error("Failed to fetch any rules. Exiting.")
         return

    # --- 2. 计算需要过滤的规则集合 ---
    # a1: A 中独有 (不在 B 或 C 中)
    a1_rules_raw = generate_unique_rules(rules_a, rules_b, rules_c)
    # b1: B 中独有 (不在 C 中) - 根据你的描述，似乎是这个意思？
    # 如果是 B 排除 A 和 C，则是 generate_unique_rules(rules_b, rules_a, rules_c)
    b1_rules_raw = generate_unique_rules(rules_b, rules_c) 
    
    # 合并所有需要验证的规则，去重以减少 DNS 查询次数
    all_rules_to_validate = list(dict.fromkeys(a1_rules_raw + b1_rules_raw)) # 去重并保持顺序
    logging.info(f"Total unique rules to validate (from a1_raw + b1_raw): {len(all_rules_to_validate)}")

    # --- 3. 过滤掉无效域名的规则 ---
    # 对合并后的列表进行一次性过滤，利用缓存效率更高
    # force_refresh=False 可以利用缓存，如果想强制检查所有域名，设为 True
    valid_rules_map = await filter_rules_async(all_rules_to_validate, force_refresh=False)
    valid_rules_set = set(valid_rules_map) # 转换为集合以便快速查找

    # --- 4. 根据过滤结果生成最终的 a1, b1 ---
    a1_rules_final = [rule for rule in a1_rules_raw if rule in valid_rules_set]
    b1_rules_final = [rule for rule in b1_rules_raw if rule in valid_rules_set]

    logging.info(f"Final a1 rule count: {len(a1_rules_final)}")
    logging.info(f"Final b1 rule count: {len(b1_rules_final)}")

    # --- 5. 写入 a1.txt 和 b1.txt ---
    write_rules_file('a1.txt', 'X dns - A1 Unique Rules (Validated)', a1_rules_final)
    write_rules_file('b1.txt', 'X dns - B1 Unique Rules (Validated)', b1_rules_final)

    # --- 6. 合并 a1 和 b1 生成 a1b1.txt ---
    # 合并时再次去重，理论上 a1 和 b1 不会有交集，但以防万一
    combined_rules = list(dict.fromkeys(a1_rules_final + b1_rules_final))
    # 合并后最好也按白名单/黑名单排序
    write_rules_file('a1b1.txt', 'X dns - Combined A1+B1 (Validated)', combined_rules)

    logging.info("Script finished successfully.")


if __name__ == '__main__':
    # 使用 asyncio.run() 来运行异步的 main 函数
    asyncio.run(main_async())
