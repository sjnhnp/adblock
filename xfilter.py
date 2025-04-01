import requests
from datetime import datetime, timedelta

def load_rules(url):
    """从 URL 获取规则，返回规则集合和注释行"""
    response = requests.get(url)
    response.raise_for_status()
    lines = response.text.splitlines()
    # 分离注释行和规则行（# 开头的也视为规则）
    comments = [line.strip() for line in lines if line.strip() and line.strip().startswith('!')]
    rules = [line.strip() for line in lines if line.strip() and not line.strip().startswith('!')]
    return rules, comments

def filter_and_merge(goodbye_adblock_url, dns_url, allow_url, heidai_url, output_file):
    """过滤 GOODBYEADS 的 adblock.txt，并与 217heidai 的规则2合并"""
    # 加载所有规则和注释
    goodbye_rules, goodbye_comments = load_rules(goodbye_adblock_url)
    dns_rules, dns_comments = load_rules(dns_url)
    allow_rules, allow_comments = load_rules(allow_url)
    heidai_rules, heidai_comments = load_rules(heidai_url)

    # 将规则转换为集合以便去重（保留大小写，用于后续过滤）
    goodbye_rules_set = set(rule.lower() for rule in goodbye_rules)
    dns_rules_set = set(rule.lower() for rule in dns_rules)
    allow_rules_set = set(rule.lower() for rule in allow_rules)
    heidai_rules_set = set(rule.lower() for rule in heidai_rules)

    # 从 GOODBYEADS 规则中移除 DNS 和白名单（基于小写去重）
    filtered_goodbye_rules_set = goodbye_rules_set - dns_rules_set - allow_rules_set

    # 合并 GOODBYEADS 和 217heidai 的规则（基于小写去重）
    merged_rules_set = filtered_goodbye_rules_set.union(heidai_rules_set)

    # 收集所有原始规则（保留大小写和顺序）
    all_rules_with_case = []
    seen_rules_lower = set()  # 用于跟踪已添加的规则（小写形式）
    for url in [goodbye_adblock_url, heidai_url]:  # 按顺序处理主要规则文件
        response = requests.get(url)
        response.raise_for_status()
        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('!'):
                rule_lower = stripped.lower()
                if rule_lower in merged_rules_set and rule_lower not in seen_rules_lower:
                    all_rules_with_case.append(stripped)  # 保留原始大小写和顺序
                    seen_rules_lower.add(rule_lower)

    # 收集所有注释行
    all_comments = []
    for url in [goodbye_adblock_url, dns_url, allow_url, heidai_url]:
        response = requests.get(url)
        response.raise_for_status()
        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped and stripped.startswith('!'):
                # 只保留非头部信息的注释行
                if not any(stripped.startswith(prefix) for prefix in ['! Title:', '! Expires:', '! Last modified:', '! Total count:', '! Description:', '! Homepage:', '! Source:', '! Version:', '! Blocked Filters:']):
                    all_comments.append(stripped)

    # 生成自定义头部信息，使用北京时间 (UTC+8)
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
    header = [
        '[Adblock Plus]',
        '! Title: X Filter',
        '! Expires: 12 Hours',
        f'! Last modified: {current_time}',
        f'! Total count: {len(merged_rules_set)}'
    ]

    # 写入新文件
    with open(output_file, 'w', encoding='utf-8') as f:
        # 写入头部信息
        for line in header:
            f.write(line + '\n')
        # 写入所有注释行（去重并按原始顺序）
        for comment in sorted(set(all_comments)):
            f.write(comment + '\n')
        # 写入合并后的规则（保留原始大小写和顺序）
        for rule in all_rules_with_case:
            f.write(rule + '\n')

    print(f"合并完成，结果已保存到 {output_file}")
    print(f"GOODBYEADS 原始规则数: {len(goodbye_rules)}")
    print(f"DNS 规则数: {len(dns_rules)}")
    print(f"白名单规则数: {len(allow_rules)}")
    print(f"GOODBYEADS 过滤后规则数: {len(filtered_goodbye_rules_set)}")
    print(f"217heidai 规则2 规则数: {len(heidai_rules)}")
    print(f"合并后规则数: {len(merged_rules_set)}")
    print(f"总注释行数: {len(set(all_comments))}")

# 执行合并
if __name__ == "__main__":
    goodbye_adblock_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt"
    dns_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt"
    allow_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt"
    heidai_rule2_url = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt"
    filter_and_merge(
        goodbye_adblock_url=goodbye_adblock_url,
        dns_url=dns_url,
        allow_url=allow_url,
        heidai_url=heidai_rule2_url,
        output_file='xfilter.txt'
    )
