# 脚本名称: merge_adblock.py
# 功能: 从 GOODBYEADS 的 adblock.txt 中移除 dns.txt 和 allow.txt 的规则，并与 217heidai 的规则2合并去重（忽略大小写）

import requests

def load_rules(url):
    """从 URL 获取规则，返回规则集合（忽略大小写）"""
    response = requests.get(url)
    response.raise_for_status()
    lines = response.text.splitlines()
    # 去除空行和注释行（以 # 或 ! 开头），忽略大小写
    rules = {line.strip().lower() for line in lines if line.strip() and line.strip()[0] not in ['#', '!']}
    return rules

def filter_and_merge(goodbye_adblock_url, dns_url, allow_url, heidai_url, output_file):
    """过滤 GOODBYEADS 的 adblock.txt，并与 217heidai 的规则2合并"""
    # 加载所有规则
    goodbye_rules = load_rules(goodbye_adblock_url)
    dns_rules = load_rules(dns_url)
    allow_rules = load_rules(allow_url)
    heidai_rules = load_rules(heidai_url)

    # 从 GOODBYEADS 规则中移除 DNS 和白名单
    filtered_goodbye_rules = goodbye_rules - dns_rules - allow_rules

    # 合并 GOODBYEADS 和 217heidai 的规则并去重
    merged_rules = filtered_goodbye_rules.union(heidai_rules)

    # 写入新文件（保持原始大小写，需从原始数据中恢复）
    all_rules_with_case = {}
    for url in [goodbye_adblock_url, dns_url, allow_url, heidai_url]:
        response = requests.get(url)
        response.raise_for_status()
        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped and stripped[0] not in ['#', '!']:
                all_rules_with_case[stripped.lower()] = stripped

    # 只保留合并后的规则并写入
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('[Adblock Plus]\n')  # 添加 Adblock 文件头
        for rule_lower in sorted(merged_rules):
            f.write(all_rules_with_case[rule_lower] + '\n')

    print(f"合并完成，结果已保存到 {output_file}")
    print(f"GOODBYEADS 原始规则数: {len(goodbye_rules)}")
    print(f"DNS 规则数: {len(dns_rules)}")
    print(f"白名单规则数: {len(allow_rules)}")
    print(f"GOODBYEADS 过滤后规则数: {len(filtered_goodbye_rules)}")
    print(f"217heidai 规则2 规则数: {len(heidai_rules)}")
    print(f"合并后规则数: {len(merged_rules)}")

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
        output_file='merged_adblock.txt'
    )
