import requests
from datetime import datetime, timedelta

# 获取规则文件内容并保持原始顺序
def fetch_rules(url):
    response = requests.get(url)
    response.raise_for_status()
    # 按行分割并去除空行和注释行，保持原始顺序
    lines = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('!')]
    return lines

# 去重并生成新规则，保持原始顺序
def generate_unique_rules(source, *others):
    source_list = source.copy()  # 复制原始列表以保持顺序
    result = source_list
    for other in others:
        common = set(source).intersection(set(other))  # 找到与每个 other 的共有规则
        # 按原始顺序过滤掉共有规则
        result = [rule for rule in result if rule not in common]
    return result

# 生成头部信息
def generate_header(title, rule_count):
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
    return [
        '[Adblock Plus]',
        f'! Title: {title}',
        '! Expires: 12 Hours',
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
    processed_rules = split_rules(rules)  # 分离白名单和黑名单
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

    # 生成 a1.txt（从 rules_a 中移除与 rules_b 的共有规则，再移除与 rules_c 的共有规则）
    a1_rules = generate_unique_rules(rules_a, rules_b, rules_c)
    write_rules_file('a1.txt', 'X dns - A1 Unique Rules', a1_rules)

    # 生成 b1.txt（从 rules_b 中移除与 rules_a 的共有规则，再移除与 rules_c 的共有规则）
    b1_rules = generate_unique_rules(rules_b, rules_a, rules_c)
    write_rules_file('b1.txt', 'X dns - B1 Unique Rules', b1_rules)

    # 合并 a1.txt 和 b1.txt 的规则，保持首次出现的顺序
    combined_rules_dict = {}
    for rule in a1_rules + b1_rules:
        if rule not in combined_rules_dict:
            combined_rules_dict[rule] = None
    combined_rules = list(combined_rules_dict.keys())
    write_rules_file('a1b1.txt', 'X dns', combined_rules)

if __name__ == '__main__':
    main()
