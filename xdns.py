import requests
from datetime import datetime, timedelta

# 定义三个规则源
urls = [
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
]

# 收集所有规则，分成白名单和黑名单两组，保持原始顺序和大小写
whitelist_rules = []  # 存储 @@|| 开头的白名单规则
blacklist_rules = []  # 存储 || 开头的黑名单规则

for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            # 只添加有效规则，跳过注释和空行
            if line and not line.startswith(('#', '!')) and '||' in line and '^' in line:
                if line.startswith('@@||') and line not in whitelist_rules:
                    whitelist_rules.append(line)  # 白名单去重
                elif line.startswith('||') and line not in blacklist_rules:
                    blacklist_rules.append(line)  # 黑名单去重
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")

# 合并白名单和黑名单规则，白名单在前，黑名单在后
rules = whitelist_rules + blacklist_rules

# 生成头部信息（北京时间 UTC+8）
current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
header = [
    '[Adblock Plus]',
    '! Title: X dns',
    '! Expires: 12 Hours',
    f'! Last modified: {current_time}',
    f'! Total count: {len(rules)}'
]

# 合并头部和规则
output = '\n'.join(header + [''] + rules)

with open('xdns.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f"Generated merged rules with {len(rules)} entries (Whitelist: {len(whitelist_rules)}, Blacklist: {len(blacklist_rules)}).")
