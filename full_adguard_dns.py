import requests
from datetime import datetime, timedelta

# 定义三个规则源
urls = [
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
]

# 收集所有规则，保持原始顺序和大小写
rules = []
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            # 只添加有效规则，跳过注释和空行
            if line and not line.startswith(('#', '!')) and '||' in line and '^' in line:
                if line not in rules:  # 去重，保持首次出现的顺序
                    rules.append(line)
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")

# 生成头部信息（北京时间 UTC+8）
current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
header = [
    '[Adblock Plus]',
    '! Title: Adguard DNS',
    '! Expires: 12 Hours',
    f'! Last modified: {current_time}',
    f'! Total count: {len(rules)}'
]

# 合并头部和规则
output = '\n'.join(header + [''] + rules)

# 保存到文件，文件名改为 merged_adguard_dns.txt
with open('merged_adguard_dns.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f"Generated merged rules with {len(rules)} entries.")
