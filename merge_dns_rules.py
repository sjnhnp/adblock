import requests
from datetime import datetime
import pytz

# 定义三个规则源
SOURCES = [
    "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt"
]

# 北京时间
beijing_tz = pytz.timezone("Asia/Shanghai")
current_time = datetime.now(beijing_tz).strftime("%Y/%m/%d %H:%M:%S")

# 获取规则并去重
rules = set()
for url in SOURCES:
    response = requests.get(url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith(("!", "[", "#")):  # 跳过注释和头部
                rules.add(line)

# 生成头部信息
header = [
    "[Adblock Plus]",
    "! Title: Adguard Filter",
    "! Expires: 12 Hours",
    f"! Last modified: {current_time}  # 北京时间",
    f"! Total count: {len(rules)}"
]

# 写入文件
with open("output/adguard_dns_merged.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(header) + "\n")
    f.write("\n".join(sorted(rules)) + "\n")

print("规则合并完成！")
