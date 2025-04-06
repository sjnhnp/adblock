import requests
import os
import sys
from datetime import datetime, timedelta

# 配置
LOCATION_CODE = "CN"  # 中国地区
LIMIT = 100          # 前 100 个域名
OUTPUT_FILENAME_CN = "100cn.txt"  # 中国域名输出文件
OUTPUT_FILENAME_WORLD = "worldcn.txt"  # 合并后的输出文件
ADGUARD_PREFIX = "@@||"  # AdGuard 白名单前缀
ADGUARD_SUFFIX = "^"
BASE_URL = "https://api.cloudflare.com/client/v4"
API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")  # 从环境变量获取

def get_api_headers():
    if not API_TOKEN:
        print("错误: 未设置 CLOUDFLARE_API_TOKEN 环境变量", file=sys.stderr)
        sys.exit(1)
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }

def fetch_top_domains(location=None):
    url = f"{BASE_URL}/radar/ranking/top"
    headers = get_api_headers()
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    params = {
        "limit": LIMIT,
        "date": yesterday
    }
    if location:
        params["location"] = location
    print(f"请求 API: {url}, 参数: {params}")
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        data = response.json()
        if data.get("success") and "top_0" in data.get("result", {}):
            return data["result"]["top_0"]
        else:
            print(f"错误: API 返回数据中无域名或格式错误: {data}", file=sys.stderr)
            return None
    except requests.exceptions.RequestException as e:
        print(f"错误: API 请求失败: {e}", file=sys.stderr)
        if 'response' in locals():
            print(f"响应内容: {response.text[:200]}", file=sys.stderr)
        return None

def process_to_adguard_rules(api_data):
    if not api_data:
        return []
    rules = [f"{ADGUARD_PREFIX}{entry['domain']}{ADGUARD_SUFFIX}" for entry in api_data if entry.get("domain")]
    print(f"生成 {len(rules)} 条 AdGuard 白名单规则")
    return rules

def write_rules_to_file(rules, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(rules))
        print(f"已写入 {len(rules)} 条规则到 {filename}")
        return True
    except IOError as e:
        print(f"错误: 写入文件失败: {e}", file=sys.stderr)
        return False

def merge_and_deduplicate(cn_rules, world_rules):
    # 去重并合并，使用集合保持唯一性，同时保留原始顺序
    combined = list(dict.fromkeys(cn_rules + world_rules))
    print(f"合并后去重，共 {len(combined)} 条规则")
    return combined

if __name__ == "__main__":
    print("--- Cloudflare Top Domains to AdGuard Whitelist ---")
    
    # 获取中国前 100 名域名
    print("获取中国前 100 名域名...")
    cn_domains = fetch_top_domains(location=LOCATION_CODE)
    if not cn_domains:
        print("获取中国域名失败", file=sys.stderr)
        sys.exit(1)
    cn_rules = process_to_adguard_rules(cn_domains)
    write_rules_to_file(cn_rules, OUTPUT_FILENAME_CN)
    
    # 获取全球前 100 名域名
    print("获取全球前 100 名域名...")
    world_domains = fetch_top_domains(location=None)  # 不指定 location 获取全球数据
    if not world_domains:
        print("获取全球域名失败", file=sys.stderr)
        sys.exit(1)
    world_rules = process_to_adguard_rules(world_domains)
    
    # 合并并去重
    print("合并中国和全球域名并去重...")
    combined_rules = merge_and_deduplicate(cn_rules, world_rules)
    if combined_rules and write_rules_to_file(combined_rules, OUTPUT_FILENAME_WORLD):
        print("--- 任务成功完成 ---")
        sys.exit(0)
    
    print("任务失败", file=sys.stderr)
    sys.exit(1)
