import requests
import os
import sys
from datetime import datetime

# 配置
LOCATION_CODE = "CN"  # 中国地区
LIMIT = 100          # 前 100 个域名
OUTPUT_FILENAME = "100cn.txt"
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

def fetch_top_domains():
    url = f"{BASE_URL}/radar/ranking/domains"  # 使用文档支持的端点
    headers = get_api_headers()
    params = {
        "location": LOCATION_CODE,
        "limit": LIMIT,
        "date": datetime.now().strftime("%Y-%m-%d")
    }
    print(f"请求 API: {url}, 参数: {params}")
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        data = response.json()
        if data.get("result", {}).get("top"):
            return data["result"]["top"]
        else:
            print(f"错误: API 返回数据中无域名: {data}", file=sys.stderr)
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

def write_rules_to_file(rules):
    try:
        with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
            f.write("\n".join(rules))
        print(f"已写入 {len(rules)} 条规则到 {OUTPUT_FILENAME}")
        return True
    except IOError as e:
        print(f"错误: 写入文件失败: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    print("--- Cloudflare Top Domains to AdGuard Whitelist ---")
    top_domains = fetch_top_domains()
    if top_domains:
        rules = process_to_adguard_rules(top_domains)
        if rules and write_rules_to_file(rules):
            print("--- 任务成功完成 ---")
            sys.exit(0)
    print("任务失败", file=sys.stderr)
    sys.exit(1)
