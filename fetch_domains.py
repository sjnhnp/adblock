import requests
import csv
from datetime import datetime
import os

# 获取当前日期（格式：YYYY-MM-DD）
current_date = datetime.now().strftime("%Y-%m-%d")
target_url = f"https://radar.cloudflare.com/charts/TopDomainsTable/attachment?location=cn&value=100&endDate={current_date}"

# 设置请求头以伪装浏览器
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Referer": "https://radar.cloudflare.com",
    "Accept": "text/csv"
}

# 下载 CSV 文件
def download_csv():
    print(f"正在抓取: {target_url}")
    response = requests.get(target_url, headers=headers)
    if response.status_code == 200:
        with open("top_domains.csv", "wb") as f:
            f.write(response.content)
        print("CSV 文件下载成功")
        return True
    else:
        print(f"下载失败，状态码: {response.status_code}")
        return False

# 将 CSV 转换为 AdGuard Home 白名单规则
def convert_to_adguard_whitelist():
    output_file = "100cn.txt"
    domains = []
    
    # 读取 CSV 文件
    with open("top_domains.csv", "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # 假设 CSV 包含 "Domain" 列，提取域名
            domain = row.get("Domain", "").strip()
            if domain:
                domains.append(domain)
    
    # 按排名顺序写入 AdGuard Home 格式
    with open(output_file, "w", encoding="utf-8") as f:
        for domain in domains:
            # AdGuard Home 白名单规则：||domain^
            f.write(f"||{domain}^\n")
    
    print(f"已生成白名单文件: {output_file}, 共 {len(domains)} 个域名")

# 主逻辑
if __name__ == "__main__":
    if download_csv():
        convert_to_adguard_whitelist()
        # 清理临时文件
        if os.path.exists("top_domains.csv"):
            os.remove("top_domains.csv")
            print("临时 CSV 文件已删除")
    else:
        print("抓取失败，请检查 URL 或网络连接")
