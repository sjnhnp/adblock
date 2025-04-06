from playwright.sync_api import sync_playwright
import csv
import os
from datetime import datetime

# 配置
current_date = datetime.now().strftime("%Y-%m-%d")
target_url = f"https://radar.cloudflare.com/charts/TopDomainsTable/attachment?location=cn&value=100&endDate={current_date}"

def download_csv():
    print(f"正在访问: https://radar.cloudflare.com")
    with sync_playwright() as p:
        # 启动无头浏览器（可以设置为有头模式调试）
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # 访问主页以完成验证
        page.goto("https://radar.cloudflare.com")
        print("等待行为验证完成（可能需要几秒）...")
        page.wait_for_timeout(5000)  # 等待验证完成，时间可调整

        # 下载目标文件
        print(f"下载文件: {target_url}")
        page.goto(target_url)
        page.wait_for_timeout(5000)  # 等待下载

        # 假设文件自动下载到默认下载目录
        download_path = os.path.join(os.getcwd(), "downloads", "top_domains.csv")
        if not os.path.exists(download_path):
            raise Exception("下载文件未找到")

        # 移动文件到当前目录
        os.rename(download_path, "top_domains.csv")
        print("CSV 文件下载成功")

        browser.close()

# 将 CSV 转换为 AdGuard Home 白名单规则
def convert_to_adguard_whitelist():
    output_file = "100cn.txt"
    domains = []
    
    if not os.path.exists("top_domains.csv"):
        print("错误: top_domains.csv 不存在")
        return
    
    with open("top_domains.csv", "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            domain = row.get("Domain", "").strip()  # 假设列名为 "Domain"
            if domain:
                domains.append(domain)
    
    with open(output_file, "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(f"||{domain}^\n")
    
    print(f"已生成白名单文件: {output_file}, 共 {len(domains)} 个域名")

if __name__ == "__main__":
    try:
        download_csv()
        convert_to_adguard_whitelist()
        if os.path.exists("top_domains.csv"):
            os.remove("top_domains.csv")
            print("临时 CSV 文件已删除")
    except Exception as e:
        print(f"发生错误: {e}")
