import requests
import csv
from datetime import datetime
from twocaptcha import TwoCaptcha
import os

# 配置
API_KEY_2CAPTCHA = os.getenv("TWOCAPTCHA_API_KEY")  # 从环境变量读取 API 密钥
solver = TwoCaptcha(API_KEY_2CAPTCHA)
current_date = datetime.now().strftime("%Y-%m-%d")
target_url = f"https://radar.cloudflare.com/charts/TopDomainsTable/attachment?location=cn&value=100&endDate={current_date}"

# 请求头
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Referer": "https://radar.cloudflare.com",
    "Accept": "text/csv"
}

# 下载 CSV 文件（带验证码处理）
def download_csv():
    print(f"正在抓取: {target_url}")
    session = requests.Session()
    session.headers.update(headers)

    # 先访问主页检查是否需要验证码
    response = session.get("https://radar.cloudflare.com")
    print(f"主页响应状态码: {response.status_code}")
    if "cf-captcha" in response.text or response.status_code == 403:
        print("检测到验证码，正在使用 2Captcha 解决...")
        try:
            # 假设 Cloudflare 使用 hCaptcha 或 reCAPTCHA（需根据实际情况调整 sitekey）
            result = solver.hcaptcha(sitekey="YOUR_SITE_KEY", url="https://radar.cloudflare.com")
            captcha_solution = result["code"]
            print(f"验证码解决成功: {captcha_solution}")
            # 提交验证码（需要根据实际表单调整，此处为伪代码）
            response = session.post("https://radar.cloudflare.com", data={"g-recaptcha-response": captcha_solution})
        except Exception as e:
            print(f"验证码解决失败: {e}")
            return False

    # 下载目标文件
    response = session.get(target_url)
    print(f"目标 URL 响应状态码: {response.status_code}")
    if response.status_code == 200:
        with open("top_domains.csv", "wb") as f:
            f.write(response.content)
        print("CSV 文件下载成功")
        return True
    else:
        print(f"下载失败，响应内容: {response.text[:200]}")
        return False

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

# 主逻辑
if __name__ == "__main__":
    if download_csv():
        convert_to_adguard_whitelist()
        if os.path.exists("top_domains.csv"):
            os.remove("top_domains.csv")
            print("临时 CSV 文件已删除")
    else:
        print("抓取失败，请检查 URL 或网络连接")
