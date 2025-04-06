import os
import requests
from datetime import datetime, timedelta

# 获取环境变量中的 API Token
api_token = os.getenv("CLOUDFLARE_API_TOKEN")
if not api_token:
    print("错误: 未设置 CLOUDFLARE_API_TOKEN 环境变量")
    exit(1)

# 设置 API 请求
url = "https://api.cloudflare.com/client/v4/radar/ranking/top"
headers = {"Authorization": f"Bearer {api_token}"}
yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
params = {
    "location": "CN",
    "limit": 100,
    "date": yesterday
}

# 发送请求并调试输出
print(f"请求 API: {url}, 参数: {params}")
response = requests.get(url, headers=headers, params=params)
if response.status_code != 200:
    print(f"错误: API 请求失败: {response.status_code} {response.reason} for url: {response.url}")
    print(f"响应内容: {response.text}")
    exit(1)

# 解析响应
data = response.json()
if not data.get("success"):
    print(f"错误: API 返回失败: {data}")
    exit(1)

# 提取域名列表
domains = [item["domain"] for item in data["result"]["top_0"]]
print(f"成功获取 {len(domains)} 个域名")

# 写入文件
with open("100cn.txt", "w") as f:
    f.write("\n".join(domains))
print("域名已写入 100cn.txt")
