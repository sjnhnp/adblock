import datetime
import csv
import io
import sys
import os
import cloudscraper # 用于绕过 Cloudflare

# --- 配置 ---
LOCATION_CODE = "cn"  # 区域代码 (中国)
LIMIT = 100          # 排名数量
OUTPUT_FILENAME = "100cn.txt" # 输出文件名
ADGUARD_PREFIX = "@@||" # AdGuard Home 白名单规则前缀
ADGUARD_SUFFIX = "^"   # AdGuard Home 白名单规则后缀
BASE_URL = "https://radar.cloudflare.com/charts/TopDomainsTable/attachment"
# --- 配置结束 ---

def get_download_url():
    """构建 Cloudflare Radar 的下载 URL"""
    today = datetime.date.today()
    end_date_str = today.strftime('%Y-%m-%d')
    url = f"{BASE_URL}?location={LOCATION_CODE}&value={LIMIT}&endDate={end_date_str}"
    print(f"目标下载 URL: {url}")
    return url

def download_csv(url):
    """使用 cloudscraper 下载 CSV 数据"""
    print("正在尝试下载 CSV 文件 (使用 cloudscraper 绕过 Cloudflare)...")
    scraper = cloudscraper.create_scraper()  # 创建一个 scraper 实例
    try:
        response = scraper.get(url, timeout=60) # 增加超时时间
        response.raise_for_status()  # 如果状态码不是 200 OK，则抛出异常
        print(f"下载成功! 状态码: {response.status_code}")

        # 检查 Content-Type 是否为 CSV
        content_type = response.headers.get('Content-Type', '')
        if 'text/csv' not in content_type:
            print(f"警告: 响应 Content-Type 不是 'text/csv'，而是 '{content_type}'. 尝试继续处理...")
            # print("响应内容预览:", response.text[:500]) # 打印前500个字符帮助调试

        return response.text # 返回文本内容
    except cloudscraper.exceptions.CloudflareChallengeError as e:
        print(f"错误: Cloudflare 质询失败: {e}", file=sys.stderr)
        sys.exit(1) # 脚本失败退出
    except requests.exceptions.RequestException as e:
        print(f"错误: 下载时发生网络错误: {e}", file=sys.stderr)
        sys.exit(1) # 脚本失败退出
    except Exception as e:
        print(f"错误: 下载过程中发生未知错误: {e}", file=sys.stderr)
        # 尝试打印响应内容以供调试
        try:
            print("响应状态码:", response.status_code)
            print("响应内容预览:", response.text[:500])
        except NameError:
            pass # response 可能未定义
        sys.exit(1)


def process_csv_to_adguard(csv_data):
    """解析 CSV 数据并转换为 AdGuard Home 白名单规则列表"""
    print("正在处理 CSV 数据...")
    whitelist_rules = []
    # 使用 io.StringIO 将字符串模拟成文件供 csv reader 使用
    csvfile = io.StringIO(csv_data)
    reader = csv.reader(csvfile)

    try:
        header = next(reader) # 读取并跳过表头
        print(f"CSV 表头: {header}")
        if not header or 'domain' not in [h.lower().strip() for h in header]:
             print("警告: 未在表头中找到 'domain' 列，将尝试使用第二列作为域名列。", file=sys.stderr)

        domain_col_index = -1
        # 尝试自动查找 'domain' 列的索引 (忽略大小写和空格)
        for i, col_name in enumerate(header):
            if col_name.lower().strip() == 'domain':
                domain_col_index = i
                break

        if domain_col_index == -1:
            # 如果找不到 'domain' 列，默认使用第二列 (索引 1)
            print("警告: 未找到明确的 'domain' 列，默认使用第二列 (索引 1)。")
            domain_col_index = 1 # 假设域名在第二列

        rank_col_index = 0 # 假设排名在第一列 (索引 0)

        processed_count = 0
        for i, row in enumerate(reader):
            if not row or len(row) <= domain_col_index:
                print(f"警告: 跳过格式不正确的行 {i+1}: {row}")
                continue
            try:
                # rank = row[rank_col_index].strip() # 排名
                domain = row[domain_col_index].strip() # 域名

                if domain: # 确保域名不为空
                    rule = f"{ADGUARD_PREFIX}{domain}{ADGUARD_SUFFIX}"
                    whitelist_rules.append(rule)
                    processed_count += 1
                else:
                    print(f"警告: 跳过排名 {row[rank_col_index].strip()} 的空域名行。")

            except IndexError:
                print(f"警告: 跳过格式不正确的行 {i+1} (列数不足): {row}")
                continue
            except Exception as e:
                print(f"警告: 处理行 {i+1} 时出错: {row} - {e}")
                continue

        print(f"成功处理 {processed_count} 个域名。")
        if processed_count == 0 and len(csv_data) > 100 : # 如果CSV有内容但没处理出域名
             print("错误：未能从CSV数据中提取任何域名。请检查CSV格式或脚本逻辑。", file=sys.stderr)
             print("CSV 内容预览:\n", csv_data[:1000])
             # sys.exit(1) # 考虑是否需要在此处强制退出

    except StopIteration:
        print("错误: CSV 文件为空或只有表头。", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"错误: 解析 CSV 时发生错误: {e}", file=sys.stderr)
        print("CSV 内容预览:\n", csv_data[:1000]) # 打印部分内容帮助调试
        sys.exit(1)

    return whitelist_rules

def write_output_file(rules):
    """将规则写入输出文件"""
    print(f"正在将 {len(rules)} 条规则写入文件: {OUTPUT_FILENAME}...")
    try:
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            for rule in rules:
                f.write(rule + '\n')
        print("文件写入成功!")
    except IOError as e:
        print(f"错误: 无法写入文件 {OUTPUT_FILENAME}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    print("--- Cloudflare CN Top 100 Whitelist Generator ---")
    download_url = get_download_url()
    csv_content = download_csv(download_url)
    if csv_content:
        adguard_rules = process_csv_to_adguard(csv_content)
        if adguard_rules:
             write_output_file(adguard_rules)
             print("--- 任务完成 ---")
        else:
             print("错误: 未能生成任何 AdGuard 规则。", file=sys.stderr)
             sys.exit(1)
