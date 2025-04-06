import datetime
import csv
import io
import sys
import os
import cloudscraper # 用于绕过 Cloudflare
import requests # <--- 添加这一行来修复 NameError

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
    # 注意：Cloudflare URL 通常使用 *周日* 作为 endDate 来获取上一周的数据
    # 如果你需要严格的“今天”的数据，请确认 Cloudflare 是否提供
    # 让我们先用今天的日期试试
    end_date_str = today.strftime('%Y-%m-%d')
    url = f"{BASE_URL}?location={LOCATION_CODE}&value={LIMIT}&endDate={end_date_str}"
    print(f"目标下载 URL: {url}")
    return url

def download_csv(url):
    """使用 cloudscraper 下载 CSV 数据"""
    print("正在尝试下载 CSV 文件 (使用 cloudscraper 绕过 Cloudflare)...")
    # 添加一个常见的浏览器 User-Agent，有时会有帮助
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
    }
    scraper = cloudscraper.create_scraper(
         browser={ # 模拟一个常见的浏览器
            'browser': 'chrome',
            'platform': 'windows',
            'mobile': False
        }
    )

    try:
        response = scraper.get(url, timeout=90, headers=headers) # 增加超时时间并添加 headers
        print(f"请求已发送，服务器响应状态码: {response.status_code}") # 打印原始状态码

        # 检查是否是 403 Forbidden
        if response.status_code == 403:
             print("错误: 收到 403 Forbidden 错误。Cloudflare 拒绝了访问。", file=sys.stderr)
             print("这可能是因为 GitHub Actions IP 被阻止或 Cloudflare 防护增强。", file=sys.stderr)
             print("Cloudscraper 可能无法绕过此特定端点的保护。", file=sys.stderr)
             # 在这里决定如何处理：可以选择退出(1)或返回 None 让主程序知道失败
             # sys.exit(1)
             return None # 返回 None 表示下载失败

        response.raise_for_status()  # 如果状态码不是 200 OK (且不是刚处理的 403)，则抛出异常
        print("下载成功!")

        content_type = response.headers.get('Content-Type', '')
        if 'text/csv' not in content_type:
            print(f"警告: 响应 Content-Type 不是 'text/csv'，而是 '{content_type}'. 尝试继续处理...")

        return response.text

    except requests.exceptions.HTTPError as e:
        # 这个块现在可以正确捕捉到 raise_for_status 抛出的非 403 HTTP 错误
        print(f"错误: 下载时发生 HTTP 错误: {e}", file=sys.stderr)
        # 打印更多响应信息帮助调试
        print(f"响应内容预览 (如果可用): {response.text[:500]}", file=sys.stderr)
        return None # 返回 None 表示下载失败
    except cloudscraper.exceptions.CloudflareChallengeError as e:
        print(f"错误: Cloudflare 质询失败: {e}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e: # 现在可以正确捕捉 RequestException
        print(f"错误: 下载时发生网络错误: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"错误: 下载过程中发生未知错误: {e}", file=sys.stderr)
        # 尝试打印响应内容以供调试
        try:
            print("响应状态码:", response.status_code)
            print("响应内容预览:", response.text[:500])
        except NameError:
            pass # response 可能未定义
        return None


def process_csv_to_adguard(csv_data):
    """解析 CSV 数据并转换为 AdGuard Home 白名单规则列表"""
    # (这部分代码保持不变，假设其逻辑正确)
    print("正在处理 CSV 数据...")
    whitelist_rules = []
    csvfile = io.StringIO(csv_data)
    reader = csv.reader(csvfile)

    try:
        header = next(reader)
        print(f"CSV 表头: {header}")
        if not header or 'domain' not in [h.lower().strip() for h in header]:
             print("警告: 未在表头中找到 'domain' 列，将尝试使用第二列作为域名列。", file=sys.stderr)

        domain_col_index = -1
        for i, col_name in enumerate(header):
            if col_name.lower().strip() == 'domain':
                domain_col_index = i
                break

        if domain_col_index == -1:
            print("警告: 未找到明确的 'domain' 列，默认使用第二列 (索引 1)。")
            domain_col_index = 1

        rank_col_index = 0

        processed_count = 0
        for i, row in enumerate(reader):
            if not row or len(row) <= domain_col_index:
                print(f"警告: 跳过格式不正确的行 {i+1}: {row}")
                continue
            try:
                domain = row[domain_col_index].strip()
                if domain:
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
        if processed_count == 0 and len(csv_data) > 100 :
             print("错误：未能从CSV数据中提取任何域名。请检查CSV格式或脚本逻辑。", file=sys.stderr)
             print("CSV 内容预览:\n", csv_data[:1000])
             # 如果需要，可以在这里强制失败
             # return None

    except StopIteration:
        print("错误: CSV 文件为空或只有表头。", file=sys.stderr)
        return None # 返回 None 表示处理失败
    except Exception as e:
        print(f"错误: 解析 CSV 时发生错误: {e}", file=sys.stderr)
        print("CSV 内容预览:\n", csv_data[:1000])
        return None # 返回 None 表示处理失败

    return whitelist_rules


def write_output_file(rules):
    """将规则写入输出文件"""
    # (这部分代码保持不变)
    print(f"正在将 {len(rules)} 条规则写入文件: {OUTPUT_FILENAME}...")
    try:
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
            for rule in rules:
                f.write(rule + '\n')
        print("文件写入成功!")
        return True # 表示写入成功
    except IOError as e:
        print(f"错误: 无法写入文件 {OUTPUT_FILENAME}: {e}", file=sys.stderr)
        return False # 表示写入失败


if __name__ == "__main__":
    print("--- Cloudflare CN Top 100 Whitelist Generator ---")
    download_url = get_download_url()
    csv_content = download_csv(download_url)

    if csv_content: # 只有在下载成功时才继续
        adguard_rules = process_csv_to_adguard(csv_content)
        if adguard_rules: # 只有在处理成功时才写入
            write_succeeded = write_output_file(adguard_rules)
            if write_succeeded:
                print("--- 任务成功完成 ---")
                sys.exit(0) # 明确以成功状态退出
            else:
                print("错误: 文件写入失败。", file=sys.stderr)
                sys.exit(1) # 文件写入失败，脚本失败退出
        else:
             print("错误: 未能从下载的数据生成任何 AdGuard 规则。", file=sys.stderr)
             sys.exit(1) # 处理失败，脚本失败退出
    else:
        # 下载失败 (可能是 403 或其他网络问题)
        print("错误: 未能成功下载 CSV 文件。跳过后续步骤。", file=sys.stderr)
        # 在这里决定：是让 workflow 失败 (exit 1) 还是成功退出 (exit 0)
        # 如果希望 workflow 不显示失败，即使数据没更新，用 exit 0
        # 如果希望 workflow 显示失败，提醒你需要检查，用 exit 1
        sys.exit(1) # 默认设置为失败，以便 GitHub Actions 显示错误
