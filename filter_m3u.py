#!/usr/bin/env python3
import requests
import re
import os
import sys
import concurrent.futures # 用于并发执行任务
import time # 用于计时或等待

# 输入M3U直播源的URL
M3U_URL = "https://raw.githubusercontent.com/vbskycn/iptv/refs/heads/master/tv/iptv4.m3u"
# 输出处理后的M3U文件名
OUTPUT_FILENAME = "filtered_iptv.m3u"
# 请求超时时间 (秒)
REQUEST_TIMEOUT = 8
# 最大并发线程数
MAX_THREADS = 30

def is_url_accessible(url):
    """
    检查给定的URL是否可以通过HEAD或GET请求成功访问。
    返回 (url, True) 如果成功，否则返回 (url, False)。
    """
    try:
        # 尝试使用HEAD请求，更快，但有些服务器可能不支持
        # 如果HEAD失败或返回不允许的方法，则尝试GET
        try:
            response = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            # 检查状态码，2xx表示成功
            if 200 <= response.status_code < 300:
                 print(f"✅ 可访问: {url} (Status: {response.status_code})")
                 return (url, True)
            else:
                 print(f"❌ 不可访问: {url} (Status: {response.status_code})")
                 return (url, False)
        except (requests.exceptions.RequestException, requests.exceptions.InvalidMethod):
            # HEAD失败或不支持，尝试GET请求
            # stream=True 避免下载整个内容
            response = requests.get(url, timeout=REQUEST_TIMEOUT, stream=True, allow_redirects=True)
            # 检查状态码
            if 200 <= response.status_code < 300:
                 print(f"✅ 可访问: {url} (Status: {response.status_code})")
                 return (url, True)
            else:
                 print(f"❌ 不可访问: {url} (Status: {response.status_code})")
                 return (url, False)
        finally:
             if 'response' in locals() and response:
                 response.close() # 确保释放连接

    except requests.exceptions.Timeout:
        print(f"❌ 超时: {url}")
        return (url, False)
    except requests.exceptions.ConnectionError as e:
        print(f"❌ 连接错误: {url} - {e}")
        return (url, False)
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求错误: {url} - {e}")
        return (url, False)
    except Exception as e:
        # 捕获其他意外错误
        print(f"❌ 未知错误: {url} - {e}")
        return (url, False)


def filter_m3u_with_validation(url, output_file):
    """
    从指定的URL获取M3U播放列表，过滤掉HTTP开头的频道，只保留HTTPS，
    并检测HTTPS源的有效性，移除tvg-logo属性，然后将结果保存到文件。
    """
    print(f"尝试从URL获取M3U文件: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
        print("M3U文件获取成功。")
    except requests.exceptions.RequestException as e:
        print(f"获取M3U文件时发生错误: {e}")
        sys.exit(1)

    lines = content.splitlines()
    processed_lines = [] # 用于存放处理过程中的 EXTINF 和 URL 对
    header = "" # 用于存放M3U头
    i = 0

    # 查找并保留M3U文件头
    if lines and lines[0].strip().startswith("#EXTM3U"):
         header = lines[0].strip()
         i = 1 # 从第二行开始处理

    print("开始解析M3U内容并识别HTTPS频道...")
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("#EXTINF"):
            # 这是一个频道信息行 (#EXTINF)
            if i + 1 < len(lines):
                next_line = lines[i+1].strip()
                # 检查下一行是否是非注释行且以 https:// 开头
                if not next_line.startswith("#") and next_line.lower().startswith("https://"):
                    # 这是一个潜在的HTTPS频道，移除tvg-logo属性
                    modified_extinf = re.sub(r'tvg-logo="[^"]*"', 'tvg-logo=""', line)
                    # 将 #EXTINF 行和 URL 行作为一个对存储起来待验证
                    processed_lines.append((modified_extinf, next_line))
                    i += 2 # 跳过EXTINF和URL行
                else:
                    # 非HTTPS URL 或格式异常，丢弃此EXTINF行和下一行（如果存在）
                    # print(f"丢弃非HTTPS频道或格式异常行 (EXTINF: {line}, Next: {lines[i+1].strip() if i+1 < len(lines) else 'EOF'})")
                    i += 2 # 跳过EXTINF和其后的一行
            else:
                # EXTINF是最后一行，没有对应URL，丢弃
                # print(f"丢弃没有对应URL行的 #EXTINF: {line}")
                i += 1
        elif line.startswith("#"):
             # 其他注释行，目前不处理（也不保留）
             i += 1
        else:
            # 非注释行，非EXTINF行，可能是空行或错误格式，丢弃
            i += 1

    print(f"解析完成。找到 {len(processed_lines)} 个潜在的HTTPS频道等待验证。")

    # -------------------------------------------------------------
    # 开始并发验证URL有效性
    print(f"开始验证 {len(processed_lines)} 个HTTPS频道链接的有效性 (最多 {MAX_THREADS} 个并发请求)...")
    valid_channels = []
    urls_to_check = [url for extinf, url in processed_lines]
    url_to_extinf = {url: extinf for extinf, url in processed_lines} # 建立URL到EXTINF的映射

    start_time = time.time()

    # 使用ThreadPoolExecutor进行并发验证
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # 提交任务并获取Future对象
        future_to_url = {executor.submit(is_url_accessible, url): url for url in urls_to_check}

        # 处理已完成的任务结果
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                # 获取任务返回结果 (url, True/False)
                checked_url, is_valid = future.result()
                if is_valid:
                    # 如果URL有效，根据URL找到对应的EXTINF行，并添加到有效频道列表
                    extinf_line = url_to_extinf[checked_url]
                    valid_channels.append((extinf_line, checked_url))
            except Exception as exc:
                # 捕获获取结果过程中的异常
                print(f"URL {url} 生成异常: {exc}")
                # 此时is_url_accessible函数应该已经打印了错误信息，这里不再重复

    end_time = time.time()
    print(f"验证完成。共耗时 {end_time - start_time:.2f} 秒。")
    # -------------------------------------------------------------

    # 构建最终的M3U内容
    final_lines = []
    if header:
        final_lines.append(header) # 添加M3U头

    # 添加经过验证的有效频道
    for extinf_line, url in valid_channels:
        final_lines.append(extinf_line)
        final_lines.append(url)

    print(f"有效且已过滤的频道数量: {len(valid_channels)}")


    # 将处理后的内容写入文件
    print(f"正在保存处理后的M3U文件到: {output_file}")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(final_lines))
        print("文件保存成功！")
    except IOError as e:
        print(f"写入输出文件时发生错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # 当脚本直接运行时，执行过滤和验证函数
    filter_m3u_with_validation(M3U_URL, OUTPUT_FILENAME)

    # 如果脚本执行到这里，表示所有操作（包括验证和文件写入）都成功完成
    print("脚本已成功完成所有操作并退出。")
    sys.exit(0) # 明确以成功状态码退出
