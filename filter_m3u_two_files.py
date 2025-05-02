#!/usr/bin/env python3
import requests
import re
import os
import sys
import time # 导入time模块用于添加延迟，避免请求过快

# 输入M3U直播源的URL
M3U_URL = "https://raw.githubusercontent.com/vbskycn/iptv/refs/heads/master/tv/iptv4.m3u"
# 输出处理后的只包含HTTPS的M3U文件名
OUTPUT_FILENAME_HTTPS = "filtered_https_only.m3u"
# 输出处理后的只包含有效HTTP的M3U文件名
OUTPUT_FILENAME_HTTP_VALID = "filtered_http_only_valid.m3u"

# 设置请求超时时间和重试次数
REQUEST_TIMEOUT = 5 # 秒
MAX_RETRIES = 2
RETRY_DELAY = 2 # 秒

def is_url_accessible(url):
    """
    检查URL是否可访问（返回2xx状态码）。
    使用HEAD请求以减少数据传输，如果HEAD不支持则尝试GET。
    """
    for attempt in range(MAX_RETRIES):
        try:
            # 尝试使用HEAD请求
            response = requests.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            print(f"  检查 {url} (HEAD): Status {response.status_code}")
            # 检查状态码是否是成功的 (2xx)
            if 200 <= response.status_code < 300:
                return True
        except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
            # HEAD请求失败，尝试使用GET请求头
            print(f"  HEAD请求失败或超时 {url}: {e}. 尝试GET请求头...")
            try:
                response = requests.get(url, timeout=REQUEST_TIMEOUT, stream=True, allow_redirects=True)
                # 即使是GET，也只读取响应头，不下载内容
                response.close() # 立即关闭连接，不下载响应体
                print(f"  检查 {url} (GET header): Status {response.status_code}")
                if 200 <= response.status_code < 300:
                     return True
            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e_get:
                 print(f"  GET请求头失败或超时 {url}: {e_get}. 尝试次数 {attempt + 1}/{MAX_RETRIES}")

        # 如果不是最后一次尝试，等待一段时间后重试
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY)

    # 所有尝试都失败
    print(f"  URL {url} 无法访问或超时 after {MAX_RETRIES} attempts.")
    return False

def filter_m3u_two_files(url, output_https, output_http_valid):
    """
    从指定的URL获取M3U播放列表，生成两个文件：
    一个只保留HTTPS频道，另一个只保留可访问的HTTP频道。
    同时移除所有频道的tvg-logo属性。
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
    https_lines = []
    http_valid_lines = []
    i = 0

    print("开始处理M3U内容...")

    # 保留M3U文件头 (#EXTM3U) 并添加到两个列表中
    header_line = ""
    if lines and lines[0].strip().startswith("#EXTM3U"):
         header_line = lines[0].strip()
         https_lines.append(header_line)
         http_valid_lines.append(header_line)
         i = 1 # 从第二行开始处理
    else:
         # 如果没有#EXTM3U头，也需要手动添加一个基本的，否则播放器可能无法识别
         header_line = "#EXTM3U"
         https_lines.append(header_line)
         http_valid_lines.append(header_line)


    processed_count = 0
    https_count = 0
    http_valid_count = 0

    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("#EXTINF"):
            # 这是一个频道信息行 (#EXTINF)，期待下一行是对应的直播源URL
            processed_count += 1
            # 检查是否还有下一行
            if i + 1 < len(lines):
                next_line = lines[i+1].strip()

                # 使用正则表达式移除或清空 tvg-logo 属性
                modified_extinf = re.sub(r'tvg-logo="[^"]*"', 'tvg-logo=""', line)

                # 检查下一行是否是一个有效的URL行 (不以#开头)
                if not next_line.startswith("#"):
                     url_candidate = next_line.lower()

                     if url_candidate.startswith("https://"):
                         # 这是一个HTTPS频道，添加到HTTPS列表中
                         https_lines.append(modified_extinf)
                         https_lines.append(next_line)
                         https_count += 1
                         # print(f"  找到HTTPS频道: {line} -> {next_line}")

                     elif url_candidate.startswith("http://"):
                         # 这是一个HTTP频道，检查其可访问性
                         print(f"  发现HTTP频道，检查可访问性: {line} -> {next_line}")
                         if is_url_accessible(next_line):
                             # 如果可访问，添加到HTTP有效列表中
                             http_valid_lines.append(modified_extinf)
                             http_valid_lines.append(next_line)
                             http_valid_count += 1
                             print(f"  HTTP频道有效并保留。")
                         else:
                             print(f"  HTTP频道无法访问，丢弃。")
                     else:
                          # URL格式不识别，丢弃这对行
                          print(f"  丢弃格式异常频道 (Unknown URL format): {line}, Next: {next_line}")
                else:
                    # 下一行不是URL行，丢弃这对行
                    print(f"  丢弃格式异常频道 (Next line not URL): {line}, Next: {next_line}")

                # 无论是否保留，都跳过当前的 #EXTINF 行和下一行 (URL 或其他)
                i += 2
            else:
                # #EXTINF 是文件的最后一行，没有对应的URL行，丢弃
                print(f"  丢弃没有对应URL行的 #EXTINF: {line}")
                i += 1
        elif line.startswith("#"):
             # 保留其他可能的注释行，如 #EXT-X-等，如果需要的话
             # filtered_lines.append(line) # 如果需要保留所有注释，取消注释此行
             i += 1 # 目前按需求只保留EXTM3U头和过滤后的频道对
        else:
            # 既不是#EXTM3U, #EXTINF, 也不是其他#开头的注释，可能是空行或者格式错误行，丢弃
            i += 1

    print(f"内容处理完成。")
    print(f"总处理频道对: {processed_count}")
    print(f"保留HTTPS频道: {https_count} 个")
    print(f"保留有效HTTP频道: {http_valid_count} 个")


    # 将处理后的HTTPS内容写入文件
    print(f"正在保存处理后的HTTPS文件到: {output_https}")
    try:
        with open(output_https, "w", encoding="utf-8") as f:
            f.write("\n".join(https_lines))
        print(f"文件 {output_https} 保存成功！")
    except IOError as e:
        print(f"写入文件 {output_https} 时发生错误: {e}")
        sys.exit(1)

    # 将处理后的有效HTTP内容写入文件
    print(f"正在保存处理后的有效HTTP文件到: {output_http_valid}")
    try:
        with open(output_http_valid, "w", encoding="utf-8") as f:
            f.write("\n".join(http_valid_lines))
        print(f"文件 {output_http_valid} 保存成功！")
    except IOError as e:
        print(f"写入文件 {output_http_valid} 时发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # 当脚本直接运行时，执行过滤函数
    # filter_m3u_two_files函数内部会在失败时调用sys.exit(1)
    filter_m3u_two_files(M3U_URL, OUTPUT_FILENAME_HTTPS, OUTPUT_FILENAME_HTTP_VALID)

    # 如果filter_m3u_two_files函数成功完成（没有调用sys.exit(1)），
    # 脚本会执行到这里。明确调用sys.exit(0)表示成功。
    print("脚本已成功完成所有操作并生成两个文件。")
    sys.exit(0) # 明确以成功状态码退出
