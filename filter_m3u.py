#!/usr/bin/env python3
import requests
import re
import os
import sys # 导入sys模块以便使用sys.exit

# 输入M3U直播源的URL
M3U_URL = "https://raw.githubusercontent.com/vbskycn/iptv/refs/heads/master/tv/iptv4.m3u"
# 输出处理后的M3U文件名
OUTPUT_FILENAME = "filtered_iptv.m3u"

def filter_m3u(url, output_file):
    """
    从指定的URL获取M3U播放列表，过滤掉HTTP开头的频道，只保留HTTPS，
    并移除频道的tvg-logo属性，然后将结果保存到文件。
    """
    print(f"尝试从URL获取M3U文件: {url}")
    try:
        # 使用requests库下载M3U文件内容
        response = requests.get(url)
        # 检查HTTP响应状态码，如果不是200，则抛出异常
        response.raise_for_status()
        content = response.text
        print("M3U文件获取成功。")
    except requests.exceptions.RequestException as e:
        # 捕获下载过程中的异常，并打印错误信息
        print(f"获取M3U文件时发生错误: {e}")
        # 返回非零状态码，指示脚本执行失败，这对GitHub Actions很重要
        sys.exit(1) # 使用sys.exit(1)

    # 按行分割内容
    lines = content.splitlines()
    filtered_lines = []
    i = 0

    print("开始处理M3U内容...")
    # 保留M3U文件头（通常是第一行 #EXTM3U）
    if lines and lines[0].strip().startswith("#EXTM3U"):
         filtered_lines.append(lines[0].strip())
         i = 1 # 从第二行开始处理

    while i < len(lines):
        line = lines[i].strip() # 移除行首尾的空白字符

        if line.startswith("#EXTINF"):
            # 这是一个频道信息行 (#EXTINF)，期待下一行是对应的直播源URL
            # 检查是否还有下一行
            if i + 1 < len(lines):
                next_line = lines[i+1].strip()
                # 检查下一行是否是一个有效的URL行，并且以 https:// 开头
                # 一个URL行通常不以 # 开头
                if not next_line.startswith("#") and next_line.lower().startswith("https://"):
                    # 这是一个符合条件的HTTPS频道
                    # 在 #EXTINF 行中移除或清空 tvg-logo 属性
                    # 使用正则表达式找到 tvg-logo="..." 并替换为 tvg-logo=""
                    # 注意：group-title="..." 和 tvg-name="..." 等其他属性保持不变
                    modified_extinf = re.sub(r'tvg-logo="[^"]*"', 'tvg-logo=""', line)

                    # 添加修改后的 #EXTINF 行和对应的HTTPS URL行到结果列表
                    filtered_lines.append(modified_extinf)
                    filtered_lines.append(next_line)
                    # 因为处理了一对 (#EXTINF 和 URL)，所以跳过这两行
                    i += 2
                else:
                    # 下一行不是有效的HTTPS URL行（可能是HTTP URL，或者是另一个#EXTINF等）
                    # 丢弃当前的 #EXTINF 行及其下一行（如果下一行是URL）
                    print(f"丢弃非HTTPS频道或格式异常行 (EXTINF: {line}, Next: {lines[i+1].strip() if i+1 < len(lines) else 'EOF'})")
                    i += 2 # 丢弃 #EXTINF 行和下一行（无论是URL还是其他）
            else:
                # #EXTINF 是文件的最后一行，没有对应的URL行，丢弃
                print(f"丢弃没有对应URL行的 #EXTINF: {line}")
                i += 1
        elif line.startswith("#"):
             # 保留其他可能的注释行，如 #EXT-X-等，如果需要的话
             # filtered_lines.append(line) # 如果需要保留所有注释，取消注释此行
             i += 1 # 目前按需求只保留EXTM3U头和过滤后的频道对
        else:
            # 既不是#EXTM3U, #EXTINF, 也不是其他#开头的注释，可能是空行或者格式错误行，丢弃
            i += 1


    print(f"内容处理完成。保留了 {len([l for l in filtered_lines if not l.startswith('#')])} 个频道信息。") # 修正统计频道数量的方式

    # 将处理后的内容写入文件
    print(f"正在保存处理后的M3U文件到: {output_file}")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            # 使用换行符连接所有行，写入文件
            f.write("\n".join(filtered_lines))
        print("文件保存成功！")
    except IOError as e:
        # 捕获文件写入异常
        print(f"写入输出文件时发生错误: {e}")
        sys.exit(1) # 使用sys.exit(1)

if __name__ == "__main__":
    # 当脚本直接运行时，执行过滤函数
    # filter_m3u函数内部会在失败时调用sys.exit(1)
    filter_m3u(M3U_URL, OUTPUT_FILENAME)

    # 如果filter_m3u函数成功完成（没有调用sys.exit(1)），
    # 脚本会执行到这里。明确调用sys.exit(0)表示成功。
    print("脚本已成功完成所有操作。")
    sys.exit(0) # 明确以成功状态码退出
