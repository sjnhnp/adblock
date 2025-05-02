#!/usr/bin/env python3
import requests
import re
import os

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
        exit(1)

    # 按行分割内容
    lines = content.splitlines()
    filtered_lines = []
    i = 0

    print("开始处理M3U内容...")
    while i < len(lines):
        line = lines[i].strip() # 移除行首尾的空白字符

        if line.startswith("#EXTM3U"):
            # 保留M3U文件头
            filtered_lines.append(line)
            i += 1
        elif line.startswith("#EXTINF"):
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
                    modified_extinf = re.sub(r'tvg-logo="[^"]*"', 'tvg-logo=""', line)

                    # 添加修改后的 #EXTINF 行和对应的HTTPS URL行到结果列表
                    filtered_lines.append(modified_extinf)
                    filtered_lines.append(next_line)
                    # 因为处理了一对 (#EXTINF 和 URL)，所以跳过这两行
                    i += 2
                else:
                    # 下一行不是有效的HTTPS URL行（可能是HTTP URL，或者是另一个#EXTINF等）
                    # 丢弃当前的 #EXTINF 行及其下一行（如果下一行是URL）
                    # 或者更简单的处理方式是：只丢弃当前的 #EXTINF 行，让循环自然处理下一行
                    # 例如：#EXTINF...\n#EXTINF...
                    # i在第一个#EXTINF，next_line是第二个#EXTINF。不以https://开头。
                    # 进入此else块，i += 1。循环下一轮，i在第二个#EXTINF，它会被再次处理。
                    # 这样处理确保即使格式略有偏差也能尽可能正确地处理。
                    print(f"丢弃非HTTPS频道或格式异常行 (EXTINF: {line}, Next: {lines[i+1].strip() if i+1 < len(lines) else 'EOF'})")
                    i += 1 # 丢弃当前的 #EXTINF 行
            else:
                # #EXTINF 是文件的最后一行，没有对应的URL行，丢弃
                print(f"丢弃没有对应URL行的 #EXTINF: {line}")
                i += 1
        else:
            # 其他类型的行（如注释 #EXT-X- 或空白行等），如果不是M3U头，则丢弃
            # 如果需要保留所有注释行，可以将此处的pass改为 filtered_lines.append(line)
            # 但根据需求，我们只关心过滤频道，所以只保留M3U头和过滤后的频道对
            # pass
            i += 1 # 丢弃当前不相关的行

    print(f"内容处理完成。保留了 {len(filtered_lines)} 行频道信息。")

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
        exit(1)

if __name__ == "__main__":
    # 当脚本直接运行时，执行过滤函数
    filter_m3u(M3U_URL, OUTPUT_FILENAME)
v
