#!/usr/bin/env python3
import aiohttp
import asyncio
import argparse
import json
import logging
import os
import re
import sys
import urllib.parse
from typing import List, Dict, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

class Config:
    """全局配置常量"""
    REQUEST_TIMEOUT = 5  # 秒
    MAX_RETRIES = 2
    RETRY_DELAY = 2  # 秒
    MAX_WORKERS = 10  # 线程池最大工作线程数
    ATTRIBUTES_TO_REMOVE = ["tvg-logo"]  # 默认移除的M3U属性
    DEFAULT_M3U_URL = "https://raw.githubusercontent.com/vbskycn/iptv/refs/heads/master/tv/iptv4.m3u"
    DEFAULT_OUTPUT_HTTPS = "filtered_https_only.m3u"
    DEFAULT_OUTPUT_HTTP_VALID = "filtered_http_only_valid.m3u"

def load_config(config_file: str = "config.json") -> Dict:
    """从JSON配置文件加载配置，失败时返回默认配置"""
    default_config = {
        "m3u_url": Config.DEFAULT_M3U_URL,
        "output_https": Config.DEFAULT_OUTPUT_HTTPS,
        "output_http_valid": Config.DEFAULT_OUTPUT_HTTP_VALID,
        "attributes_to_remove": Config.ATTRIBUTES_TO_REMOVE,
        "request_timeout": Config.REQUEST_TIMEOUT,
        "max_retries": Config.MAX_RETRIES,
        "retry_delay": Config.RETRY_DELAY,
        "max_workers": Config.MAX_WORKERS
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            default_config.update(config)
            logger.info(f"已加载配置文件: {config_file}")
        except (IOError, json.JSONDecodeError) as e:
            logger.warning(f"加载配置文件 {config_file} 失败，使用默认配置: {e}")
    return default_config

async def is_url_accessible_async(url: str, session: aiohttp.ClientSession, cache: Dict[str, bool] = None) -> bool:
    """
    异步检查URL是否可访问（返回2xx状态码）。

    Args:
        url: 要检查的URL地址。
        session: aiohttp ClientSession 对象。
        cache: 用于存储URL检查结果的缓存字典。

    Returns:
        bool: 如果URL可访问返回True，否则返回False。
    """
    if cache and url in cache:
        logger.debug(f"使用缓存结果 for {url}: {cache[url]}")
        return cache[url]

    for attempt in range(Config.MAX_RETRIES):
        try:
            async with session.head(url, timeout=Config.REQUEST_TIMEOUT, allow_redirects=True) as response:
                logger.debug(f"检查 {url} (HEAD): Status {response.status}")
                if 200 <= response.status < 300:
                    if cache is not None:
                        cache[url] = True
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"HEAD请求失败 {url}: {e}. 尝试GET...")
            try:
                async with session.get(url, timeout=Config.REQUEST_TIMEOUT, allow_redirects=True) as response:
                    logger.debug(f"检查 {url} (GET): Status {response.status}")
                    if 200 <= response.status < 300:
                        if cache is not None:
                            cache[url] = True
                        return True
            except (aiohttp.ClientError, asyncio.TimeoutError) as e_get:
                logger.debug(f"GET请求失败 {url}: {e_get}. 尝试次数 {attempt + 1}/{Config.MAX_RETRIES}")
        if attempt < Config.MAX_RETRIES - 1:
            await asyncio.sleep(Config.RETRY_DELAY)

    logger.info(f"URL {url} 无法访问 after {Config.MAX_RETRIES} attempts.")
    if cache is not None:
        cache[url] = False
    return False

async def check_urls_async(urls: List[str], cache: Dict[str, bool]) -> List[bool]:
    """批量异步检查URL列表的可访问性"""
    async with aiohttp.ClientSession() as session:
        tasks = [is_url_accessible_async(url, session, cache) for url in urls]
        return await asyncio.gather(*tasks)

def remove_attributes(extinf_line: str, attributes: List[str]) -> str:
    """移除EXTINF行中的指定属性"""
    for attr in attributes:
        extinf_line = re.sub(rf'{attr}="[^"]*"', f'{attr}=""', extinf_line)
    return extinf_line

def is_ip_address(host: str) -> bool:
    """
    检查主机名是否为IP地址（IPv4或IPv6）。

    Args:
        host: URL的主机名部分。

    Returns:
        bool: 如果是IP地址返回True，否则返回False。
    """
    # IPv4 正则表达式
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # IPv6 正则表达式（简化的，包含压缩格式）
    ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"

    # 去掉IPv6地址的方括号（例如 [2001:db8::1]）
    host = host.strip("[]")

    return bool(re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host))

async def filter_m3u_two_files(url: str, output_https: str, output_http_valid: str, attributes_to_remove: List[str]) -> None:
    """
    从指定URL获取M3U播放列表，生成两个文件：一个只保留HTTPS频道，另一个只保留可访问的HTTP频道。
    HTTP地址如果是IP形式，直接丢弃。

    Args:
        url: M3U文件的URL。
        output_https: HTTPS频道的输出文件名。
        output_http_valid: 有效HTTP频道的输出文件名。
        attributes_to_remove: 要移除的M3U属性列表。
    """
    logger.info(f"尝试从URL获取M3U文件: {url}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=Config.REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                content = await response.text()
        logger.info("M3U文件获取成功。")
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"获取M3U文件时发生错误: {e}")
        sys.exit(1)

    lines = content.splitlines()
    https_lines: List[str] = []
    http_valid_lines: List[str] = []
    http_urls: List[str] = []
    url_cache: Dict[str, bool] = {}
    i = 0
    processed_count = https_count = http_valid_count = 0

    # 处理M3U文件头
    header_line = "#EXTM3U"
    if lines and lines[0].strip().startswith("#EXTM3U"):
        header_line = lines[0].strip()
        i = 1
    else:
        logger.warning("M3U文件缺少标准 #EXTM3U 头，已添加默认头。")
    https_lines.append(header_line)
    http_valid_lines.append(header_line)

    logger.info("开始处理M3U内容...")
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("#EXTINF"):
            processed_count += 1
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                modified_extinf = remove_attributes(line, attributes_to_remove)

                if not next_line.startswith("#"):
                    url_candidate = next_line.lower()
                    if url_candidate.startswith("https://"):
                        https_lines.extend([modified_extinf, next_line])
                        https_count += 1
                    elif url_candidate.startswith("http://"):
                        # 解析URL，提取主机名
                        parsed_url = urllib.parse.urlparse(next_line)
                        host = parsed_url.hostname
                        if host and is_ip_address(host):
                            logger.info(f"丢弃HTTP频道（IP地址形式）: {next_line}")
                        else:
                            http_urls.append(next_line)
                            http_valid_lines.append((modified_extinf, next_line))  # 临时存储，待检查
                    else:
                        logger.warning(f"丢弃格式异常频道 (Unknown URL format): {next_line}")
                else:
                    logger.warning(f"丢弃格式异常频道 (Next line not URL): {next_line}")
                i += 2
            else:
                logger.warning(f"丢弃没有对应URL行的 #EXTINF: {line}")
                i += 1
        else:
            i += 1

    # 批量检查HTTP URL
    if http_urls:
        logger.info(f"发现 {len(http_urls)} 个非IP地址的HTTP频道，开始批量检查可访问性...")
        results = await check_urls_async(http_urls, url_cache)
        http_valid_lines_final = [header_line]
        for (extinf, url), is_valid in zip(http_valid_lines[1:], results):
            if is_valid:
                http_valid_lines_final.extend([extinf, url])
                http_valid_count += 1
                logger.info(f"HTTP频道有效并保留: {url}")
            else:
                logger.info(f"HTTP频道无法访问，丢弃: {url}")
        http_valid_lines = http_valid_lines_final

    logger.info(f"内容处理完成。总处理频道对: {processed_count}, 保留HTTPS频道: {https_count}, 保留有效HTTP频道: {http_valid_count}")

    # 写入文件
    for lines, filename in [(https_lines, output_https), (http_valid_lines, output_http_valid)]:
        logger.info(f"正在保存文件到: {filename}")
        try:
            if os.path.exists(filename):
                logger.warning(f"文件 {filename} 已存在，将被覆盖。")
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            logger.info(f"文件 {filename} 保存成功！")
        except IOError as e:
            logger.error(f"写入文件 {filename} 时发生错误: {e}")
            sys.exit(1)

def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Filter M3U playlist into HTTPS and valid HTTP files.")
    parser.add_argument("--url", default=Config.DEFAULT_M3U_URL, help="URL of the M3U playlist")
    parser.add_argument("--https-output", default=Config.DEFAULT_OUTPUT_HTTPS, help="Output file for HTTPS channels")
    parser.add_argument("--http-output", default=Config.DEFAULT_OUTPUT_HTTP_VALID, help="Output file for valid HTTP channels")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    return parser.parse_args()

async def main():
    """主函数"""
    args = parse_args()
    config = load_config(args.config)
    await filter_m3u_two_files(
        args.url if args.url != Config.DEFAULT_M3U_URL else config["m3u_url"],
        args.https_output if args.https_output != Config.DEFAULT_OUTPUT_HTTPS else config["output_https"],
        args.http_output if args.http_output != Config.DEFAULT_OUTPUT_HTTP_VALID else config["output_http_valid"],
        config["attributes_to_remove"]
    )
    logger.info("脚本已成功完成所有操作并生成两个文件。")

if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
