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
from typing import List, Dict, Optional, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

class Config:
    """全局默认配置常量"""
    REQUEST_TIMEOUT = 5  # 秒
    MAX_RETRIES = 2
    RETRY_DELAY = 2  # 秒
    # ATTRIBUTES_TO_REMOVE: 从 #EXTINF 行移除的属性列表
    ATTRIBUTES_TO_REMOVE = ["tvg-logo", "tvg-id"]
    DEFAULT_M3U_URL = "https://raw.githubusercontent.com/vbskycn/iptv/refs/heads/master/tv/iptv4.m3u"
    DEFAULT_OUTPUT_HTTPS = "filtered_https_only.m3u"
    DEFAULT_OUTPUT_HTTP_VALID = "filtered_http_only_valid.m3u"

def load_config(config_file: str = "config.json") -> Dict:
    """从JSON配置文件加载配置，失败时使用默认值"""
    default_config = {
        "m3u_url": Config.DEFAULT_M3U_URL,
        "output_https": Config.DEFAULT_OUTPUT_HTTPS,
        "output_http_valid": Config.DEFAULT_OUTPUT_HTTP_VALID,
        "attributes_to_remove": Config.ATTRIBUTES_TO_REMOVE,
        "request_timeout": Config.REQUEST_TIMEOUT,
        "max_retries": Config.MAX_RETRIES,
        "retry_delay": Config.RETRY_DELAY,
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            # 合并配置，用户配置优先
            merged_config = default_config.copy()
            merged_config.update(user_config)
            # 确保关键配置项存在（如果用户删除了某个键）
            for key in default_config:
                 if key not in merged_config:
                     merged_config[key] = default_config[key]
            logger.info(f"已加载配置文件: {config_file}")
            return merged_config
        except (IOError, json.JSONDecodeError) as e:
            logger.warning(f"加载配置文件 {config_file} 失败，使用默认配置: {e}")
            return default_config
    else:
        logger.info("未找到配置文件，使用默认配置。")
        return default_config

async def is_url_accessible_async(url: str, session: aiohttp.ClientSession, config: Dict, cache: Dict[str, bool]) -> bool:
    """
    异步检查URL是否可访问（返回2xx状态码）。
    使用配置中的超时、重试次数和延迟。
    """
    if url in cache:
        # logger.debug(f"使用缓存结果 for {url}: {cache[url]}")
        return cache[url]

    max_retries = config.get("max_retries", Config.MAX_RETRIES)
    request_timeout = config.get("request_timeout", Config.REQUEST_TIMEOUT)
    retry_delay = config.get("retry_delay", Config.RETRY_DELAY)
    is_accessible = False # 默认不可访问

    for attempt in range(max_retries):
        current_try = attempt + 1
        # 优先尝试 HEAD 请求
        try:
            # logger.debug(f"尝试 HEAD {url} (Attempt {current_try}/{max_retries})...")
            async with session.head(url, timeout=request_timeout, allow_redirects=True) as response:
                # logger.debug(f"检查 {url} (HEAD Attempt {current_try}/{max_retries}): Status {response.status}")
                is_accessible = 200 <= response.status < 300
                if is_accessible: break # 成功则跳出重试循环
                # 对于 4xx/5xx 错误，如果不是 405，可能无需尝试GET，直接进入下次重试或结束
                if response.status != 405: # 405 Method Not Allowed 需要尝试GET
                    logger.debug(f"HEAD 请求失败 (非405) {url}: Status {response.status}. Attempt {current_try}/{max_retries}")
                    # if 400 <= response.status < 500 and response.status != 405: break # 可选：如果是客户端错误，直接判定失败

        except (aiohttp.ClientResponseError) as e_head:
            logger.debug(f"HEAD 请求 HTTP 错误 {url}: Status {e_head.status}. Attempt {current_try}/{max_retries}")
            if e_head.status != 405: # 非405，直接准备下次重试或结束
                 pass # 继续到重试延迟或尝试GET
            # 如果是 405，则必须尝试 GET
        except (aiohttp.ClientConnectorError, aiohttp.ClientPayloadError, asyncio.TimeoutError) as e_head:
            logger.debug(f"HEAD 请求连接/超时/载荷失败 {url}: {type(e_head).__name__}. Attempt {current_try}/{max_retries}. 尝试GET...")
        except Exception as e_head: # 捕获其他潜在 aiohttp 异常
            logger.warning(f"HEAD 请求时发生意外错误 {url}: {e_head}. Attempt {current_try}/{max_retries}. 尝试GET...")

        # 如果HEAD失败 或 状态码指示需要尝试GET (e.g. 405), 尝试GET请求
        if not is_accessible:
            try:
                # logger.debug(f"尝试 GET {url} (Attempt {current_try}/{max_retries})...")
                async with session.get(url, timeout=request_timeout, allow_redirects=True) as response:
                    # 读取少量数据确保连接有效，但不下载整个流
                    try:
                        await asyncio.wait_for(response.content.readany(), timeout=request_timeout/2) # 尝试快速读取少量数据
                    except asyncio.TimeoutError:
                        logger.debug(f"GET {url} 读取初始数据超时，但连接可能已建立，检查状态码。")
                    except Exception as read_err:
                         logger.debug(f"GET {url} 读取初始数据时出错: {read_err}，检查状态码。")

                    # logger.debug(f"检查 {url} (GET Attempt {current_try}/{max_retries}): Status {response.status}")
                    is_accessible = 200 <= response.status < 300
                    if is_accessible: break # 成功则跳出重试循环
            except (aiohttp.ClientError, asyncio.TimeoutError) as e_get:
                logger.debug(f"GET 请求失败 {url}: {type(e_get).__name__}. Attempt {current_try}/{max_retries}")
            except Exception as e_get:
                 logger.warning(f"GET 请求时发生意外错误 {url}: {e_get}. Attempt {current_try}/{max_retries}")


        # 如果未成功且还有重试次数，则等待后重试
        if not is_accessible and attempt < max_retries - 1:
            # logger.debug(f"URL {url} 第 {current_try} 次尝试失败，等待 {retry_delay} 秒后重试...")
            await asyncio.sleep(retry_delay)

    # 记录最终结果到缓存
    cache[url] = is_accessible
    if not is_accessible:
        logger.info(f"URL {url} 最终判定为无法访问 after {max_retries} attempts.")
    # else: logger.debug(f"URL {url} 最终判定为可访问。")
    return is_accessible


async def check_urls_async(urls: List[str], config: Dict, cache: Dict[str, bool]) -> List[bool]:
    """批量异步检查URL列表的可访问性"""
    # 增加连接器设置以提高并发性，但要小心系统资源和目标服务器限制
    conn = aiohttp.TCPConnector(limit_per_host=20, limit=100, ssl=False) # ssl=False 忽略证书验证错误
    timeout = aiohttp.ClientTimeout(total=config.get("request_timeout", Config.REQUEST_TIMEOUT) * 1.5) # 设置总超时
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        tasks = [is_url_accessible_async(url, session, config, cache) for url in urls]
        results = await asyncio.gather(*tasks)
        return results

def remove_attributes(extinf_line: str, attributes_to_remove: List[str]) -> str:
    """从EXTINF行中完全移除指定的属性及其值"""
    modified_line = extinf_line
    for attr in attributes_to_remove:
        # 正则表达式查找 key="value" 或 key=value (无引号) 并移除，包括前面的空格
        # 模式解释:
        # \s+                  匹配属性名前的一个或多个空格
        # {re.escape(attr)}    匹配属性名 (转义特殊字符)
        # =                    匹配等号
        # (?:                  非捕获组，匹配值的两种形式
        #   "[^"]*"            匹配双引号括起来的值 (非贪婪)
        #   |                  或者
        #   '[^']*'            匹配单引号括起来的值 (非贪婪)
        #   |                  或者
        #   [^\s,]+            匹配不含空格或逗号的无引号值 (直到下一个空格或逗号停止)
        # )
        pattern = rf'\s+{re.escape(attr)}=(?:"[^"]*"|\'[^\']*\'|[^\s,]+)'
        modified_line = re.sub(pattern, '', modified_line, flags=re.IGNORECASE) # 忽略大小写匹配属性名
    return modified_line.strip() # 移除处理后可能产生的首尾多余空格

def is_ip_address(host: Optional[str]) -> bool:
    """
    检查主机名是否为IP地址（IPv4或IPv6）。
    更健壮的IPv6检查。
    """
    if not host:
        return False

    # 去掉IPv6地址可能的方括号和端口号
    if ':' in host and not host.startswith('['): # 可能是 IPv4:port
        host = host.split(':', 1)[0]
    elif host.startswith('['): # 可能是 [IPv6]:port 或 [IPv6]
        host = host.strip('[]')
        if ']:' in host: # 理论上解析后 hostname 不会包含这个，但以防万一
             host = host.split(']:', 1)[0]

    # IPv4 正则表达式
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.fullmatch(ipv4_pattern, host):
        return True

    # IPv6 正则表达式 (更通用)
    # Source: https://stackoverflow.com/a/17871737 combined with common sense checks
    # Checks for valid components and structure, including :: compression.
    try:
        # Python's ipaddress module is the most reliable way
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Fallback regex (less comprehensive than ipaddress but decent)
        # This regex is complex and might have edge cases, ipaddress is preferred.
        ipv6_pattern = r"^(?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){2}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:|(?:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))|(?:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}|(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::$"
        return bool(re.fullmatch(ipv6_pattern, host, re.IGNORECASE))
    except ImportError:
        logger.warning("ipaddress module not found. IPv6 validation might be less reliable.")
        # Use basic check if module not available (very rough)
        return ':' in host and host.count(':') >= 2


async def filter_m3u(config: Dict) -> None:
    """
    从指定URL获取M3U播放列表，过滤并生成两个文件：
    1. 只包含HTTPS频道的M3U。
    2. 只包含经检测有效的、非IP地址的HTTP频道的M3U。
    移除指定的#EXTINF属性。
    """
    m3u_url = config["m3u_url"]
    output_https = config["output_https"]
    output_http_valid = config["output_http_valid"]
    attributes_to_remove = config["attributes_to_remove"]
    request_timeout = config.get("request_timeout", Config.REQUEST_TIMEOUT)

    logger.info(f"开始处理 M3U: {m3u_url}")
    logger.info(f"HTTPS 输出文件: {output_https}")
    logger.info(f"有效HTTP 输出文件: {output_http_valid}")
    logger.info(f"将移除的属性: {attributes_to_remove}")

    content = ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(m3u_url, timeout=request_timeout*2) as response: # Give more time for initial download
                response.raise_for_status() # Raise exception for bad status codes
                content = await response.text(encoding='utf-8', errors='ignore') # Specify encoding
        logger.info("M3U文件获取成功。")
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"获取M3U文件时发生错误: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"获取M3U文件时发生未知错误: {e}")
        sys.exit(1)

    lines = content.splitlines()
    https_output_lines: List[str] = []
    http_to_check: List[Tuple[str, str]] = [] # Store (modified_extinf, url) for checking
    http_urls_to_check_set = set() # Use set for faster lookup during check phase
    url_cache: Dict[str, bool] = {} # Cache for URL accessibility checks

    m3u_header = ""
    if lines and lines[0].strip().startswith("#EXTM3U"):
        m3u_header = lines[0].strip()
        lines = lines[1:] # Process remaining lines
    else:
        logger.warning("M3U文件缺少标准 #EXTM3U 头，将添加默认头。")
        m3u_header = "#EXTM3U"

    https_output_lines.append(m3u_header)
    # http_valid_output_lines will be built after checking

    logger.info("开始解析和初步过滤M3U内容...")
    processed_count = 0
    https_count = 0
    http_ip_discarded_count = 0
    http_candidate_count = 0
    current_extinf = None

    for line in lines:
        line = line.strip()
        if not line: # Skip empty lines
            continue

        if line.startswith("#EXTINF"):
            current_extinf = remove_attributes(line, attributes_to_remove)
        elif current_extinf and not line.startswith("#"): # This should be the URL
            processed_count += 1
            url_candidate = line
            scheme = urllib.parse.urlparse(url_candidate.lower()).scheme

            if scheme == "https":
                https_output_lines.extend([current_extinf, url_candidate])
                https_count += 1
                # logger.debug(f"保留 HTTPS: {url_candidate}")
            elif scheme == "http":
                try:
                    parsed_url = urllib.parse.urlparse(url_candidate)
                    host = parsed_url.hostname
                except ValueError: # Handle potential invalid URLs early
                     logger.warning(f"无法解析的URL，丢弃: {url_candidate}")
                     current_extinf = None # Reset for next entry
                     continue

                if host and is_ip_address(host):
                    # logger.debug(f"丢弃 HTTP (IP地址): {url_candidate}")
                    http_ip_discarded_count += 1
                else:
                    # logger.debug(f"候选 HTTP (非IP): {url_candidate}")
                    # Avoid adding duplicate URLs to the check list
                    if url_candidate not in http_urls_to_check_set:
                         http_to_check.append((current_extinf, url_candidate))
                         http_urls_to_check_set.add(url_candidate)
                         http_candidate_count += 1
                    else:
                         # If URL is duplicate, still need EXTINF if it's different,
                         # but only check the URL once. For simplicity here, we add it
                         # and rely on check_urls_async's cache.
                         # More optimal: Store dict[url] -> list[extinf]
                         http_to_check.append((current_extinf, url_candidate)) # Add pair anyway
                         http_candidate_count += 1 # Count this instance


            else:
                logger.warning(f"丢弃未知协议或格式错误的频道: {url_candidate}")

            current_extinf = None # Reset after processing URL
        elif line.startswith("#"): # Keep other M3U tags (like #EXTVLCOPT) with HTTPS streams if needed?
            # Decide if other # lines should be kept. Currently only keeping #EXTM3U and #EXTINF/URL pairs.
            # If you want to keep other # lines associated with HTTPS:
            # if https_output_lines and https_output_lines[-1].startswith("https://"):
            #     https_output_lines.append(line)
            pass # Ignore other comment lines for now
        else: # Line is not #EXTINF, not URL, not # comment - likely malformed M3U entry part
             logger.warning(f"发现非标准行，忽略: {line}")
             current_extinf = None # Reset if sequence broken


    logger.info(f"初步解析完成。总处理频道条目: {processed_count}, HTTPS频道: {https_count}, HTTP IP频道(已丢弃): {http_ip_discarded_count}, HTTP候选频道(待检查): {http_candidate_count}")

    # 批量检查HTTP URL
    http_valid_output_lines: List[str] = [m3u_header]
    http_valid_count = 0
    if http_to_check:
        logger.info(f"开始批量检查 {len(http_urls_to_check_set)} 个唯一的 HTTP URL 的可访问性...")
        # Extract unique URLs for checking
        unique_http_urls = list(http_urls_to_check_set)
        results = await check_urls_async(unique_http_urls, config, url_cache)
        # Create a map from URL to its validity result
        validity_map = dict(zip(unique_http_urls, results))
        logger.info("HTTP URL 检查完成。")

        logger.info("构建有效的 HTTP 频道列表...")
        for extinf, url in http_to_check:
            if validity_map.get(url, False): # Get validity from map, default to False if somehow missing
                http_valid_output_lines.extend([extinf, url])
                http_valid_count += 1
                # logger.debug(f"保留有效 HTTP: {url}")
            # else: logger.debug(f"丢弃无效 HTTP: {url}")

    logger.info(f"HTTP 检查和过滤完成。保留有效HTTP频道: {http_valid_count}")

    # 写入文件
    output_files = {
        output_https: https_output_lines,
        output_http_valid: http_valid_output_lines
    }

    for filename, lines_to_write in output_files.items():
        logger.info(f"正在写入文件: {filename} (共 { (len(lines_to_write) -1) // 2 if len(lines_to_write) > 0 else 0 } 个频道)")
        try:
            # Ensure directory exists if path contains folders
            output_dir = os.path.dirname(filename)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                logger.info(f"创建目录: {output_dir}")

            with open(filename, "w", encoding="utf-8") as f:
                # Add a newline character between lines for proper M3U format
                f.write("\n".join(lines_to_write) + "\n") # Ensure trailing newline
            logger.info(f"文件 {filename} 保存成功！")
        except IOError as e:
            logger.error(f"写入文件 {filename} 时发生错误: {e}")
            # Continue to next file instead of exiting? Decide based on requirement.
            # sys.exit(1) # Exit if any write fails
        except Exception as e:
            logger.error(f"写入文件 {filename} 时发生未知错误: {e}")


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Filter M3U playlist into HTTPS and valid non-IP HTTP files, removing specified attributes.")
    # Allow overriding config values via CLI arguments
    parser.add_argument("--url", help=f"URL of the source M3U playlist (overrides config value). Default: {Config.DEFAULT_M3U_URL}")
    parser.add_argument("--https-output", help=f"Output file for HTTPS channels (overrides config value). Default: {Config.DEFAULT_OUTPUT_HTTPS}")
    parser.add_argument("--http-output", help=f"Output file for valid HTTP channels (overrides config value). Default: {Config.DEFAULT_OUTPUT_HTTP_VALID}")
    parser.add_argument("--config", default="config.json", help="Path to JSON configuration file.")
    # Add arguments for other config options if needed, e.g.:
    # parser.add_argument("--timeout", type=int, help="Request timeout in seconds (overrides config value)")
    return parser.parse_args()

async def main():
    """主函数入口"""
    args = parse_args()
    config = load_config(args.config)

    # Override config with CLI arguments if provided
    if args.url:
        config["m3u_url"] = args.url
    if args.https_output:
        config["output_https"] = args.https_output
    if args.http_output:
        config["output_http_valid"] = args.http_output
    # Example for overriding timeout:
    # if args.timeout is not None:
    #    config["request_timeout"] = args.timeout

    # Set global constants from final config (mainly for is_url_accessible_async if it doesn't receive config dict)
    # This part is less critical now as config dict is passed down
    Config.REQUEST_TIMEOUT = config["request_timeout"]
    Config.MAX_RETRIES = config["max_retries"]
    Config.RETRY_DELAY = config["retry_delay"]
    Config.ATTRIBUTES_TO_REMOVE = config["attributes_to_remove"]


    await filter_m3u(config)
    logger.info("脚本执行完毕。")

if __name__ == "__main__":
    # On Windows, the default event loop policy might cause issues with aiohttp.
    # Using the ProactorEventLoop can sometimes help, but SelectorEventLoop is often fine.
    # if sys.platform == "win32":
    #     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("脚本被用户中断。")
        sys.exit(1)
    except Exception as e:
         logger.exception(f"脚本执行过程中发生未捕获的异常: {e}")
         sys.exit(1)

