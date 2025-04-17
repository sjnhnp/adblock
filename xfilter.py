import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple

async def fetch_and_parse_url(session: aiohttp.ClientSession, url: str) -> Tuple[List[str], Set[str], List[str]]:
    """
    从URL获取内容，并在单次遍历中提取规则（原始大小写和小写）以及注释

    Args:
        session (aiohttp.ClientSession): 用于发送HTTP请求的会话
        url (str): 要获取的规则列表URL

    Returns:
        Tuple[List[str], Set[str], List[str]]: 包含原始大小写规则列表、小写规则集合和注释列表的元组

    Raises:
        aiohttp.ClientError: 当HTTP请求失败时
        asyncio.TimeoutError: 当请求超时时
    """
    try:
        async with session.get(url, timeout=60) as response:  # 设置60秒超时
            response.raise_for_status()
            content = await response.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Error fetching {url}: {e}")
        return [], set(), []  # 返回空列表和集合，允许脚本继续运行

    rules_with_case = []
    rules_lower = set()
    comments = []
    
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('!'):
            if not any(stripped.startswith(prefix) for prefix in ['! Title:', '! Expires:', '! Last modified:', '! Total count:', '! Description:', '! Homepage:', '! Source:', '! Version:', '! Blocked Filters:']):
                comments.append(stripped)
        else:
            rules_with_case.append(stripped)
            rules_lower.add(stripped.lower())
    
    return rules_with_case, rules_lower, comments

async def filter_and_merge(goodbye_adblock_url: str, dns_url: str, allow_url: str, heidai_url: str, output_file: str):
    """
    过滤GOODBYEADS的adblock.txt，并与217heidai的规则合并

    此函数从多个URL获取广告拦截规则，过滤和合并这些规则，然后将结果写入输出文件。
    它保留原始规则的大小写和顺序，同时确保最终规则列表中不包含重复项。

    Args:
        goodbye_adblock_url (str): GOODBYEADS adblock规则的URL
        dns_url (str): DNS规则的URL
        allow_url (str): 白名单规则的URL
        heidai_url (str): 217heidai规则的URL
        output_file (str): 输出文件的路径

    Raises:
        aiohttp.ClientError: 当HTTP请求失败时
        asyncio.TimeoutError: 当请求超时时
        IOError: 当写入输出文件失败时
    """
    async with aiohttp.ClientSession() as session:
        # 并发获取所有规则列表
        tasks = [
            fetch_and_parse_url(session, goodbye_adblock_url),
            fetch_and_parse_url(session, dns_url),
            fetch_and_parse_url(session, allow_url),
            fetch_and_parse_url(session, heidai_url)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 检查结果，处理可能的异常
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"Error fetching rules from URL {i+1}: {result}")
            results[i] = ([], set(), [])  # 替换为空数据
    
    goodbye_rules, goodbye_lower, goodbye_comments = results[0]
    dns_rules, dns_lower, dns_comments = results[1]
    allow_rules, allow_lower, allow_comments = results[2]
    heidai_rules, heidai_lower, heidai_comments = results[3]
    
    # 过滤和合并规则
    filtered_goodbye_lower = goodbye_lower - dns_lower - allow_lower
    merged_rules_lower_set = filtered_goodbye_lower | heidai_lower
    
    # 保留原始大小写和顺序
    final_rules_with_case = []
    seen_lower = set()
    for rule in goodbye_rules + heidai_rules:
        rule_lower = rule.lower()
        if rule_lower in merged_rules_lower_set and rule_lower not in seen_lower:
            final_rules_with_case.append(rule)
            seen_lower.add(rule_lower)
    
    # 合并所有注释
    all_comments = sorted(set(goodbye_comments + dns_comments + allow_comments + heidai_comments))
    
    # 生成自定义头部信息，使用北京时间 (UTC+8)
    current_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
    header = [
        '[Adblock Plus]',
        '! Title: X Filter',
        '! Expires: 12 Hours',
        f'! Last modified: {current_time}',
        f'! Total count: {len(merged_rules_lower_set)}'
    ]
    
    # 写入新文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header) + '\n\n')
            f.write('\n'.join(all_comments) + '\n\n')
            f.write('\n'.join(final_rules_with_case) + '\n')
    except IOError as e:
        print(f"Error writing to output file: {e}")
        raise
    
    print(f"合并完成，结果已保存到 {output_file}")
    print(f"GOODBYEADS 原始规则数: {len(goodbye_rules)}")
    print(f"DNS 规则数: {len(dns_rules)}")
    print(f"白名单规则数: {len(allow_rules)}")
    print(f"GOODBYEADS 过滤后规则数: {len(filtered_goodbye_lower)}")
    print(f"217heidai 规则数: {len(heidai_rules)}")
    print(f"合并后规则数: {len(merged_rules_lower_set)}")
    print(f"总注释行数: {len(all_comments)}")

# 执行合并
if __name__ == "__main__":
    goodbye_adblock_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt"
    dns_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt"
    allow_url = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt"
    heidai_rule2_url = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt"
    
    try:
        asyncio.run(filter_and_merge(
            goodbye_adblock_url=goodbye_adblock_url,
            dns_url=dns_url,
            allow_url=allow_url,
            heidai_url=heidai_rule2_url,
            output_file='xfilter.txt'
        ))
    except Exception as e:
        print(f"An error occurred during execution: {e}")
        raise  # 重新抛出异常，确保GitHub Action失败
