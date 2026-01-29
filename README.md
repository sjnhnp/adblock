# Adblock 规则与 IPTV 工具集

本仓库托管了一套自动化工作流，致力于构建、验证和维护高质量的广告拦截规则及 IPTV 播放列表。

> **状态**: 所有工作流均由 GitHub Actions 自动托管运行，确保持续集成与实时更新。

---

## 1. 🧹 IPTV 直播源清洗 (Filtered M3U)

**工作流:** `Update Filtered M3U`  
**更新频率:** `每 6 小时`  
**核心引擎:** `filter_m3u.py` (基于 Python 3.11 + `aiohttp` 异步并发)

该工作流从上游获取原始 M3U 列表，执行合并、深度清洗和有效性验证，最终生成纯净的高速列表。

### 核心处理逻辑
- **合并与去重**: 聚合多个上游源，并基于流媒体 URL 进行去重处理。
- **属性精简**: 自动剥离冗余的元数据（如 `tvg-logo`, `tvg-id`），显著减小文件体积。
- **协议分离**: 智能分离 **HTTPS** 与 **HTTP** 资源，适应不同播放器需求。
- **特定过滤**: 在 HTTPS 列表中自动剔除特定频道（如 CGTN）。
- **实时存活检测**: 针对 HTTP 直播源进行**实时连通性测试** (HEAD/GET 请求)。只有返回 `200 OK` 状态码的有效源才会被保留。同时，在特定输出中会剔除纯 IP 形式的 URL，优先保留域名形式的高质量源。

### 生成文件清单

| 文件名 | 说明 | 上游来源 |
| :--- | :--- | :--- |
| **[filtered_https_only.m3u](filtered_https_only.m3u)** | **纯 HTTPS 源**。安全性高，已剔除 CGTN，已精简元数据。 | `vbskycn/iptv`<br>`suxuang/myIPTV` |
| **[filtered_http_only_valid.m3u](filtered_http_only_valid.m3u)** | **HTTP 有效源**。经过**实时连通性验证**，仅保留可用源。已剔除纯 IP URL。 | `vbskycn/iptv`<br>`suxuang/myIPTV` |
| **[filtered_global_attributes_removed.m3u](filtered_global_attributes_removed.m3u)** | **Global 精简版**。基于 YueChan 全球源，仅执行属性移除，保留所有频道。 | `YueChan/Live` |

---

## 2. 🛡️ AdGuard DNS 过滤器 (X DNS)

**工作流:** `x abc dns1`  
**更新频率:** `每日 20:15 UTC` (北京时间次日凌晨 04:15)  
**核心引擎:** `adugarddns_script.py` (异步 DNS 验证)

专为 AdGuard Home 等 DNS 拦截器设计的高级规则生成器。通过实际 DNS 查询验证域名有效性，彻底清除"僵尸"规则。

### 核心处理逻辑
- **异步 DNS 验证**: 使用 `aiodns` 对数万条规则进行高并发 DNS 查询。
- **NXDOMAIN 清洗**: 如果域名已停止解析（返回 `NXDOMAIN`），将从列表中**自动移除**。这能有效防止规则库臃肿，提升解析性能。
- **智能缓存**: 内置 7 天验证结果缓存 (`domain_cache1.json`)，大幅减少重复查询，加速构建过程。
- **集合运算**: 通过集合差集运算生成独享规则 (A - B)。

### 生成文件清单

| 文件名 | 说明 | 逻辑 / 来源 |
| :--- | :--- | :--- |
| **[a11b11.txt](a11b11.txt)** | **推荐使用**。整合型高可用列表。包含 A 和 B 的有效规则。 | `源 A` + `源 B` (经过验证) |
| **[a11.txt](a11.txt)** |仅包含 **源 A** (GOODBYEADS) 的独有规则。 | `源 A` - `源 B` - `源 C` |
| **[b11.txt](b11.txt)** | 仅包含 **源 B** (Hagezi) 的独有规则。 | `源 B` - `源 C` |

**上游参考:**
- **源 A**: `GOODBYEADS/dns.txt`
- **源 B**: `hagezi/pro.mini.txt`
- **源 C**: `217heidai/adblockdnslite.txt` (仅作为减法基准)

---

## 3. ⚔️ 通用去广告规则 (X Filter)

**工作流:** `X Filter`  
**更新频率:** `每日 00:00 UTC` (北京时间 08:00)  
**核心引擎:** `xfilter.py`

适用于浏览器插件（如 uBlock Origin / Adblock Plus）的通用规则合集。

### 核心处理逻辑
- **高级合并策略**: 抓取多源规则并进行逻辑重组。
- **逻辑运算**: `(GOODBYEADS_Adblock - GOODBYEADS_DNS - GOODBYEADS_Allow) + 217heidai_Rules`
    - **去冲突**: 主动剔除纯 DNS 层面的规则及白名单规则，避免与浏览器插件逻辑冲突。
- **完整性保留**: 保持规则原始大小写，同时进行基于小写的去重。完整保留各源的注释信息。

### 生成文件清单

| 文件名 | 说明 |
| :--- | :--- |
| **[xfilter.txt](xfilter.txt)** | 最终生成的合并规则列表。 |

**上游来源:**
- `GOODBYEADS`: adblock.txt, dns.txt, allow.txt
- `217heidai`: adblockfilters.txt
