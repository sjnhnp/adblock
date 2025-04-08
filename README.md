# adblock上游如下，去重+合并

#### 上游
- https://github.com/8680/GOODBYEADS a 
- https://github.com/217heidai/adblockfilters c 1'lite
- https://github.com/hagezi/dns-blocklists b pro.mini

#### adguard dns：a1、b1、a1b1、xfilter
- a1：a dns-与b重复-与c重复-失效域名
- b1：b-与c重复-失效域名
- a1b1：a1+b1
- xfilter：a拦截规则-a dns- a白名单+c规则2filter

#### adguard home 或 adguard dns过滤器建议方案，排序如下，因为adguard dns 是按首次匹配立即停止
- [秋风规则](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
- c 1'lite
- b1
- a1
- [oisd nsfw small](https://nsfw-small.oisd.nl) 去色情NSFW domains found in the top 1 million domains (Using Tranco List)

#### adguard 内容过滤器，用合并即可，因为是历遍所有规则，所以白名单不需要刻意排前
- xfilter

#### adguard home 或 adguard 有相关功能
- 建议开启安全搜索
  - home里没有提供一些其他搜索，比如baidu，那么可以透过hagezi安全搜索黑名单禁用home之外的搜索。
- 如果中国大陆服务器开启家庭保护和安全浏览，可能会影响访问网站，因为大陆服务器不能顺利访问adguard的数据库服务器进行比对
- 如果不开启以上两者，可以透过过滤黑名单，比如nsfw去色情，其他相关可以去[hagezi](https://github.com/hagezi/dns-blocklists)寻找相关

