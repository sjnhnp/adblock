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

#### adguard 内容过滤器，用合并即可，因为是历遍所有规则，所以白名单不需要刻意排前
- xfilter


