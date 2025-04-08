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
