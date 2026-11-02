# 浏览器实测、上传、DNS AAAA 与 QUIC/Hysteria2

日期：2026-11-03。环境：`wlan0`，Chrome（Playwright，headless），代理
`--family 6 --n 2 --spray 8 --timeout 3s`。每个站点直连/代理各 2 轮，fresh
context，记录 Navigation Timing、LCP、TTFB、wall。样本小，只代表这一时段。

## 1. 浏览器：哪些站点有实质提升

| 站点 | 直连 LCP | 代理 LCP | 直连 TTFB | 代理 TTFB | 直连 wall | 代理 wall |
|---|---:|---:|---:|---:|---:|---:|
| USTC 镜像 | 348ms | 368ms | 89ms | 86ms | 1675ms | 1669ms |
| 百度 | 212ms | 204ms | 75ms | 78ms | 1994ms | 1948ms |
| Cloudflare Speed | 272ms | 316ms | 80ms | 109ms | 2175ms | 2292ms |
| Comate | 582ms | **340ms** | 27ms | 33ms | 1731ms | 1678ms |
| DeepSeek | **1700ms** | **516ms** | **1404ms** | **195ms** | 3647ms | 2457ms |
| Bing | 364ms | 386ms | 134ms | 158ms | 1833ms | 1851ms |

结论：

- **DeepSeek 有实质提升**：直连两次 DNS 分别 1942ms / 634ms，LCP 1700ms；
  代理 LCP 516ms、TTFB 195ms。根因是 AAAA（见下），代理的并发 A/AAAA +
  缓存把等待消掉了。
- **Comate 有提升**：LCP 582→340ms，两轮都一致；更可能是 v6 首包/连接
  长尾被复读覆盖，不是带宽。
- **USTC/百度/Bing 基本持平**；代理在 20–30ms 内，属于噪声。
- **Cloudflare Speed 代理略慢 44ms**，页面触发了 Cloudflare challenge 401；
  这不是代理的吞吐问题。
- 直连和代理的 `nextHopProtocol` 都是 `h2`/`http/1.1`，没有看到 `h3`；
  Chrome 在配置代理时没有走 QUIC。代理的稳定收益在 **DNS/connect 长尾**，
  不是所有页面都更快。

页面里的 `localhost.weixin.qq.com:13xxx` 是 DeepSeek 的微信扫码登录探测，
本机没有微信客户端，所以直连 `CONNECTION_REFUSED`、代理
`TUNNEL_CONNECTION_FAILED`；这不是代理缺陷，页面主体正常加载。

## 2. 上传带宽

Cloudflare `__up`，100MB，IPv6：

| 方式 | 吞吐 | 总时间 | 代理 CPU | RSS |
|---|---:|---:|---:|---:|
| 直连 | 15.1 MB/s | 6.95s | — | — |
| 代理 | 11.1 MB/s | 9.43s | ≈0（<10ms ticks） | 17.46MB → 17.47MB |

上传方向代理慢约 26%；CPU 仍然接近 0，helper 0.01s。这说明上传不是 CPU
瓶颈，而是多了一跳用户态代理/两个 TCP socket 的传输路径；单次测量，网络
波动也会贡献一部分。下载方向此前没有出现明显回退，但上传需要更多轮次才能
给稳定结论。代理的 `io.Copy` 仍是 `splice`。

## 3. `chat.deepseek.com` 为什么有时卡：AAAA

A/AAAA 对照（UDP 53，2s 超时）：

| 域名 | A | AAAA |
|---|---|---|
| chat.deepseek.com | 腾讯/阿里/校园/114/Google 都 OK | 腾讯 SERVFAIL，阿里/校园/114/Google 超时或 SERVFAIL |
| mirrors.tuna / baidu / qq / aliyun / bing / cloudflare / ustc | OK | 都 OK |

所以 **不是所有 AAAA 都卡**；是 `chat.deepseek.com` 这一条特殊。

DoH（TCP 443）结果：

- `doh.pub`（腾讯）：AAAA 53ms，`Status 0`，只返回 CNAME，没有 AAAA；
- `dns.alidns.com`（阿里）：AAAA 28ms，只返回 CNAME + SOA，没有 AAAA；
- `dns.google` / `cloudflare-dns.com`：在校园网被超时/重置，不可用；
- A 查询：CNAME 到 `c51...vip1.huaweicloudwaf.com`，A 116.205.40.113/114。

`d3bbv8sr76az5s.cloudfront.net`（AAAA 曾出现的 CNAME 目标）在所有 UDP
resolver 上都没有 AAAA，A 是 3.173.21.63。也就是说 DeepSeek 的 AAAA
CNAME 目标本身没有 AAAA，站点是 v4-only；浏览器/`getaddrinfo` 在 UDP
AAAA 上等 6 秒（重试/超时），然后才回退 A，造成“有时秒开、有时卡一下”。

判断：

- **不是腾讯云 DNS 单独的问题**：腾讯/阿里/校园/114/Google 的 UDP AAAA 都
  失败；DoH 走 443 就正常。更像是校园/上游对这条 AAAA 的 UDP 过滤，叠加
  域名本身 AAAA CNAME 目标没有 AAAA。
- **不是全面 AAAA 劫持**：其他域名 AAAA 正常；`1.1.1.1` 的 A/AAAA 全部
  超时，说明 1.1.1.1 被校园拦截/本地接管，这是另一个问题。
- **腾讯 DoH/阿里 DoH 可用**，Cloudflare/Google DoH 被校园阻断。

修复：

- 代理已改为 **A/AAAA 并发查询**：AAAA 只等 500ms，A 快时再给 150ms 宽限，
  然后回退 A；DNS 结果缓存 30 秒。DeepSeek 的代理 LCP 从 1700ms 降到
  516ms。
- 浏览器直连可开 **Chrome Secure DNS / DoH**（腾讯 `doh.pub` 或阿里
  `dns.alidns.com`），绕开 UDP AAAA 过滤；或者使用本代理。
- 如果继续用系统 UDP DNS，`chat.deepseek.com` 的 AAAA 会周期性超时；
  “秒开”是 AAAA 失败结果被缓存/快速失败的时候，“卡一下”是重新等 AAAA
  超时的时候。

## 4. QUIC / Hysteria2 兼容性

- 本代理是 **TCP** HTTP CONNECT / SOCKS5 TCP + 可选 SOCKS5 UDP ASSOCIATE。
  浏览器配置 HTTP/SOCKS5 代理时会走 TCP，QUIC 会回退或禁用；实测
  `nextHopProtocol` 都是 h2/http1.1，没有 h3。
- **QUIC/HTTP3**：如果客户端支持 SOCKS5 UDP ASSOCIATE，可以把 QUIC 的 UDP
  5 元组交给代理；首包 16 连发，QUIC 自己按包号去重。Chrome 的 SOCKS5 不
  代理 UDP，所以浏览器场景需要 TUN/其它支持 UDP 的客户端。
- **Hysteria2**：它本身是 QUIC/UDP 代理协议，TCP CONNECT 代理不能承载。
  Hysteria2 客户端默认直接向服务器发 QUIC，不会走 SOCKS5 UDP；要套本代理，
  需要 TUN/透明重定向把它的 UDP 送到 SOCKS5 UDP，或客户端支持 UDP detour。
  这不是 drop-in 兼容；Hysteria2 自己的 Brutal/QUIC 也会重传，代理的 16 份
  首包只对“握手首包丢失”有帮助，且 UDP relay 是逐包用户态转发，高吞吐时
  CPU 比 TCP splice 高。

## 5. IPv4 多路径与源端口

- IPv4 出口已恢复全好桶；**多源端口竞速对成功率不再有收益**，但 `probe`
  仍有价值：周期性探测可以提前发现坏桶复发。正常流量建议 N=1/直连，
  探测到坏桶再切 N=5/8。IPv4 是计费的，N=5 的额外连接也有成本。
- **目标 IP 的运营商不会因为源端口改变**：目标前缀/ASN 固定。源端口改变的是
  校园出口的 **5 元组哈希桶/ECMP 成员**，可能换到不同的链路/上联，甚至在
  校园对同一前缀有多条等代价跨运营商路径时换出口；但不是把“电信目标”变成
  “联通目标”。之前的 8 桶位图和目的地分组说明的是出口成员/上联，不是目标
  运营商本身。回程路径也可能由对端/中间网络的逐流 ECMP 改变。
- 要确认某目标是否真的换运营商，用不同源端口做 `nexttrace`/`traceroute`，
  看前几跳/出口 ASN；目标 ASN 不会变。

## 复现

浏览器脚本思路：Chrome `--proxy-server=http://127.0.0.1:18080` vs
`--no-proxy-server`，fresh context，`domcontentloaded` + `load` + 1.5s，
读 Navigation Timing / paint / LCP。上传：`curl -x ... -X POST --data-binary`
到 `https://speed.cloudflare.com/__up`。DNS：UDP 53 多 resolver 对照 +
`doh.pub`/`dns.alidns.com` DoH。

仅在自己/授权网络测试；不要对第三方批量发起 SYN/UDP 探测。
