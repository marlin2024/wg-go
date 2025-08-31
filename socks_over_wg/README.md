# socks over wg

一个“下游 SOCKS5 -> WireGuard(用户态) -> 上游(可选 SOCKS5-UDP)”的最小实现：
- 外层 WireGuard 传输：默认直接 IPv4 UDP；也可通过支持 UDP ASSOCIATE 的 SOCKS5 上游中继（`-wg-socks`）。
- 下游 SOCKS5 服务：基于 `things-go/go-socks5`，应用侧的 TCP 流量通过用户态 `netstack` 进入 WireGuard 隧道。
- 支持从 `wg.conf` 注入配置，或使用参数传入 Base64 密钥与 Endpoint。

## 主要特性
- 仅 IPv4 作为 WireGuard 外层出口（Endpoint 解析 A 记录）。
- 可选的 SOCKS5-UDP 外层中继（`-wg-socks`，支持 `-wg-socks-user/-wg-socks-pass`）。
- 下游 SOCKS5 的出站使用 `netstack`，应用侧流量实际走 WG 隧道。

## 快速开始

- 运行（从配置文件注入）：
```
go run ./socks_over_wg \
  -config socks_over_wg/wg.conf \
  -listen 127.0.0.1:9999
```

- 运行（显式参数）：
```
go run ./socks_over_wg \
  -listen 127.0.0.1:9999 \
  -wg-ip 172.16.0.2 \
  -wg-dns 1.1.1.1,1.0.0.1 \
  -mtu 1280 \
  -private-key BASE64_PRIVATE_KEY \
  -peer-public-key BASE64_PEER_PUB \
  -endpoint engage.cloudflareclient.com:2408 \
  -allowed-ips 0.0.0.0/0,::/0 \
  -keepalive 25
```

- 通过 SOCKS5-UDP 中继 WireGuard 外层：
```
go run ./socks_over_wg \
  -config socks_over_wg/wg.conf \
  -wg-socks 127.0.0.1:1080 \
  -wg-socks-user USER -wg-socks-pass PASS
```
> 注意：`-wg-socks` 所指的上游必须支持 UDP ASSOCIATE，否则 WG 外层无法建立。

## 测试
- TCP（经隧道）：
```
 curl -x socks5://77.238.237.224:20000 https://ipinfo.io/json
```

## 常用参数
- `-listen`: 下游 SOCKS5 监听地址（默认 `127.0.0.1:9999`）。
- `-config`: WireGuard 配置文件（如 `demo1/wg.conf`）。
- `-private-key`/`-peer-public-key`: Base64（在内部自动转 hex 以适配 wireguard-go）。
- `-endpoint`: 对端公网 `host:port`（仅解析 A 记录，外层仅 IPv4）。
- `-allowed-ips`: 逗号分隔的 CIDR，默认 `0.0.0.0/0,::/0`。
- `-wg-socks`/`-wg-socks-user`/`-wg-socks-pass`: 指定用于 WG 外层的 SOCKS5-UDP 上游与认证。
