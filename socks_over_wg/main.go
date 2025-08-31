package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgnet "golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/ini.v1"
)

/* -------------------- IPv4-only Bind (direct UDP) -------------------- */

type v4OnlyBind struct {
	mu   sync.Mutex
	udp4 *net.UDPConn
	port uint16
}

func newV4OnlyBind() conn.Bind { return &v4OnlyBind{} }

func (b *v4OnlyBind) Open(uport uint16) (receivers []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: int(uport)}
	c, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, 0, err
	}
	b.udp4 = c
	if uport == 0 {
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			b.port = uint16(ua.Port)
		}
	} else {
		b.port = uport
	}

	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, nil
		}
		n, raddr, err := b.udp4.ReadFromUDP(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		ap, _ := netip.ParseAddrPort(raddr.String())
		eps[0] = &conn.StdNetEndpoint{AddrPort: ap}
		return 1, nil
	}

	return []conn.ReceiveFunc{recv}, b.port, nil
}

func (b *v4OnlyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp4 != nil {
		err := b.udp4.Close()
		b.udp4 = nil
		return err
	}
	return nil
}
func (b *v4OnlyBind) SetMark(_ uint32) error { return nil }
func (b *v4OnlyBind) Send(buffers [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.udp4
	b.mu.Unlock()
	if c == nil {
		return errors.New("bind closed")
	}
	sne, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return errors.New("endpoint type not supported")
	}
	ap := sne.AddrPort
	raddr := &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
	for _, buf := range buffers {
		if len(buf) == 0 {
			continue
		}
		if _, err := c.WriteToUDP(buf, raddr); err != nil {
			return err
		}
	}
	return nil
}
func (b *v4OnlyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ap, _ := netip.ParseAddrPort(net.JoinHostPort(ip4.String(), portStr))
			return &conn.StdNetEndpoint{AddrPort: ap}, nil
		}
		return nil, syscall.EAFNOSUPPORT
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve v4 failed for %s: %w", host, err)
	}
	ip4 := ips[0].To4()
	if ip4 == nil {
		return nil, syscall.EAFNOSUPPORT
	}
	ap, _ := netip.ParseAddrPort(net.JoinHostPort(ip4.String(), portStr))
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}
func (b *v4OnlyBind) BatchSize() int   { return 128 }
func (b *v4OnlyBind) NetworkCost() int { return 0 }

/* -------------------- SOCKS5-UDP Bind (WG over SOCKS5) -------------------- */
/*
   把 WireGuard 的外层 UDP 通过 SOCKS5 UDP ASSOCIATE 发送/接收。
   注意：要求上游 SOCKS5 支持 UDP。
*/

type socks5UDPBind struct {
	// config
	server  string // upstream socks5 host:port (IP 或域名皆可：这里用系统解析)
	user    string
	pass    string
	timeout time.Duration

	// state
	mu        sync.Mutex
	tcpCtrl   net.Conn     // 维持 UDP ASSOCIATE 的 TCP 控制连接
	udpCli    *net.UDPConn // 本地 UDP socket
	relayAddr *net.UDPAddr // 服务端返回的 UDP 中继地址
	port      uint16
}

func newSocks5UDPBind(server, user, pass string, timeout time.Duration) conn.Bind {
	return &socks5UDPBind{server: server, user: user, pass: pass, timeout: timeout}
}

func (b *socks5UDPBind) Open(uport uint16) (receivers []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1) 建立到 SOCKS5 的 TCP 控制连接
	dialer := &net.Dialer{Timeout: b.timeout}
	c, err := dialer.Dial("tcp", b.server)
	if err != nil {
		return nil, 0, fmt.Errorf("dial socks5 tcp failed: %w", err)
	}
	// 握手方法
	methods := []byte{0x00} // no auth
	if b.user != "" || b.pass != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err = c.Write([]byte{0x05, byte(len(methods))}); err != nil {
		c.Close()
		return nil, 0, err
	}
	if _, err = c.Write(methods); err != nil {
		c.Close()
		return nil, 0, err
	}
	// 选择的方法
	reply := make([]byte, 2)
	if _, err = io.ReadFull(c, reply); err != nil {
		c.Close()
		return nil, 0, err
	}
	if reply[0] != 0x05 {
		c.Close()
		return nil, 0, fmt.Errorf("bad socks5 version: %d", reply[0])
	}
	switch reply[1] {
	case 0x00: // no auth
	case 0x02: // username/password
		ub := []byte(b.user)
		pb := []byte(b.pass)
		if len(ub) > 255 || len(pb) > 255 {
			c.Close()
			return nil, 0, errors.New("user/pass too long for socks5")
		}
		// subnegotiation: ver=1, ulen, uname, plen, passwd
		buf := make([]byte, 0, 3+len(ub)+len(pb))
		buf = append(buf, 0x01, byte(len(ub)))
		buf = append(buf, ub...)
		buf = append(buf, byte(len(pb)))
		buf = append(buf, pb...)
		if _, err = c.Write(buf); err != nil {
			c.Close()
			return nil, 0, err
		}
		authrep := make([]byte, 2)
		if _, err = io.ReadFull(c, authrep); err != nil {
			c.Close()
			return nil, 0, err
		}
		if authrep[1] != 0x00 {
			c.Close()
			return nil, 0, errors.New("socks5 auth failed")
		}
	default:
		c.Close()
		return nil, 0, fmt.Errorf("socks5 unsupported method: 0x%02x", reply[1])
	}

	// 2) 发送 UDP ASSOCIATE
	//   VER=5 CMD=3 RSV=0 ATYP=1 ADDR=0.0.0.0 PORT=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err = c.Write(req); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("socks5 udp-associate write failed: %w", err)
	}
	//   解析应答
	//   VER REP RSV ATYP BND.ADDR BND.PORT
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(c, hdr); err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("socks5 udp-associate read header failed: %w", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		c.Close()
		return nil, 0, fmt.Errorf("socks5 udp-associate failed, rep=0x%02x", hdr[1])
	}
	atyp := hdr[3]
	var uaddr *net.UDPAddr
	switch atyp {
	case 0x01: // IPv4
		rest := make([]byte, 6)
		if _, err = io.ReadFull(c, rest); err != nil {
			c.Close()
			return nil, 0, err
		}
		ip := net.IP(rest[0:4])
		port := int(rest[4])<<8 | int(rest[5])
		uaddr = &net.UDPAddr{IP: ip, Port: port}
	case 0x03: // DOMAIN
		lb := make([]byte, 1)
		if _, err = io.ReadFull(c, lb); err != nil {
			c.Close()
			return nil, 0, err
		}
		host := make([]byte, lb[0])
		if _, err = io.ReadFull(c, host); err != nil {
			c.Close()
			return nil, 0, err
		}
		rest := make([]byte, 2)
		if _, err = io.ReadFull(c, rest); err != nil {
			c.Close()
			return nil, 0, err
		}
		addr := net.JoinHostPort(string(host), fmt.Sprintf("%d", int(rest[0])<<8|int(rest[1])))
		uaddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			c.Close()
			return nil, 0, fmt.Errorf("resolve relay addr failed: %w", err)
		}
	case 0x04: // IPv6
		rest := make([]byte, 18)
		if _, err = io.ReadFull(c, rest); err != nil {
			c.Close()
			return nil, 0, err
		}
		ip := net.IP(rest[0:16])
		port := int(rest[16])<<8 | int(rest[17])
		uaddr = &net.UDPAddr{IP: ip, Port: port}
	default:
		c.Close()
		return nil, 0, fmt.Errorf("socks5 atyp unsupported: 0x%02x", atyp)
	}

	// 3) 建立本地 UDP socket（与中继地址族匹配）
	netw := "udp4"
	lip := net.IPv4zero
	if uaddr.IP.To4() == nil { // IPv6
		netw = "udp6"
		lip = net.IPv6unspecified
	}
	udpCli, err := net.ListenUDP(netw, &net.UDPAddr{IP: lip, Port: 0})
	if err != nil {
		c.Close()
		return nil, 0, fmt.Errorf("listen %s failed: %w", netw, err)
	}
	var lport uint16
	if ua, ok := udpCli.LocalAddr().(*net.UDPAddr); ok {
		lport = uint16(ua.Port)
	}

	b.tcpCtrl = c
	b.udpCli = udpCli
	b.relayAddr = uaddr
	b.port = lport

	// 4) 返回接收函数
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, nil
		}
		buf := packets[0]
		n, _, err := b.udpCli.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		// 解析 SOCKS5 UDP 包头
		pl, ep, perr := parseSocks5UDP(buf[:n])
		if perr != nil {
			return 0, perr
		}
		copy(buf, buf[pl:n]) // 把 payload 前移到起始位置
		sizes[0] = n - pl    // payload 长度
		eps[0] = &conn.StdNetEndpoint{AddrPort: ep}
		return 1, nil
	}

	return []conn.ReceiveFunc{recv}, b.port, nil
}

func (b *socks5UDPBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var e1, e2 error
	if b.udpCli != nil {
		e1 = b.udpCli.Close()
		b.udpCli = nil
	}
	if b.tcpCtrl != nil {
		e2 = b.tcpCtrl.Close()
		b.tcpCtrl = nil
	}
	if e1 != nil {
		return e1
	}
	return e2
}
func (b *socks5UDPBind) SetMark(_ uint32) error { return nil }

func (b *socks5UDPBind) Send(buffers [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.udpCli
	relay := b.relayAddr
	b.mu.Unlock()
	if c == nil || relay == nil {
		return errors.New("bind not open")
	}
	sne, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return errors.New("endpoint type not supported")
	}
	ap := sne.AddrPort

	for _, p := range buffers {
		if len(p) == 0 {
			continue
		}
		// 构造 SOCKS5 UDP 头：RSV(2)=0, FRAG=0, ATYP=IPv4, ADDR, PORT
		addr := ap.Addr()
		if !addr.Is4() {
			return errors.New("only IPv4 endpoint supported in socks5UDPBind")
		}
		ip4 := addr.As4()
		hdr := []byte{
			0x00, 0x00, // RSV
			0x00, // FRAG
			0x01, // ATYP IPv4
			ip4[0], ip4[1], ip4[2], ip4[3],
			byte(ap.Port() >> 8), byte(ap.Port() & 0xff),
		}
		packet := append(hdr, p...)
		if _, err := c.WriteToUDP(packet, relay); err != nil {
			return err
		}
	}
	return nil
}
func (b *socks5UDPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// 只支持 IPv4:port
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ap, _ := netip.ParseAddrPort(net.JoinHostPort(ip4.String(), portStr))
			return &conn.StdNetEndpoint{AddrPort: ap}, nil
		}
		return nil, syscall.EAFNOSUPPORT
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve v4 failed for %s: %w", host, err)
	}
	ip4 := ips[0].To4()
	if ip4 == nil {
		return nil, syscall.EAFNOSUPPORT
	}
	ap, _ := netip.ParseAddrPort(net.JoinHostPort(ip4.String(), portStr))
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}
func (b *socks5UDPBind) BatchSize() int   { return 128 }
func (b *socks5UDPBind) NetworkCost() int { return 0 }

// 解析 SOCKS5 UDP 包头，返回 payload 起始偏移、源地址（对 WG 而言是 peer 的 UDP 源）
func parseSocks5UDP(b []byte) (payloadStart int, src netip.AddrPort, err error) {
	if len(b) < 4 {
		return 0, netip.AddrPort{}, errors.New("socks5 udp: short header")
	}
	// RSV b[0:2], FRAG b[2]
	if b[0] != 0x00 || b[1] != 0x00 || b[2] != 0x00 {
		return 0, netip.AddrPort{}, errors.New("socks5 udp: bad RSV/FRAG")
	}
	atyp := b[3]
	i := 4
	switch atyp {
	case 0x01: // IPv4
		if len(b) < i+4+2 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short ipv4")
		}
		ip := net.IPv4(b[i], b[i+1], b[i+2], b[i+3])
		i += 4
		port := int(b[i])<<8 | int(b[i+1])
		i += 2
		ap, _ := netip.ParseAddrPort(net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
		return i, ap, nil
	case 0x03: // DOMAIN (理论上不会用于 WG，对付兼容)
		if len(b) < i+1 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short domain len")
		}
		l := int(b[i])
		i++
		if len(b) < i+l+2 {
			return 0, netip.AddrPort{}, errors.New("socks5 udp: short domain")
		}
		host := string(b[i : i+l])
		i += l
		port := int(b[i])<<8 | int(b[i+1])
		i += 2
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
		if err != nil || len(ips) == 0 {
			return 0, netip.AddrPort{}, fmt.Errorf("socks5 udp: resolve domain %s failed: %w", host, err)
		}
		ap, _ := netip.ParseAddrPort(net.JoinHostPort(ips[0].String(), fmt.Sprintf("%d", port)))
		return i, ap, nil
	case 0x04: // IPv6 (这里不支持 WG 外层 v6)
		return 0, netip.AddrPort{}, errors.New("socks5 udp: ipv6 unsupported in this bind")
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("socks5 udp: atyp 0x%02x unsupported", atyp)
	}
}

/* -------------------- helpers & config -------------------- */

func mustParseAddrs(csv string) []netip.Addr {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	addrs := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		a, err := netip.ParseAddr(strings.TrimSpace(p))
		if err != nil {
			log.Fatalf("invalid IP addr %q: %v", p, err)
		}
		addrs = append(addrs, a)
	}
	return addrs
}

// 只解析为 IPv4:port；域名仅查 A 记录（外层仅 v4）
func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", ep, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + ":" + port, nil
		}
		return "", fmt.Errorf("endpoint must be IPv4, got IPv6: %s", host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("DNS A lookup failed for %q: %w", host, err)
	}
	return ips[0].String() + ":" + port, nil
}

func base64ToHex(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	return hex.EncodeToString(decoded), nil
}

type Conf struct {
	PrivateKey string
	Address    string
	DNS        string
	MTU        int

	PublicKey  string
	AllowedIPs string
	Endpoint   string
	Keepalive  int
}

func loadWG(path string) (*Conf, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, err
	}
	secI := cfg.Section("Interface")
	secP := cfg.Section("Peer")

	c := &Conf{}
	c.PrivateKey = strings.TrimSpace(secI.Key("PrivateKey").String())
	c.Address = strings.TrimSpace(secI.Key("Address").String())
	c.DNS = strings.TrimSpace(secI.Key("DNS").String())
	if v, err := secI.Key("MTU").Int(); err == nil && v > 0 {
		c.MTU = v
	} else {
		c.MTU = 1420
	}

	c.PublicKey = strings.TrimSpace(secP.Key("PublicKey").String())
	c.AllowedIPs = strings.TrimSpace(secP.Key("AllowedIPs").String())
	c.Endpoint = strings.TrimSpace(secP.Key("Endpoint").String())
	if v, err := secP.Key("PersistentKeepalive").Int(); err == nil && v > 0 {
		c.Keepalive = v
	}
	return c, nil
}

func trimMask(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

/* -------------------- tnet -> proxy ContextDialer (for app traffic) -------------------- */

type tnetCtxDialer struct{ n *wgnet.Net }

func (d *tnetCtxDialer) Dial(network, address string) (net.Conn, error) {
	return d.n.Dial(network, address)
}
func (d *tnetCtxDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.n.DialContext(ctx, network, address)
}

/* -------------------- main -------------------- */

func main() {
	// 基础参数
	listen := flag.String("listen", "127.0.0.1:9999", "SOCKS5 监听地址（TCP）")
	wgIPs := flag.String("wg-ip", "172.16.0.2", "隧道内本机 IP（可逗号分隔，多地址可含 IPv6）")
	wgDNS := flag.String("wg-dns", "1.1.1.1,1.0.0.1", "隧道内 DNS（逗号分隔，可含 IPv6）")
	mtu := flag.Int("mtu", 1280, "隧道 MTU（WARP 常用 1280）")

	privateKey := flag.String("private-key", "", "本机私钥（Base64）")
	peerPublicKey := flag.String("peer-public-key", "", "对端公钥（Base64）")
	endpoint := flag.String("endpoint", "engage.cloudflareclient.com:2408", "对端公网 host:port（仅 IPv4 外发）")
	allowedIPs := flag.String("allowed-ips", "0.0.0.0/0,::/0", "AllowedIPs（逗号分隔）")
	keepalive := flag.Int("keepalive", 25, "PersistentKeepalive 秒数（0 关闭）")
	config := flag.String("config", "", "WireGuard 配置文件路径（可选）")

	// 只用于 *WireGuard 外层传输* 的 SOCKS5（支持 UDP）
	wgSocks := flag.String("wg-socks", "", "用于 WireGuard 外层 UDP 的 SOCKS5（host:port，需支持 UDP ASSOCIATE）")
	wgSocksUser := flag.String("wg-socks-user", "", "WG外层 SOCKS5 用户名（可选）")
	wgSocksPass := flag.String("wg-socks-pass", "", "WG外层 SOCKS5 密码（可选）")

	// 连接/握手超时
	handshakeTimeout := flag.Duration("handshake-timeout", 10*time.Second, "上游握手与目标连接超时")
	flag.Parse()

	// 从 ini 注入（适配你给的 WARP 配置）
	if *config != "" {
		_cfg, err := loadWG(*config)
		if err != nil {
			log.Fatalf("loadWG failed: %v", err)
		}
		*wgIPs = trimMask(_cfg.Address)
		*wgDNS = _cfg.DNS
		if _cfg.MTU > 0 {
			*mtu = _cfg.MTU
		}
		*privateKey = _cfg.PrivateKey
		*peerPublicKey = _cfg.PublicKey
		*endpoint = _cfg.Endpoint
		*allowedIPs = _cfg.AllowedIPs
		if _cfg.Keepalive > 0 {
			*keepalive = _cfg.Keepalive
		}
	}

	if *privateKey == "" || *peerPublicKey == "" || *endpoint == "" {
		log.Fatalf("必须提供 -private-key, -peer-public-key, -endpoint（或用 -config 注入）")
	}

	// 1) 创建用户态 netstack（用于 *应用流量* 走隧道）
	tun, tnet, err := wgnet.CreateNetTUN(
		mustParseAddrs(*wgIPs),
		mustParseAddrs(*wgDNS),
		*mtu,
	)
	if err != nil {
		log.Fatalf("CreateNetTUN failed: %v", err)
	}

	// 2) 创建 WireGuard 设备；Bind 决定外层 UDP 如何发送
	logger := device.NewLogger(device.LogLevelVerbose, "wg-user ")
	var bind conn.Bind
	if strings.TrimSpace(*wgSocks) != "" {
		log.Printf("[wg-bind] using SOCKS5-UDP for outer transport: %s", *wgSocks)
		bind = newSocks5UDPBind(*wgSocks, *wgSocksUser, *wgSocksPass, *handshakeTimeout)
	} else {
		log.Printf("[wg-bind] using direct IPv4 UDP")
		bind = newV4OnlyBind()
	}
	dev := device.NewDevice(tun, bind, logger)

	// 组装 WG 配置
	cfg := new(strings.Builder)
	_priv, err := base64ToHex(*privateKey)
	if err != nil {
		log.Fatalf("base64ToHex failed for private_key: %v", err)
	}
	_pub, err := base64ToHex(*peerPublicKey)
	if err != nil {
		log.Fatalf("base64ToHex failed for peer_public_key: %v", err)
	}
	fmt.Fprintf(cfg, "private_key=%s\n", _priv)
	fmt.Fprintf(cfg, "public_key=%s\n", _pub)

	for _, cidr := range strings.Split(*allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			fmt.Fprintf(cfg, "allowed_ip=%s\n", cidr)
		}
	}
	ipPort, err := resolveEndpoint(*endpoint) // A 记录（外层仅 v4）
	if err != nil {
		log.Fatalf("resolveEndpoint failed for %q: %v", *endpoint, err)
	}
	fmt.Fprintf(cfg, "endpoint=%s\n", ipPort)
	if *keepalive > 0 {
		fmt.Fprintf(cfg, "persistent_keepalive_interval=%d\n", *keepalive)
	}

	if err := dev.IpcSet(cfg.String()); err != nil {
		log.Fatalf("IpcSet failed: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("dev.Up failed: %v", err)
	}
	defer dev.Close()

	// 3) 下游 SOCKS5（仅 TCP CONNECT），**直接通过隧道拨目标**（出口=WG peer）
	srv := socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, *handshakeTimeout)
			defer cancel()
			return tnet.DialContext(dctx, "tcp", addr)
		}),
	)

	log.Printf("SOCKS5 @ %s；AllowedIPs=%s；Endpoint(v4)=%s；MTU=%d；WG-outer=%s",
		*listen, *allowedIPs, ipPort, *mtu, func() string {
			if *wgSocks == "" {
				return "direct-udp"
			}
			if *wgSocksUser != "" || *wgSocksPass != "" {
				return fmt.Sprintf("socks5-udp %s (auth)", *wgSocks)
			}
			return fmt.Sprintf("socks5-udp %s", *wgSocks)
		}(),
	)

	if err := srv.ListenAndServe("tcp", *listen); err != nil {
		log.Fatalf("SOCKS5 ListenAndServe failed: %v", err)
	}
}
