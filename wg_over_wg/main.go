package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/ini.v1"
)

type Conf struct {
	PrivateKey string
	Address    string
	DNS        string
	MTU        int

	PublicKey  string
	AllowedIPs string
	Endpoint   string
	Keepalive  int
	// 可选：Cloudflare Warp 的 reserved 字节，例如 "1,2,3"
	Reserved string
}

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

func trimMask(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// 解析 endpoint: 如果是域名，则解析成 IP:port（优先 IPv4，其次 IPv6）
func resolveEndpoint(ep string) (string, error) {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", ep, err)
	}
	// 如果本身就是 IP，直接返回
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "[" + ip.String() + "]:" + port, nil
		}
		return ip.String() + ":" + port, nil
	}
	// 域名解析（启动时解析一次）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	// 优先 IPv4
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String() + ":" + port, nil
		}
	}
	// 否则第一个 IPv6
	return "[" + ips[0].IP.String() + "]:" + port, nil
}

func base64ToHex(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}
	return hex.EncodeToString(decoded), nil
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
	// 兼容自定义字段 reserved（非标准 wireguard 字段；用于 Cloudflare Warp）
	if secP.HasKey("Reserved") {
		c.Reserved = strings.TrimSpace(secP.Key("Reserved").String())
	}
	return c, nil
}

// ---------- netstackBind：让内层 WG 的 UDP 走外层 tnet ----------

type netstackBind struct {
	tnet *netstack.Net

	mu     sync.RWMutex
	pc     net.PacketConn // 用户态 UDP "监听"
	lport  uint16
	closed bool
}

var packetBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 65535)
	},
}

func NewNetstackBind(tnet *netstack.Net) *netstackBind {
	return &netstackBind{
		tnet:   tnet,
		closed: false,
	}
}

// WireGuard 期望能一次收多包；为了简单起步，BatchSize=1 即可跑通
func (b *netstackBind) BatchSize() int { return 128 }

func (b *netstackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	log.Printf("[DEBUG] netstackBind.Open(port=%d) called", port)

	b.mu.Lock()
	defer b.mu.Unlock()

	// 重置 closed 状态，允许重新打开
	b.closed = false

	// 如果已经打开，先关闭旧的连接
	if b.pc != nil {
		log.Printf("[DEBUG] netstackBind.Open: closing existing connection")
		b.pc.Close()
		b.pc = nil
	}

	// 在用户态栈上开一个 UDP PacketConn
	log.Printf("[DEBUG] netstackBind.Open: attempting to listen on port %d", port)

	// 使用 ListenUDP 创建监听套接字
	var pc net.PacketConn
	var err error

	// 创建监听地址
	localAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(port),
	}

	// 在 netstack 中使用 ListenUDP
	pc, err = b.tnet.ListenUDP(localAddr)
	if err != nil {
		log.Printf("[DEBUG] netstackBind.Open: ListenUDP failed on port %d: %v", port, err)
		// 如果指定端口失败，且不是端口0，尝试随机端口
		if port != 0 {
			log.Printf("[DEBUG] netstackBind.Open: trying random port")
			randomAddr := &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
			pc, err = b.tnet.ListenUDP(randomAddr)
			if err != nil {
				log.Printf("[DEBUG] netstackBind.Open: random port also failed: %v", err)
				return nil, 0, fmt.Errorf("failed to create UDP listener: %w", err)
			}
		} else {
			return nil, 0, fmt.Errorf("failed to create UDP listener: %w", err)
		}
	}

	b.pc = pc
	laddr := pc.LocalAddr().(*net.UDPAddr)
	b.lport = uint16(laddr.Port)
	log.Printf("[DEBUG] netstackBind.Open: successfully listening on port %d", b.lport)

	recv := func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		b.mu.RLock()
		pc := b.pc
		b.mu.RUnlock()

		if pc == nil {
			return 0, fmt.Errorf("bind not open")
		}

		n, raddr, err := pc.ReadFrom(pkts[0])
		if err != nil {
			return 0, err
		}
		if len(pkts) == 0 || len(eps) == 0 || len(sizes) == 0 {
			return 0, fmt.Errorf("bad batch buffers")
		}
		sizes[0] = n

		udp := raddr.(*net.UDPAddr)
		ap := netip.AddrPortFrom(udp.AddrPort().Addr(), uint16(udp.AddrPort().Port()))
		eps[0] = &conn.StdNetEndpoint{AddrPort: ap}
		return 1, nil
	}

	log.Printf("[DEBUG] netstackBind.Open: returning success with port %d", b.lport)
	return []conn.ReceiveFunc{recv}, b.lport, nil
}

func (b *netstackBind) Close() error {
	log.Printf("[DEBUG] netstackBind.Close() called")

	b.mu.Lock()
	defer b.mu.Unlock()

	// 注意：不要设置 closed = true，因为 WireGuard 会在设备初始化时先 Close 再 Open
	// b.closed = true  // 移除这行

	if b.pc != nil {
		log.Printf("[DEBUG] netstackBind.Close: closing packet connection")
		err := b.pc.Close()
		b.pc = nil
		return err
	}
	log.Printf("[DEBUG] netstackBind.Close: no connection to close")
	return nil
}

// 内层发送：把 bufs 合并成一个 UDP datagram，写到用户态 UDP 的远端
func (b *netstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.RLock()
	pc := b.pc
	closed := b.closed
	b.mu.RUnlock()

	if closed {
		return fmt.Errorf("bind closed")
	}
	if pc == nil {
		return fmt.Errorf("bind not open")
	}

	// 我们用 conn.StdNetEndpoint 来获取 UDPAddr
	std, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		// 尝试从字符串再解析
		ap, err := netip.ParseAddrPort(ep.DstToString())
		if err != nil {
			return fmt.Errorf("unexpected endpoint type: %v", err)
		}
		std = &conn.StdNetEndpoint{AddrPort: ap}
	}

	udp := net.UDPAddrFromAddrPort(std.AddrPort)
	buf := packetBufPool.Get().([]byte)
	n := 0
	for _, b := range bufs {
		n += copy(buf[n:], b)
	}
	_, err := pc.WriteTo(buf[:n], udp)
	packetBufPool.Put(buf)
	return err
}

func (b *netstackBind) SetMark(mark uint32) error {
	log.Printf("[DEBUG] netstackBind.SetMark(mark=%d) called", mark)

	b.mu.RLock()
	closed := b.closed
	b.mu.RUnlock()

	if closed {
		log.Printf("[DEBUG] netstackBind.SetMark: bind is closed, returning error")
		return fmt.Errorf("bind closed")
	}

	// 这个方法在 netstack 环境下不需要实际操作
	return nil
}

// 解析 "host:port" -> Endpoint（这里约定传入已是 IP:port；若是域名请先解析）
func (b *netstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		// 兼容可能的 "[v6]:port"/"host:port" 形式
		udpAddr, err2 := net.ResolveUDPAddr("udp", s)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse endpoint %q: %v", s, err)
		}
		ap = netip.AddrPortFrom(udpAddr.AddrPort().Addr(), uint16(udpAddr.Port))
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

// ---------- 构造 WG 设备通用函数 ----------

func buildDevice(tun tun.Device, bind conn.Bind, logPrefix string, conf *Conf) (*device.Device, error) {
	logger := device.NewLogger(device.LogLevelVerbose, logPrefix)
	dev := device.NewDevice(tun, bind, logger)

	priHex, err := base64ToHex(conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("privateKey b64->hex: %w", err)
	}
	pubHex, err := base64ToHex(conf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("peerPublicKey b64->hex: %w", err)
	}
	endpoint, err := resolveEndpoint(conf.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}

	sb := new(strings.Builder)
	fmt.Fprintf(sb, "private_key=%s\n", priHex)
	// peer
	fmt.Fprintf(sb, "public_key=%s\n", pubHex)
	for _, cidr := range strings.Split(conf.AllowedIPs, ",") {
		fmt.Fprintf(sb, "allowed_ip=%s\n", strings.TrimSpace(cidr))
	}
	fmt.Fprintf(sb, "endpoint=%s\n", endpoint)
	if conf.Keepalive > 0 {
		fmt.Fprintf(sb, "persistent_keepalive_interval=%d\n", conf.Keepalive)
	}
	// Cloudflare Warp 专用（可选）
	if strings.TrimSpace(conf.Reserved) != "" {
		fmt.Fprintf(sb, "reserved=%s\n", strings.TrimSpace(conf.Reserved))
	}

	if err := dev.IpcSet(sb.String()); err != nil {
		return nil, fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("dev.Up: %w", err)
	}
	return dev, nil
}

func main() {
	// ---- 外层配置来源（推荐用 --outer-config 指向标准 wireguard conf）----
	outerCfgPath := flag.String("outer-config", "", "外层 WireGuard 配置文件（INI: [Interface]/[Peer]）")
	outerAddr := flag.String("outer-addr", "10.7.0.2", "外层隧道地址（逗号可多）")
	outerDNS := flag.String("outer-dns", "10.7.0.1", "外层隧道 DNS（逗号分隔）")
	outerMTU := flag.Int("outer-mtu", 1420, "外层 MTU")

	// 也支持从 flag 直接给（与 --outer-config 二选一/或覆盖）
	outerPrivate := flag.String("outer-private", "", "外层本机私钥（Base64）")
	outerPeerPub := flag.String("outer-peerpub", "", "外层对端公钥（Base64）")
	outerEndpoint := flag.String("outer-endpoint", "", "外层对端 host:port")
	outerAllowed := flag.String("outer-allowed", "0.0.0.0/0,::/0", "外层 AllowedIPs")
	outerKeep := flag.Int("outer-keepalive", 25, "外层 keepalive 秒")

	// ---- 内层配置 ----
	innerCfgPath := flag.String("inner-config", "", "内层 WireGuard 配置文件（INI: [Interface]/[Peer]）")
	innerAddr := flag.String("inner-addr", "10.8.0.2", "内层隧道地址（逗号可多）")
	innerDNS := flag.String("inner-dns", "10.8.0.1", "内层隧道 DNS（逗号分隔）")
	innerMTU := flag.Int("inner-mtu", 1280, "内层 MTU（建议小于外层）")

	innerPrivate := flag.String("inner-private", "", "内层本机私钥（Base64）")
	innerPeerPub := flag.String("inner-peerpub", "", "内层对端公钥（Base64）")
	innerEndpoint := flag.String("inner-endpoint", "", "内层对端 host:port")
	innerAllowed := flag.String("inner-allowed", "0.0.0.0/0,::/0", "内层 AllowedIPs")
	innerKeep := flag.Int("inner-keepalive", 25, "内层 keepalive 秒")
	innerReserved := flag.String("inner-reserved", "", "（可选）Cloudflare Warp reserved，例如 1,2,3")

	// ---- SOCKS5 ----
	socksOuter := flag.String("socks-outer", "127.0.0.1:1080", "SOCKS5（外层）监听")
	socksInner := flag.String("socks-inner", "127.0.0.1:2080", "SOCKS5（内层/双层）监听")

	flag.Parse()

	// 1) 组装外层 conf
	var oc Conf
	if *outerCfgPath != "" {
		cfg, err := loadWG(*outerCfgPath)
		if err != nil {
			log.Fatalf("load outer-config failed: %v", err)
		}
		oc = *cfg
		*outerAddr = trimMask(cfg.Address)
		*outerDNS = cfg.DNS
		*outerMTU = cfg.MTU
	} else {
		oc = Conf{
			PrivateKey: *outerPrivate,
			Address:    *outerAddr,
			DNS:        *outerDNS,
			MTU:        *outerMTU,
			PublicKey:  *outerPeerPub,
			AllowedIPs: *outerAllowed,
			Endpoint:   *outerEndpoint,
			Keepalive:  *outerKeep,
		}
	}
	if oc.PrivateKey == "" || oc.PublicKey == "" || oc.Endpoint == "" {
		log.Fatalf("外层必须提供 private/public/endpoint（用 --outer-config 或相应 flags）")
	}

	// 2) 组装内层 conf
	var ic Conf
	if *innerCfgPath != "" {
		cfg, err := loadWG(*innerCfgPath)
		if err != nil {
			log.Fatalf("load inner-config failed: %v", err)
		}
		ic = *cfg
		*innerAddr = trimMask(cfg.Address)
		*innerDNS = cfg.DNS
		*innerMTU = cfg.MTU
	} else {
		ic = Conf{
			PrivateKey: *innerPrivate,
			Address:    *innerAddr,
			DNS:        *innerDNS,
			MTU:        *innerMTU,
			PublicKey:  *innerPeerPub,
			AllowedIPs: *innerAllowed,
			Endpoint:   *innerEndpoint,
			Keepalive:  *innerKeep,
			Reserved:   *innerReserved,
		}
	}
	if ic.PrivateKey == "" || ic.PublicKey == "" || ic.Endpoint == "" {
		log.Fatalf("内层必须提供 private/public/endpoint（用 --inner-config 或相应 flags）")
	}

	// ---------- 外层：CreateNetTUN + 默认 Bind ----------
	tunOuter, tnetOuter, err := netstack.CreateNetTUN(
		mustParseAddrs(*outerAddr),
		mustParseAddrs(*outerDNS),
		*outerMTU,
	)
	if err != nil {
		log.Fatalf("outer CreateNetTUN: %v", err)
	}
	devOuter, err := buildDevice(tunOuter, conn.NewDefaultBind(), "wg-outer ", &oc)
	if err != nil {
		log.Fatalf("build outer wg: %v", err)
	}
	defer devOuter.Close()

	// 等待外层 WireGuard 稳定启动
	log.Println("等待外层 WireGuard 启动...")
	time.Sleep(2 * time.Second)

	// ---------- 内层：CreateNetTUN + 自定义 Bind(走外层 tnet) ----------
	log.Println("初始化内层 WireGuard...")
	tunInner, tnetInner, err := netstack.CreateNetTUN(
		mustParseAddrs(*innerAddr),
		mustParseAddrs(*innerDNS),
		*innerMTU,
	)
	if err != nil {
		log.Fatalf("inner CreateNetTUN: %v", err)
	}
	innerBind := NewNetstackBind(tnetOuter) // 关键：内层 UDP 通过外层用户态 UDP 发出
	devInner, err := buildDevice(tunInner, innerBind, "wg-inner ", &ic)
	if err != nil {
		log.Fatalf("build inner wg: %v", err)
	}
	defer devInner.Close()

	// ---------- 两个 SOCKS5 ----------
	// 外层 SOCKS：走 tnetOuter（单层）
	go func() {
		srv := socks5.NewServer(
			socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
				d, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				return tnetOuter.DialContext(d, network, addr)
			}),
		)
		log.Printf("SOCKS5(outer) @ %s -> via OUTER WG", *socksOuter)
		if err := srv.ListenAndServe("tcp", *socksOuter); err != nil {
			log.Fatalf("SOCKS OUTER: %v", err)
		}
	}()

	// 内层 SOCKS：走 tnetInner（双层）
	go func() {
		srv := socks5.NewServer(
			socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
				d, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				return tnetInner.DialContext(d, network, addr)
			}),
		)
		log.Printf("SOCKS5(inner) @ %s -> via INNER (warp-in-warp)", *socksInner)
		if err := srv.ListenAndServe("tcp", *socksInner); err != nil {
			log.Fatalf("SOCKS INNER: %v", err)
		}
	}()

	log.Printf("外层与内层 WireGuard 已启动。外层 MTU=%d，内层 MTU=%d。", *outerMTU, *innerMTU)
	select {} // 阻塞主 goroutine
}
