package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"lanchat/internal/crypto"
	"lanchat/internal/p2p"
	"lanchat/internal/qrcode"
	"lanchat/internal/server"
	"lanchat/internal/store"
	"lanchat/internal/web"
)

func main() {
	var (
		port       = flag.Int("port", 52520, "HTTP/WebUI & P2P listen port (0 for random available port)")
		udpPort    = flag.Int("udp-port", p2p.DefaultUDPPort, "UDP port for opt-in discovery & silent HMAC probes")
		deviceName = flag.String("name", "", "Custom device display name (default: Hostname + OS)")
		maxMsgs    = flag.Int("max-msgs", 200, "Maximum number of messages kept in memory ring buffer")
		maxMemMB   = flag.Int64("max-mem", 20, "Maximum memory pool size in MB for messages & clipboard images")
		noOpen     = flag.Bool("no-open", false, "Do not automatically open the browser on startup")
		daemonMode = flag.Bool("daemon", false, "Run in headless background daemon mode (implies --no-open)")
		trayMode   = flag.Bool("tray", false, "Launch lightweight native desktop status controller / tray helper")
		configDir  = flag.String("config-dir", "", "Directory to store device identity & trusted peer keys")
	)
	flag.Parse()

	im, err := crypto.LoadOrCreateIdentity(*configDir, *deviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to initialize identity: %v\n", err)
		os.Exit(1)
	}

	spoolDir, err := os.MkdirTemp("", "lanchat-spool-*")
	if err != nil {
		spoolDir = filepath.Join(os.TempDir(), fmt.Sprintf("lanchat-spool-%d", os.Getpid()))
		_ = os.MkdirAll(spoolDir, 0700)
	}
	defer func() {
		_ = os.RemoveAll(spoolDir)
	}()

	maxBytes := (*maxMemMB) * 1024 * 1024
	maxInlineBytes := int64(2 * 1024 * 1024) // 2MB single inline clipboard image cap
	ring := store.NewRingBuffer(*maxMsgs, maxBytes, maxInlineBytes, func(meta *store.FileMeta) {
		if meta != nil && meta.IsTempSpool && meta.LocalPath != "" {
			_ = os.Remove(meta.LocalPath)
		}
	})

	// Bind TCP listener (if default port 52520 is busy, automatically fall back to a free port)
	ln, actualPort, err := listenTCPWithFallback(*port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to bind TCP port: %v\n", err)
		os.Exit(1)
	}

	staticFS, err := web.StaticFS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load embedded WebUI: %v\n", err)
		os.Exit(1)
	}

	appSrv := server.NewAppServer(im, ring, actualPort, *udpPort, spoolDir, staticFS)
	if err := appSrv.StartMesh(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ P2P mesh startup warning: %v\n", err)
	}
	defer appSrv.Stop()

	httpSrv := &http.Server{
		Handler:           appSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "❌ HTTP server error: %v\n", err)
		}
	}()

	ips := p2p.GetLANIPs()
	primaryIP := ips[0]
	localURL := fmt.Sprintf("http://127.0.0.1:%d", actualPort)
	_, pin, _ := im.DiscoverableState()
	pairURI := fmt.Sprintf("%s:%d#%s", primaryIP, actualPort, pin)
	mobileURL := fmt.Sprintf("http://%s:%d/?token=%s", primaryIP, actualPort, im.MobileAccessToken())

	printBanner(im.Name(), localURL, pairURI, mobileURL, *maxMsgs, *maxMemMB)

	if *trayMode {
		go launchDesktopTrayHelper(localURL, im.Name())
	} else if !*noOpen && !*daemonMode {
		go func() {
			time.Sleep(250 * time.Millisecond)
			openBrowser(localURL)
		}()
	}

	if !*daemonMode {
		go interactiveConsoleLoop(im, ring, localURL, actualPort)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n🧹 正在退出并销毁所有内存消息与临时文件句柄...")
	ring.Clear()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func listenTCPWithFallback(preferredPort int) (net.Listener, int, error) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", preferredPort))
	if err != nil && preferredPort != 0 {
		ln, err = net.Listen("tcp4", "0.0.0.0:0")
	}
	if err != nil {
		return nil, 0, err
	}
	addr := ln.Addr().(*net.TCPAddr)
	return ln, addr.Port, nil
}

func printBanner(name, localURL, pairURI, mobileURL string, maxMsgs int, maxMemMB int64) {
	fmt.Println("======================================================================")
	fmt.Printf(" ⚡ LanChat 已启动 · 节点名称: %s\n", name)
	fmt.Println("----------------------------------------------------------------------")
	fmt.Printf(" 🔒 隐私状态 : 默认隐身 (0 公开广播，未授权节点不可访问)\n")
	fmt.Printf(" 🧠 内存上限 : 最多 %d 条记录 / %d MB 环形池 (进程退出即焚)\n", maxMsgs, maxMemMB)
	fmt.Printf(" 💻 本机界面 : %s\n", localURL)
	fmt.Printf(" 🔗 隐身直连 : %s  (在另一台电脑输入即可配对)\n", pairURI)
	fmt.Printf(" 📱 手机直连 : %s\n", mobileURL)
	fmt.Println("----------------------------------------------------------------------")
	if qrArt, err := qrcode.RenderTerminal(mobileURL); err == nil {
		fmt.Println(" 📱 手机相机扫码直接进入移动版聊天与文件互传 (支持添加到主屏幕 PWA):")
		fmt.Print(qrArt)
	}
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println(" ⌨️  终端快捷键: 输入 [o] 打开网页 | [d] 开启3分钟可被发现 | [c] 清空内存 | [q] 退出")
	fmt.Println("======================================================================")
}

func interactiveConsoleLoop(im *crypto.IdentityManager, ring *store.RingBuffer, localURL string, port int) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cmd := strings.ToLower(strings.TrimSpace(scanner.Text()))
		switch cmd {
		case "o", "open":
			openBrowser(localURL)
		case "d", "discover":
			pin, _ := im.SetDiscoverable(true, 3*time.Minute)
			ips := p2p.GetLANIPs()
			fmt.Printf("📡 已开启「允许被发现」3分钟！配对码: %s (直连串: %s:%d#%s)\n", pin, ips[0], port, pin)
		case "s", "stealth":
			im.SetDiscoverable(false, 0)
			fmt.Println("🔒 已恢复「默认隐身」模式。")
		case "c", "clear":
			ring.Clear()
			fmt.Println("🧹 已清空本机内存聊天记录。")
		case "q", "quit", "exit":
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(os.Interrupt)
			return
		}
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		// Linux / BSD
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// launchDesktopTrayHelper opens the WebUI in compact app-window mode (or system controller) when --tray is passed.
func launchDesktopTrayHelper(localURL string, nodeName string) {
	time.Sleep(250 * time.Millisecond)
	switch runtime.GOOS {
	case "darwin":
		// On macOS, open default browser + show non-blocking native notification
		_ = exec.Command("osascript", "-e",
			fmt.Sprintf(`display notification "节点 %s 已在后台隐身运行" with title "LanChat" subtitle "%s"`, nodeName, localURL)).Start()
		openBrowser(localURL)
	case "windows":
		// Try Edge/Chrome app-mode compact window first, fallback to default browser
		if err := exec.Command("cmd", "/c", "start", "msedge", "--app="+localURL, "--window-size=980,680").Start(); err != nil {
			openBrowser(localURL)
		}
	default:
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			_ = exec.Command("notify-send", "LanChat 已启动", localURL).Start()
			openBrowser(localURL)
		}
	}
}
