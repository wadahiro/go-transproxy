package transproxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/cybozu-go/netutil"
	"github.com/cybozu-go/transocks"
	"os"
)

type TCPListener struct {
	net.Listener
}

type TCPConn struct {
	*net.TCPConn
	OrigAddr string // ip:port
}

func NewTCPListener(listenAddress string) (*TCPListener, error) {
	l, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}
	return &TCPListener{
		Listener: l,
	}, nil
}

func (l *TCPListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}

	tc, ok := c.(*net.TCPConn)
	if !ok {
		return c, fmt.Errorf("Accepted non-TCP connection - %v", c)
	}

	origAddr, err := transocks.GetOriginalDST(tc)
	if err != nil {
		return c, fmt.Errorf("GetOriginalDST failed - %s", err.Error())
	}

	log.Printf("debug: OriginalDST: %s", origAddr)
	log.Printf("debug: LocalAddr: %s", tc.LocalAddr().String())
	log.Printf("debug: RemoteAddr: %s", tc.RemoteAddr().String())

	return &TCPConn{tc, origAddr.String()}, nil
}

func ListenTCP(listenAddress string, handler func(tc *TCPConn)) {
	l, err := NewTCPListener(listenAddress)
	if err != nil {
		log.Fatalf("alert: Error listening for tcp connections - %s", err.Error())
	}

	for {
		conn, err := l.Accept() // wait here
		if err != nil {
			log.Printf("warn: Error accepting new connection - %s", err.Error())
			return
		}

		log.Printf("debug: Accepted new connection")

		go func(conn net.Conn) {
			defer func() {
				conn.Close()
			}()

			tc, _ := conn.(*TCPConn)

			handler(tc)
		}(conn)
	}
}

var pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64<<10)
	},
}

func Pipe(srcConn *TCPConn, destConn net.Conn) {
	defer destConn.Close()

	log.Printf("debug: Start proxy")

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() error {
		defer func() {
			wg.Done()
		}()

		buf := pool.Get().([]byte)
		_, err := io.CopyBuffer(destConn, srcConn, buf)
		pool.Put(buf)
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseWrite()
		}
		srcConn.CloseRead()
		return err
	}()

	wg.Add(1)
	go func() error {
		defer func() {
			wg.Done()
		}()

		buf := pool.Get().([]byte)
		_, err := io.CopyBuffer(srcConn, destConn, buf)
		pool.Put(buf)
		srcConn.CloseWrite()
		if hc, ok := destConn.(netutil.HalfCloser); ok {
			hc.CloseRead()
		}
		return err
	}()

	wg.Wait()

	log.Printf("debug: End proxy")
}

type NoProxy struct {
	IPs     []string
	CIDRs   []*net.IPNet
	Domains []string
}

func httpProxyFromRule(noProxy NoProxy) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if useProxy(noProxy, strings.Split(req.Host, ":")[0]) {

			return http.ProxyFromEnvironment(req)
		} else {
			return nil, nil
		}
	}
}

func useProxy(noProxy NoProxy, target string) bool {
	// TODO resolve target domain

	for _, d := range noProxy.Domains {
		if strings.HasSuffix(target, d) {
			log.Printf("debug: NO_PROXY: Matched no_proxy domain. Direct for %s", target)
			return false
		}
	}

	for _, ip := range noProxy.IPs {
		if ip == target {
			log.Printf("debug: NO_PROXY: Matched no_proxy ip. Direct for %s", target)
			return false
		}
	}

	for _, cidr := range noProxy.CIDRs {
		targetIP := net.ParseIP(target)
		if cidr.Contains(targetIP) {
			log.Printf("debug: NO_PROXY: Matched no_proxy cidr. Direct for %s", target)
			return false
		}
	}

	log.Printf("debug: Use proxy for %s", target)
	return true
}

func GetProxyEnv(key string) string {
	env := os.Getenv(key)
	if env == "" {
		env = os.Getenv(strings.ToUpper(key))
	}
	return env
}
