package transproxy

import (
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type TCPProxy struct {
	TCPProxyConfig
}

type TCPProxyConfig struct {
	ListenAddress string
	NoProxy       NoProxy
}

func NewTCPProxy(c TCPProxyConfig) *TCPProxy {
	return &TCPProxy{
		TCPProxyConfig: c,
	}
}

func (s TCPProxy) Start() error {
	//pdialer := proxy.FromEnvironment()

	dialer := &net.Dialer{
		KeepAlive: 3 * time.Minute,
		DualStack: true,
	}
	u, err := url.Parse(GetProxyEnv("http_proxy"))
	if err != nil {
		return err
	}

	pdialer, err := proxy.FromURL(u, dialer)
	if err != nil {
		return err
	}

	npdialer := proxy.Direct

	log.Printf("info: Start listener on %s category='TCP-Proxy'", s.ListenAddress)

	go func() {
		ListenTCP(s.ListenAddress, func(tc *TCPConn) {
			// access logging
			host, _, _ := net.SplitHostPort(tc.RemoteAddr().String())
			log.Printf("info: category='TCP-Proxy' remoteAddr='%s' method=CONNECT host='%s'", host, tc.OrigAddr)

			var destConn net.Conn
			// TODO Convert OrigAddr to domain and check useProxy with domain too?
			if useProxy(s.NoProxy, strings.Split(tc.OrigAddr, ":")[0]) {

				destConn, err = pdialer.Dial("tcp", tc.OrigAddr)
			} else {
				destConn, err = npdialer.Dial("tcp", tc.OrigAddr)
			}

			if err != nil {
				log.Printf("error: Failed to connect to destination - %s category='TCP-Proxy'", err.Error())
				return
			}

			Pipe(tc, destConn)
		})
	}()

	return nil
}
