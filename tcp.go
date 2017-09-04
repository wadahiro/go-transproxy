package tproxy

import (
	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type TCPProxy struct {
	TCPProxyConfig
}

type TCPProxyConfig struct {
	ListenAddress    string
	NoProxyAddresses []string
	NoProxyDomains   []string
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
	u, err := url.Parse(os.Getenv("http_proxy"))
	if err != nil {
		return err
	}

	pdialer, err := proxy.FromURL(u, dialer)
	if err != nil {
		return err
	}

	npdialer := proxy.Direct

	log.Infof("TCP-Proxy: Start listener on %s", s.ListenAddress)

	go func() {
		ListenTCP(s.ListenAddress, func(tc *TCPConn) {
			var destConn net.Conn
			if useProxy(s.NoProxyDomains, s.NoProxyAddresses,
				strings.Split(tc.OrigAddr, ":")[0]) {

				destConn, err = pdialer.Dial("tcp", tc.OrigAddr)
			} else {
				destConn, err = npdialer.Dial("tcp", tc.OrigAddr)
			}

			if err != nil {
				log.Errorf("TCP-Proxy: Failed to connect to destination - %s", err.Error())
				return
			}

			Pipe(tc, destConn)
		})
	}()

	return nil
}
