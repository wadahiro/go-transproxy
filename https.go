package transproxy

import (
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/inconshreveable/go-vhost"
	"golang.org/x/net/proxy"
)

type HTTPSProxy struct {
	HTTPSProxyConfig
}

type HTTPSProxyConfig struct {
	ListenAddress string
	NoProxy       NoProxy
}

func NewHTTPSProxy(c HTTPSProxyConfig) *HTTPSProxy {
	return &HTTPSProxy{
		HTTPSProxyConfig: c,
	}
}

func (s HTTPSProxy) Start() error {
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

	log.Printf("info: Start listener on %s category='HTTPS-Proxy'", s.ListenAddress)

	go func() {
		ListenTCP(s.ListenAddress, func(tc *TCPConn) {
			tlsConn, err := vhost.TLS(tc)
			if err != nil {
				log.Printf("error: Failed handling TLS connection - %s", err.Error())
				return
			}

			defer func() {
				tlsConn.Free()
			}()

			origServer := tlsConn.Host()
			if origServer == "" {
				log.Printf("warn: Cannot get SNI, so fallback using `SO_ORIGINAL_DST` or `IP6T_SO_ORIGINAL_DST`")
				origServer = tc.OrigAddr // IPAddress:Port

				// TODO getting domain from origAddr, then check whether we should use proxy or not
			} else {
				log.Printf("debug: SNI: %s", origServer)
				origServer = net.JoinHostPort(origServer, "443")
			}

			// access logging
			host, _, _ := net.SplitHostPort(tc.RemoteAddr().String())
			log.Printf("info: category='HTTPS-Proxy' remoteAddr='%s' method=CONNECT host='%s'", host, origServer)

			var destConn net.Conn
			if useProxy(s.NoProxy, strings.Split(origServer, ":")[0]) {

				destConn, err = pdialer.Dial("tcp", origServer)
			} else {
				destConn, err = npdialer.Dial("tcp", origServer)
			}

			if err != nil {
				log.Printf("warn: Failed to connect to destination - %s", err.Error())
				return
			}

			// First, write ClientHello to real destination because we have already read it
			ch := tlsConn.ClientHelloMsg.Raw
			chSize := len(ch)
			chHeader := []byte{0x16, 0x03, 0x01, byte(chSize >> 8), byte(chSize)}
			chRecord := append(chHeader, ch...)
			destConn.Write(chRecord)

			// Then, pipe the data
			Pipe(tc, destConn)
		})
	}()

	return nil
}
