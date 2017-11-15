package transproxy

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
)

type HTTPProxy struct {
	HTTPProxyConfig
}

type HTTPProxyConfig struct {
	ListenAddress string
	NoProxy       NoProxy
	Verbose       bool
}

func NewHTTPProxy(c HTTPProxyConfig) *HTTPProxy {
	return &HTTPProxy{
		HTTPProxyConfig: c,
	}
}

func (s HTTPProxy) Start() error {
	l, err := NewTCPListener(s.ListenAddress)
	if err != nil {
		log.Printf("error: Failed listening for tcp connections - %s category='HTTP-Proxy'", err.Error())
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.Proxy = httpProxyFromRule(s.NoProxy)
	proxy.Verbose = s.Verbose

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf("debug: Accept: %s, %s", req.Host, req.URL)
		if req.Host == "" {
			// TODO use origAddr from TCPCon
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		// Convert to proxy request (abs URL request) for passing goproxy handler
		req.URL.Scheme = "http"
		req.URL.Host = req.Host

		// access logging
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		log.Printf("info: category='HTTP-Proxy' remoteAddr='%s' method='%s' url='%s'", host, req.Method, req.URL)

		// proxy to real target
		proxy.ServeHTTP(w, req)
	})

	log.Printf("info: Start listener on %s category='HTTP-Proxy'", s.ListenAddress)

	go func() {
		http.Serve(l, proxy)
	}()

	return nil
}
