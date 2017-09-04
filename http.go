package tproxy

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/elazarl/goproxy"
	"net/http"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

type HTTPProxy struct {
	HTTPProxyConfig
}

type HTTPProxyConfig struct {
	ListenAddress    string
	NoProxyAddresses []string
	NoProxyDomains   []string
	Verbose          bool
}

func NewHTTPProxy(c HTTPProxyConfig) *HTTPProxy {
	return &HTTPProxy{
		HTTPProxyConfig: c,
	}
}

func (s HTTPProxy) Start() error {
	l, err := NewTCPListener(s.ListenAddress)
	if err != nil {
		log.Fatalf("HTTP-Proxy: Error listening for tcp connections - %s", err.Error())
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.Proxy = httpProxyFromRule(s.NoProxyDomains, s.NoProxyAddresses)
	proxy.Verbose = s.Verbose

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Debugf("HTTP-Proxy: Accept: %s, %s", req.Host, req.URL)
		if req.Host == "" {
			// TODO use origAddr from TCPCon
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		// Convert to proxy request (abs URL request) for passing goproxy handler
		req.URL.Scheme = "http"
		req.URL.Host = req.Host

		// proxy to real target
		proxy.ServeHTTP(w, req)
	})

	log.Infof("HTTP-Proxy: Start listener on %s", s.ListenAddress)

	go func() {
		http.Serve(l, proxy)
	}()

	return nil
}
