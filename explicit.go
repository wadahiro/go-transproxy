package transproxy

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	log "github.com/Sirupsen/logrus"
)

type ExplicitProxy struct {
	ExplicitProxyConfig
	proxyHost          string
	proxyAuthorization string
}

type ExplicitProxyConfig struct {
	ListenAddress string
}

func NewExplicitProxy(c ExplicitProxyConfig) *ExplicitProxy {
	return &ExplicitProxy{
		ExplicitProxyConfig: c,
	}
}

func (s ExplicitProxy) Start() error {
	u, err := url.Parse(os.Getenv("http_proxy"))
	if err != nil {
		return err
	}

	// For HTTPS
	s.proxyAuthorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String()))
	s.proxyHost = u.Host

	// For HTTP
	http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(u)}

	handler := http.HandlerFunc(s.handleRequest)

	log.Infof("Explicit-Proxy: Start listener on %s", s.ListenAddress)

	go func() {
		http.ListenAndServe(s.ListenAddress, handler)
	}()

	return nil
}

func (s ExplicitProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Infof("Explicit-Proxy: %s %s", r.Method, r.URL)
	if r.Method == "CONNECT" {
		handleHttps(s.proxyHost, s.proxyAuthorization, w, r)
	} else {
		handleHttp(w, r)
	}
}

func handleHttps(proxyHost, auth string, w http.ResponseWriter, r *http.Request) {
	hj, _ := w.(http.Hijacker)
	if proxyConn, err := net.Dial("tcp", proxyHost); err != nil {
		log.Fatal(err)
	} else if clientConn, _, err := hj.Hijack(); err != nil {
		proxyConn.Close()
		log.Fatal(err)
	} else {
		r.Header.Set("Proxy-Authorization", auth)
		r.Write(proxyConn)
		go func() {
			io.Copy(clientConn, proxyConn)
			proxyConn.Close()
		}()
		go func() {
			io.Copy(proxyConn, clientConn)
			clientConn.Close()
		}()
	}
}

func handleHttp(w http.ResponseWriter, r *http.Request) {
	hj, _ := w.(http.Hijacker)
	client := &http.Client{}
	r.RequestURI = ""
	if resp, err := client.Do(r); err != nil {
		log.Fatal(err)
	} else if conn, _, err := hj.Hijack(); err != nil {
		log.Fatal(err)
	} else {
		defer conn.Close()
		resp.Write(conn)
	}
}
