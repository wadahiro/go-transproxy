package transproxy

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
)

type ExplicitProxy struct {
	ExplicitProxyConfig
	user               string
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
	s.user = u.User.Username()

	// For HTTPS
	s.proxyAuthorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String()))
	s.proxyHost = u.Host

	// For HTTP
	http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(u)}

	handler := http.HandlerFunc(s.handleRequest)

	log.Printf("info: Start listener on %s category='Explicit-Proxy'", s.ListenAddress)

	go func() {
		http.ListenAndServe(s.ListenAddress, handler)
	}()

	return nil
}

func (s ExplicitProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// access logging
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	log.Printf("info: category='Explicit-Proxy' remoteAddr='%s' method='%s' uri='%s'", host, r.Method, r.RequestURI)

	if r.Method == "CONNECT" {
		s.handleHttps(w, r)
	} else {
		s.handleHttp(w, r)
	}
}

func (s ExplicitProxy) handleHttps(w http.ResponseWriter, r *http.Request) {
	hj, _ := w.(http.Hijacker)
	if proxyConn, err := net.Dial("tcp", s.proxyHost); err != nil {
		log.Printf("error: %s", err)
	} else if clientConn, _, err := hj.Hijack(); err != nil {
		proxyConn.Close()
		log.Printf("error: %s", err)
	} else {
		r.Header.Set("Proxy-Authorization", s.proxyAuthorization)
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

func (s ExplicitProxy) handleHttp(w http.ResponseWriter, r *http.Request) {
	hj, _ := w.(http.Hijacker)
	client := &http.Client{}
	r.RequestURI = ""
	if resp, err := client.Do(r); err != nil {
		log.Printf("error: %s", err)
	} else if conn, _, err := hj.Hijack(); err != nil {
		log.Printf("error: %s", err)
	} else {
		defer conn.Close()
		resp.Write(conn)
	}
}
