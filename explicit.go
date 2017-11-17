package transproxy

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type ExplicitProxy struct {
	ExplicitProxyConfig
	user     string
	category string
	// For HTTP
	proxyTransport     *http.Transport
	proxyAuthTransport *http.Transport
	// For HTTPS
	proxyHost          string
	proxyAuthorization string
}

type ExplicitProxyConfig struct {
	ListenAddress         string
	UseProxyAuthorization bool
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

	if s.UseProxyAuthorization {
		s.category = "Explicit-Proxy(Auth)"

		// For HTTPS
		s.proxyAuthorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String()))
		s.proxyHost = u.Host

		// For HTTP
		s.proxyAuthTransport = &http.Transport{Proxy: http.ProxyURL(u)}
	} else {
		s.category = "Explicit-Proxy(NoAuth)"

		// For HTTPS
		s.proxyHost = u.Host

		// For HTTP
		u, _ = url.Parse(u.String())
		u.User = nil
		s.proxyTransport = &http.Transport{Proxy: http.ProxyURL(u)}
	}

	handler := http.HandlerFunc(s.handleRequest)

	log.Printf("info: Start listener on %s category='%s'", s.ListenAddress, s.category)

	go func() {
		http.ListenAndServe(s.ListenAddress, handler)
	}()

	return nil
}

func (s ExplicitProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// access logging
	s.accessLog(r)

	if r.Method == "CONNECT" {
		s.handleHttps(w, r)
	} else {
		s.handleHttp(w, r)
	}
}

func (s ExplicitProxy) accessLog(r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.UseProxyAuthorization {
		log.Printf("info: category='%s' remoteAddr='%s' method='%s' uri='%s'", s.category, host, r.Method, r.RequestURI)
	} else {
		var decodedAuth string

		values := r.Header["Proxy-Authorization"]
		if len(values) > 0 {
			auth := strings.Split(values[0], " ")
			if len(auth) > 0 {
				b, _ := base64.StdEncoding.DecodeString(auth[1])
				decodedAuth = strings.Split(string(b[:]), ":")[0]
			}
		}
		log.Printf("info: category='%s' user='%s' remoteAddr='%s' method='%s' uri='%s'", s.category, decodedAuth, host, r.Method, r.RequestURI)
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
		if s.UseProxyAuthorization {
			r.Header.Set("Proxy-Authorization", s.proxyAuthorization)
		}
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
	var client *http.Client
	if s.UseProxyAuthorization {
		client = &http.Client{
			Transport: s.proxyAuthTransport,
		}
	} else {
		client = &http.Client{
			Transport: s.proxyTransport,
		}
	}

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
