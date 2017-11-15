package transproxy

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	secop "github.com/fardog/secureoperator"
	"github.com/miekg/dns"
)

type DNSProxy struct {
	DNSProxyConfig
	udpServer *dns.Server
	tcpServer *dns.Server
	udpClient *dns.Client // used for fowarding to internal DNS
	tcpClient *dns.Client // used for fowarding to internal DNS
	waitGroup *sync.WaitGroup
}

type DNSProxyConfig struct {
	Enabled             bool
	ListenAddress       string
	EnableUDP           bool
	EnableTCP           bool
	Endpoint            string
	PublicDNS           string
	PrivateDNS          string
	DNSOverHTTPSEnabled bool
	NoProxyDomains      []string
}

func NewDNSProxy(c DNSProxyConfig) *DNSProxy {
	// Suppress standard logger for secureoperator
	logrus.SetLevel(logrus.ErrorLevel)

	// fix dns address
	if c.PublicDNS != "" {
		_, _, err := net.SplitHostPort(c.PublicDNS)
		if err != nil {
			c.PublicDNS = net.JoinHostPort(c.PublicDNS, "53")
		}
	}
	if c.PrivateDNS != "" {
		_, _, err := net.SplitHostPort(c.PrivateDNS)
		if err != nil {
			c.PrivateDNS = net.JoinHostPort(c.PrivateDNS, "53")
		}
	}

	// fix domains
	var noProxyRoutes []string
	for _, s := range c.NoProxyDomains {
		if !strings.HasSuffix(s, ".") {
			s += "."
		}
		noProxyRoutes = append(noProxyRoutes, s)
	}
	c.NoProxyDomains = noProxyRoutes

	return &DNSProxy{
		DNSProxyConfig: c,
		udpServer:      nil,
		tcpServer:      nil,
		udpClient: &dns.Client{
			Net:            "udp",
			Timeout:        time.Duration(10) * time.Second,
			SingleInflight: true,
		},
		tcpClient: &dns.Client{
			Net:            "tcp",
			Timeout:        time.Duration(10) * time.Second,
			SingleInflight: true,
		},
		waitGroup: new(sync.WaitGroup),
	}
}

func (s *DNSProxy) Start() error {
	if !s.Enabled {
		log.Printf("debug: Disabled category='DNS-Proxy'")
		return nil
	}

	log.Printf("info: Start listener on %s category='DNS-Proxy'", s.ListenAddress)
	if s.DNSOverHTTPSEnabled {
		log.Printf("info: Use DNS-over-HTTPS service as public DNS category='DNS-Proxy'")
	}
	if !s.DNSOverHTTPSEnabled && s.PublicDNS != "" {
		log.Printf("info: Use %s as public DNS category='DNS-Proxy'", s.PublicDNS)
	}
	if s.PrivateDNS != "" {
		log.Printf("info: Use %s as private DNS for %s domains category='DNS-Proxy'", s.PrivateDNS, s.NoProxyDomains)
	}

	// Prepare external DNS handler
	provider, err := secop.NewGDNSProvider(s.Endpoint, &secop.GDNSOptions{
		Pad: true,
	})

	if err != nil {
		log.Fatal("alert: %s category='DNS-Proxy'", err)
	}

	options := &secop.HandlerOptions{}
	publicOverHTTPSHandler := secop.NewHandler(provider, options)

	// Setup DNS Handler
	dnsHandle := func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			dns.HandleFailed(w, req)
			return
		}

		// access logging
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		log.Printf("info: category='DNS-Proxy' remoteAddr='%s' questionName='%s' questionType='%s'", host, req.Question[0].Name, dns.TypeToString[req.Question[0].Qtype])

		// Resolve by proxied private DNS
		for _, domain := range s.NoProxyDomains {
			log.Printf("debug: Checking DNS route, request: %s, no_proxy: %s", req.Question[0].Name, domain)
			if strings.HasSuffix(req.Question[0].Name, domain) {
				log.Printf("debug: Matched! Routing to private DNS, request: %s, no_proxy: %s", req.Question[0].Name, domain)
				s.handlePrivate(w, req)
				return
			}
		}

		// Resolve by public DNS over HTTPS over http proxy
		if s.DNSOverHTTPSEnabled {
			publicOverHTTPSHandler.Handle(w, req)
			return
		}

		// Resolve by specified public DNS over http proxy
		s.handlePublic(w, req)
	}

	dns.HandleFunc(".", dnsHandle)

	// Start DNS Server

	if s.EnableUDP {
		s.udpServer = &dns.Server{
			Addr:       s.ListenAddress,
			Net:        "udp",
			TsigSecret: nil,
		}
	}
	if s.EnableTCP {
		s.tcpServer = &dns.Server{
			Addr:       s.ListenAddress,
			Net:        "tcp",
			TsigSecret: nil,
		}
	}

	go func() {
		if s.udpServer != nil {
			if err := s.udpServer.ListenAndServe(); err != nil {
				log.Fatal("alert: %s", err.Error())
			}
		}
		if s.tcpServer != nil {
			if err := s.tcpServer.ListenAndServe(); err != nil {
				log.Fatal("alert: %s", err.Error())
			}
		}
	}()

	return nil
}

func (s *DNSProxy) handlePublic(w dns.ResponseWriter, req *dns.Msg) {
	log.Printf("debug: DNS request. %#v, %s", req, req)

	// Need to use TCP because of using TCP-Proxy
	resp, _, err := s.tcpClient.Exchange(req, s.PublicDNS)
	if err != nil {
		log.Printf("warn: DNS Client failed. %s, %#v, %s", err.Error(), req, req)
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

func (s *DNSProxy) handlePrivate(w dns.ResponseWriter, req *dns.Msg) {
	var c *dns.Client
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		c = s.tcpClient
	} else {
		c = s.udpClient
	}

	log.Printf("debug: DNS request. %#v, %s", req, req)

	resp, _, err := c.Exchange(req, s.PrivateDNS)
	if err != nil {
		log.Printf("warn: DNS Client failed. %s, %#v, %s", err.Error(), req, req)
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

func (s *DNSProxy) Stop() {
	if !s.Enabled {
		return
	}

	log.Printf("info: Shutting down DNS service on interrupt\n")

	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			log.Printf("error: %s", err.Error())
		}
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			log.Printf("error: %s", err.Error())
		}
		s.tcpServer = nil
	}
}
