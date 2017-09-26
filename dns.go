package tproxy

import (
	log "github.com/Sirupsen/logrus"
	secop "github.com/fardog/secureoperator"
	"github.com/miekg/dns"
	"net"
	"strings"
	"sync"
	"time"
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
		log.Infof("DNS-Proxy: Disabled")
		return nil
	}

	log.Infof("DNS-Proxy: Start listener on %s", s.ListenAddress)
	if s.DNSOverHTTPSEnabled {
		log.Infof("DNS-Proxy: Use DNS-over-HTTPS service as public DNS")
	}
	if !s.DNSOverHTTPSEnabled && s.PublicDNS != "" {
		log.Infof("DNS-Proxy: Use %s as public DNS", s.PublicDNS)
	}
	if s.PrivateDNS != "" {
		log.Infof("DNS-Proxy: Use %s as private DNS for %s domains", s.PrivateDNS, s.NoProxyDomains)
	}

	// Prepare external DNS handler
	provider, err := secop.NewGDNSProvider(s.Endpoint, &secop.GDNSOptions{
		Pad: true,
	})

	if err != nil {
		log.Fatal(err)
	}

	options := &secop.HandlerOptions{}
	publicOverHTTPSHandler := secop.NewHandler(provider, options)

	// Setup DNS Handler
	dnsHandle := func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			dns.HandleFailed(w, req)
			return
		}
		// Resolve by proxied private DNS
		for _, domain := range s.NoProxyDomains {
			log.Debugf("DNS-Proxy: Checking DNS route, request: %s, no_proxy: %s", req.Question[0].Name, domain)
			if strings.HasSuffix(req.Question[0].Name, domain) {
				log.Debugf("DNS-Proxy: Matched! Routing to private DNS, request: %s, no_proxy: %s", req.Question[0].Name, domain)
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
				log.Fatal(err.Error())
			}
		}
		if s.tcpServer != nil {
			if err := s.tcpServer.ListenAndServe(); err != nil {
				log.Fatal(err.Error())
			}
		}
	}()

	return nil
}

func (s *DNSProxy) handlePublic(w dns.ResponseWriter, req *dns.Msg) {
	log.Debugf("DNS-Proxy: DNS request. %#v, %s", req, req)

	// Need to use TCP because of using TCP-Proxy
	resp, _, err := s.tcpClient.Exchange(req, s.PublicDNS)
	if err != nil {
		log.Warnf("DNS-Proxy: DNS Client failed. %s, %#v, %s", err.Error(), req, req)
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

	log.Debugf("DNS-Proxy: DNS request. %#v, %s", req, req)

	resp, _, err := c.Exchange(req, s.PrivateDNS)
	if err != nil {
		log.Warnf("DNS-Proxy: DNS Client failed. %s, %#v, %s", err.Error(), req, req)
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

func (s *DNSProxy) Stop() {
	if !s.Enabled {
		return
	}

	log.Infof("DNS-Proxy: Shutting down DNS service on interrupt\n")

	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			log.Error(err.Error())
		}
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			log.Error(err.Error())
		}
		s.tcpServer = nil
	}
}
