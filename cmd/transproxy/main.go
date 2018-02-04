package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/comail/colog"
	transproxy "github.com/wadahiro/go-transproxy"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

var (
	fs       = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	loglevel = fs.String(
		"loglevel",
		"info",
		"Log level, one of: debug, info, warn, error, fatal, panic",
	)

	privateDNS = fs.String("private-dns", "",
		"Private DNS address for no_proxy targets (IP[:port])")

	publicDNS = fs.String("public-dns", "",
		"Public DNS address (IP[:port]) Note: Your proxy needs to support CONNECT method to the Public DNS port, and the public DNS needs to support TCP")

	tcpProxyDestPorts = fs.String(
		"tcp-proxy-dports", "22", "TCP Proxy dports, as `port1,port2,...`",
	)

	tcpProxyListenAddress = fs.String(
		"tcp-proxy-listen", ":3128", "TCP Proxy listen address, as `[host]:port`",
	)

	httpProxyListenAddress = fs.String(
		"http-proxy-listen", ":3129", "HTTP Proxy listen address, as `[host]:port`",
	)

	httpsProxyListenAddress = fs.String(
		"https-proxy-listen", ":3130", "HTTPS Proxy listen address, as `[host]:port`",
	)

	dnsProxyListenAddress = fs.String(
		"dns-proxy-listen", ":3131", "DNS Proxy listen address, as `[host]:port`",
	)

	explicitProxyListenAddress = fs.String(
		"explicit-proxy-listen", ":3132", "Explicit Proxy listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy doesn't use authentication info of the `http_proxy` and `https_proxy` environment variables",
	)

	explicitProxyWithAuthListenAddress = fs.String(
		"explicit-proxy-with-auth-listen", ":3133", "Explicit Proxy with auth listen address for HTTP/HTTPS, as `[host]:port` Note: This proxy uses authentication info of the `http_proxy` and `https_proxy` environment variables",
	)

	dnsOverTCPDisabled = fs.Bool(
		"dns-over-tcp-disabled", false, "Disable DNS-over-TCP for querying to public DNS")

	dnsOverHTTPSEnabled = fs.Bool(
		"dns-over-https-enabled", false, "Use DNS-over-HTTPS service as public DNS")

	dnsOverHTTPSEndpoint = fs.String(
		"dns-over-https-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = fs.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = fs.Bool("dns-udp", true, "DNS Listen on UDP")
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "go-transproxy.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

	// setup logger
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LInfo)
	level, err := colog.ParseLevel(*loglevel)
	if err != nil {
		log.Fatalf("alert: Invalid log level: %s", err.Error())
	}
	colog.SetMinLevel(level)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds,
	})
	colog.ParseFields(true)
	colog.Register()

	// handling no_proxy environment
	noProxy := os.Getenv("no_proxy")
	if noProxy == "" {
		noProxy = os.Getenv("NO_PROXY")
	}
	np := parseNoProxy(noProxy)

	// start servers
	tcpProxy := transproxy.NewTCPProxy(
		transproxy.TCPProxyConfig{
			ListenAddress: *tcpProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := tcpProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	dnsProxy := transproxy.NewDNSProxy(
		transproxy.DNSProxyConfig{
			Enabled:             useDNSProxy(),
			ListenAddress:       *dnsProxyListenAddress,
			EnableUDP:           *dnsEnableUDP,
			EnableTCP:           *dnsEnableTCP,
			Endpoint:            *dnsOverHTTPSEndpoint,
			PublicDNS:           *publicDNS,
			PrivateDNS:          *privateDNS,
			DNSOverHTTPSEnabled: *dnsOverHTTPSEnabled,
			NoProxyDomains:      np.Domains,
		},
	)
	dnsProxy.Start()

	httpProxy := transproxy.NewHTTPProxy(
		transproxy.HTTPProxyConfig{
			ListenAddress: *httpProxyListenAddress,
			NoProxy:       np,
			Verbose:       level == colog.LDebug,
		},
	)
	if err := httpProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	httpsProxy := transproxy.NewHTTPSProxy(
		transproxy.HTTPSProxyConfig{
			ListenAddress: *httpsProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := httpsProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	explicitProxyWithAuth := transproxy.NewExplicitProxy(
		transproxy.ExplicitProxyConfig{
			ListenAddress:         *explicitProxyWithAuthListenAddress,
			UseProxyAuthorization: true,
		},
	)
	if err := explicitProxyWithAuth.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	explicitProxy := transproxy.NewExplicitProxy(
		transproxy.ExplicitProxyConfig{
			ListenAddress:         *explicitProxyListenAddress,
			UseProxyAuthorization: false,
		},
	)
	if err := explicitProxy.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}

	log.Printf("info: All proxy servers started.")

	dnsToPort := toPort(*dnsProxyListenAddress)
	httpToPort := toPort(*httpProxyListenAddress)
	httpsToPort := toPort(*httpsProxyListenAddress)
	tcpToPort := toPort(*tcpProxyListenAddress)
	tcpDPorts := toPorts(*tcpProxyDestPorts)

	outgoingPublicDNS := *publicDNS
	if *dnsOverTCPDisabled {
		outgoingPublicDNS = ""
	}

	t, err := transproxy.NewIPTables(&transproxy.IPTablesConfig{
		DNSToPort:   dnsToPort,
		HTTPToPort:  httpToPort,
		HTTPSToPort: httpsToPort,
		TCPToPort:   tcpToPort,
		TCPDPorts:   tcpDPorts,
		PublicDNS:   outgoingPublicDNS,
	})
	if err != nil {
		log.Printf("alert: %s", err.Error())
	}

	t.Start()

	log.Printf(`info: iptables rules inserted as follows.
---
%s
---`, t.Show())

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("info: Proxy servers stopping.")

	// start shutdown process
	t.Stop()
	log.Printf("info: iptables rules deleted.")

	if dnsProxy != nil {
		dnsProxy.Stop()
	}

	log.Printf("info: go-transproxy exited.")
}

func useDNSProxy() bool {
	if *privateDNS == "" && *publicDNS == "" && *dnsOverHTTPSEnabled == false {
		return false
	}
	return true
}

func toPort(addr string) int {
	array := strings.Split(addr, ":")
	if len(array) != 2 {
		log.Printf("alert: Invalid address, no port: %s", addr)
	}

	i, err := strconv.Atoi(array[1])
	if err != nil {
		log.Printf("alert: Invalid address, the port isn't number: %s", addr)
	}

	if i > 65535 || i < 0 {
		log.Printf("alert: Invalid address, the port must be an integer value in the range 0-65535: %s", addr)
	}

	return i
}

func toPorts(ports string) []int {
	array := strings.Split(ports, ",")

	var p []int

	for _, v := range array {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("alert: Invalid port, It's not number: %s", ports)
		}

		if i > 65535 || i < 0 {
			log.Printf("alert: Invalid port, It must be an integer value in the range 0-65535: %s", ports)
		}

		p = append(p, i)
	}

	return p
}

func parseNoProxy(noProxy string) transproxy.NoProxy {
	p := strings.Split(noProxy, ",")

	var ipArray []string
	var cidrArray []*net.IPNet
	var domainArray []string

	for _, v := range p {
		ip := net.ParseIP(v)
		if ip != nil {
			ipArray = append(ipArray, v)
			continue
		}

		_, ipnet, err := net.ParseCIDR(v)
		if err == nil {
			cidrArray = append(cidrArray, ipnet)
			continue
		}

		domainArray = append(domainArray, v)
	}

	return transproxy.NoProxy{
		IPs:     ipArray,
		CIDRs:   cidrArray,
		Domains: domainArray,
	}
}
