package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/wadahiro/go-tproxy"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
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

	dnsPrivateServer = fs.String("private-dns", "",
		"Private DNS address for no_proxy targets (IP[:port])")

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

	dnsEndpoint = fs.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = fs.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = fs.Bool("dns-udp", true, "DNS Listen on UDP")
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "go-tproxy.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

	level, err := log.ParseLevel(*loglevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", err.Error())
	}
	formatter := &log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	}
	log.SetFormatter(formatter)
	log.SetLevel(level)

	// handling no_proxy environment
	noProxy := os.Getenv("no_proxy")
	if noProxy == "" {
		noProxy = os.Getenv("NO_PROXY")
	}
	np := parseNoProxy(noProxy)

	// start servers
	tcpProxy := tproxy.NewTCPProxy(
		tproxy.TCPProxyConfig{
			ListenAddress: *tcpProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := tcpProxy.Start(); err != nil {
		log.Fatalf(err.Error())
	}

	dnsProxy := tproxy.NewDNSProxy(
		tproxy.DNSProxyConfig{
			ListenAddress:  *dnsProxyListenAddress,
			EnableUDP:      *dnsEnableUDP,
			EnableTCP:      *dnsEnableTCP,
			Endpoint:       *dnsEndpoint,
			PrivateDNS:     *dnsPrivateServer,
			NoProxyDomains: np.Domains,
		},
	)
	dnsProxy.Start()

	httpProxy := tproxy.NewHTTPProxy(
		tproxy.HTTPProxyConfig{
			ListenAddress: *httpProxyListenAddress,
			NoProxy:       np,
			Verbose:       level == log.DebugLevel,
		},
	)
	if err := httpProxy.Start(); err != nil {
		log.Fatalf(err.Error())
	}

	httpsProxy := tproxy.NewHTTPSProxy(
		tproxy.HTTPSProxyConfig{
			ListenAddress: *httpsProxyListenAddress,
			NoProxy:       np,
		},
	)
	if err := httpsProxy.Start(); err != nil {
		log.Fatalf(err.Error())
	}

	log.Infoln("All proxy servers started.")

	dnsToPort := toPort(*dnsProxyListenAddress)
	httpToPort := toPort(*httpProxyListenAddress)
	httpsToPort := toPort(*httpsProxyListenAddress)
	tcpToPort := toPort(*tcpProxyListenAddress)
	tcpDPorts := toPorts(*tcpProxyDestPorts)

	t, err := tproxy.NewIPTables(&tproxy.IPTablesConfig{
		DNSToPort:   dnsToPort,
		HTTPToPort:  httpToPort,
		HTTPSToPort: httpsToPort,
		TCPToPort:   tcpToPort,
		TCPDPorts:   tcpDPorts,
	})
	if err != nil {
		log.Fatalf("IPTables: %s", err.Error())
	}

	t.Start()

	log.Infof(`IPTables: iptables rules inserted as follows.
---
%s
---`, t.Show())

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Infoln("Proxy servers stopping.")

	// start shutdown process
	t.Stop()
	log.Infoln("IPTables: iptables rules deleted.")

	dnsProxy.Stop()
	log.Infoln("go-tproxy exited.")
}

func toPort(addr string) int {
	array := strings.Split(addr, ":")
	if len(array) != 2 {
		log.Fatalf("Invalid address, no port: %s", addr)
	}

	i, err := strconv.Atoi(array[1])
	if err != nil {
		log.Fatalf("Invalid address, the port isn't number: %s", addr)
	}

	if i > 65535 || i < 0 {
		log.Fatalf("Invalid address, the port must be an integer value in the range 0-65535: %s", addr)
	}

	return i
}

func toPorts(ports string) []int {
	array := strings.Split(ports, ",")

	var p []int

	for _, v := range array {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("Invalid port, It's not number: %s", ports)
		}

		if i > 65535 || i < 0 {
			log.Fatalf("Invalid port, It must be an integer value in the range 0-65535: %s", ports)
		}

		p = append(p, i)
	}

	return p
}

func parseNoProxy(noProxy string) tproxy.NoProxy {
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

	return tproxy.NoProxy{
		IPs:     ipArray,
		CIDRs:   cidrArray,
		Domains: domainArray,
	}
}
