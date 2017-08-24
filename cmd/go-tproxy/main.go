package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/wadahiro/go-tproxy"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
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
	logLevel = flag.String(
		"logLevel",
		"info",
		"Log level, one of: debug, info, warn, error, fatal, panic",
	)

	noProxyAddresses = flag.String("no-proxy-addresses", "",
		"List of no proxy ip addresses, as `192.168.0.10` or `192.168.0.0/24`")

	noProxyDomains = flag.String("no-proxy-domains", "",
		"List of noproxy subdomains")

	tcpProxyListenAddress = flag.String(
		"tcp-proxy-listen", ":3128", "TCP Proxy listen address, as `[host]:port`",
	)

	httpProxyListenAddress = flag.String(
		"http-proxy-listen", ":3129", "HTTP Proxy listen address, as `[host]:port`",
	)

	httpsProxyListenAddress = flag.String(
		"https-proxy-listen", ":3130", "HTTPS Proxy listen address, as `[host]:port`",
	)

	dnsProxyListenAddress = flag.String(
		"dns-proxy-listen", ":3131", "DNS Proxy listen address, as `[host]:port`",
	)

	dnsInternalServer = flag.String("dns-internal-server", "",
		"Internal DNS server where to send queries if route matched (IP[:port])")

	dnsEndpoint = flag.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = flag.Bool("dns-udp", true, "DNS Listen on UDP")
)

func main() {
	flag.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "go-tproxy.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		flag.PrintDefaults()
	}
	flag.Parse()

	// seed the global random number generator, used in secureoperator
	rand.Seed(time.Now().UTC().UnixNano())

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", err.Error())
	}
	formatter := &log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	}
	log.SetFormatter(formatter)
	log.SetLevel(level)

	// start servers
	tcpProxy := tproxy.NewTCPProxy(
		tproxy.TCPProxyConfig{
			ListenAddress:    *tcpProxyListenAddress,
			NoProxyAddresses: strings.Split(*noProxyAddresses, ","),
			NoProxyDomains:   strings.Split(*noProxyDomains, ","),
		},
	)
	if err := tcpProxy.Run(); err != nil {
		log.Fatalf(err.Error())
	}

	dnsProxy := tproxy.NewDNSProxy(
		tproxy.DNSProxyConfig{
			ListenAddress:  *dnsProxyListenAddress,
			EnableUDP:      *dnsEnableUDP,
			EnableTCP:      *dnsEnableTCP,
			Endpoint:       *dnsEndpoint,
			InternalDNS:    *dnsInternalServer,
			NoProxyDomains: strings.Split(*noProxyDomains, ","),
		},
	)
	dnsProxy.Run()

	httpProxy := tproxy.NewHTTPProxy(
		tproxy.HTTPProxyConfig{
			ListenAddress:    *httpProxyListenAddress,
			NoProxyAddresses: strings.Split(*noProxyAddresses, ","),
			NoProxyDomains:   strings.Split(*noProxyDomains, ","),
		},
	)
	if err := httpProxy.Run(); err != nil {
		log.Fatalf(err.Error())
	}

	httpsProxy := tproxy.NewHTTPSProxy(
		tproxy.HTTPSProxyConfig{
			ListenAddress:    *httpsProxyListenAddress,
			NoProxyAddresses: strings.Split(*noProxyAddresses, ","),
			NoProxyDomains:   strings.Split(*noProxyDomains, ","),
		},
	)
	if err := httpsProxy.Run(); err != nil {
		log.Fatalf(err.Error())
	}

	log.Infoln("tproxy servers started.")

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Infoln("tproxy servers stopping.")

	// start shutdown
	dnsProxy.Stop()

	log.Infoln("tproxy servers exited.")
}
