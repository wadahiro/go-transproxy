package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
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

	dnsPrivateServer = flag.String("private-dns", "",
		"Private DNS address for no_proxy targets (IP[:port])")

	tcpProxyDestPorts = flag.String(
		"tcp-proxy-dports", "22", "TCP Proxy dports, as `port1,port2,...`",
	)

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

	dnsEndpoint = flag.String(
		"dns-endpoint",
		"https://dns.google.com/resolve",
		"DNS-over-HTTPS endpoint URL",
	)

	dnsEnableTCP = flag.Bool("dns-tcp", true, "DNS Listen on TCP")
	dnsEnableUDP = flag.Bool("dns-udp", true, "DNS Listen on UDP")
)

const (
	NAT        = "nat"
	PREROUTING = "PREROUTING"
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
			PrivateDNS:     *dnsPrivateServer,
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

	t, err := iptables.New()
	if err != nil {
		log.Fatalf(err.Error())
	}

	dnsTCPRule := []string{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strings.Split(*dnsProxyListenAddress, ":")[1]}
	dnsUDPRule := []string{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strings.Split(*dnsProxyListenAddress, ":")[1]}
	httpRule := []string{"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", strings.Split(*httpProxyListenAddress, ":")[1]}
	httpsRule := []string{"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", strings.Split(*httpsProxyListenAddress, ":")[1]}
	tcpRule := []string{"-p", "tcp", "-m", "multiport", "--dport", *tcpProxyDestPorts, "-j", "REDIRECT", "--to-ports", strings.Split(*tcpProxyListenAddress, ":")[1]}

	exists, err := t.Exists(NAT, PREROUTING, dnsTCPRule...)
	if exists {
		failIptables(dnsTCPRule)
	}
	exists, err = t.Exists(NAT, PREROUTING, dnsUDPRule...)
	if exists {
		failIptables(dnsTCPRule)
	}
	exists, err = t.Exists(NAT, PREROUTING, httpRule...)
	if exists {
		failIptables(dnsTCPRule)
	}
	exists, err = t.Exists(NAT, PREROUTING, httpsRule...)
	if exists {
		failIptables(dnsTCPRule)
	}
	exists, err = t.Exists(NAT, PREROUTING, tcpRule...)
	if exists {
		failIptables(dnsTCPRule)
	}

	t.Insert(NAT, PREROUTING, 1, dnsTCPRule...)
	t.Insert(NAT, PREROUTING, 2, dnsUDPRule...)
	t.Insert(NAT, PREROUTING, 3, httpRule...)
	t.Insert(NAT, PREROUTING, 4, httpsRule...)
	t.Insert(NAT, PREROUTING, 5, tcpRule...)

	log.Infoln("iptables inserted.")

	// serve until exit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	t.Delete(NAT, PREROUTING, dnsTCPRule...)
	t.Delete(NAT, PREROUTING, dnsUDPRule...)
	t.Delete(NAT, PREROUTING, httpRule...)
	t.Delete(NAT, PREROUTING, httpsRule...)
	t.Delete(NAT, PREROUTING, tcpRule...)

	log.Infoln("iptables deleted.")

	log.Infoln("tproxy servers stopping.")

	// start shutdown
	dnsProxy.Stop()

	log.Infoln("tproxy servers exited.")
}

func failIptables(rule []string) {
	log.Fatalf("Same iptables rule already exists : iptables -t nat -I PREROUTING %s", strings.Join(rule, " "))
}
