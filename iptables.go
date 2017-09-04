package tproxy

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"strconv"
	"strings"
)

const (
	NAT        = "nat"
	PREROUTING = "PREROUTING"
)

type IPTables struct {
	iptables   *iptables.IPTables
	dnsTCPRule []string
	dnsUDPRule []string
	httpRule   []string
	httpsRule  []string
	tcpRule    []string
	err        error
}

type IPTablesConfig struct {
	DNSToPort   int
	HTTPToPort  int
	HTTPSToPort int
	TCPToPort   int
	TCPDPorts   []int
}

func NewIPTables(c *IPTablesConfig) (*IPTables, error) {
	t, err := iptables.New()
	if err != nil {
		return nil, err
	}

	var tcpDPorts []string
	for _, v := range c.TCPDPorts {
		tcpDPorts = append(tcpDPorts, strconv.Itoa(v))
	}

	dnsTCPRule := []string{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
	dnsUDPRule := []string{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.DNSToPort)}
	httpRule := []string{"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPToPort)}
	httpsRule := []string{"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.HTTPSToPort)}
	tcpRule := []string{"-p", "tcp", "-m", "multiport", "--dport", strings.Join(tcpDPorts, ","), "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.TCPToPort)}

	return &IPTables{
		iptables:   t,
		dnsTCPRule: dnsTCPRule,
		dnsUDPRule: dnsUDPRule,
		httpRule:   httpRule,
		httpsRule:  httpsRule,
		tcpRule:    tcpRule,
	}, nil
}

func (t *IPTables) Start() error {
	t.Check(t.dnsTCPRule)
	t.Check(t.dnsUDPRule)
	t.Check(t.httpRule)
	t.Check(t.httpsRule)
	t.Check(t.tcpRule)

	t.insertRule(t.dnsTCPRule)
	t.insertRule(t.dnsUDPRule)
	t.insertRule(t.httpRule)
	t.insertRule(t.httpsRule)
	t.insertRule(t.tcpRule)

	return t.err
}

func (t *IPTables) Stop() error {
	t.deleteRule(t.dnsTCPRule)
	t.deleteRule(t.dnsUDPRule)
	t.deleteRule(t.httpRule)
	t.deleteRule(t.httpsRule)
	t.deleteRule(t.tcpRule)

	return t.err
}

func (t *IPTables) Show() string {
	return fmt.Sprintf(`iptables -t %s
iptables -t %s
iptables -t %s
iptables -t %s
iptables -t %s`,
		NAT+" "+PREROUTING+" "+strings.Join(t.tcpRule, " "),
		NAT+" "+PREROUTING+" "+strings.Join(t.httpsRule, " "),
		NAT+" "+PREROUTING+" "+strings.Join(t.httpRule, " "),
		NAT+" "+PREROUTING+" "+strings.Join(t.dnsUDPRule, " "),
		NAT+" "+PREROUTING+" "+strings.Join(t.dnsTCPRule, " "),
	)
}

func (t *IPTables) Check(rule []string) {
	if t.err != nil {
		return
	}

	exists, err := t.iptables.Exists(NAT, PREROUTING, rule...)
	if exists {
		t.err = fmt.Errorf("Same iptables rule already exists : iptables -t nat -I PREROUTING %s", strings.Join(rule, " "))
	}

	if err != nil {
		t.err = fmt.Errorf("Checking iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) insertRule(rule []string) {
	if t.err != nil {
		return
	}

	if err := t.iptables.Insert(NAT, PREROUTING, 1, rule...); err != nil {
		t.err = fmt.Errorf("Insert iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) deleteRule(rule []string) {
	// Don't skip when it has error for deleting all rules

	if err := t.iptables.Delete(NAT, PREROUTING, rule...); err != nil {
		t.err = fmt.Errorf("Delete iptables rule failed : %s", err.Error())
	}
}
