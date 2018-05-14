# go-transproxy

Transparent proxy servers for HTTP, HTTPS, DNS and TCP. 
This repository is heavily under development.

## Description

**go-transproxy** provides transparent proxy servers for HTTP, HTTPS, DNS and TCP with single binary.
Nothing needs to setup many tools. Nothing needs to configure iptables.
**go-transproxy** will start multiple proxy servers for these protocols.
Futheremore, it will configure iptables automatically.

**go-transproxy** also provides two types of explicit proxy(not transparent proxy).
One is a simple proxy delegating to upstream your proxy, another is for adding `Proxy-Authorization` header automatically.

## Requirement

**go-transproxy** supports only Linux iptables.

## Install

### Binaly install
Download from [Releases page](https://github.com/wadahiro/go-transproxy/releases).

### Source install
Use Go 1.8 and [dep](https://github.com/golang/dep).

```
dep ensure
go build -o transproxy cmd/transproxy/main.go
chmod +x transproxy
```

## Usage

```
Usage:

  transproxy [options]

Options:

  -disable-iptables
    	Disable automatic iptables configuration
  -dns-over-https-enabled
        Use DNS-over-HTTPS service as public DNS
  -dns-over-https-endpoint string
        DNS-over-HTTPS endpoint URL (default "https://dns.google.com/resolve")
  -dns-over-tcp-disabled
        Disable DNS-over-TCP for querying to public DNS
  -dns-proxy-listen [host]:port
        DNS Proxy listen address, as [host]:port (default ":3131")
  -dns-tcp
        DNS Listen on TCP (default true)
  -dns-udp
        DNS Listen on UDP (default true)
  -explicit-proxy-listen [host]:port
        Explicit Proxy listen address for HTTP/HTTPS, as [host]:port Note: This proxy doesn't use authentication info of the `http_proxy` and `https_proxy` environment variables (default ":3132")
  -explicit-proxy-only
        Boot Explicit Proxies only
  -explicit-proxy-with-auth-listen [host]:port
        Explicit Proxy with auth listen address for HTTP/HTTPS, as [host]:port Note: This proxy uses authentication info of the `http_proxy` and `https_proxy` environment variables (default ":3133")
  -http-proxy-listen [host]:port
        HTTP Proxy listen address, as [host]:port (default ":3129")
  -https-proxy-listen [host]:port
        HTTPS Proxy listen address, as [host]:port (default ":3130")
  -loglevel string
        Log level, one of: debug, info, warn, error, fatal, panic (default "info")
  -private-dns string
        Private DNS address for no_proxy targets (IP[:port])
  -public-dns string
        Public DNS address (IP[:port]) Note: Your proxy needs to support CONNECT method to the Public DNS port, and the public DNS needs to support TCP
  -tcp-proxy-dports port1,port2,...
        TCP Proxy dports, as port1,port2,... (default "22")
  -tcp-proxy-listen [host]:port
        TCP Proxy listen address, as [host]:port (default ":3128")
```

Proxy configuration is used from standard environment variables, `http_proxy`, `https_proxy` and `no_proxy`.
Also you can use **IP Address**, **CIDR**, **Suffix Domain Name** in `no_proxy`.

### Example 

```
# Set your proxy environment
export http_proxy=http://foo:bar@yourproxy.example.org:3128

# Set no_proxy if you need to access directly for internal
export no_proxy=example.org,192.168.0.0/24

# Start go-transproxy with admin privileges(sudo)
sudo -E transproxy -private-dns 192.168.0.100 -public-dns 8.8.8.8
```

For testing, using docker is easy way. Now, you can access to google from docker container with no proxy configuration as follows.

```
docker run --rm -it centos curl http://www.google.com
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>302 Moved</TITLE></HEAD><BODY>
<H1>302 Moved</H1>
The document has moved
<A HREF="http://www.google.co.jp/?gfe_rd=cr&amp;dcr=0&amp;ei=GCKtWbD0AaLEXuTmr7gK">here</A>.
</BODY></HTML>
```

If your proxy doesn't support CONNECT method to DNS port, it cannot resolve public domain name transparently.
Fortunately, Google privides [DNS-over-HTTPS service](https://developers.google.com/speed/public-dns/docs/dns-over-https), so you can use this service as public DNS by adding `-dns-over-https-enabled` option instead of `-public-dns` option as below even if your proxy supports CONNECT method to 443 port only.

```
sudo -E transproxy -private-dns 192.168.0.100 -dns-over-https-enabled
```

If you can resolve all domains directly from local LAN, run command without dns related options as below. 
It disables DNS-Proxy.

```
sudo -E transproxy
```

If you need to use both public DNS and private DNS, and need to use public DNS directly, run command with `-dns-over-tcp-disabled` option as below.
It suppresses to insert a iptables OUTPUT rule for DNS over TCP.

```
sudo -E transproxy -private-dns 192.168.0.100 -public-dns 172.16.0.1 -dns-over-tcp-disabled
```

If you want to use an application which access to internet using port 5000, run command with `-tcp-proxy-dports` option as below.

```
sudo -E transproxy -private-dns 192.168.0.100 -public-dns 8.8.8.8 -tcp-proxy-dports 22,5000
```

## Current Limitation

* HTTP proxy: Only works with HTTP host header.
* HTTPS proxy: `no_proxy` only works with IP Address and CIDR if your https client doesn't support [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).
* TCP proxy: `no_proxy` only works with IP Address and CIDR.

## Licence

Licensed under the [MIT](/LICENSE) license.

## Author

[Hiroyuki Wada](https://github.com/wadahiro)

