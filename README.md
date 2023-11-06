# Meaning
In very formal Polish language, _denat_ stands for a deceased person and is mostly used for individuals who have passed away suddenly or under unknown circumstances.

# Info
_denat_ is a straightforward tool that allows you to redirect network packets to another host, 
effectively creating a dynamic forward proxy. 
It achieves the same functionality as netfilter/iptables DNAT (for example, `iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.59.120:10080`). 
However, instead of relying on netfilter functionalities, it leverages eBPF technology. 


You might wonder why it's called "denat," as it's likely not a widely used tool. I created it for two primary reasons:
1. To gain a deep understanding of how `bpf_neigh_redirect` and `bpf_redirect` work.
2. I required such functionality for another project of mine, so I decided to create this standalone tool to explore the advantages and disadvantages of packet DNAT (Destination Network Address Translation) as an approach, as opposed to the Linux tproxy method of redirection.

# Pre-requisites
- _libbpf_ installed
- _iproute2_ package installed

# Features
- IPv4 Compatibility
- IPv6 Readiness
- TCP Support
- UDP Support
- Routing Loop Prevention

# Use
```bash
sudo denat -dfproxy=192.168.59.120:10080 -dfports=80
```
where: 
- `pfproxy` is the L4 proxy address to which the packets will be redirected
- `dfports` is the list of ports to which the packets will be redirected, e.g. `80,443,8080`

To use it with envoy config:
On 192.168.59.120 I run:

```
func-e run -c envoy-config-80.yml
```
where [func-e](https://func-e.io/)

# TODO:
- [ ] add support for default policy(e.g. block all except 80,443,8080, or allow to bypass the proxy for other ports)
- [ ] add verbose flag and remove all redundant logs



