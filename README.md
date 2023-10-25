# Meaning
In very formal Polish language, "denat" stands for a deceased person and is mostly used for individuals who have passed away suddenly or under unknown circumstances.

# Info
_denat_ is a straightforward tool that allows you to redirect network packets to another host, 
effectively creating a dynamic forward proxy. 
It achieves the same functionality as netfilter/iptables DNAT (for example, `iptables -t nat -A OUTPUT -o eth0 -p tcp --dport 443 -j REDIRECT --to-port 10080`). 
However, instead of relying on netfilter functionalities, it leverages eBPF technology. 


You might wonder why it's called "denat," as it's likely not a widely used tool. I created it for two primary reasons:
1. To gain a deep understanding of how `bpf_neigh_redirect` and `bpf_redirect` work.
2. I required such functionality for another project of mine, so I decided to create this standalone tool to explore the advantages and disadvantages of packet DNAT (Destination Network Address Translation) as an approach, as opposed to the Linux tproxy method of redirection.

# Use
```bash
sudo denat -pfproxy=192.168.59.120:10080 --dfports=80,443
```

To use it with envoy config:
On 192.168.59.120 I run:

```
func-e run -c envoy-config-80.yml
```
where [func-e](https://func-e.io/)





