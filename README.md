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
- _iproute2_ package installed

# Features
- IPv4 Compatibility
- IPv6 Readiness
- TCP Support
- UDP Support
- Routing Loop Prevention
- Dynamic Forward Proxy with Non-forwarded Traffic Policy (Block/Allow)

# Build
To construct a silent version of the project, which omits all debug logs, simply execute:
```
make all
```
To compile the project with debug logs included, use the following command:
```
DENAT_VERBOSE=1 make all
```
To build project with verifier logs, run:
```
DENAT_VERIFIER=1 make all
```
Lastly, to generate a build with debug logs and some extra logs, issue the command:
```
DENAT_EXTRA_LOG=1 DENAT_VERBOSE=1 make all
```

# Usage:
```
 Usage: denat -dfproxy=[IP]:port -dfports=port1,port2,... [-policy=block|allow]
    -dfproxy: the IP address and port of the dynamic forward proxy
    -dfports: the list of forwarded ports
    -policy: the policy to apply to the forwarded ports (block or allow), default value is allow
    -help: print this help message
```

# Examples
`denat` command takes at least two arguments, e.g.
`sudo ./denat -dfproxy=192.168.100.2:11111 -dfports=80 -policy=block`

where:
- `dfproxy` is the L4 proxy address to which the packets will be redirected
- `dfports` is the list of ports to redirect, e.g. `80,443,8080`
- `policy` all ports except 80 will be blocked

To use it with envoy config I run (please modify listener address first to align with your network setup):
```
func-e run -c envoy-config-80.yml
```
where [func-e](https://func-e.io/)

Some examples:

## Only IPv4:
```bash
sudo denat -dfproxy=192.168.59.120:11111 -dfports=80 
```
## Only IPv6:
```bash
sudo denat -dfproxy=[fd0c:41e9:207b:5400:d740:627c:a774:5131]:11111 -dfports=80,443
```

## Preventing routing loops on the same machine
Your proxy must tag its traffic with the `0x29A` mark (this is the literal value used to verify the mark immediately upon entering the TC egress program).
For example, in Envoy, this can be achieved by using the original source listener filter (you have to have CAP_NET_ADMIN capability):
```yaml
static_resources:
  listeners:
  - name: listener_0
    address:
    # ...  
    listener_filters:
    - name: envoy.filters.listener.original_src
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.original_src.v3.OriginalSrc
        mark: 0x29A
```

## Local testing
To test it locally put your proxy on your default interface, e.g. in my case it is eno1 with adress 192.168.100.2



# TODO:
- [ ] putting proxy on loopback
- [ ] add verbose flag and remove all redundant logs





