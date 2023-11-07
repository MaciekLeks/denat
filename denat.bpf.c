#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "denat.bpf.h"



static __always_inline int
get_tuple(struct __sk_buff *skb, struct bpf_sock_tuple *sock_tuple, struct connt_l2 *l2, __u16 *iphdrl,
          bool *is_ipv6, bool *is_ipv4, bool *is_arp, bool *is_udp, bool *is_tcp, bool *is_icmp) {

    int off = 0;
    __u8 l4_protocol = 0;
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    //L2
    // common for all hdr_start_off(s)
    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        *is_ipv6 = true;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV4)) {
        *is_ipv4 = true;
    } else if (skb->protocol == bpf_htons(ETH_P_ARP)) {
        *is_arp = true;
        return 1;
    } else {
        return 1;
    }

    if (data + ETH_HLEN > data_end)
        return -101;

    /*
    struct ethhdr *eth = (data + off);
    //read mac addresses
    if (data + off + sizeof(struct ethhdr) > data_end)
        return -2;
    bpf_printk("eth->h_source:x.%x.%x.%x.%x.%x ", eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("eth->h_dest:x..%x.%x.%x.%x.%x\n", eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    */
    //bpf_core_read(eth, sizeof(struct ethhdr), data);
    struct ethhdr *eth = data;
    bpf_core_read(l2, sizeof(struct connt_l2), eth);

    //L3
    off = ETH_HLEN; //off for tc must be moved ETH_HLEN octets forward
    __u8 version = *(__u8 *) (long) (data + off) >> 4;
    //__u8 version = *(__u8 *) (long) (data + off) & 0xF0 >> 2;
    if (data + off + sizeof(__u8) > data_end) {
        return -11;
    }
    if (*is_ipv6 && version != 6) {
        return -12;
    } else if (*is_ipv4 && version != 4) {
        return -13;
    }


    // __u32 _tot_len;
    if (*is_ipv4) {
        struct iphdr *ipv4 = (data + off);
        if (data + off + sizeof(struct iphdr) > data_end)
            return -14;
        *iphdrl = (ipv4->ihl & 0xF) << 2;
        if (data + off + *iphdrl > data_end)
            return -15;
        l4_protocol = ipv4->protocol;
        //bpf_printk("[IPv4] --- l4_protocol:%d", l4_protocol);
        //_tot_len = bpf_ntohs(ipv4->tot_len);

        // read saddr and daddr from ipv4hdr
        bpf_core_read(&sock_tuple->ipv4.saddr, sizeof(sock_tuple->ipv4.saddr) + sizeof(sock_tuple->ipv4.daddr),
                      &ipv4->saddr);
    } else if (*is_ipv6) {
        struct ipv6hdr *ipv6 = data + off;
        *iphdrl = sizeof(struct ipv6hdr);
        if (data + off + *iphdrl > data_end) {
            return -16;
        }
        l4_protocol = ipv6->nexthdr;
        //_tot_len = bpf_ntohs(ipv6->payload_len) + *iphdrl;

        //read saddr and daddr from ipv6hdr
        bpf_core_read(&sock_tuple->ipv6, 2 * sizeof(sock_tuple->ipv6.saddr), &ipv6->saddr);
    }


    // ip header pointer to either iphdr or ipv6hdr
    //void *ip = (data + off);

    //L4
    off += *iphdrl;
    if (l4_protocol == IPPROTO_TCP) {
        if (data + off + sizeof(struct tcphdr) > data_end)
            return 0;

        struct tcphdr *tcp = (data + off);
        off += sizeof(struct tcphdr);

        *is_tcp = true;

        if (*is_ipv4) {
            bpf_core_read(&sock_tuple->ipv4.sport, sizeof(sock_tuple->ipv4.sport) + sizeof(sock_tuple->ipv4.dport),
                          &tcp->source);
#if DEBUG_ALL == 1
                bpf_printk("sock_tuple: saddr:sport=%x:%x, daddr:dport=%x:%x",
                           sock_tuple->ipv4.saddr, sock_tuple->ipv4.sport,
                           sock_tuple->ipv4.daddr, sock_tuple->ipv4.dport);
#endif
        } else if (*is_ipv6) {
            bpf_core_read(&sock_tuple->ipv6.sport, sizeof(sock_tuple->ipv6.sport) + sizeof(sock_tuple->ipv4.dport),
                          &tcp->source);
        }

    } else if (l4_protocol == IPPROTO_UDP) {
        if (data + off + sizeof(struct udphdr) > data_end)
            return -17;

        //_l4 = data + off;
        struct udphdr *udp = (data + off);
        off += sizeof(struct udphdr);

        *is_udp = true;

        if (*is_ipv4) {
            bpf_core_read(&sock_tuple->ipv4.sport, sizeof(sock_tuple->ipv4.sport) + sizeof(sock_tuple->ipv4.dport),
                          &udp->source);
        } else if (*is_ipv6) {
            bpf_core_read(&sock_tuple->ipv6.sport, sizeof(sock_tuple->ipv6.sport) + sizeof(sock_tuple->ipv4.dport),
                          &udp->source);
        }
    } else if (l4_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = data + off;
        if (data + off + sizeof(struct icmphdr) > data_end)
            return -18;

        bpf_printk("[ICMP] type:%d", icmp->type);
        *is_icmp = true;
    }

    return 0;
}

/* Use for egress only.
 * Adds key with sport.
 */
static __always_inline long
add_connt(const struct bpf_sock_tuple *sock_tuple, const struct connt_l2 *l2, __u32 ifindx, bool is_ipv4) {
    struct connt_key key = {0};
    struct connt_value val = {.ifindx = ifindx};
    if (is_ipv4) {
        key.sport = sock_tuple->ipv4.sport;
        val.orig_d_naddr[0] = sock_tuple->ipv4.daddr;
        val.orig_s_naddr[0] = sock_tuple->ipv4.saddr;
        val.orig_d_nport = sock_tuple->ipv4.dport;
    } else {
        key.sport = sock_tuple->ipv6.sport;
        for (int i = 0; i < 4; i++) {
            val.orig_d_naddr[i] = sock_tuple->ipv6.daddr[i];
            val.orig_s_naddr[i] = sock_tuple->ipv6.saddr[i];
        }
        val.orig_d_nport = sock_tuple->ipv6.dport;
    }
    __builtin_memcpy(&val.macs, l2, sizeof(struct connt_l2));
//    bpf_printk("eth->h_dest:x.%x.%x.%x.%x.%x ", eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4],
//               eth->h_dest[5]);
//    if (eth) {
////        bpf_core_read(val.orig_d_mac, sizeof(val.orig_d_mac), eth->h_dest);
////        bpf_core_read(val.orig_s_mac, sizeof(val.orig_s_mac), eth->h_source);
//        __builtin_memcpy(val.orig_s_mac, eth->h_source, sizeof(val.orig_s_mac));
//        __builtin_memcpy(val.orig_d_mac, eth->h_dest, sizeof(val.orig_d_mac));
//    }

    return bpf_map_update_elem(&connt_map, &key, &val, 0);
}


/* Use ifor egress only.
 * Deletes key with sport.
 */
static __always_inline void del_connt(const struct bpf_sock_tuple *sock_tuple, bool is_ipv4) {
    struct connt_key key = {0};
    if (is_ipv4) {
        key.sport = sock_tuple->ipv4.sport;
    } else {
        key.sport = sock_tuple->ipv6.sport;
    }
    bpf_map_delete_elem(&connt_map, &key);
}

/* Use for ingress only.
 * Return connt_value if dport exists added on egress with sport
 */
static __always_inline struct connt_value *get_connt(const struct bpf_sock_tuple *sock_tuple, bool is_ipv4) {
    struct connt_key key = {0};
    if (is_ipv4) {
        key.sport = sock_tuple->ipv4.dport;
    } else {
        key.sport = sock_tuple->ipv6.dport;
    }
    return bpf_map_lookup_elem(&connt_map, &key);
}

static __always_inline long get_config(struct edge **edge) {
    __u32 key = EGRESS_CFG_INDX;
    *edge = bpf_map_lookup_elem(&config_map, &key);
    if (!*edge) {
        bpf_printk("Failed to lookup config map: %d\n", key);
        return -1;
    }

#if DEBUG_ALL == 1
    bpf_printk("ifindx=%d, g_naddr=%d, d_naddr=%d", (*edge)->ifindx, (*edge)->g_naddr[0], (*edge)->d_naddr[0]);
#endif
    return 0;
}


static __always_inline bool
is_forwarded_port(__be16
port) {
struct forwarded_port key = {.nport = port};
__u32 *valp = bpf_map_lookup_elem(&forwarded_port_map, &key);
if (valp) {
bpf_printk("port:%d is forwarded, value=%d",
bpf_ntohs(port), *valp
);
return
true;
} else {
bpf_printk("port:%d is not forwarded",

bpf_ntohs(port)
);
return
false;
}
}


static __always_inline int
process_relative(struct __sk_buff *skb/*, enum bpf_hdr_start_off hdr_start_off*/, bool is_egress) {
    if (is_egress && (skb->mark & PACKET_MARK_PREVENT_LOOP) == PACKET_MARK_PREVENT_LOOP) {
        bpf_printk("mark: %u", skb->mark);
        return TC_ACT_OK;
    }

    bool is_arp = false;
    bool is_ipv4 = false;
    bool is_ipv6 = false;
    bool is_udp = false;
    bool is_tcp = false;
    bool is_icmp = false;
    struct bpf_sock_tuple original_tuple = {0};
    __u16 iphdrl = 0;
    struct connt_l2 l2 = {0};
    struct edge *edge = NULL;
    long ret;

    ret = get_config(&edge);
    if (ret < 0) {
        return TC_ACT_OK;
    }

    ret = get_tuple(skb, &original_tuple, &l2, &iphdrl, &is_ipv6, &is_ipv4, &is_arp, &is_udp, &is_tcp, &is_icmp);
    //print all local vars
    if (DEBUG_ALL) {
        bpf_printk("ret: %d, is_ipv4:%d, is_ipv6:%d, is_udp:%d, is_tcp:%d",
                   ret, is_ipv4, is_ipv6, is_udp, is_tcp);
    }
    if (ret < 0) {
        return TC_ACT_SHOT;
    } else if (ret > 0) {
        return TC_ACT_OK;
    }


    //print original_tuple elements
#if DEBUG_ALL == 1
        if (is_ipv4) {
            //char src_ip4_buffer[32], dest_ip4_buffer[120];
            //u32_to_ipv4(bpf_ntohl(original_tuple.ipv4.saddr), src_ip4_buffer);
            bpf_printk("bpf_sock:original_tuple(is_egress:%d): saddr:sport=%s:%d, daddr:dport=%s:%d",
                       is_egress,
                       BE32_TO_IPV4(original_tuple.ipv4.saddr), bpf_ntohs(original_tuple.ipv4.sport),
                       BE32_TO_IPV4(original_tuple.ipv4.daddr), bpf_ntohs(original_tuple.ipv4.dport));
        } else if (is_ipv6) {
            bpf_printk("bpf_sock:original_tuple: saddr:sport=%x:%x, daddr:dport=%x:%x",
                       original_tuple.ipv6.saddr, original_tuple.ipv6.sport,
                       original_tuple.ipv6.daddr, original_tuple.ipv6.dport);
        }
    }
#endif

    // return TC_ACT_OK;

//    struct bpf_sock *sk = NULL;
//    if (is_ipv4)
//        sk = bpf_sk_lookup_tcp(skb, &original_tuple, sizeof(original_tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
//    else if (is_ipv6)
//        sk = bpf_sk_lookup_tcp(skb, &original_tuple, sizeof(original_tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
//
//    if (sk) {
//        bpf_printk("bpf_sock.state:%d src_ip4:src_port:%s:%d->  dst_ip4:dst_port:%s:%d  egress:%d\n",
//                   sk->state,
//                   BE32_TO_IPV4(sk->src_ip4), sk->src_port,
//                   BE32_TO_IPV4(sk->dst_ip4), bpf_ntohs(sk->dst_port), is_egress);
//        bpf_sk_release(sk);
//    }



    //if ((sport == 10080 || dport == 10080) && !is_egress) {
    __u16 sport = is_ipv4 ? original_tuple.ipv4.sport : (is_ipv6 ? original_tuple.ipv6.sport : 0);
    //if (!is_egress && sport == bpf_htons(10080)) {
    __u16 dport = is_ipv4 ? original_tuple.ipv4.dport : (is_ipv6 ? original_tuple.ipv6.dport : 0); //move before egress

    if (!is_egress && sport == edge->d_nport) {
        bpf_printk(">>>in>>>000: port: sport=%d, dport=%d, is_egress=%d, ifindex=%d, is_forwarded:%d", bpf_ntohs(sport),
                   bpf_ntohs(dport), is_egress,
                   skb->ifindex, is_forwarded_port(dport));

        struct bpf_sock *sk = skb->sk;
        if (sk) {
            bpf_printk(">>>>in>>>:skb->sock->state: %d", sk->state);
        }

        //!__u32 ifindx = 2; //eno
        //!__u16 new_net_sport = bpf_htons(80);
        //__u32 new_saddr = 0xc0a86402; //192.168.100.2
        //__u32 new_saddr = 0xbcb864b6; //188.184.100.182 (info.cern.ch)
        //!!!__u32 new_net_saddr = 0xb664b8bc; //188.184.100.182 (info.cern.ch)
        //__u32 new_daddr = 0xc0a86402; //192.168.100.2 (host)
        ///!!!__u32 new_net_daddr = 0x0264a8c0; //192.168.100.2 (host)
        //!__u8 new_h_dest[] = {0xa4, 0xbb, 0x6d, 0xd5, 0x94, 0x68}; //a4:bb:6d:d5:94:68 //eno01
        //!__u8 new_h_source[] = {0x0c, 0x41, 0xe9, 0x20, 0x7b, 0x54}; //0c:41:e9:20:7b:54  //router

        __be32 *new_net_saddr, *new_net_daddr;
        __u16 new_net_sport;
        struct connt_value *valp = get_connt(&original_tuple, is_ipv4);
        if (valp) {
            new_net_saddr = valp->orig_d_naddr; //data from e.g. info.cern.ch
            new_net_daddr = valp->orig_s_naddr; //data to e.g. 192.168.100.2
            new_net_sport = valp->orig_d_nport; //e.g. 80
            bpf_printk(">>>>>>new_net_sport: %d\n", bpf_ntohs(new_net_sport));
            //if (DEBUG_ALL) {
                if (is_ipv4) {
                    bpf_printk("valp->ifindx:%d, new_net_saddr[0]:%x new_net_daddr[0]:%x, for port:%d", valp->ifindx,
                               *new_net_saddr,
                               *new_net_daddr, original_tuple.ipv4.dport);
                } else {
                    bpf_printk("valp->ifindx:%d, new_net_saddr[0]:%x new_net_daddr[0]:%x, for port:%d", valp->ifindx,
                               *new_net_saddr,
                               *new_net_daddr, original_tuple.ipv6.dport);
                }
            //}
        } else {
            bpf_printk("valp is null for port:%d", bpf_ntohs(original_tuple.ipv4.dport));
            return TC_ACT_SHOT;
        }



        /*{fib
        //to get smac and dmac we must reverse lookup, that is, try to find out the egress route 192.168.100.2->info.cern.ch
        struct bpf_fib_lookup fib_params = {
                .family = is_ipv4 ? AF_INET : AF_INET6,
                .l4_protocol = is_tcp ? IPPROTO_TCP : (is_udp ? IPPROTO_UDP : is_icmp ? IPPROTO_ICMP : 0),
                .ifindex = 2,
        };
        if (is_ipv4) {
            //fib_params.ipv4_dst = valp->orig_d_naddr[0]; //data from e.g. info.cern.ch
            fib_params.ipv4_dst = new_net_saddr; //data from e.g. info.cern.ch
            fib_params.ipv4_src = new_net_daddr; ////data to e.g. 192.168.100.2
         }

        ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
        if (ret < 0) {
            bpf_printk("bpf_fib_lookup failed: %d\n", ret);
            return TC_ACT_SHOT;
        } else {
            bpf_printk("bpf_fib_lookup: ifindex: %d, ret: %d", fib_params.ifindex, ret);
            bpf_printk("bpf_fib_lookup: s_addr:%s, d_addr:%s", BE32_TO_IPV4(fib_params.ipv4_src),
                       BE32_TO_IPV4(fib_params.ipv4_dst));
            bpf_printk("bpf_fib_lookup: smac: x.%x.%x.%x.%x.%x", fib_params.smac[1], fib_params.smac[2],
                       fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
            bpf_printk("bpf_fib_lookup: dmac: x.%x.%x.%x.%x.%x", fib_params.dmac[1], fib_params.dmac[2],
                       fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
        }
        //fib}*/

//        bpf_printk("val->orig_d_mac: x.%x.%x.%x.%x.%x", valp->orig_d_mac[1], valp->orig_d_mac[2], valp->orig_d_mac[3],
//                   valp->orig_d_mac[4], valp->orig_d_mac[5]);
//        bpf_printk("val->orig_s_mac: x.%x.%x.%x.%x.%x", valp->orig_s_mac[1], valp->orig_s_mac[2], valp->orig_s_mac[3],
//                   valp->orig_s_mac[4], valp->orig_s_mac[5]);

        //long ret = rewrite_mac(skb, new_h_dest, 1);
        ret = rewrite_mac(skb, valp->macs.orig_s_mac, 1);
        //!fib!long ret = rewrite_mac(skb, fib_params.smac, 1);
        if (ret < 0) {
            bpf_printk("rewrite h_dest error: %d", ret);
            return TC_ACT_SHOT;
        }

        //ret = rewrite_mac(skb, new_h_source, 0);
        ret = rewrite_mac(skb, valp->macs.orig_d_mac, 0);
        //!fib!ret = rewrite_mac(skb, fib_params.dmac, 0);
        if (ret < 0) {
            bpf_printk("rewrite h_source error: %d", ret);
            return TC_ACT_SHOT;
        }

        ret = rewrite_addr(skb, iphdrl, is_ipv4, new_net_saddr, 0);
        if (ret < 0) {
            bpf_printk("[ingress] rewrite saddr error: %d", ret);
            return TC_ACT_SHOT;
        }

        ret = rewrite_port(skb, iphdrl, is_tcp, is_udp, new_net_sport, 0);
        if (ret < 0) {
            bpf_printk("[ingress] rewrite sport error: %d", ret);
            return TC_ACT_SHOT;
        }

        ret = rewrite_addr(skb, iphdrl, is_ipv4, new_net_daddr, 1);
        if (ret < 0) {
            bpf_printk("[ingress] rewrite daddr error: %d", ret);
            return TC_ACT_SHOT;
        }

        //ret =   bpf_redirect_neigh(ifindx, 0, 0, 0);
        ret = bpf_redirect(valp->ifindx, BPF_F_INGRESS);
        bpf_printk("[ingress] bpf_redirect_neigh: %d", ret);

        return (int) ret;
    }




    // __u16 dport = is_ipv4 ? original_tuple.ipv4.dport : (is_ipv6 ? original_tuple.ipv6.dport : 0); //move before egress
    //if (is_egress && dport == bpf_htons(80)) {
    if (is_egress && is_forwarded_port(dport)) {
        bpf_printk("<<<out<<<000: port: sport=%d, dport=%d, is_egress=%d, ifindex=%d, is_forwarded:%d", bpf_ntohs(sport),
                   bpf_ntohs(dport), is_egress,
                   skb->ifindex, is_forwarded_port(dport));
        //__u32 ifindx = 1; //local loopback
        //__u32 ifindx = 8; //ubu-ebpf3
        //__u32 ifindx = 2; //eno1
        //__u16 new_dport = 10080;
        //__u16 new_dport = 80;
        //__u32 new_daddr = 0x7f000001; //127.0.0.1
        //__u32 new_daddr = 0xc0a83b78; //192.168.59.120 (ubu-ebpf3)
        //__u32 new_daddr = 0xbcb864b6; //188.184.100.182 (info.cern.ch)
        //__u32 new_saddr = 0xc0a83b01; //192.168.59.1 (host)
        //__u32 new_saddr = 0xc0a86402; //192.168.100.2 (host)

        //long ret = rewrite_addr(skb, iphdrl, new_daddr, 1);
        ret = rewrite_addr(skb, iphdrl, is_ipv4, edge->d_naddr, 1);
        if (ret < 0) {
            bpf_printk("rewrite daddr error: %d", ret);
            return TC_ACT_SHOT;
        }

        bpf_printk("<<<out<<<000: rewrite dport: %d", bpf_ntohs(edge->d_nport));
        ret = rewrite_port(skb, iphdrl, is_tcp, is_udp, edge->d_nport, 1);
        if (ret < 0) {
            bpf_printk("rewrite dport error: %d", ret);
            return TC_ACT_SHOT;
        }

        //ret = rewrite_addr(skb, iphdrl, new_saddr, 0);
        ret = rewrite_addr(skb, iphdrl, is_ipv4, edge->g_naddr, 0);
        if (ret < 0) {
            bpf_printk("rewrite saddr error: %d", ret);
            return TC_ACT_SHOT;
        }

        struct bpf_sock *sk = skb->sk;
        if (sk) {
            sport = is_ipv4 ? original_tuple.ipv4.sport : (is_ipv6 ? original_tuple.ipv6.sport : 0);
            switch (sk->state) {
                case BPF_TCP_ESTABLISHED:
                    bpf_printk("<<<out<<<BPF_TCP_ESTABLISHED, sport:%d", sport);
                    break;
                case BPF_TCP_SYN_SENT: {
                    ret = add_connt(&original_tuple, &l2, skb->ifindex, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_SYN_SENT, sport:%d, ret:%u", sport, ret);
                    break;
                }
                case BPF_TCP_SYN_RECV:
                    bpf_printk("<<<out<<<BPF_TCP_SYN_RECV");
                    break;
                case BPF_TCP_FIN_WAIT1:
                    del_connt(&original_tuple, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_FIN_WAIT1");
                    break;
                case BPF_TCP_FIN_WAIT2:
                    del_connt(&original_tuple, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_FIN_WAIT2, sport:%d", sport);
                    break;
                case BPF_TCP_TIME_WAIT:
                    bpf_printk("<<<out<<<BPF_TCP_TIME_WAIT");
                    break;
                case BPF_TCP_CLOSE:
                    del_connt(&original_tuple, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_CLOSE, sport:%d", sport);
                    break;
                case BPF_TCP_CLOSE_WAIT:
                    bpf_printk("<<<out<<<BPF_TCP_CLOSE_WAIT");
                    break;
                case BPF_TCP_LAST_ACK:
                    del_connt(&original_tuple, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_LAST_ACK");
                    break;
                case BPF_TCP_LISTEN:
                    bpf_printk("<<<out<<<BPF_TCP_LISTEN");
                    break;
                case BPF_TCP_CLOSING:
                    del_connt(&original_tuple, is_ipv4);
                    bpf_printk("<<<out<<<BPF_TCP_CLOSING, sport:%d", sport);
                    break;
                case BPF_TCP_NEW_SYN_RECV:
                    bpf_printk("<<<out<<<BPF_TCP_NEW_SYN_RECV");
                    break;
                case BPF_TCP_MAX_STATES:
                    bpf_printk("<<<out<<<BPF_TCP_MAX_STATES");
                    break;
                default:
                    bpf_printk("<<<out<<<BPF_TCP_UNKNOWN");
                    break;

            }
        }

        ret = bpf_redirect_neigh(edge->ifindx, 0, 0, 0); //bpf_reditect_neigh does not work
        bpf_printk("[egress]bpf_redirect_neigh: %d", ret);

        return (int) ret;
    }

    return TC_ACT_OK;
}

SEC(

"classifier")

int tc_egress(struct __sk_buff *skb) {
    return process_relative(skb, true);
}


SEC(

"tc")

int tc_ingress(struct __sk_buff *skb) {
    return process_relative(skb, false);
    //return TC_ACT_OK;
}

//SEC("tc")
//int tc_egress_proxy(struct __sk_buff *skb) {
//    return process_relative(skb, BPF_HDR_START_MAC, true,true);
//    //return TC_ACT_OK;
//}

char LICENSE[]
SEC("license") = "GPL";
