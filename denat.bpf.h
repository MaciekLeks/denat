//#include <linux/icmp.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
#include "commons.h"
#include "vmlinux.h"

//{from <linux/pkt_cls.h>
#define TC_ACT_UNSPEC    (-1)
#define TC_ACT_OK        0
#define TC_ACT_RECLASSIFY    1
#define TC_ACT_SHOT        2
#define TC_ACT_PIPE        3
#define TC_ACT_STOLEN        4
#define TC_ACT_QUEUED        5
#define TC_ACT_REPEAT        6
#define TC_ACT_REDIRECT        7
#define TC_ACT_TRAP        8
#define TC_ACT_VALUE_MAX    TC_ACT_TRAP
//}

//<netinet/in.h>
#define AF_INET        2    /* IP protocol family.  */
#define AF_INET6    10    /* IP version 6.  */
//<netinet/in.h>}

//{from linux/if_ether.h
#define ETH_HLEN 14
#define ETH_P_IPV4 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 0x86DD

#define BPF_F_CURRENT_NETNS (-1L)
#define MAX_L4_CONNTACK_ENTRIES 1024 //redefine the number

#define PACKET_MARK_PREVENT_LOOP 0x29A
//}

// I've put -Wnomacro-redefined to suppress the warning
#if !defined(DENAT_VERBOSE)
#define bpf_printk(fmt,...)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value,
    struct edge);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,
    struct forwarded_port);
    __type(value, __u32);
    __uint(max_entries, 256);
    //__uint(pinning, LIBBPF_PIN_BY_NAME);
} forwarded_port_map
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,
    struct connt_key);
    __type(value,
    struct connt_value);
    __uint(max_entries, MAX_L4_CONNTACK_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connt_map
SEC(".maps");


//{addons
#ifdef DENAT_EXTRA_LOG
static char *be32_to_ipv4(__be32 ip_value, char *ip_buffer) {
    __u64 ip_data[4] = {0};

    ip_data[3] = ((__u64) (ip_value >> 24) & 0xFF);
    ip_data[2] = ((__u64) (ip_value >> 16) & 0xFF);
    ip_data[1] = ((__u64) (ip_value >> 8) & 0xFF);
    ip_data[0] = ((__u64) ip_value & 0xFF);

    bpf_snprintf(ip_buffer, 16, "%u.%u.%u.%u", ip_data, 4 * sizeof(__u64));
    return ip_buffer;
}

#define BE32_TO_IPV4(ip_value) ({ \
    be32_to_ipv4((ip_value), (char [32]){}); \
})
#endif
//}addons


#define L2_MEMBER_OFF(member) \
   (offsetof(struct ethhdr, member))

static __always_inline long rewrite_mac(struct __sk_buff *skb, __u8 *mac, bool dest) {
    if (dest)
        return bpf_skb_store_bytes(skb, L2_MEMBER_OFF(h_dest), mac, 6, 0);
    else
    return bpf_skb_store_bytes(skb, L2_MEMBER_OFF(h_source), mac, 6, 0);
}

#define L3_CSUM_OFF(proto) \
   (ETH_HLEN + offsetof(struct proto ## hdr, check))
#define L3_MEMBER_OFF(proto, member) \
   (ETH_HLEN + offsetof(struct proto ## hdr, member))

#define L4_CSUM_OFF(iphdrl, proto) \
   (ETH_HLEN + iphdrl + offsetof(struct proto ## hdr, check))

#define L4_MEMBER_OFF(iphdrl, proto, member) \
   (ETH_HLEN + iphdrl + offsetof(struct proto ## hdr, member))

static inline long
rewrite_addr(struct __sk_buff *skb, int iphdrl, bool is_ipv4, __be32 *new_net_addr, int rw_daddr) {
    long ret;
    int off, flags = BPF_F_PSEUDO_HDR;
    __u8 proto;

    if (is_ipv4) {
        ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, protocol), &proto, 1);
        if (ret < 0) return ret;
    } else {
        ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ipv6, nexthdr), &proto, 1);
        if (ret < 0) return ret;
    }

    if (proto == IPPROTO_TCP) {
        off = L4_CSUM_OFF(iphdrl, tcp);
    } else if (proto == IPPROTO_UDP) {
        off = L4_CSUM_OFF(iphdrl, udp);
        flags |= BPF_F_MARK_MANGLED_0;
    } else {
        off = 0;
    }

    if (off) {
        if (is_ipv4) {
            struct in_addr old_net_addr = {0};
            if (rw_daddr) {
                ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip,
                                                            daddr), &old_net_addr.s_addr, sizeof(old_net_addr.s_addr));
                if (ret < 0) return ret;
            } else {
                ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip,
                                                            saddr), &old_net_addr.s_addr, sizeof(old_net_addr.s_addr));
                if (ret < 0) return ret;
            }

            ret = bpf_l4_csum_replace(skb, off, old_net_addr.s_addr, *new_net_addr,
                                      flags | sizeof(old_net_addr.s_addr));
            if (ret < 0) return ret;

            ret = bpf_l3_csum_replace(skb, L3_CSUM_OFF(
                    ip), old_net_addr.s_addr, *new_net_addr, sizeof(old_net_addr.s_addr));
            if (ret < 0) return ret;

            if (rw_daddr) {
                ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, daddr), new_net_addr, sizeof(old_net_addr.s_addr), 0);
                if (ret < 0) return ret;
            } else {
                ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, saddr), new_net_addr, sizeof(old_net_addr.s_addr), 0);
                if (ret < 0) return ret;
            }
        } else {
            struct in6_addr old_net_addr;

            //bpf_printk("ipv6[rewrite_addr]: 1");
            if (rw_daddr) {
                ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ipv6,
                                                            daddr), &old_net_addr.in6_u, sizeof(old_net_addr.in6_u));
                if (ret < 0) return ret;
            } else {
                ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ipv6,
                                                            saddr), &old_net_addr.in6_u, sizeof(old_net_addr.in6_u));
                if (ret < 0) return ret;
            }

            //bpf_printk("ipv6[rewrite_addr]: 2");
            __wsum diff = bpf_csum_diff((void *) &old_net_addr.in6_u, sizeof(old_net_addr.in6_u),
                                        (void *) new_net_addr,
                                        sizeof(old_net_addr.in6_u), 0);
            ret = bpf_l4_csum_replace(skb, off, 0, diff, flags | 0);
            if (ret < 0) return ret;

            //bpf_printk("ipv6[rewrite_addr]: 3");
            if (rw_daddr) {
                ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ipv6,
                                                             daddr), new_net_addr, sizeof(old_net_addr.in6_u), 0/*BPF_F_RECOMPUTE_CSUM*/);
                if (ret < 0) return ret;
            } else {
                ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ipv6,
                                                             saddr), new_net_addr, sizeof(old_net_addr.in6_u), 0/*BPF_F_RECOMPUTE_CSUM*/);
                if (ret < 0) return ret;
            }

            bpf_printk("ipv6[rewrite_addr]: 4");
        }
    }

    return 0;
}


static __always_inline long rewrite_port(struct __sk_buff *skb, int iphdrl, bool is_tcp, bool is_udp, __be16 new_net_port, int rw_daddr) {
    long ret;
    int off, flags = 0;

    if (is_tcp) {
        off = L4_CSUM_OFF(iphdrl, tcp);
    } else if (is_udp) {
        off = L4_CSUM_OFF(iphdrl, udp);
        flags |= BPF_F_MARK_MANGLED_0;
    } else {
        // can't both be false
        return -10;
    }

    if (off) {
        __be16 old_net_port = 0;

        // load port
        if (rw_daddr) {
            ret = bpf_skb_load_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, dest), &old_net_port,
                    sizeof(old_net_port));
        } else {
            ret = bpf_skb_load_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, source), &old_net_port,
                    sizeof(old_net_port));
        }

        if (ret < 0) {
            bpf_printk("bpf_skb_load_bytes([dest|source]) error: %d", ret);
            return ret;
        }


        ret = bpf_l4_csum_replace(skb, off, old_net_port, new_net_port, flags | sizeof(new_net_port));
        //ret = bpf_l4_csum_replace(skb, off, 0, diff,flags | sizeof(new_net_addr));
        if (ret < 0) {
            bpf_printk("bpf_l4_csum_replace failed fot new_net_port: %d\n");
            return ret;
        }
    }

    if (rw_daddr) {
        if (is_tcp)  ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, dest), &new_net_port,
                sizeof(new_net_port), 0);
        else ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, udp, dest), &new_net_port,
                sizeof(new_net_port), 0);
    } else {
        if (is_tcp)  ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, source), &new_net_port,
                sizeof(new_net_port),0);
        else ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, udp, source), &new_net_port,
                sizeof(new_net_port),0);
    }

    if (ret < 0) {
        bpf_printk("bpf_skb_store_bytes failed for new_net_port: %d\n", ret);
        return ret;
    }

    return ret;
}

/* not needed
static inline long rewrite_tos(struct __sk_buff *skb, int hdr_start_off, __u8 new_tos) {
    long ret;
    __u8 old_tos;

    ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, tos), &old_tos, sizeof(old_tos));

    if (ret < 0) {
        bpf_printk("bpf_skb_load_bytes(tos) error: %d", ret);
        return ret;
    }


    ret = bpf_l3_csum_replace(skb, L3_CSUM_OFF(ip), old_tos, new_tos, 2);
    if (ret < 0) {
        bpf_printk("bpf_l3_csum_replace failed: %d\n", ret);
        return ret;
    }

    ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, tos), &new_tos, sizeof(new_tos),0);


    if (ret < 0) {
        bpf_printk("bpf_skb_store_bytes failed for new_net_port: %d\n", ret);
        return ret;
    }

    return ret;
}
*/

