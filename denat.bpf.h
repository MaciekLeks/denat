//#include <linux/icmp.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
#include "commons.h"

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
#define AF_INET		2	/* IP protocol family.  */
#define AF_INET6	10	/* IP version 6.  */
//<netinet/in.h>}

//{from linux/if_ether.h
#define ETH_HLEN 14
#define ETH_P_IPV4 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 0x86DD
#define GENEVE_UDP_PORT             6081
#define GENEVE_VER                  0

#define BPF_F_CURRENT_NETNS (-1L)
#define MAX_L4_CONNTACK_ENTRIES 1024 //redefine the number
//}

//struct tuple_key {
//    __u32 daddr;
//    __u32 saddr;
//    __u16 sport;
//    __u16 dport;
//};
//

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct edge);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct forwarded_port);
    __type(value, __u32);
    __uint(max_entries, 256);
    //__uint(pinning, LIBBPF_PIN_BY_NAME);
} forwarded_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct connt_key);
    __type(value, struct connt_value);
    __uint(max_entries, MAX_L4_CONNTACK_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connt_map SEC(".maps");


//{addons
static __always_inline void ipv4_print_ip(char *prefix, char *suffix, __u32 ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    bpf_printk("%s:%d.%d.%d.%d%s", prefix, bytes[0], bytes[1], bytes[2], bytes[3], suffix);
}

//static void be32_to_ipv4(__u32 ip_value, char *ip_buffer) {
//    __u64 ip_data[4];
//
//    ip_data[3] = ((__u64) (ip_value >> 24) & 0xFF);
//    ip_data[2] = ((__u64) (ip_value >> 16) & 0xFF);
//    ip_data[1] = ((__u64) (ip_value >> 8) & 0xFF);
//    ip_data[0] = ((__u64) ip_value & 0xFF);
//
//    bpf_printk("ip:%x, ip_data[0]:%d, ip_data[1]:%d, ip_data[2]:%d, ip_data[3]:%d\n", ip_value, ip_data[0], ip_data[1],
//               ip_data[2], ip_data[3]);
//    bpf_snprintf(ip_buffer, 16, "%d.%d.%d.%d", ip_data, 4 * sizeof(__u64));
//}
//
//#define BE32_TO_IPV4(ip_value) ({ \
//    char _ip_buffer[32];          \
//    be32_to_ipv4((ip_value), _ip_buffer); \
//    _ip_buffer; \
//})

static char* be32_to_ipv4(__be32 ip_value, char *ip_buffer) {
    __u64 ip_data[4];

    ip_data[3] = ((__u64) (ip_value >> 24) & 0xFF);
    ip_data[2] = ((__u64) (ip_value >> 16) & 0xFF);
    ip_data[1] = ((__u64) (ip_value >> 8) & 0xFF);
    ip_data[0] = ((__u64) ip_value & 0xFF);

//    bpf_printk("ip:%x, ip_data[0]:%d, ip_data[1]:%d, ip_data[2]:%d, ip_data[3]:%d\n", ip_value, ip_data[0], ip_data[1],
//               ip_data[2], ip_data[3]);
    bpf_snprintf(ip_buffer, 16, "%d.%d.%d.%d", ip_data, 4 * sizeof(__u64));
    return ip_buffer;
}

#define BE32_TO_IPV4(ip_value) ({ \
    be32_to_ipv4((ip_value), (char [32]){}); \
})

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


static inline long rewrite_addr(struct __sk_buff *skb, int iphdrl, __be32 new_net_addr, int rw_daddr) {
    long ret;
    int off = 0, flags = BPF_F_PSEUDO_HDR;
    __u8 proto;

    ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, protocol), &proto, 1);
    if (ret < 0) {
        bpf_printk("bpf_l4_csum_replace failed: %d\n", ret);
        return ret;
    }

    switch (proto) {
        case IPPROTO_TCP:
            off = L4_CSUM_OFF(iphdrl, tcp);
            break;

        case IPPROTO_UDP:
            off = L4_CSUM_OFF(iphdrl, udp);
            flags |= BPF_F_MARK_MANGLED_0;
            break;
    }

    __be32 old_net_addr = 0;
    if (off) {

        // load old addr
        if (rw_daddr) {
            ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, daddr), &old_net_addr, sizeof(old_net_addr));
        } else {
            ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, saddr), &old_net_addr, sizeof(old_net_addr));
        }

        if (ret < 0) {
            bpf_printk("bpf_skb_load_bytes([daddr|saddr]) error: %d", ret);
            return ret;
        }

        if (ret < 0) {
            bpf_printk("bpf_skb_load_bytes([dest|source]) error: %d", ret);
            return ret;
        }

        bpf_printk("rw_daddr:%d, proto: %d, old_addr: %d, new_addr:%d, iphdrl:%d", rw_daddr, proto, old_net_addr,
                   new_net_addr, iphdrl);
        ipv4_print_ip("--- old addr", "", old_net_addr);
        ipv4_print_ip("--- new addr", "", new_net_addr);

        //__wsum diff = bpf_csum_diff((void *)&old_net_addr , sizeof(old_net_addr),(void *)&new_net_addr, sizeof (new_net_addr),  0);
        ret = bpf_l4_csum_replace(skb, off, old_net_addr, new_net_addr, flags | sizeof(new_net_addr));
        //ret = bpf_l4_csum_replace(skb, off, 0, diff,flags | sizeof(new_net_addr));
        if (ret < 0) {
            bpf_printk("bpf_l4_csum_replace failed fot new_net_addr: %d\n");
            return ret;
        }
    }

    ret = bpf_l3_csum_replace(skb, L3_CSUM_OFF(ip), old_net_addr, new_net_addr, sizeof(new_net_addr));
    if (ret < 0) {
        bpf_printk("bpf_l3_csum_replace failed: %d\n", ret);
        return ret;
    }

    if (rw_daddr)
        ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, daddr), &new_net_addr, sizeof(new_net_addr),
                /*BPF_F_RECOMPUTE_CSUM*/0);
    else
        ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, saddr), &new_net_addr, sizeof(new_net_addr),
                /*BPF_F_RECOMPUTE_CSUM*/0);

    if (ret < 0) {
        bpf_printk("bpf_skb_store_bytes() failed for new_net_addr: %d\n", ret);
        return ret;
    }

    return ret;
}

static inline long rewrite_port(struct __sk_buff *skb, int iphdrl, __be16 new_net_port, int rw_daddr) {
    long ret;
    int off = 0, flags = 0;
    __u8 proto;

    ret = bpf_skb_load_bytes(skb, L3_MEMBER_OFF(ip, protocol), &proto, 1);
    if (ret < 0) {
        bpf_printk("bpf_l4_csum_replace failed: %d\n", ret);
        return ret;
    }

    switch (proto) {
        case IPPROTO_TCP:
            off = L4_CSUM_OFF(iphdrl, tcp);
            break;

        case IPPROTO_UDP:
            off = L4_CSUM_OFF(iphdrl, udp);
            flags |= BPF_F_MARK_MANGLED_0;
            break;
    }

    __be16 old_net_port = 0;
    if (off) {

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

    if (rw_daddr)
        ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, dest), &new_net_port,
                                  sizeof(new_net_port),
                /*BPF_F_RECOMPUTE_CSUM*/0);
    else
        ret = bpf_skb_store_bytes(skb, L4_MEMBER_OFF(iphdrl, tcp, source), &new_net_port,
                                  sizeof(new_net_port),
                /*BPF_F_RECOMPUTE_CSUM*/0);

    if (ret < 0) {
        bpf_printk("bpf_skb_store_bytes failed for new_net_port: %d\n", ret);
        return ret;
    }

    return ret;
}


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

    ret = bpf_skb_store_bytes(skb, L3_MEMBER_OFF(ip, tos), &new_tos, sizeof(new_tos),
            /*BPF_F_RECOMPUTE_CSUM*/0);


    if (ret < 0) {
        bpf_printk("bpf_skb_store_bytes failed for new_net_port: %d\n", ret);
        return ret;
    }

    return ret;
}

