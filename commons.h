//
// Created by mlk on 17.10.23.
//

#ifndef DENAT_COMMONS_H
#define DENAT_COMMONS_H

#define INGRESS_CFG_INDX 0
#define EGRESS_CFG_INDX 1
#define EGRESS_POLICY_BLOCKING 0x1
#define EGRESS_POLICY_ALLOWING 0x0

// all fields in network byte order except ifindex
struct edge {
    unsigned int ifindx;
    unsigned int g_naddr[4]; //e.g. 192.168.59.1 in network byte order (vboxvnet3)
    unsigned int d_naddr[4]; //e.g. 192.168.59.120 in network byte order
    unsigned short d_nport; //e.g. 10080 in network byte order
    unsigned short options; //e.g. default policy
};

struct forwarded_port {
    unsigned int nport;
};

struct connt_key {
    unsigned short sport;
};

struct connt_l2 {
    unsigned char orig_d_mac[6]; //0c:41:e9:20:7b:54 for 192.168.100.1, info: bpf_lookup_fib could be used instead of burdening memory with macs
    unsigned char orig_s_mac[6]; ////a4:bb:6d:d5:94:68 for 192.168.100.2, info: bpf_lookup_fib could be used instead of burdening memory with macs
};

struct connt_value {
    unsigned int ifindx;
    unsigned int orig_d_naddr[4]; //e.g. IP of cern.info.ch
    unsigned short orig_d_nport; //network byte order port, e.g. 80
    unsigned int orig_s_naddr[4]; //e.g. 192.168.100.2
    struct connt_l2 macs;
};


#endif //DENAT_COMMONS_H
