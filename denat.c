#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include "commons.h"
#include "denat.skel.h"

#define TRACE_PIPE_PATH "/sys/kernel/debug/tracing/trace_pipe"
#define LO_IFINDEX 1
#define ENO1_IFINDEX 2
#define HOOK_COUNT 2

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
    printf("lost event\n");
}

void read_trace_pipe() {
    FILE *trace_file;
    char buffer[1024];

    trace_file = fopen(TRACE_PIPE_PATH, "r");
    if (trace_file == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(buffer, sizeof(buffer), trace_file) != NULL) {
        printf("%s", buffer);
    }

    fclose(trace_file);
}

struct hook_err {
    int err;
    bool created;
};

// src: ~/dev/tests/c_iproute.c
// Simplified method to get hop interface namme and inet address of that interface
int get_hop_info(const char *addr_in, char *iface, char *rt_addr_in) {
    char command[128];
    sprintf(command, "ip route get %s", addr_in);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("ip route pipe error");
        return 1;
    }

    char buffer[256];
    char *dev_start = NULL;
    char *src_start = NULL;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        dev_start = strstr(buffer, "dev");
        src_start = strstr(buffer, "src");

        if (dev_start && src_start) {
            dev_start += strlen("dev");
            src_start += strlen("src");

            sscanf(dev_start, "%s", iface);
            sscanf(src_start, "%s", rt_addr_in);

            printf("Info: config for iface: %s, rt_addr_in: %s\n", iface, rt_addr_in);

            pclose(fp);
            return 0;
        }
    }

    pclose(fp);
    return 1;
}


static struct hook_err
setup_hook(struct denat_bpf *obj, int ifindex, enum bpf_tc_attach_point attach_point,
           struct bpf_tc_hook **ptc_hook, struct bpf_tc_opts **ptc_opts) {
    int err;
    struct bpf_program *prog;
    bool hook_created = false;


    *ptc_hook = malloc(sizeof(struct bpf_tc_hook));
    *ptc_opts = malloc(sizeof(struct bpf_tc_opts));

    if (ptc_hook == NULL || ptc_opts == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for TC hook or options\n");
        return (struct hook_err) {.err = -ENOMEM, .created = hook_created};
    }

    memset(*ptc_hook, 0, sizeof(struct bpf_tc_hook));
    (*ptc_hook)->sz = sizeof(struct bpf_tc_hook);
    (*ptc_hook)->ifindex = ifindex;
    (*ptc_hook)->attach_point = attach_point;

    memset(*ptc_opts, 0, sizeof(struct bpf_tc_opts));
    (*ptc_opts)->sz = sizeof(struct bpf_tc_opts);
    (*ptc_opts)->handle = 1;
    (*ptc_opts)->priority = 1;

    fprintf(stdout, "tc_opts %p; tc_hook: %p\n", *ptc_opts, *ptc_hook);

    err = bpf_tc_hook_create(*ptc_hook);
    if (!err)
        hook_created = true;
    if (err && err != -EEXIST) {
        fprintf(stderr, "Error: Failed to create TC hook: %d\n", err);
        return (struct hook_err) {.err = err, .created = hook_created};
    }

    if (attach_point == BPF_TC_EGRESS)
        prog = obj->progs.tc_egress;
    else
        prog = obj->progs.tc_ingress; // Assuming this program exists for ingress

    (*ptc_opts)->prog_fd = bpf_program__fd(prog);
    err = bpf_tc_attach(*ptc_hook, *ptc_opts);
    if (err) {
        fprintf(stderr, "Error: Failed to attach TC: %d\n", err);
        return (struct hook_err) {.err = err, .created = hook_created};
    }

    return (struct hook_err) {.err = 0, .created = hook_created}; // Success
}

static int detach_hook(struct bpf_tc_hook *tc_hook, struct bpf_tc_opts *tc_opts) {
    tc_opts->flags = tc_opts->prog_fd = tc_opts->prog_id = 0;
    return bpf_tc_detach(tc_hook, tc_opts);
}

int store_config(const struct denat_bpf *obj, const char *proxy_daddr_in, unsigned short proxy_dport,
                 struct edge *edge) {

    char rt_addr_in[128];
    char rt_ifname[128];


    int ret = get_hop_info(proxy_daddr_in, rt_ifname, rt_addr_in);
    if (ret) {
        fprintf(stderr, "Error: Failed to get hop info\n");
        return 1;
    }

    int ifindx = if_nametoindex(rt_ifname); //e.g. f(vboxnet3) -> 192.168.59.1
    if (!ifindx) {
        fprintf(stderr, "Error: Failed to get ifindx of %s: %s\n", rt_ifname, strerror(errno));
    }

    //convert presentation to numeric using inet_pton for rt_addr_in
//    struct in_addr gaddr, daddr;
//    inet_pton(AF_INET, rt_addr_in, &gaddr);
//    inet_pton(AF_INET, proxy_daddr_in, &daddr);
//
//    edge->g_naddr[0] = gaddr.s_addr;
//    edge->d_naddr[0] = daddr.s_addr;
    // Determine if the address is IPv4 or IPv6

    if (strchr(proxy_daddr_in, ':')) {
        struct in6_addr addr6;
        // This is an IPv6 address
        if (inet_pton(AF_INET6, proxy_daddr_in, &addr6) != 1) {
            fprintf(stderr, "Error: Invalid IPv6 address format\n");
            return -1;
        }
        // Copy the IPv6 address to edge structure (assuming g_naddr and d_naddr are large enough)
        memcpy(edge->d_naddr, &addr6, sizeof(addr6));
        memset(&addr6, 0, sizeof(struct in6_addr));

        if (inet_pton(AF_INET6, rt_addr_in, &addr6) != 1) {
            fprintf(stderr, "Error: Invalid IPv6 route address format\n");
            return 1;
        }
        memcpy(edge->g_naddr, &addr6, sizeof(addr6));
    } else {
        struct in_addr addr4;
        // This is an IPv4 address
        if (inet_pton(AF_INET, proxy_daddr_in, &addr4) != 1) {
            fprintf(stderr, "Error: Invalid IPv4 address format\n");
            return -1;
        }
        // Only set the first element as IPv4 is 32-bit
        edge->d_naddr[0] = addr4.s_addr;
        addr4.s_addr = 0; // Clear the address

        if (inet_pton(AF_INET, rt_addr_in, &addr4) != 1) {
            fprintf(stderr, "Error: Invalid IPv4 route address format\n");
            return 1;
        }
        edge->g_naddr[0] = addr4.s_addr;
    }




    edge->d_nport = htons(proxy_dport);
    edge->ifindx = ifindx;

    __u32 key = EGRESS_CFG_INDX;
    ret = bpf_map__update_elem(obj->maps.config_map, &key, sizeof(__u32), edge, sizeof(struct edge), BPF_ANY);
    if (ret) {
        fprintf(stderr, "Error: Failed to update config map: %d\n", ret);
        return -1;
    }

    return 0;
}

int store_forwarded_ports(const struct denat_bpf *obj, unsigned int ports[], int num_ports) {
    for (int i = 0; i < num_ports; i++) {
        fprintf(stdout, "Info: Storing forwarded port: %d\n", ports[i]);
        struct forwarded_port key;
        key.nport = htons(ports[i]);
        __u32 value = 123456; //not used
        int ret = bpf_map__update_elem(obj->maps.forwarded_port_map, &key, sizeof(struct forwarded_port),  &value,
                                       sizeof(__u32), BPF_ANY);
        if (ret) {
            fprintf(stderr, "Error: Failed to update forwarded_port_map: %d\n", ret);
            return -1;
        }
    }

    return 0;
}


void parse_args(int argc, char *argv[], char **ip_address, int *proxy_port, unsigned int **port_list, int *num_ports) {
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-dfproxy=", 9) == 0) {
            char *proxy_str = strchr(argv[i], '=') + 1;
            // Check if IPv6 address format [address]:port
            char *bracket = strchr(proxy_str, '[');
            char *colon = strrchr(proxy_str, ':');
            if (bracket != NULL && colon != NULL) {
                char *end_bracket = strchr(proxy_str, ']');
                if (end_bracket != NULL) {
                    *end_bracket = '\0'; // Null-terminate the address
                    *ip_address = bracket + 1; // Start after the opening bracket
                    if (colon[1] != '\0') {
                        *proxy_port = strtoul(colon + 1, NULL, 10);
                    } else {
                        fprintf(stderr, "Error: Port number format error\n");
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Error: Missing closing bracket for IPv6 address\n");
                    exit(1);
                }
            } else if (colon != NULL) { // IPv4 address format address:port
                *colon = '\0';
                *ip_address = proxy_str;
                if (colon[1] != '\0') {
                    *proxy_port = strtoul(colon + 1, NULL, 10);
                } else {
                    fprintf(stderr, "Error: Port number format error\n");
                    exit(1);
                }
            } else {
                fprintf(stderr, "Error: Wrong proxy IP and port number format\n");
                exit(1);
            }
        } else if (strncmp(argv[i], "-dfports=", 9) == 0) {
            char *ports_str = strchr(argv[i], '=') + 1;
            char *token = strtok(ports_str, ",");
            while (token != NULL) {
                if (strlen(token) > 0) {
                    (*num_ports)++;
                    *port_list = realloc(*port_list, (*num_ports) * sizeof(int));
                    (*port_list)[(*num_ports) - 1] = strtoul(token, NULL, 10);
                } else {
                    fprintf(stderr, "Error: Wrong port list format\n");
                    exit(1);
                }
                token = strtok(NULL, ",");
            }
        }
    }
}


//void parse_args(int argc, char *argv[], char **ip_address, int *proxy_port, unsigned int **port_list, int *num_ports) {
//    for (int i = 1; i < argc; i++) {
//        if (strncmp(argv[i], "-dfproxy=", 9) == 0) {
//            char *proxy_str = strchr(argv[i], '=') + 1;
//            char *colon = strchr(proxy_str, ':');
//            if (colon != NULL) {
//                *colon = '\0';
//                *ip_address = proxy_str;
//                if (colon[1] != '\0' && strlen(colon + 1) > 0) {
//                    *proxy_port = strtoul(colon + 1, NULL, 10);
//                } else {
//                    fprintf(stderr, "Error: Port number format error\n");
//                    exit(1);
//                }
//            } else {
//                fprintf(stderr, "Error: Wrong proxy IP and port number format\n");
//                exit(1);
//            }
//        } else if (strncmp(argv[i], "-dfports=", 9) == 0) {
//            char *ports_str = strchr(argv[i], '=') + 1;
//            char *token = strtok(ports_str, ",");
//            while (token != NULL) {
//                if (strlen(token) > 0) {
//                    (*num_ports)++;
//                    *port_list = realloc(*port_list, (*num_ports) * sizeof(int));
//                    (*port_list)[(*num_ports) - 1] = strtoul(token, NULL, 10);
//                } else {
//                    fprintf(stderr, "Error: Wrong port list format\n");
//                    exit(1);
//                }
//                token = strtok(NULL, ",");
//            }
//        }
//    }
//}


int main(int argc, char *argv[]) {
    char *proxy_ip_address = NULL;
    int proxy_port = 0;
    unsigned int *port_list = NULL;
    int num_ports = 0;
    struct denat_bpf *obj;
    int err;

    parse_args(argc, argv, &proxy_ip_address, &proxy_port, &port_list, &num_ports);

    // Show args
    if (proxy_ip_address != NULL) {
        printf("Info: Dynamic Forward Proxy IP: %s:%d\n", proxy_ip_address, proxy_port);
    }
    if (num_ports > 0) {
        printf("Info: Forwarded Ports: ");
        for (int i = 0; i < num_ports; i++) {
            printf("%d ", port_list[i]);
        }
        printf("\n");
    }


    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    char log_buf[64 * 1024];
    LIBBPF_OPTS(bpf_object_open_opts, opts,
                .kernel_log_buf = log_buf,
                .kernel_log_size = sizeof(log_buf),
                .kernel_log_level = 1,
    );

    obj = denat_bpf__open_opts(&opts);
    if (!obj) {
        fprintf(stderr, "Error: Failed to open BPF object\n");
        goto cleanup;
    }

    err = denat_bpf__load(obj);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF object\n");
        goto cleanup;
    }

    // store edge config
    struct edge edge;
    err = store_config(obj, proxy_ip_address, proxy_port, &edge);
    if (err) {
        fprintf(stderr, "Error: Failed to store config\n");
        goto cleanup;
    }

    // store egde ports
    //err = store_forwarded_ports(obj, (unsigned int[]) {80, 443});
    err = store_forwarded_ports(obj, port_list, num_ports);
    if (err) {
        fprintf(stderr, "Error: Failed to store config ports\n");
        goto cleanup;
    }


    // Print the verifier log
    for (int i = 0; i < sizeof(log_buf); i++) {
        if (log_buf[i] == 0 && log_buf[i + 1] == 0) {
            break;
        }
        fprintf(stdout, "%c", log_buf[i]);
    }


    struct bpf_tc_hook *tc_hook[HOOK_COUNT];
    struct bpf_tc_opts *tc_opts[HOOK_COUNT];
    struct hook_err ingress_err = setup_hook(obj, edge.ifindx, BPF_TC_INGRESS, &tc_hook[0], &tc_opts[0]);
    if (ingress_err.err && ingress_err.err != -EEXIST) {
        fprintf(stderr, "Error: Failed to create proxy TC ingress hook: %d\n", err);
        goto cleanup;
    }

    struct hook_err egress_err = setup_hook(obj, /*eno1*/2, BPF_TC_EGRESS, &tc_hook[1], &tc_opts[1]);
    if (egress_err.err && egress_err.err != -EEXIST) {
        fprintf(stderr, "Error: Failed to create TC egress hook: %d\n", err);
        goto cleanup;
    }
//
//    struct hook_err ingress_err = setup_hook(obj, "eno1", BPF_TC_INGRESS, &tc_hook[2], &tc_opts[2]);
//    if (ingress_err.err && ingress_err.err != -EEXIST) {
//        fprintf(stderr, "Failed to create TC egress hook: %d\n", err);
//        goto cleanup;
//    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "Error: Can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    //{ wait and print events
    read_trace_pipe();
    //}

    fprintf(stdout, "Stopping... Last error code:%d\n", err);

    for (int i = 0; i < HOOK_COUNT; i++) {
        fprintf(stdout, "tc_hook[%p]  tc_opts[%p]\n", tc_hook[i], tc_opts[i]);
        if (tc_hook[i] && tc_opts[i]) {
            fprintf(stdout, "Info: Detaching:%d\n", i);
            err = detach_hook(tc_hook[i], tc_opts[i]);
            if (err) {
                fprintf(stderr, "Error: Failed to detach TC: %d\n", err);
                goto cleanup;
            }
        }
    }

    cleanup:
    fprintf(stdout, "Info: Cleaning up... Last error code:%d\n", err);
    free(port_list);
    if (ingress_err.created)
        bpf_tc_hook_destroy(tc_hook[0]);
    if (egress_err.created)
        bpf_tc_hook_destroy(tc_hook[1]);
    denat_bpf__destroy(obj);
    for (int i = 0; i < HOOK_COUNT; i++) {
        free(tc_hook[i]);
        free(tc_opts[i]);
    }
    return err != 0;
}
