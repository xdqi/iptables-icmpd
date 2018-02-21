#ifndef _NETFILTER_NF_ICMPD_H
#define _NETFILTER_NF_ICMPD_H

#include <linux/netfilter.h>
#include <linux/if.h>

enum {
    IPT_ICMPD_TO = 0,
    IPT_ICMPD_IFADDR
};

#define IPT_ICMPD_MAXMODE IPT_ICMPD_IFADDR

union ipt_ICMPD_target {
    union nf_inet_addr addr;
    char ifname[IFNAMSIZ];
};

struct ipt_ICMPD_info {
    __u32                   mode;
    union ipt_ICMPD_target  target;
};

#endif /* _NETFILTER_NF_ICMPD_H */
