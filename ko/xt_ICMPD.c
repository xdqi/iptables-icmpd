/*
 * Source IP modification target (stateless) for IP tables
 * (C) 2018 by Xiaodong Qi <xdqi@outlook.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <net/checksum.h>

#include <linux/netfilter/x_tables.h>
#include "../nf_icmpd.h"

MODULE_AUTHOR("Xiaodong Qi <xdqi@outlook.com>");
MODULE_DESCRIPTION("Xtables: Source IP field modification target (stateless)");
MODULE_LICENSE("GPL");

static void get_ip_from_device(const char *name, __be32 *out) {
	const struct net_device *dev;
	const struct in_device *addr;
	const struct in_ifaddr *list;

	dev = dev_get_by_name(&init_net, name);
	if (!dev) {
		return;
	}
	addr = dev->ip_ptr;
	if (!addr) {
		return;
	}
	list = addr->ifa_list;
	for (; list != NULL; list = list->ifa_next) {
		if (strcmp(list->ifa_label, name) == 0) {
			*out = list->ifa_address;
			break;
		}
	}
}

static void get_ipv6_from_device(const char *name, struct in6_addr *out) {
	const struct net_device *dev;
	const struct inet6_dev *addr;
	const struct ifacaddr6 *list;

	dev = dev_get_by_name(&init_net, name);
	if (!dev) {
		return;
	}
	addr = dev->ip6_ptr;
	if (!addr) {
		return;
	}
	list = addr->ac_list;
	for (; list != NULL; list = list->aca_next) {
		if (list->aca_idev == addr) {
			memcpy(out, &list->aca_addr, sizeof(struct in6_addr));
			break;
		}
	}
}

static unsigned int
icmpd_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *iph;
	const struct ipt_ICMPD_info *info = par->targinfo;
	__be32 new_addr = 0;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	iph = ip_hdr(skb);

	switch (info->mode) {
	case IPT_ICMPD_TO:
		new_addr = info->target.addr.ip;
		break;
	case IPT_ICMPD_IFADDR:
		get_ip_from_device(info->target.ifname, &new_addr);
		break;
	default:
		new_addr = info->target.addr.ip;
		break;
	}

	if (new_addr != iph->saddr) {
		csum_replace4(&iph->check, iph->saddr, new_addr);
		iph->saddr = new_addr;
	}

	return XT_CONTINUE;
}

static unsigned int
icmpd_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6hdr *ip6h;
	const struct ipt_ICMPD_info *info = par->targinfo;
	struct in6_addr new_addr = {0};

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);

	switch (info->mode) {
	case IPT_ICMPD_TO:
		memcpy(&new_addr, &info->target.addr, sizeof(struct in6_addr));
		break;
	case IPT_ICMPD_IFADDR:
		get_ipv6_from_device(info->target.ifname, &new_addr);
		break;
	default:
		memcpy(&new_addr, &info->target.addr, sizeof(struct in6_addr));
		break;
	}

	memcpy(&ip6h->saddr, &new_addr, sizeof(struct in6_addr));

	return XT_CONTINUE;
}

static int icmpd_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_ICMPD_info *info = par->targinfo;

	if (info->mode > IPT_ICMPD_MAXMODE) {
		pr_info("ICMPD: invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	return 0;
}

static int icmpd_tg6_check(const struct xt_tgchk_param *par)
{
	const struct ipt_ICMPD_info *info = par->targinfo;

	if (info->mode > IPT_ICMPD_MAXMODE) {
		pr_info("invalid or unknown mode %u\n", info->mode);
		return -EINVAL;
	}
	return 0;
}

static struct xt_target icmpd_tg_reg[] __read_mostly = {
	{
		.name       = "ICMPD",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = icmpd_tg,
		.targetsize = sizeof(struct ipt_ICMPD_info),
		.table      = "mangle",
		.checkentry = icmpd_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "ICMPD",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = icmpd_tg6,
		.targetsize = sizeof(struct ipt_ICMPD_info),
		.table      = "mangle",
		.checkentry = icmpd_tg6_check,
		.me         = THIS_MODULE,
	},
};

static int __init icmpd_tg_init(void)
{
	return xt_register_targets(icmpd_tg_reg, ARRAY_SIZE(icmpd_tg_reg));
}

static void __exit icmpd_tg_exit(void)
{
	xt_unregister_targets(icmpd_tg_reg, ARRAY_SIZE(icmpd_tg_reg));
}

module_init(icmpd_tg_init);
module_exit(icmpd_tg_exit);
MODULE_ALIAS("ipt_ICMPD");
MODULE_ALIAS("ip6t_ICMPD");
