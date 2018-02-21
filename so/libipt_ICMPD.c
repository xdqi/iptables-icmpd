#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>
#include "../nf_icmpd.h"

enum {
	O_TO        = 0,
	O_IFADDR,
	F_TO        = 1 << O_TO,
	F_IFADDR    = 1 << O_IFADDR,
	F_ANY       = F_TO | O_IFADDR,
};

static void ICMPD_help(void)
{
	printf(
"ICMPD target options:\n"
" [--to [<ipaddr>]]\n"
"				Address to map source to.\n"
" [--ifaddr [<device>]]\n"
"               Address on which device to map source to");
}

static const struct xt_option_entry ICMPD_opts[] = {
	{.name = "to", .id = O_TO, .type = XTTYPE_STRING},
	{.name = "ifaddr", .id = O_IFADDR, .type = XTTYPE_STRING},
	XTOPT_TABLEEND,
};


static void ICMPD_parse(struct xt_option_call *cb)
{
	struct ipt_ICMPD_info *info = cb->data;
	const struct in_addr *ip = NULL;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO:
		info->mode = IPT_ICMPD_TO;
		ip = xtables_numeric_to_ipaddr(cb->arg);
		if (!ip) {
			xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n", cb->arg);
			return;
		}
		info->target.addr.ip = ip->s_addr;
		break;
	case O_IFADDR:
		info->mode = IPT_ICMPD_IFADDR;
		memcpy(&info->target.ifname, cb->arg, IFNAMSIZ);
		break;
	default:
		printf("Unknown mode\n");
	}
}

static void ICMPD_fcheck(struct xt_fcheck_call *cb)
{
	struct ipt_ICMPD_info *mr = cb->data;

}

static void ICMPD_print(const void *ip, const struct xt_entry_target *target,
						int numeric)
{
	const struct ipt_ICMPD_info *info = (const void *)target->data;

	struct in_addr a;

	printf(" to:");
	switch (info->mode) {
	case IPT_ICMPD_TO:
		a = info->target.addr.in;
		printf(" %s", xtables_ipaddr_to_numeric(&a));
		break;
	case IPT_ICMPD_IFADDR:
		printf(" address of interface %s", info->target.ifname);
		break;
	}
}

static void ICMPD_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_ICMPD_info *info = (const void *)target->data;
	unsigned int i = 0;

	struct in_addr a;

	switch (info->mode) {
	case IPT_ICMPD_TO:
		a.s_addr = info->target.addr.ip;
		printf(" --to %s", xtables_ipaddr_to_numeric(&a));
		break;
	case IPT_ICMPD_IFADDR:
		printf(" --ifaddr %s", info->target.ifname);
		break;
	}
}

static struct xtables_target icmpd_tg_reg = {
	.name		= "ICMPD",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct ipt_ICMPD_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_ICMPD_info)),
	.help		= ICMPD_help,
	.x6_parse	= ICMPD_parse,
	.x6_fcheck	= ICMPD_fcheck,
	.print		= ICMPD_print,
	.save		= ICMPD_save,
	.x6_options	= ICMPD_opts,
};

void _init(void)
{
	xtables_register_target(&icmpd_tg_reg);
}
