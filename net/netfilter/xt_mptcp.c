/*
 *	mptcp match for Xtables
 *	written by Nicolas Maître <nimai@skynet.be>, 2012
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#include <linux/netfilter/xt_mptcp.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>


static bool mptcp_mt4(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_mptcp_mtinfo *info = par->matchinfo;
	const struct iphdr *iph = ip_hdr(skb);

    const bool mptcp_present = 
        !!nf_mptcp_get_ptr((const struct tcphdr*)(iph + 1));

	printk(KERN_INFO
	       "xt_mptcp: IN=%s OUT=%s "
           "SRC=%pI4 DIST=%pI4 MPTCP_present=%s \n",
	       (par->in != NULL) ? par->in->name : "",
	       (par->out != NULL) ? par->out->name : "",
	       &iph->saddr, &iph->daddr,
           mptcp_present?"true":"false");

    printk(KERN_DEBUG "match flags: %u ?= %u, f&c: %u", info->flags, XT_MPTCP_PRESENT, info->flags&XT_MPTCP_PRESENT);
/*	if (info->flags & XT_MPTCP_PRESENT) */
		if (mptcp_present) {
			printk(KERN_NOTICE "mptcp in use - match\n");
			return true;
        }
    /*
	if (info->flags & XT_MPTCP_PRESENT)
		if (mptcp_present ^
		    !!(info->flags & XT_MPTCP_PRESENT_INV)) {
			printk(KERN_NOTICE "mptcp in use - match\n");
			return true;
		}
    */
	printk(KERN_NOTICE "mptcp NOT in use - no match\n");
	return false;
}

static bool mptcp_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_mptcp_mtinfo *info = par->matchinfo;
	const struct ipv6hdr *iph = ipv6_hdr(skb);
    
    const bool mptcp_present = 
        !!nf_mptcp_get_ptr((const struct tcphdr*)(iph + 1));

	printk(KERN_INFO
	       "xt_mptcp: IN=%s OUT=%s "
           "SRC=%pI6 DIST=%pI6 MPTCP_present=%s \n",
	       (par->in != NULL) ? par->in->name : "",
	       (par->out != NULL) ? par->out->name : "",
	       &iph->saddr, &iph->daddr,
           mptcp_present ? "true":"false");

	/*if (info->flags & XT_MPTCP_PRESENT) {*/
		if (mptcp_present) {
			printk(KERN_NOTICE "mptcp in use - match\n");
			return true;
        }

	printk(KERN_NOTICE "mptcp NOT in use - no match\n");
	return false;
}

static int mptcp_mt_check(const struct xt_mtchk_param *par)
{
	/*const struct xt_mptcp_mtinfo *info = par->matchinfo;*/

	printk(KERN_INFO "xt_mptcp: Added a rule with -m mptcp in "
	       "the %s table; this rule is reachable through hooks 0x%x\n",
	       par->table, par->hook_mask);

	return 0;
}

static void mptcp_mt_destroy(const struct xt_mtdtor_param *par)
{
	printk(KERN_INFO "One rule with mptcp match got deleted\n");
}

static struct xt_match mptcp_mt_reg[] __read_mostly = {
	{
		.name       = "mptcp",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
        .proto		= IPPROTO_TCP,
		.match      = mptcp_mt4,
		.checkentry = mptcp_mt_check,
		.destroy    = mptcp_mt_destroy,
		.matchsize  = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
		.me         = THIS_MODULE,
	},
	{
		.name       = "mptcp",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
        .proto		= IPPROTO_TCP,
		.match      = mptcp_mt6,
		.checkentry = mptcp_mt_check,
		.destroy    = mptcp_mt_destroy,
		.matchsize  = XT_ALIGN(sizeof(struct xt_mptcp_mtinfo)),
		.me         = THIS_MODULE,
	},
};

static int __init mptcp_mt_init(void)
{
	return xt_register_matches(mptcp_mt_reg, ARRAY_SIZE(mptcp_mt_reg));
}

static void __exit mptcp_mt_exit(void)
{
	xt_unregister_matches(mptcp_mt_reg, ARRAY_SIZE(mptcp_mt_reg));
}

module_init(mptcp_mt_init);
module_exit(mptcp_mt_exit);
MODULE_DESCRIPTION("Xtables: Match Multipath TCP (mptcp) traffic");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_mptcp");
MODULE_ALIAS("ip6t_mptcp");

