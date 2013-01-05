/*
 *	mptcp match for Xtables
 *	written by Nicolas Maître <nimai@skynet.be>, 2012
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/netfilter/xt_mptcp.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>


static bool mptcp_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_mptcp_mtinfo *info = par->matchinfo;
	const struct tcphdr *th;
	struct tcphdr _tcph;
    bool mptcp_present;
	struct mptcp_option *dss;
	
	th = skb_header_pointer(skb, par->thoff, sizeof(_tcph), &_tcph);
	mptcp_present = !!nf_mptcp_get_ptr(th);

	if (!mptcp_present)
		return false;
	
	if (info->subtypes & XT_MPCAPABLE_PRESENT) {
		if (!nf_mptcp_find_subtype(th, MPTCP_SUB_CAPABLE) ^
				!!(info->invflags & XT_MPCAPABLE_PRESENT)) {
			pr_debug("Not matching MP_CAPABLE packet.");
			return false;
		}
	}

	if (info->subtypes & XT_MPJOIN_PRESENT) {
		if (!nf_mptcp_find_subtype(th, MPTCP_SUB_JOIN) ^
				!!(info->invflags & XT_MPJOIN_PRESENT)) {
			pr_debug("Not matching MP_JOIN packet.");
			return false;
		}
	}

	if (info->subtypes & XT_DSS_FLAGS) {
		if ((!(dss = nf_mptcp_find_subtype(th, MPTCP_SUB_DSS)) &&
					/* does masked dssflags from pkt match flags to compare?*/
					((((unsigned char *)dss)[3] & info->dss_flg_mask) == info->dss_flg_cmp)) ^
				!!(info->invflags & XT_DSS_FLAGS)) {
			pr_debug("Not matching DSS flags %hhx (from packet) to %hhx.",
					((unsigned char *)dss)[3] & info->dss_flg_mask, info->dss_flg_cmp);
			return false;
		}
	}
	pr_debug("Match found.");
	return true;
}


static int mptcp_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_mptcp_mtinfo *info = par->matchinfo;

	printk(KERN_INFO "xt_mptcp: Added a rule with -m mptcp in "
	       "the %s table; this rule is reachable through hooks 0x%x\n",
	       par->table, par->hook_mask);

	if ((info->subtypes & (XT_MPCAPABLE_PRESENT | XT_MPJOIN_PRESENT ))
		&& (info->subtypes & (XT_DSS_FLAGS | XT_MPJOIN_PRESENT))
		&& (info->subtypes & (XT_DSS_FLAGS | XT_MPCAPABLE_PRESENT))) {
		pr_info("incompatible combination: no packet will match that rule\n");
		return -EINVAL;
	}
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
		.match      = mptcp_mt,
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
		.match      = mptcp_mt,
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

