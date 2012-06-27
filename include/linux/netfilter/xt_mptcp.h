#ifndef _LINUX_NETFILTER_XT_MPTCP_H
#define _LINUX_NETFILTER_XT_MPTCP_H 1

enum {
	XT_MPTCP_PRESENT     = 1 << 0,
    XT_MPTCP_PRESENT_INV = 1 << 1,
};

struct xt_mptcp_mtinfo {
	__u8 flags;
};

#endif /* _LINUX_NETFILTER_XT_MPTCP_H */
