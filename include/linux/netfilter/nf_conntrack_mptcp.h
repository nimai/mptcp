#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/list.h>
#include <linux/tcp.h>
#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack.h>
/*#include <linux/netfilter/nf_conntrack_tuple_common.h>*/
#include <linux/module.h>

/* MPTCP connection tracking helper */

/* This structure exists only once per mptcp-level connection */
struct nf_conn_mptcp {
	/* Directions are relative to MP_CAPABLE SYN packet.
	 * For data relative to a specific host:
	 *	IP_CT_DIR_ORIGINAL: initiator host
	 *	IP_CT_DIR_REPLY: receiver
	 */
	__u64 key[IP_CT_DIR_MAX]; 
	__u32 token[IP_CT_DIR_MAX];	/* token = lefttrunc32(sha1(key)) */ 
    struct list_head collide_tk; /* item of hash tables */ 
	bool confirmed;
};

struct mptcp_subflow_info {
	__u32 nonce[IP_CT_DIR_MAX];
};

struct nf_conn_mptcp *nf_mptcp_hash_find(u32 token);
void nf_mptcp_hash_insert(struct nf_conn_mptcp *mpconn, u32 token);
void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn);


struct mp_join *nf_mptcp_find_join(const struct tcphdr *th);
u32 nf_mptcp_get_token(const struct tcphdr *th);

struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th);



#if 0 
struct mptcp_option *(*nf_mptcp_get_ptr_impl)(const struct tcphdr *th);

struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th) 
{
	struct mptcp_option *ret = NULL;
	if (try_module_get(nf_conntrack_mptcp_mod)) {
		ret = (*nf_mptcp_get_ptr_impl)(th);
		module_put(nf_conntrack_mptcp_mod);
	}
	else {
		printk(KERN_DEBUG "NO IMPLEM -- not loaded");
	}
	return ret;
}

struct mptcp_option *nf_mptcp_get_ptr_impl0(const struct tcphdr *th) {
		printk(KERN_DEBUG "NO IMPLEM -- dont know why :(");
		return NULL;


struct mptcp_option *(*nf_mptcp_get_ptr)(const struct tcphdr *th) = 
	&nf_mptcp_get_ptr_impl0;
#endif



/* Debugging help function 
char* format_stack_bytes(const __u8 *ptr, unsigned short n)
{
    int i, s= n * 3 + n/16 + 3;
    char* dbgstr, *p;
    dbgstr = (char*)kmalloc(s, GFP_KERNEL);
    p=dbgstr;
    for (i=0; i<n; i++) {
        if (i % 16 == 0)
            p+=sprintf(p, "\n");
        p+=sprintf(p, "%02x ", *(ptr+i));
    }
    p += sprintf(p, "\n");
    return dbgstr;
}*/
#endif /* _NF_CONNTRACK_MPTCP_H */
