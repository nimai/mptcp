#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/list.h>
#include <linux/tcp.h>
#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/module.h>

/* Finite State Machine setup */
enum mptcp_ct_state {
	MPTCP_CONNTRACK_NONE,
	MPTCP_CONNTRACK_SYN_SENT,
	MPTCP_CONNTRACK_SYN_SENT2,
	MPTCP_CONNTRACK_SYN_RECV,
	MPTCP_CONNTRACK_ESTABLISHED,
	MPTCP_CONNTRACK_NO_SUBFLOW,
	MPTCP_CONNTRACK_FINWAIT,
	MPTCP_CONNTRACK_TIMEWAIT,
	MPTCP_CONNTRACK_CLOSEWAIT,
	MPTCP_CONNTRACK_LASTACK,
	MPTCP_CONNTRACK_CLOSED,
	MPTCP_CONNTRACK_MAX,
	MPTCP_CONNTRACK_IGNORE,
	MPTCP_CONNTRACK_FALLBACK
};


struct mptcp_subflow_info {
	u_int8_t addr_id;
	u_int32_t nonce[IP_CT_DIR_MAX];
	/* original direction relative to MPTCP base subflow
	 *	IP_CT_DIR_ORIGINAL: same as MPTCP
	 *	IP_CT_DIR_REPLY: opposite */
	enum ip_conntrack_dir rel_dir;	
	struct {
		u_int64_t dataseq_start;
		u_int32_t subseq_start;
		u_int16_t len;
	} map[IP_CT_DIR_MAX];
};

/* This structure exists only once per mptcp-level connection */
struct nf_conn_mptcp {
	/* Directions are relative to MP_CAPABLE SYN packet.
	 * For data relative to a specific host:
	 *	IP_CT_DIR_ORIGINAL: initiator host
	 *	IP_CT_DIR_REPLY: receiver
	 */
	u_int64_t key[IP_CT_DIR_MAX]; 
	u_int32_t token[IP_CT_DIR_MAX];	/* token = lefttrunc32(sha1(key)) */ 
	u_int64_t last_dseq;
	u_int64_t last_dack;
	u_int64_t last_dend; /* last dseq + last segment payload */
    struct list_head collide_tk; /* item of hash tables */ 
	enum mptcp_ct_state state;
	u_int8_t counter_sub; /* number of subflows for this data connection */
	spinlock_t lock; /* struct mustnt be modified by several 
						subflows at the same time*/
};


struct nf_conn_mptcp *nf_mptcp_hash_find(u32 token);
void nf_mptcp_hash_insert(struct nf_conn_mptcp *mpconn, u32 token);
void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn);


struct mp_join *nf_mptcp_find_join(const struct tcphdr *th);
u32 nf_mptcp_get_token(const struct tcphdr *th);

struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th);


u8 *nf_mptcp_next_opt(const struct tcphdr *th, u8 *hptr);
struct mptcp_option *nf_mptcp_next_mpopt(const struct tcphdr *th, u8 *hptr);
struct mptcp_option *nf_mptcp_first_mpopt(const struct tcphdr *th);


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
