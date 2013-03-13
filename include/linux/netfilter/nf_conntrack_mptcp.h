#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/list.h>
#include <linux/tcp.h>
#include <net/mptcp.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <net/netfilter/nf_conntrack.h>



/* Finite State Machine setup */
enum mptcp_ct_state {
	MPTCP_CONNTRACK_NONE,
	MPTCP_CONNTRACK_SYN_SENT,
	MPTCP_CONNTRACK_SYN_RECV,
	MPTCP_CONNTRACK_ESTABLISHED,
	MPTCP_CONNTRACK_NO_SUBFLOW,
	MPTCP_CONNTRACK_FINWAIT,
	MPTCP_CONNTRACK_CLOSEWAIT,
	MPTCP_CONNTRACK_LASTACK,
	MPTCP_CONNTRACK_TIMEWAIT,
	MPTCP_CONNTRACK_SYN_SENT2,
	MPTCP_CONNTRACK_MAX,
	MPTCP_CONNTRACK_FALLBACK,
	MPTCP_CONNTRACK_IGNORE
};


struct mp_per_dir {
	enum ip_conntrack_dir dir;
	u_int64_t key; 
	u_int32_t token;	/* token = lefttrunc32(sha1(key)) */ 
	u_int64_t last_dseq;
	u_int64_t last_dack;
	u_int64_t last_dend; /* last dseq + last segment payload */
    struct list_head collide_tk; /* item of hash tables */ 
};


/* This structure exists only once per mptcp-level connection */
struct nf_conn_mptcp {
	/* Directions are relative to MP_CAPABLE SYN packet.
	 * For data relative to a specific host:
	 *	IP_CT_DIR_ORIGINAL: initiator host
	 *	IP_CT_DIR_REPLY: receiver
	 */
	struct mp_per_dir d[IP_CT_DIR_MAX];
	enum mptcp_ct_state state;
	u_int8_t counter_sub; /* number of subflows for this data connection */
	spinlock_t lock; /* struct mustnt be modified by several 
						subflows at the same time*/
	struct timer_list timeout; /* timer for destruction of the data connection state */
};

struct mpct_ref {
	struct nf_conn_mptcp *mpct;
	enum ip_conntrack_dir rel_dir;
	struct list_head cand_lst;
};

/* forward ref */
struct nf_conn;

#define perdir_to_mpct(mp) \
	container_of((mp), struct nf_conn_mptcp, d[(mp)->dir])

/* return the mptcp dir from the current packet's dir and the subflow original
 * relative dir*/
#define subdir_to_mpdir(reldir, subdir) \
	((reldir) ^ (subdir))

#define is_subflow(ct) \
		((ct)->proto.tcp.mpmaster || !list_empty(&(ct)->proto.tcp.mpflow.tmp_mpct))

/* hashtable related */
bool nf_mptcp_hash_find(u32 token, struct list_head *mplist, enum ip_conntrack_dir dir); 
bool nf_mptcp_hash_insert(struct mp_per_dir *mp, u32 token);
void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn);


/* general use functions for MPTCP */
struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th);

struct mptcp_option *nf_mptcp_get_mpopt(const struct tcphdr *th, u8 *hptr, 
		unsigned int *len, short *mptcptype);
#define for_each_mpopt(opt, mptcpsubtype, len, tcph) \
	for (opt=(u8*)((tcph)+1); \
			(opt = (u8*)nf_mptcp_get_mpopt((tcph), (opt), &(len), &(mptcpsubtype))); \
			opt+=(len))

struct mptcp_option *nf_mptcp_find_subtype(const struct tcphdr *th, 
		unsigned int subtype);


/* crypto functions */
void nf_mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		       u32 *hash_out);
void nf_mptcp_key_sha1(u64 key, u32 *token, u64 *idsn);

/* hmac check */
bool nf_mpctp_valid_hmac(struct mptcp_subflow_info *mpsub,
		u32 *rcvd_hmac, struct nf_conn_mptcp *mpct, 
		enum ip_conntrack_dir dir, enum ip_conntrack_dir mptcp_dir);
bool nf_mptcp_hmac_prune_mpct(struct nf_conn *ct, enum ip_conntrack_dir dir, u32 *hmac); 

/* MPTCP connection tracking */

int nf_ct_mptcp_error(struct net *net, struct nf_conn *tmpl,
		     struct sk_buff *skb,
		     unsigned int dataoff,
		     enum ip_conntrack_info *ctinfo,
		     u_int8_t pf,
		     unsigned int hooknum);

bool nf_ct_mptcp_new(struct nf_conn *ct, const struct sk_buff *skb,
		    unsigned int dataoff);

int nf_ct_mptcp_packet(struct nf_conn *ct,
		      const struct sk_buff *skb,
		      unsigned int dataoff,
		      enum ip_conntrack_info ctinfo,
		      u_int8_t pf,
		      unsigned int hooknum);

/* make available the tcp packets regular handlers for conntracking */
int tcp_error(struct net *net, struct nf_conn *tmpl,
		     struct sk_buff *skb,
		     unsigned int dataoff,
		     enum ip_conntrack_info *ctinfo,
		     u_int8_t pf,
		     unsigned int hooknum);

bool tcp_new(struct nf_conn *ct, const struct sk_buff *skb,
		    unsigned int dataoff);

int tcp_packet(struct nf_conn *ct,
		      const struct sk_buff *skb,
		      unsigned int dataoff,
		      enum ip_conntrack_info ctinfo,
		      u_int8_t pf,
		      unsigned int hooknum);

void nf_mptcp_fallback(struct nf_conn *ct, struct nf_conn_mptcp *mpct);
void nf_mptcp_put(struct nf_conn_mptcp* mpct);

void nf_ct_mptcp_destroy(struct nf_conn *ct);

bool nf_mptcp_add_subflow(struct nf_conn_mptcp *mpct);
bool nf_mptcp_remove_subflow(struct nf_conn_mptcp *mpct);

struct nf_conn_mptcp *nf_mptcp_try_assoc_subflow(struct nf_conn *ct);

void nf_mptcp_update(struct nf_conn_mptcp *mpct, bool zero_counter);

/* Time to wait before a MPTCP connection without subflow opened should be
 * considered closed */
/*unsigned int nf_ct_mptcp_timeout_no_subflow;*/ /* __read_mostly; */


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
