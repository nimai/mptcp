#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/list.h>
#include <linux/tcp.h>
#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

/* MPTCP connection tracking helper */

/* This structure exists only once per master */
struct nf_conn_mptcp {
	/* Directions are relative to MP_CAPABLE SYN packet.
	 * For data relative to a specific host:
	 *	IP_CT_DIR_ORIGINAL: initiator host
	 *	IP_CT_DIR_REPLY: receiver
	 */
	__u64 key[IP_CT_DIR_MAX]; 
	__u32 nonce[IP_CT_DIR_MAX];
	__u32 token[IP_CT_DIR_MAX];	/* token = lefttrunc32(sha1(key)) */ 
    struct list_head collide_tk; /* item of 2 hash tables */ 
	bool confirmed;
};


struct nf_conn_mptcp *nf_mptcp_hash_find(u32 token);
void nf_mptcp_hash_insert(struct nf_conn_mptcp *mpconn, u32 token);
void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn);


struct mp_join *nf_mptcp_find_join(const struct tcphdr *th);
u32 nf_mptcp_get_token(const struct tcphdr *th);

struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th)
{
    __u8 *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);
    
    /*
    char *dbgstr;
    printk(KERN_DEBUG "tcp header:\n"
            "source: %u dest: %u\n"
            "offset: %u window: %u\n\n", th->source, th->dest,
            th->doff, th->window);
    dbgstr = format_stack_bytes((unsigned char*)th, 80))    
    printk(KERN_DEBUG "%s", dbgstr);
    kfree(dbgstr);
    */

    ptr = (__u8*)(th + 1); /* skip the common tcp header */
    printk(KERN_DEBUG "find_mptcp_option: length=%i, opcode=%i\n", length, *ptr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return NULL;
        case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
			opsize = *ptr++;
            printk(KERN_DEBUG "find_mptcp_option: opsize = %i\n", opsize);
			if (opsize < 2) /* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;	/* don't parse partial options */
			if (opcode == TCPOPT_MPTCP)
                return (struct mptcp_option*)(ptr-2);
            ptr += opsize-2;
		    length -= opsize;
        }
    }
    /* no mptcp option has been found after the whole parsing */
    return NULL;
}

/* Trampoline code to use nf_mptcp_get_ptr_impl from external module only if
 * loaded */
struct module* nf_conntrack_mptcp_mod;

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

void nf_ct_mptcp_new_impl0(const struct tcphdr *th, struct nf_conn *ct) {}
void (*nf_ct_mptcp_new)(const struct tcphdr *th, struct nf_conn *ct) =
	&nf_ct_mptcp_new_impl0;


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
