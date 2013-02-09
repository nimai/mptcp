/*
 * #include <linux/netfilter/nf_conntrack_mptcp.h>
 * */
#include <linux/module.h>
#include <net/mptcp.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>


/* Look for the presence of MPTCP in the set of TCP options from a given
 * TCP packet pointed by th.
 * Return a pointer to the option in the skb
 * or NULL if it can't be found.
 */

struct mptcp_option *nf_mptcp_get_ptr(const struct tcphdr *th) {
	unsigned int len;
	short mptcptype;
	return nf_mptcp_get_mpopt(th, (u8*)(th+1), &len, &mptcptype);
}
EXPORT_SYMBOL(nf_mptcp_get_ptr);

/* Get a pointer to the first met MPTCP option in the TCP header.
 * hptr is a pointer to a valid TCP option
 * Return NULL if no more option in the header 
 *
 * Inspired by tcp_parse_options() from tcp-input.c
 */
struct mptcp_option *nf_mptcp_get_mpopt(const struct tcphdr *th, u8 *hptr, 
		unsigned int *len, short *mptcptype)
{
	u8 *ptr = hptr;
	/* length is the size of the rest of the TCP header from option pointed by
	 * ptr to the end*/
	int length = (th->doff * 4) - (ptr-(u8*)th);
	*mptcptype = -1;
	pr_debug("MPOPT: length=%i, ptr=%p\n",length,ptr);
	while (length >= 0) {
		int opcode = *ptr;
		int opsize;
		pr_debug("opcode=%i\n",opcode);

        switch (opcode) {
        case TCPOPT_EOL:
            return NULL;
        case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
            length--;
			ptr++;
            continue;
        default:
			opsize = *(ptr+1);
			if (opsize < 2) /* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;	/* don't parse partial options */
			pr_debug("nextopt: opcode=%u, opsize=%u\n", opcode, opsize); 
			if (opcode != TCPOPT_MPTCP) {
				ptr += opsize;
				length -= opsize;
				continue;
			}
			/* we have an MPTCP option */
			*len = opsize;
			*mptcptype = ((struct mptcp_option*)ptr)->sub;
            return (struct mptcp_option*)ptr;
        }
    }
    return NULL;
}

/* Search for the JOIN subkind in a MPTCP segment 
 * Return a pointer to the JOIN subtype in the skb
 * or NULL if it can't be found 
 * */
struct mptcp_option *nf_mptcp_find_subtype(const struct tcphdr *th, unsigned int subtype)
{
	u8 *opt;
	unsigned int len;
	short sub;
	/* iterates over the mptcp options */
	for_each_mpopt(opt, sub, len, th) {
		if (sub == subtype)
			return (struct mptcp_option*)opt;
	}
	return NULL;
}

