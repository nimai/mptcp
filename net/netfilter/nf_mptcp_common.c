/*
 * #include <linux/netfilter/nf_conntrack_mptcp.h>
 * */
#include <linux/module.h>
#include <net/mptcp.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>


/* Look for the presence of MPTCP in the set of TCP options from a given
 * TCP packet pointed by th.
 * Inspired by tcp_parse_options() from tcp-input.c
 * Return a pointer to the option in the skb
 * or NULL if it can't be found.
 */

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
			if (opcode == TCPOPT_MPTCP) {
				printk(KERN_DEBUG "find_mptcp_option: FOUND, kind=%u, size=%u\n", 
						((struct mptcp_option*)(ptr-2))->sub,opsize);
                return (struct mptcp_option*)(ptr-2);
			}
            ptr += opsize-2;
		    length -= opsize;
        }
    }
    /* no mptcp option has been found after the whole parsing */
    return NULL;
}
EXPORT_SYMBOL(nf_mptcp_get_ptr);

/* Get a pointer to the first met MPTCP option in the TCP header.
 * hptr is a pointer to a valid TCP option
 * Return NULL if no more option in the header */
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

