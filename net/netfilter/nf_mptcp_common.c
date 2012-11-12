#include <linux/netfilter/nf_conntrack_mptcp.h>

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
EXPORT_SYMBOL(nf_mptcp_get_ptr);

/* Get a pointer to the next (non-EOL/NOP) option in the TCP header.
 * hptr is a pointer to a valid TCP option
 * Return NULL if no more option in the header */
u8 *nf_mptcp_get_next_opt(const struct tcphdr *th, const u8 *hptr)
{
	u8 *ptr = hptr;
	int length = (th->doff * 4) - (ptr-th);
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
			if (opsize < 2) /* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;	/* don't parse partial options */
            return ptr-2;
        }
    }
    return NULL;
}

/* Same as next_opt but returns only the MPTCP options */
u8 *nf_mptcp_get_next(const struct tcphdr *th, const u8 *hptr)
{
	u8 *opt, *ptr = hptr;
	while ((opt = nf_mptcp_get_next_opt(th, (const u8)ptr)) != NULL) {
		if (*opt == TCPOPT_MPTCP)
			return opt;
		ptr = opt;
	}
	return NULL;
}
