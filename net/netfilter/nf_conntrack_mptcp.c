#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <crypto/sha.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>
#include <net/mptcp.h>


#define NF_MPTCP_HASH_SIZE 256



extern struct module* nf_conntrack_mptcp_mod;
extern void (*nf_ct_mptcp_new_implptr)(const struct tcphdr *th, struct nf_conn *ct);

/* Hashtables to retrieve nf_conn_mptcp from token, one for each direction */
static struct list_head mptcp_conn_htb[NF_MPTCP_HASH_SIZE];
static rwlock_t htb_lock;	

/* Hashtable-related features */
static inline u32 nf_mptcp_hash_tk(u32 token)
{
	return token % NF_MPTCP_HASH_SIZE;
}

struct nf_conn_mptcp *nf_mptcp_hash_find(u32 token) 
{
	u32 hash = nf_mptcp_hash_tk(token);
	struct nf_conn_mptcp *mptcp_conn;

	read_lock(&htb_lock);
	list_for_each_entry(mptcp_conn, &mptcp_conn_htb[hash], collide_tk) {
		if (token == mptcp_conn->token[0] || token == mptcp_conn->token[1]) { 
	        read_unlock(&htb_lock);
            return mptcp_conn;
        }
	}
	read_unlock(&htb_lock);
	return NULL;
}


void nf_mptcp_hash_insert(struct nf_conn_mptcp *mpconn, 
							u32 token)
{
	u32 hash = nf_mptcp_hash_tk(token);

	write_lock_bh(&htb_lock);
	list_add(&mpconn->collide_tk, &mptcp_conn_htb[hash]);
	write_unlock_bh(&htb_lock);
}


void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn)
{
	/* remove from the token hashtable */
	write_lock_bh(&htb_lock);
	list_del(&mpconn->collide_tk);
	write_unlock_bh(&htb_lock);
}

void nf_mptcp_hash_free(struct list_head *bucket)
{
	struct nf_conn_mptcp *mpconn, *tmp;
	list_for_each_entry_safe(mpconn, tmp, bucket, collide_tk) {
		list_del(&mpconn->collide_tk);
		kfree(mpconn);
	}
}
/* End of hashtable implem */


/* Finite State Machine setup */
enum mptcp_conntrack {
	MPTCP_CONNTRACK_NONE,
	MPTCP_CONNTRACK_SYN_SENT,
	MPTCP_CONNTRACK_SYN_SENT2,
	MPTCP_CONNTRACK_SYN_RECV,
	MPTCP_CONNTRACK_ESTABLISHED,
	MPTCP_CONNTRACK_FALLBACK,
	MPTCP_CONNTRACK_FINWAIT1,
	MPTCP_CONNTRACK_FINWAIT2,
	MPTCP_CONNTRACK_TIMEWAIT,
	MPTCP_CONNTRACK_CLOSEWAIT1,
	MPTCP_CONNTRACK_CLOSEWAIT2,
	MPTCP_CONNTRACK_LASTACK,
	MPTCP_CONNTRACK_CLOSED,
	MPTCP_CONNTRACK_MAX,
	MPTCP_CONNTRACK_IGNORE
}

/* Define states' names  TODO */ 
static const char *const mptcp_conntrack_names[] = {
	"M_NONE",
	"M_SYN_SENT",
	"M_SYN_SENT2",
	"M_SYN_RECV",
	"M_ESTABLISHED",
	"M_FALLBACK",
	"M_FINWAIT1",
	"M_FINWAIT2",
	"M_TIMEWAIT",
	"M_CLOSEWAIT1",
	"M_CLOSEWAIT2",
	"M_LASTACK",
	"M_CLOSED"
};

#define sMNO MPTCP_CONNTRACK_NONE
#define sMSS MPTCP_CONNTRACK_SYN_SENT
#define sMS2 MPTCP_CONNTRACK_SYN_SENT2
#define	sMSR MPTCP_CONNTRACK_SYN_RECV
#define sMES MPTCP_CONNTRACK_ESTABLISHED
#define sMFB MPTCP_CONNTRACK_FALLBACK
#define sMFW MPTCP_CONNTRACK_FINWAIT1
#define sMF2 MPTCP_CONNTRACK_FINWAIT2
#define sMTW MPTCP_CONNTRACK_TIMEWAIT
#define sMCW MPTCP_CONNTRACK_CLOSEWAIT1
#define sMC2 MPTCP_CONNTRACK_CLOSEWAIT2
#define sMLA MPTCP_CONNTRACK_LASTACK
#define sMCL MPTCP_CONNTRACK_CLOSED
#define sMIV MPTCP_CONNTRACK_MAX
#define sMIG MPTCP_CONNTRACK_IGNORE

#define sNO sMNO
#define sSS sMSS
#define sSR sMSR
#define sES sMES
#define sFW sMFW
#define sCW sMCW
#define sLA sMLA
#define sTW sMTW
#define sCL sMCL
#define sS2 sMS2
#define sIV sMIV
#define sIG sMIG

/* Possible packet types related to MPTCP connection */
enum mptcp_pkt_type {
	MPTCP_CAP_SYN,
	MPTCP_CAP_SYNACK,
	MPTCP_CAP_ACK,
	MPTCP_JOIN_SYN,
	MPTCP_JOIN_SYNACK,
	MPTCP_JOIN_ACK,
	MPTCP_DATA_FIN,
	MPTCP_DATA_ACKFIN,
	MPTCP_DATA_ACK,
	MPTCP_FAIL,
	MPTCP_NOOPT,
/*	MPTCP_SUB_FIN,*/
	MPTCP_PKT_INDEX_MAX,
};
	

/* STATES from the FSM
 *
 * INVALID and IGNORED: states for invalid packets and possibly invalid,
 * respectively
 *
 * M_NONE:		initial state
 * M_SYN_SENT:	MPCAP_SYN packet seen
 * M_SYN_SENT2:	MPCAP_SYN packet seen from reply dir, simultaneous open
 * M_SYN_RECV:	MPCAP_SYNACK packet seen
 * M_ESTABLISHED:	MPCAP_ACK packet seen and valid
 * M_FALLBACK:	checksum, key exchange, token or hash not valid
 * M_FINWAIT1:	MPTCP CLOSE demanded
 * M_FINWAIT2: Closing all subflows and rcvd DATA_ACK+FIN
 * M_TIMEWAIT:	waiting for subflows to be closed
 * M_CLOSEWAIT1:	simultaneous closing: DATA_FIN rcvd and sent
 * M_CLOSEWAIT2:	received DATA_FIN
 * M_LASTACK:	waiting for last ack
 * M_CLOSED:	connection closed, mptcp pcb deleted
 */

/* Return the index of the packet-type corresponding to the packet seen
 * This refers to a value from enum mptcp_pkt_type */
static unsigned int get_conntrack_index(const struct tcphdr *tcph)
{
	struct mptcp_option *mp;
	int opsize;

    u8 *opt = (__u8*)(tcph + 1); /* skip the common tcp header */
	/* iterates over the mptcp options until one matching packet-type is found */
	while (opt = nf_mptcp_get_next(tcph, opt)) {
		mp = opt;

		switch (mp->sub) {
		case MPTCP_SUB_JOIN:
			if (tcph->syn) return (tcph->ack ? MPTCP_JOIN_SYNACK : MPTCP_JOIN_SYN);
			else if (tcph->ack) return MPTCP_JOIN_ACK;
		case MPTCP_SUB_CAPABLE:
			if (tcph->syn) return (tcph->ack ? MPTCP_CAP_SYNACK : MPTCP_CAP_SYN);
			else if (tcph->ack) return MPTCP_CAP_ACK;
		case MPTCP_SUB_DSS:
			struct mp_dss *mpdss = (struct mp_dss*)mp;
			if (mpdss->A) return (mpdss->F ? MPTCP_DATA_ACKFIN : MPTCP_DATA_ACK);
			else if (mpdss->F) return MPTCP_DATA_FIN;
		case MPTCP_SUB_FAIL:
			if (tcph->rst) return MPTCP_FAIL;
		}
	}
	return MPTCP_NOOPT;
}

/* MPTCP state transition table */
static const u8 mptcp_conntracks[2][MPTCP_PKT_INDEX_MAX][MPTCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL DIR */
/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/
/* CAPsyn */	{sMSS, sMSS, sMS2, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG,
				sMIG, sMIG, sMIG },
/*
 *	sMNO -> sMSS	Initialize a new connection
 *	sMSS -> sMSS	Retransmitted SYN
 *	sMS2 -> sMS2	Late retransmitted SYN
 *	sMSR -> sMIG
 *	sMES -> sMIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sMFW -> sMIG
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG	Reopening a MPTCP connection is meaningless
 *	sMCL -> sMIG
 *
 *	sMFB -> sMIG
 *	sMF2 -> sMIG
 *  sMC2 -> sMIG
 *	*/

/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/
/* DataFIN */	{sMIG, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG, sMIG,
				sMIG, sMIG, sMIG },

/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/
/* DataACKFIN */ {},

/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/
/* DataACK */	{},
/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/
/*		        {sMNO, sMSS, sMS2, sMSR, sMES, sMFB, sMFW, sMF2, sMTW, sMCW, 
 *		        sMC2, sMLA, sMCL }*/


	},
	{
/* REPLY DIR */
	}
 };

/* Per subflow FSM (for JOIN)
 * J_NONE:		initial state 
 * J_SYN_SENT:	MPJOIN_SYN packet seen and valid
 * J_SYN_SENT2:	MPJOIN_SYN packet seen from reply dir, sim open
 * J_SYN_RECV:	MPJOIN_SYNACK packet seen and valid
 * J_ACK_RECV:	last MPJOIN_ACK packet seen	
 * J_ESTABLISHED:	MPJOIN_ACK seen and valid
 * J_CLOSED: */


/* Search for the JOIN subkind in a MPTCP segment 
 * Inspired by tcp_parse_options() from tcp-input.c
 * Return a pointer to the JOIN subtype in the skb
 * or NULL if it can't be found 
 * */
struct mp_join *nf_mptcp_find_join(const struct tcphdr *th)
{
	struct mptcp_option *mp;

	if ((mp = nf_mptcp_get_ptr(th))->sub == MPTCP_SUB_JOIN)
		return (struct mp_join*)((__u8*)mp-2);

	return NULL;
}

#if 0
struct mp_join *mptcp_find_joinv2(struct tcphdr *th) 
{
	struct tcphdr *th = tcp_hdr(skb);
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);

	/* Jump through the options to check whether JOIN is there */
	ptr = (__u8*)(th + 1);
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
			opsize = *ptr++;			if (opsize < 2)	/* "silly options" */
				return NULL;
			if (opsize > length)
				return NULL;  /* don't parse partial options */
			if (opcode == TCPOPT_MPTCP &&
			    ((struct mptcp_option *)(ptr - 2))->sub == MPTCP_SUB_JOIN) {
				return (struct mp_join *)(ptr - 2);
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
	return NULL;
}
#endif


/* Look for the presence of MPTCP in the set of TCP options from a given
 * TCP packet pointed by th.
 * Inspired by tcp_parse_options() from tcp-input.c
 * Return a pointer to the option in the skb
 * or NULL if it can't be found.
 */
#if 0
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
#endif 

/* Get the token from a mp_join structure from a SYN packet */
static inline __u32 __nf_mptcp_get_token(struct mp_join *mpj)
{
    if (mpj && mpj->u.syn.token)
        return mpj->u.syn.token;
    return 0;
}

/* Get the token from a TCP header of a SYN packet */
__u32 nf_mptcp_get_token(const struct tcphdr *th)
{
    struct mp_join *mpj;
    /* The token is only available in a SYN segment */
    if (!th->syn)
        return 0;

    mpj = nf_mptcp_find_join(th);
	return __nf_mptcp_get_token(mpj);
}


u64 __nf_mptcp_get_key(struct mp_capable * mpc)
{
	if (mpc && mpc->sender_key)
		return mpc->sender_key;
	return 0;
}

/**
 * sha_init - initialize the vectors for a SHA1 digest
 * @buf: vector to initialize
 * (copied from sha1.c)
 */
void sha_init(__u32 *buf)
{
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;
	buf[4] = 0xc3d2e1f0;
}

/* Return the token and initial data sequence number from a 64bits key. 
 * This is a copy of mptcp_key_sha1() from net/mptcp/mptcp_ctrl.c as the
 * netfilter mptcp support does not depend on CONFIG_MPTCP */
void nf_mptcp_key_sha1(u64 key, u32 *token, u64 *idsn)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 mptcp_hashed_key[SHA_DIGEST_WORDS];
	u8 input[64];
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too */
	memcpy(input, &key, sizeof(key)); /* Copy key to the msg beginning */
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	for (i = 0; i < 5; i++)
		mptcp_hashed_key[i] = cpu_to_be32(mptcp_hashed_key[i]);

	if (token)
		*token = mptcp_hashed_key[0];
	if (idsn)
		*idsn = ((u64)mptcp_hashed_key[3] << 32) | mptcp_hashed_key[4];
}


/* Called at the end of the proto handling for new TCP packets (new connections) */

void nf_ct_mptcp_new_impl(const struct tcphdr *th,
		struct nf_conn *ct)
{
	struct mptcp_option *mptr;
	u32 token;
	u64 key, isdn;
	struct nf_conn_mptcp *mpct;
    
	if (!(mptr = nf_mptcp_get_ptr(th)))
		return; /* return value ?*/

	/* Is this a subflow of an existing MultipathTCP connection ? */
    /* TODO: EXPECTED -> NEW_SUBFLOW ? */
	switch (mptr->sub) {
	case MPTCP_SUB_JOIN:
		token = __nf_mptcp_get_token((struct mp_join*)mptr);
		/* if we find an existing valid mptcp connection matching 
		 * this conn's token
		 * for the original direction, it is highly probable that the
		 * sender is an end-host of that mptcp connection. */
		mpct = nf_mptcp_hash_find(token);
		if (mpct && mpct->confirmed) {
			pr_debug("conntrack: new mptcp subflow arrives ct=%p\n",ct);
			/* mark as RELATED */
			__set_bit(IPS_EXPECTED_BIT, &ct->status);
		}
		else {
			pr_debug("conntrack: unexpected token in mp_join segment, ct=%p\n",ct);
			/* TODO: log */
		}
		break;
	
	case MPTCP_SUB_CAPABLE:
		key = __nf_mptcp_get_key((struct mp_capable*)mptr);
		nf_mptcp_key_sha1(key, &token, &isdn);
		mpct = nf_mptcp_hash_find(token);
		if (mpct) {
			pr_debug("conntrack: unexpected mp_capable arrives ct=%p\n",ct);
		}
		else {
			pr_debug("conntrack: new mptcp connection, ct=%p\n", ct);
			mpct = kmalloc(sizeof(struct nf_conn_mptcp), GFP_KERNEL);
			mpct->key[0] = key;
			mpct->token[0] = token;
			mpct->confirmed = true; /* FIXME temporary */
			nf_mptcp_hash_insert(mpct, token);
			/* Keep a ref to master mptcp connnection in every nf_conn */
			ct->mpmaster = mpct;
		}
		break;
	}
}

void nf_ct_mptcp_packet(const struct tcphdr *th, struct nf_conn *ct,
		enum ip_conntrack_info ctinfo)
{
	struct mptcp_option *mptr;
	u32 token;
	u64 key, isdn;
	struct nf_conn_mptcp *mpct;
	enum ip_conntrack_dir dir;
    
	if (!(mptr = nf_mptcp_get_ptr(th)))
		return; /* FIXME should not use NF_ACCEPT */

	mpct = ct->mpmaster; 
	switch (mptr->sub) {
	case MPTCP_SUB_CAPABLE:
		break;
	case MPTCP_SUB_JOIN:
		break;
	}

}
#if 0
/* FOR EXTENSION HELPER -- not used */
static int help(struct sk_buff *skb,
		unsigned int l4protoff,
		struct nf_conn *ct,
		enum ip_conntrack_info ctinfo)
{
	unsigned int dataoff, datalen;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	const char *fb_ptr;
	int ret;
	struct mptcp_option *mptr;
	__u32 token;
	__u64 key;
	struct nf_conn_mptcp *ct_mptcp_info = &nfct_help(ct)->help.ct_mptcp_info;
    
	th = skb_header_pointer(skb, l4protoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return NF_ACCEPT;

	if (!(mptr = mptcp_get_ptr))
		return NF_ACCEPT;

	/* Is this a subflow of an existing MultipathTCP connection ? */
    /* TODO: EXPECTED -> NEW_SUBFLOW */
	switch (mptr->sub) {
	case MPTCP_SUB_JOIN:
		token = __mptcp_get_token((mp_join*)mptr);
		/* if we find an existing conn matching this conn's token, 
		 * mark the new connection as an expected one */
		mptcp_conn = nf_mptcp_hash_find(token, ctinfo);
		if (mptcp_conn) {
			pr_debug("conntrack: new mptcp subflow arrives ct=%p\n",ct);
			__set_bit(IPS_EXPECTED_BIT, &ct->status);
		}
		else {
			pr_debug("conntrack: unexpected token in mp_join segment, ct=%p\n",ct);
			/* TODO: log */
		}
		break;

	case MPTCP_SUB_CAPABLE:
		key = nf_mptcp_get_key((mp_capable*)mptr);
		token = nf_mptcp_token_from_key(key);
		mptcp_conn = nf_mptcp_hash_find(token, ctinfo);
		if (mptcp_conn) {
			pr_debug("conntrack: unexpected mp_capable arrives ct=%p\n",ct);
		}
		else {
			pr_debug("conntrack: new mptcp connection, ct=%p\n",ct);
			ct_mptcp_info = kmalloc(sizeof(nf_conn_mptcp), GFP_KERNEL);
			ct_mptcp_info->key[ctinfo] = key;
			ct_mptcp_info->token[ctinfo] = token;
			nf_mptcp_hash_insert(ct_mptcp_info, token, ctinfo);
		}
		break;
	}



}
/* helper structure */
static struct nf_conntrack_helper mptcp_helper __read_mostly;

static int nf_conntrack_mptcp_fini(void)
{

	pr_debug("nf_ct_mptcp: unregistering helper");
	nf_conntrack_helper_unregister(&mptcp_helper);
}

static int __init nf_conntrack_mptcp_init(void)
{
	int i;
	for (i = 0; i < NF_MPTCP_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&mptcp_token_htb[IP_CT_DIR_REPLY][i]);
		INIT_LIST_HEAD(&mptcp_token_htb[IP_CT_DIR_ORIGINAL][i]);
	}
	rwlock_init(&tk_hash_lock);
	
	/* init conntrack helper struct */
	mptcp_helper.tuple.dst.protonum = IPPROTO_TCP;
	mptcp_helper.expect_policy = NULL;
	mptcp_helper.me = THIS_MODULE;
	mptcp_helper.help = help;

    return 0;
/*    FIXME: return value */
}

module_init(nf_conntrack_mptcp_init);
#endif

static int __init nf_conntrack_mptcp_init(void)
{
	int i;
	
	
	/*
	extern void (*nf_ct_mptcp_new)(const struct tcphdr*, struct nf_conn*);
	extern  nf_ct_mptcp_new;
	extern struct mptcp_option* nf_mptcp_get_ptr;
	extern (struct mptcp_option*)(const struct tcphdr*) nf_mptcp_get_ptr;
	extern struct mptcp_option* (*nf_mptcp_get_ptr)(const struct tcphdr *th);
	nf_mptcp_get_ptr_impl = &__nf_mptcp_get_ptr;
	*/
	printk(KERN_DEBUG "nf_ct_mptcp: loading mptcp module\n");
	/* trampoline init */
	nf_conntrack_mptcp_mod = THIS_MODULE; 
	nf_ct_mptcp_new_implptr = &nf_ct_mptcp_new_impl;
	
	/* hashtable init */
	for (i = 0; i < NF_MPTCP_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&mptcp_conn_htb[i]);
	}
	rwlock_init(&htb_lock);

	return 0;
}
static void __exit nf_conntrack_mptcp_fini(void)
{
	int i;
	printk(KERN_DEBUG "nf_ct_mptcp: unloading mptcp module\n");
	for (i = 0; i < NF_MPTCP_HASH_SIZE; i++) {
		nf_mptcp_hash_free(&mptcp_conn_htb[i]);
	}

	nf_ct_mptcp_new_implptr = NULL;
}

module_init(nf_conntrack_mptcp_init);
module_exit(nf_conntrack_mptcp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Maître <nimai@skynet.be>");
MODULE_DESCRIPTION("MPTCP connection tracker");

