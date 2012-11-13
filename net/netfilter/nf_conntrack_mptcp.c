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
 * This refers to a value from enum mptcp_pkt_type 
 * Set a pointer mp to the considered option start address */
static enum mptcp_pkt_type _get_conntrack_index(const struct tcphdr *tcph, 
		struct mptcp_option **mp)
{
	int opsize;

    u8 *opt = (__u8*)(tcph + 1); /* skip the common tcp header */
	/* iterates over the mptcp options until one matching packet-type is found */
	while (opt = nf_mptcp_get_next(tcph, opt)) {
		*mp = opt;

		switch (mp->sub) {
		case MPTCP_SUB_JOIN:
			if (tcph->syn) return (tcph->ack ? MPTCP_JOIN_SYNACK : MPTCP_JOIN_SYN);
			else if (tcph->ack) return MPTCP_JOIN_ACK;
		case MPTCP_SUB_CAPABLE:
			if (tcph->syn) return (tcph->ack ? MPTCP_CAP_SYNACK : MPTCP_CAP_SYN);
			else if (tcph->ack) return MPTCP_CAP_ACK;
		case MPTCP_SUB_DSS:
			struct mp_dss *mpdss = (struct mp_dss*)*mp;
			if (mpdss->A) return (mpdss->F ? MPTCP_DATA_ACKFIN : MPTCP_DATA_ACK);
			else if (mpdss->F) return MPTCP_DATA_FIN;
		case MPTCP_SUB_FAIL:
			if (tcph->rst) return MPTCP_FAIL;
		}
	}
	*mp = NULL;
	return MPTCP_NOOPT;
}

static enum mptcp_pkt_type get_conntrack_index(const struct tcphdr *tcph)
{
	struct mptcp_option *mp;
	return _get_conntrack_index(tcph, &mp);
}

/* MPTCP state transition table */
static const u8 mptcp_conntracks[2][MPTCP_PKT_INDEX_MAX][MPTCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
/*
 *	sNO -> sSS	Initialize a new connection
 *	sSS -> sSS	Retransmitted SYN
 *	sS2 -> sS2	Late retransmitted SYN
 *	sSR -> sIG
 *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sFW -> sIG
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sSS	Reopened connection (RFC 1122).
 *	sCL -> sSS
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sIV, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *	sNO -> sIV	Too late and no reason to do anything
 *	sSS -> sIV	Client can't send SYN and then SYN/ACK
 *	sS2 -> sSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sSR -> sIG
 *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sFW -> sIG
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sIG
 *	sCL -> sIG
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sNO -> sIV	Too late and no reason to do anything...
 *	sSS -> sIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions, waiting for
 *			the last ACK.
 *			Migth be a retransmitted FIN as well...
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN. Remain in the same state.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *	sNO -> sES	Assumed.
 *	sSS -> sIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sS2 -> sIV
 *	sSR -> sES	Established state is reached.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected.
 *	sTW -> sTW	Retransmitted last ACK. Remain in the same state.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	},
	{
/* REPLY */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*syn*/	   { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sS2 },
/*
 *	sNO -> sIV	Never reached.
 *	sSS -> sS2	Simultaneous open
 *	sS2 -> sS2	Retransmitted simultaneous SYN
 *	sSR -> sIV	Invalid SYN packets sent by the server
 *	sES -> sIV
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sIV	Reopened connection, but server may not do it.
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*synack*/ { sIV, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *	sSS -> sSR	Standard open.
 *	sS2 -> sSR	Simultaneous open
 *	sSR -> sIG	Retransmitted SYN/ACK, ignore it.
 *	sES -> sIG	Late retransmitted SYN/ACK?
 *	sFW -> sIG	Might be SYN/ACK answering ignored SYN
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sIG
 *	sCL -> sIG
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sSS -> sIV	Server might not send FIN in this state.
 *	sS2 -> sIV
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions.
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*ack*/	   { sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG },
/*
 *	sSS -> sIG	Might be a half-open connection.
 *	sS2 -> sIG
 *	sSR -> sSR	Might answer late resent SYN.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected.
 *	sTW -> sTW	Retransmitted last ACK.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
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
	/* TODO: use get_next() */
	if ((mp = nf_mptcp_get_ptr(th))->sub == MPTCP_SUB_JOIN)
		return (struct mp_join*)((__u8*)mp-2);

	return NULL;
}


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



static bool mpcap_new(struct nf_conn *ct, struct tcphdr *th, 
		struct nf_conn_mptcp mpct)
{
	enum mptcp_conntrack new_state;
	u32 token;
	u64 key, isdn;
	struct nf_conn_mptcp *mpct;
	
	/* verify if there exists an mptcp tracker for this packet */
	key = __nf_mptcp_get_key((struct mp_capable*)mptr);
	nf_mptcp_key_sha1(key, &token, &isdn);
	mpct = nf_mptcp_hash_find(token);
	if (mpct) {
		/* this is not really a new mptcp connection, mptcp_packet will handle
		 * it */
		pr_debug("conntrack: unexpected mp_capable arrives for existing"
				" mptcp connection %p, ct=%p\n",mpct, ct);
		return false;
	}
	
	new_state = mptcp_conntracks[0][get_conntrack_index(th)][MPTCP_CONNTRACK_NONE];

	/* Invalid connection attempt */
	if (new_state >= MPTCP_CONNTRACK_MAX) {
		pr_debug("nf_ct_mptcp: invalid new connection attempt, deleting.\n");
		return false;
	}

	if (new_state == MPTCP_CONNTRACK_SYN_SENT) {
		/* client is trying to establish an MPTCP conn */
		pr_debug("conntrack: new mptcp connection, ct=%p\n", ct);
		mpct = kmalloc(sizeof(struct nf_conn_mptcp), GFP_KERNEL);
		mpct->key[0] = key;
		mpct->token[0] = token;
		nf_mptcp_hash_insert(mpct, token);
		/* Keep a ref to master mptcp connnection in every nf_conn */
		ct->mpmaster = mpct; /* FIXME */
	}


}

static bool mpjoin_new(struct nf_conn *ct, struct tcphdr *th)
{
	/* client is trying to establish a new subflow */
			/* TODO: add subflow to mptcp struct */
	struct mptcp_option *mptr;
	u32 token;
	u64 key, isdn;
	struct nf_conn_mptcp *mpct;
    
	if (!(mptr = nf_mptcp_get_ptr(th)))
		return false;

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
	}

}


/* Called at the end of the proto handling for new TCP packets (new connections) */
void nf_ct_mptcp_new_impl(struct nf_conn *ct, struct tcphdr *th)
{
	struct mptcp_option *mptr;
    
	if (!(mptr = nf_mptcp_get_ptr(th)))
		return; /* no mptcp option present */

	switch (_get_conntrack_index(th, &mptr)) {
	case MPTCP_JOIN_SYN:
		mpjoin_new(ct, th, mptr)
		break;
	case MPTCP_CAP_SYN:
		mpcap_new(ct, th, mptr);
		break;
	default:
		pr_debug("nf_ct_mptcp: unexpected mptcp option for connection or "
				"subflow establishment, mpct %p, option subkind %hhi", mpct, mptr->kind);
		return;
	}
}



void nf_ct_mptcp_packet_impl(const struct tcphdr *th, struct nf_conn *ct,
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

