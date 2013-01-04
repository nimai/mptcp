#if 0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#endif

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/net.h>

#include <linux/skbuff.h>
#include <crypto/sha.h>
#include <net/mptcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_log.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <linux/netfilter/nf_conntrack_mptcp.h>


#define NF_MPTCP_HASH_SIZE 256


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
	struct mp_per_dir *mp;

	read_lock(&htb_lock);
	list_for_each_entry(mp, &mptcp_conn_htb[hash], collide_tk) {
		if (token == mp->token) {
	        read_unlock(&htb_lock);
            return nf_ct_perdir_to_conntrack(mp);
        }
	}
	read_unlock(&htb_lock);
	return NULL;
}


void nf_mptcp_hash_insert(struct mp_per_dir *mp, 
							u32 token)
{
	u32 hash = nf_mptcp_hash_tk(token);

	write_lock_bh(&htb_lock);
	list_add(&mp->collide_tk, &mptcp_conn_htb[hash]);
	write_unlock_bh(&htb_lock);
}


void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn)
{
	/* remove from the token hashtable */
	write_lock_bh(&htb_lock);
	list_del(&mpconn->d[IP_CT_DIR_ORIGINAL].collide_tk);
	list_del(&mpconn->d[IP_CT_DIR_REPLY].collide_tk);
	write_unlock_bh(&htb_lock);
}

void nf_mptcp_hash_free(struct list_head *bucket)
{
	struct mp_per_dir *mp, *tmp;
	struct nf_conn_mptcp *mpct;
	list_for_each_entry_safe(mp, tmp, bucket, collide_tk) {
		mpct = nf_ct_perdir_to_conntrack(mp);
		list_del(&mp->collide_tk);
		list_del(&mpct->d[!&mp->dir].collide_tk);
		kfree(mpct);
	}
}
/* End of hashtable implem */



/* Search for the JOIN subkind in a MPTCP segment 
 * Return a pointer to the JOIN subtype in the skb
 * or NULL if it can't be found 
 * */
struct mp_join *nf_mptcp_find_join(const struct tcphdr *th)
{
    struct mptcp_option *opt = 
		(struct mptcp_option*)(th + 1); /* skip the common tcp header */
	/* iterates over the mptcp options */
	while ((opt = nf_mptcp_next_mpopt(th, (u8*)opt)))
		if (opt->sub == MPTCP_SUB_JOIN)
			return (struct mp_join*)opt;

	return NULL;
}


/* Get the token from a mp_join structure from a SYN packet */
__u32 __nf_mptcp_get_token(struct mp_join *mpj)
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

static void sha_init(__u32 *buf)
{
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;
	buf[4] = 0xc3d2e1f0;
}
 */

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

/* Return the hmac computed over keys and nonces.
 * This is a copy of mptcp_hmac_sha1() from net/mptcp/mptcp_ctrl.c as the
 * netfilter mptcp support does not depend on CONFIG_MPTCP */
void nf_mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
		       u32 *hash_out)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;

	memset(workspace, 0, sizeof(workspace));

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], rand_1, 4);
	memcpy(&input[68], rand_2, 4);
	input[72] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[73], 0, 53);

	/* Padding: Length of the message = 512 + 64 bits */
	input[126] = 0x02;
	input[127] = 0x40;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);
}


/* STATES from the FSM */
/* Define states' names */ 
static const char *const mptcp_conntrack_names[] = {
	"M_NONE",
	"M_SYN_SENT",
	"M_SYN_SENT2",
	"M_SYN_RECV",
	"M_ESTABLISHED",
	"M_NO_SUBFLOW",
	"M_FINWAIT",
	"M_TIMEWAIT",
	"M_CLOSEWAIT",
	"M_LASTACK",
	"M_CLOSED"
};

#define sMNO MPTCP_CONNTRACK_NONE
#define sMSS MPTCP_CONNTRACK_SYN_SENT
#define sMS2 MPTCP_CONNTRACK_SYN_SENT2
#define	sMSR MPTCP_CONNTRACK_SYN_RECV
#define sMES MPTCP_CONNTRACK_ESTABLISHED
#define sMNS MPTCP_CONNTRACK_NO_SUBFLOW
#define sMFW MPTCP_CONNTRACK_FINWAIT
#define sMTW MPTCP_CONNTRACK_TIMEWAIT
#define sMCW MPTCP_CONNTRACK_CLOSEWAIT
#define sMLA MPTCP_CONNTRACK_LASTACK
#define sMCL MPTCP_CONNTRACK_CLOSED
#define sMIV MPTCP_CONNTRACK_MAX
#define sMIG MPTCP_CONNTRACK_IGNORE
#define sMFB MPTCP_CONNTRACK_FALLBACK

/* Possible packet types related to MPTCP connection */
enum mptcp_pkt_type {
	MPTCP_CAP_SYN,
	MPTCP_CAP_SYNACK,
	MPTCP_CAP_ACK,
	MPTCP_JOIN_SYN,
	MPTCP_JOIN_SYNACK,
	MPTCP_JOIN_ACK,
	MPTCP_SUBFLOW_ACK,
	MPTCP_SUBFLOW_FIN,
	MPTCP_SUBFLOW_RST,
	MPTCP_DATA_FIN,
	MPTCP_DATA_ACK,
	MPTCP_FAIL,
	MPTCP_FASTCLOSE,
	MPTCP_NOOPT,
	MPTCP_PKT_INDEX_MAX,
};
	

/* There are only 3 states of MPTCP's conntrack that can elicit a timeout:
 * MPTCP_CONNTRACK_NO_SUBFLOW and MPTCP_CONNTRACK_CLOSED,
 * MPTCP_CONNTRACK_TIMEWAIT.
 * In all the other cases, there is at least one single-path TCP conntrack that will expires 
 *	and bring back the MPTCP's state to MPTCP_CONNTRACK_NO_SUBFLOW */
#define SECS * HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS
unsigned int mptcp_timeouts[MPTCP_CONNTRACK_MAX] __read_mostly = {
	[MPTCP_CONNTRACK_NO_SUBFLOW]	= 10 MINS,
	[MPTCP_CONNTRACK_TIMEWAIT]		= 2 MINS,
	[MPTCP_CONNTRACK_CLOSED]			= 10 SECS,
};


/* Return the index of the packet-type corresponding to the packet seen
 * This refers to a value from enum mptcp_pkt_type 
 * Set a pointer mp to the considered option start address 
 *
 * FIXME this assumes that there is only one indexable by packet, is this a
 * problm ?*/
static enum mptcp_pkt_type _get_conntrack_index(const struct tcphdr *tcph, 
		struct mptcp_option **mp)
{
	struct mptcp_option *opt = (struct mptcp_option*)(tcph + 1); /* skip the common tcp header */
	struct mp_dss *mpdss;

#if 0
	if (tcph->fin) {
		/* in a TCP FIN segment, no other MPTCP option than DSS should be
		 * present */
		*mp = nf_mptcp_first_mpopt(tcph);
		if (tcph->ack) return MPTCP_SUBFLOW_FINACK;
		return MPTCP_SUBFLOW_FIN;
	} else if (tcph->rst) {
		/* idem */
		*mp = nf_mptcp_first_mpopt(tcph);
		return MPTCP_SUBFLOW_RST;
	}
#endif
		
	/* iterates over the mptcp options until one matching packet-type is found */
	while ((opt = nf_mptcp_next_mpopt(tcph, (u8*)opt))) {
		*mp = opt;

		switch ((*mp)->sub) {
		case MPTCP_SUB_JOIN:
			if (tcph->syn) return (tcph->ack ? MPTCP_JOIN_SYNACK : MPTCP_JOIN_SYN);
			else if (tcph->ack) return MPTCP_JOIN_ACK;
		case MPTCP_SUB_CAPABLE:
			if (tcph->syn) return (tcph->ack ? MPTCP_CAP_SYNACK : MPTCP_CAP_SYN);
			else if (tcph->ack) return MPTCP_CAP_ACK;
		case MPTCP_SUB_FAIL:
			return MPTCP_FAIL;
		case MPTCP_SUB_FCLOSE:
			return MPTCP_FASTCLOSE;
		case MPTCP_SUB_DSS:
			mpdss = (struct mp_dss*)*mp;
			if (mpdss->F) return MPTCP_DATA_FIN;
			else if (mpdss->A) return MPTCP_DATA_ACK;
		default:
			break;
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
/*					sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpcap syn*/	   { sMSS, sMSS, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMSS, sMSS, sMS2 },
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
 *	sMTW -> sMSS	Reopened connection (RFC 1122).
 *	sMCL -> sMSS
 */
/*				 sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpcap synack*/{ sMIV, sMIV, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMIG, sMIG, sMSR },
/*
 *	sMNO -> sMIV	Too late and no reason to do anything
 *	sMSS -> sMIV	Client can't send SYN and then SYN/ACK
 *	sMS2 -> sMSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sMSR -> sMIG
 *	sMES -> sMIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sMFW -> sMIG
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG
 *	sMCL -> sMIG
 */
/*	    	     sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpcap ack*/ { sMIV, sMIV, sMES, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV },
/*
 *	sMNO -> sMIV	Too late and no reason to do anything
 *	sMSS -> sMIV	Client can't send SYN and then SYN/ACK
 *	sMS2 -> sMSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sMSR -> sMIG
 *	sMES -> sMIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sMFW -> sMIG
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG
 *	sMCL -> sMIG
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*datafin*/    { sMIV, sMIV, sMFW, sMFW, sMIG, sMLA, sMLA, sMLA, sMTW, sMCL, sMIV },
/*
 *	sMNO -> sMIV	Too late and no reason to do anything...
 *	sMSS -> sMIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sMS2 -> sMIV
 *	sMSR -> sMFW	Close started.
 *	sMES -> sMFW
 *	sMNS -> sMIG	
 *	sMFW -> sMLA	FIN seen in both directions, waiting for
 *			the last ACK.
 *			Migth be a retransmitted FIN as well...
 *	sMCW -> sMLA
 *	sMLA -> sMLA	Retransmitted FIN. Remain in the same state.
 *	sMTW -> sMTW
 *	sMCL -> sMCL
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*dataack*/	   { sMES, sMIV, sMES, sMES, sMIG, sMCW, sMCW, sMTW, sMTW, sMCL, sMIV },
/*
 *	sMNO -> sMES	Assumed.
 *	sMSS -> sMIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sMS2 -> sMIV
 *	sMSR -> sMES	Established state is reached.
 *	sMES -> sMES	:-)
 *	sMFW -> sMCW	Normal close request answered by ACK.
 *	sMCW -> sMCW
 *	sMLA -> sMTW	Last ACK detected.
 *	sMTW -> sMTW	Retransmitted last ACK. Remain in the same state.
 *	sMCL -> sMCL
 */
/*
 *  */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*fclose*/    { sMIV, sMCL, sMCL, sMCL, sMIV, sMCL, sMCL, sMCL, sMCL, sMCL, sMCL },
/*no_opt*/   { sMFB, sMFB, sMFB, sMES, sMIG, sMFW, sMCW, sMLA, sMTW, sMCL, sMFB }
	},
	{
/* REPLY */
/*				sMNO, sMSS, sMSR, sMES, sMNF, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpcapsyn*/	{ sMIV, sMS2, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMS2 },
/*
 *	sMNO -> sMIV	Never reached.
 *	sMSS -> sMS2	Simultaneous open
 *	sMS2 -> sMS2	Retransmitted simultaneous SYN
 *	sMSR -> sMIV	Invalid SYN packets sent by the server
 *	sMES -> sMIV
 *	sMFW -> sMIV
 *	sMCW -> sMIV
 *	sMLA -> sMIV
 *	sMTW -> sMIV	Reopened connection, but server may not do it.
 *	sMCL -> sMIV
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpcapsynack*/ { sMIV, sMSR, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMIG, sMIG, sMSR },
/*
 *	sMSS -> sMSR	Standard open.
 *	sMS2 -> sMSR	Simultaneous open
 *	sMSR -> sMIG	Retransmitted SYN/ACK, ignore it.
 *	sMES -> sMIG	Late retransmitted SYN/ACK?
 *	sMFW -> sMIG	Might be SYN/ACK answering ignored SYN
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG
 *	sMCL -> sMIG
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*datafin*/    { sMIV, sMIV, sMFW, sMFW, sMIV, sMLA, sMLA, sMLA, sMTW, sMCL, sMIV },
/*
 *	sMSS -> sMIV	Server might not send FIN in this state.
 *	sMS2 -> sMIV
 *	sMSR -> sMFW	Close started.
 *	sMES -> sMFW
 *	sMFW -> sMLA	FIN seen in both directions.
 *	sMCW -> sMLA
 *	sMLA -> sMLA	Retransmitted FIN.
 *	sMTW -> sMTW
 *	sMCL -> sMCL
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*dataack*/	   { sMIV, sMIG, sMSR, sMES, sMIV, sMCW, sMCW, sMTW, sMTW, sMCL, sMIG },
/*
 *	sMSS -> sMIG	Might be a half-open connection.
 *	sMS2 -> sMIG
 *	sMSR -> sMSR	Might answer late resent SYN.
 *	sMES -> sMES	:-)
 *	sMFW -> sMCW	Normal close request answered by ACK.
 *	sMCW -> sMCW
 *	sMLA -> sMTW	Last ACK detected.
 *	sMTW -> sMTW	Retransmitted last ACK.
 *	sMCL -> sMCL
 */
/*				 sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMCL, sMS2	*/
/*mpfastclose*/  { sMIV, sMCL, sMCL, sMCL, sMIV, sMCL, sMCL, sMCL, sMCL, sMCL, sMCL },
/*mpnoopt*/		{ sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV }
	}
};

/* Timer */
static void nf_mptcp_death_by_timeout(unsigned long ul_mpct) {
	struct nf_conn_mptcp *mpct = (struct nf_conn_mptcp*)ul_mpct;
	/* delete references from hashtable: there are 2, one for each token */
	spin_lock_bh(&mpct->lock);
	nf_mptcp_hash_remove(mpct);
	spin_unlock_bh(&mpct->lock);
	kfree(mpct);
}

void nf_mptcp_update_timers(struct nf_conn_mptcp *mpct) {
	BUG_ON(mpct->state != MPTCP_CONNTRACK_NO_SUBFLOW &&
			mpct->state != MPTCP_CONNTRACK_CLOSED &&
			mpct->state != MPTCP_CONNTRACK_TIMEWAIT);
	if (!mpct->timeout.function)
		setup_timer(&mpct->timeout, nf_mptcp_death_by_timeout, (unsigned long)mpct);
	/* adjust the timer or reactivate it: mptcp conntrack will die whenever the 
	 * timeout associated to the current state expires*/
	mod_timer(&mpct->timeout, mptcp_timeouts[mpct->state]);
}

static void nf_mptcp_delete_timer(struct nf_conn_mptcp *mpct) {
	del_timer(&mpct->timeout);
}

static bool mpcap_new(struct nf_conn *ct, const struct tcphdr *th, 
		struct mptcp_option* mptr)
{
	enum mptcp_ct_state new_state;
	u32 token;
	u64 key, idsn;
	struct nf_conn_mptcp *mpct;
	struct mp_per_dir *d;
	struct mptcp_subflow_info *mpsub;
	
	/* verify if there exists an mptcp tracker for this packet */
	key = __nf_mptcp_get_key((struct mp_capable*)mptr);
	nf_mptcp_key_sha1(key, &token, &idsn);
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
		pr_debug("conntrack: new mptcp connection mptcp=%p, created from "
				"subflow ct=%p\n", mpct, ct);
		/* allocate and fill the mptcp connection struct */
		mpct = kmalloc(sizeof(struct nf_conn_mptcp), GFP_KERNEL);
		d = &mpct->d[IP_CT_DIR_ORIGINAL];
		d->dir = IP_CT_DIR_ORIGINAL;
		d->key = key;
		d->token = token;
		d->last_dseq = idsn;
		mpct->counter_sub = 1;
		nf_mptcp_hash_insert(d, token);

		/* Fill subflow-related info as well */
		mpsub->addr_id = 0; /* first subflow is always 0 */
		/* relative direction is always ORIGINAL for original subflow by definition */
		mpsub->rel_dir = IP_CT_DIR_ORIGINAL; 
		/* Keep a ref to master mptcp connnection in every subflow conntrack */
		ct->proto.tcp.mpmaster = mpct;
	}
	
	mpct->state = new_state;
	return true;

}


static int mptcp_packet(struct nf_conn *ct, const struct tcphdr *th,
		enum ip_conntrack_info ctinfo,
		u_int8_t pf,
		const struct sk_buff *skb,
		struct mptcp_option *mptr)
{
	enum mptcp_ct_state old_state, new_state;
	struct nf_conntrack_tuple *tuple;
	enum ip_conntrack_dir dir;
	struct nf_conn_mptcp *mpct;
	struct mp_per_dir *mp;
	unsigned int index;
	struct net *net = nf_ct_net(ct);
	
	mpct = ct->proto.tcp.mpmaster;
	old_state = mpct->state;
	dir = CTINFO2DIR(ctinfo);
	index = get_conntrack_index(th);
	new_state = mptcp_conntracks[dir][index][old_state];
	tuple = &ct->tuplehash[dir].tuple;
	mp = &mpct->d[dir];
		
	pr_debug("nf_ct_mptcp_packet: received segmenttype %i, oldstate %s -> newstate %s\n",
			index, mptcp_conntrack_names[old_state], mptcp_conntrack_names[new_state]);

	switch (new_state) {
	case MPTCP_CONNTRACK_SYN_RECV:
		/* Possible cases:
		 *	- regular SYNACK answer: extract info from it (key, ..)
		 *	- simultaneous open: OK
		 *	- ack answering late resent SYN - simultaneous open
		 */
		if (index == MPTCP_CAP_SYNACK) {
			/*&& dir == IP_CT_DIR_REPLY) {* -- not needed because simultaneous
			 * open possible */
			/* extract key for server */
			pr_debug("nf_ct_mptcp_pkt: received synack, ct=%p, mpct=%p\n", ct, mpct);
			mp->key = ((struct mp_capable*)mptr)->sender_key;
			nf_mptcp_key_sha1(((struct mp_capable*)mptr)->sender_key, 
					&mp->token, &mp->last_dseq);
			nf_mptcp_hash_insert(mp, mp->token);
		}

		else if (index == MPTCP_CAP_ACK && dir == IP_CT_DIR_REPLY) {
			/* 
			 * SYN -> 
			 * <- SYNACK
			 * SYN ->
			 * <- ACK  [Answer to late resent SYN]
			 * ACK -> 
			 * Does not carry any information */ 
			pr_debug("nf_ct_mptcp_pkt: received ack, reply to late SYN, "
					"ct=%p, mpct=%p\n", ct, mpct);
		}
		break;
	case MPTCP_CONNTRACK_ESTABLISHED:
		/* Possible cases:
		 *	- data being transfered
		 *	- just-negociated connection
		 */
		ct->proto.tcp.mpflow.established = true;
		if (index == MPTCP_CAP_ACK) { 
			/* can be for both directions in case of simultaneous open */
			/* check if keys match local data */
			if (!(((struct mp_capable*)mptr)->sender_key == mp->key && 
						((struct mp_capable*)mptr)->receiver_key == mpct->d[!dir].key)) {
				pr_debug("nf_ct_mptcp: keys from final MP_CAPABLE ACK don't match:"
						"local1=%llx, local2=%llx, remote1=%llx, remote2=%llx",
						mp->key, 
						((struct mp_capable*)mptr)->sender_key,
						mpct->d[!dir].key,
						((struct mp_capable*)mptr)->receiver_key);
				if (LOG_INVALID(net, IPPROTO_TCP))
					nf_log_packet(pf, 0, skb, NULL, NULL, NULL,
							"nf_ct_mptcp: keys from final MP_CAPABLE ACK don't match");
				return -NF_ACCEPT;
			}
		}
		break;
	default:
		break;
	}
	
	if (new_state == MPTCP_CONNTRACK_CLOSED || new_state == MPTCP_CONNTRACK_TIMEWAIT)
		nf_mptcp_update_timers(mpct);
	
	return NF_ACCEPT;
}
int nf_ct_mptcp_error(struct net *net, struct nf_conn *tmpl,
		     struct sk_buff *skb,
		     unsigned int dataoff,
		     enum ip_conntrack_info *ctinfo,
		     u_int8_t pf,
		     unsigned int hooknum)
{
	return tcp_error(net, tmpl, skb, dataoff, ctinfo, pf, hooknum);
}

/* TCP packet without connection tracker (new connections) */
bool nf_ct_mptcp_new(struct nf_conn *ct, const struct sk_buff *skb,
		    unsigned int dataoff)
{
	struct mptcp_option *mptr;
	int ret, ret_mp = 1;
	const struct tcphdr *th;
	struct tcphdr _tcph;

	/* initiate subflow's conntrack as usual */
	ret = tcp_new(ct, skb, dataoff);
	
	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);
    
	if (!(mptr = nf_mptcp_get_ptr(th)))
		return ret; /* no mptcp option present */

	/* Get mptcp packet type and return a pointer mptr to the right option in
	 * skb */
	switch (_get_conntrack_index(th, &mptr)) {
	case MPTCP_CAP_SYN:
		ret_mp = mpcap_new(ct, th, mptr);
		break;
	default:
		/* FIXME */
		break;
	}
	return ret && ret_mp;
}

int nf_ct_mptcp_packet(struct nf_conn *ct,
		      const struct sk_buff *skb,
		      unsigned int dataoff,
		      enum ip_conntrack_info ctinfo,
		      u_int8_t pf,
		      unsigned int hooknum)
{
	struct mptcp_option *mptr;
	struct nf_conn_mptcp *mpct;
	int ret, ret_mp = 1;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	enum mptcp_pkt_type index;

	mpct = ct->proto.tcp.mpmaster;
	/* mpct cannot be modified by several subflows at the same time */
	spin_lock_bh(&mpct->lock);

	/* first handle as single path packet */
	ret = tcp_packet(ct, skb, dataoff, ctinfo, pf, hooknum);

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);
	/* Do not handle TCP packet with MPTCP FSM if:
	 * no mpmaster for the connection:
	 * - MPCAP: associated to mpct in new()
	 * - Subflow: associated in new()
	 *	no mpmaster <=> not part of mptcp conn 
	 * OR if tcp_packet is not accepted anyway */
	if (!mpct || ret <= 0)
		return ret; 

	/* a packet part of the mptcp connection has been received, a subflow
	 * is alive, we are sure that the data connection must not die before
	 * all are destroyed or the data connection is in CLOSED state */
	nf_mptcp_delete_timer(mpct);
    
	/* dispatching */
	/* Get mptcp packet type and return a pointer mptr to the right option in
	 * skb */
	index = _get_conntrack_index(th, &mptr);
	switch (index) {
	/* mptcp packet: only transitions from MPTCP's FSM */
	case MPTCP_CAP_SYN:
	case MPTCP_CAP_SYNACK:
	case MPTCP_CAP_ACK:
	case MPTCP_DATA_ACK:
	case MPTCP_DATA_FIN:
	case MPTCP_FASTCLOSE:
		/* actual MPTCP-level connection tracking */
		ret_mp = mptcp_packet(ct, th, ctinfo, pf, skb, mptr);
	default:
		break;
	}
	spin_unlock_bh(&mpct->lock);
	
	/* Take MPTCP decision into account only if negative */
	if (ret_mp > 0)
		return ret;
	return ret_mp;

}

/* MPTCP subflow tracking -related */
/* update the subflow counter and MPTCP FSM when a subflow is added
 * Take care of the timer
 * Return true if the FSM state has been effectively changed */
bool nf_mptcp_add_subflow(struct nf_conn_mptcp *mpct) {
	mpct->counter_sub += 1;
	BUG_ON(mpct->counter_sub <= 0);
	if (mpct->state == MPTCP_CONNTRACK_NO_SUBFLOW) {
		mpct->state = MPTCP_CONNTRACK_ESTABLISHED;
		nf_mptcp_update_timers(mpct);
		return true;
	}
	return false;
}
/* update the subflow counter and MPTCP FSM when a subflow is removed
 * Take care of the timer
 * Return true if the FSM state has been effectively changed */
bool nf_mptcp_remove_subflow(struct nf_conn_mptcp *mpct) {
	mpct->counter_sub -= 1;
	BUG_ON(mpct->counter_sub < 0);
	if (mpct->state == MPTCP_CONNTRACK_ESTABLISHED && mpct->counter_sub == 0) {
		mpct->state = MPTCP_CONNTRACK_NO_SUBFLOW;
		nf_mptcp_update_timers(mpct);
		return true;
	}
	return false;
}

/* Called whenever a TCP conntrack is going to be destroyed */
void nf_ct_mptcp_destroy(struct nf_conn *ct) {
	struct nf_conn_mptcp *mpct;

	mpct = ct->proto.tcp.mpmaster;
	
	/* the mptcp conntrack does not need to die, it's only one subflow less,
	 * however, if it was the last subflow, trigger death after timeout */
	spin_lock_bh(&mpct->lock);
	nf_mptcp_remove_subflow(mpct);
	spin_unlock_bh(&mpct->lock);
}

#if 0
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
	nf_ct_mptcp_packet_implptr = &nf_ct_mptcp_packet_impl;
	
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
	nf_ct_mptcp_packet_implptr = NULL;
}

module_init(nf_conntrack_mptcp_init);
module_exit(nf_conntrack_mptcp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Maître <nimai@skynet.be>");
MODULE_DESCRIPTION("MPTCP connection tracker");
#endif

