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

/* Return the hash of a token
 * The mod operator is used as hashing function */
static inline u32 nf_mptcp_hash_tk(u32 token)
{
	return token % NF_MPTCP_HASH_SIZE;
}

/* Return the MPTCP conntrack from a token.
 * This does so by looking up the hashtable
 *
 *FIXME Also depends on the direction: it avoids some easy token collisions.
 * /!\ here, dir defines the host, not the dir of the packet.
 * That is, IP_CT_DIR_ORIGINAL designate the connection's initiator, not the
 * fact that the packet handled is transiting in the original dir.
 */
struct nf_conn_mptcp *nf_mptcp_hash_find(u32 token) 
{
	u32 hash = nf_mptcp_hash_tk(token);
	struct mp_per_dir *mp;
	struct nf_conn_mptcp *mpct;

	read_lock(&htb_lock);
	list_for_each_entry(mp, &mptcp_conn_htb[hash], collide_tk) {
        mpct = nf_ct_perdir_to_conntrack(mp);
		pr_debug("mpct=%p: state=%i, token0=%x (key0=%llx), "
				"token1=%x (key1=%llx)\n", mpct,
				mpct->state, mpct->d[0].token, 
				mpct->d[0].key, mpct->d[1].token, mpct->d[1].key);
		if (token == mp->token) {
	        read_unlock(&htb_lock);
            return nf_ct_perdir_to_conntrack(mp);
        }
	}
	read_unlock(&htb_lock);
	return NULL;
}


/* Insert in the hashtable the per-direction part of the MPTCP conntrack, 
 * keyed by the corresponding token */
void __nf_mptcp_hash_insert(struct mp_per_dir *mp, 
							u32 token)
{
	u32 hash = nf_mptcp_hash_tk(token);

	write_lock_bh(&htb_lock);
	list_add(&mp->collide_tk, &mptcp_conn_htb[hash]);
	write_unlock_bh(&htb_lock);
}
/* Idem but check that the entry is not already there. Return true iff the
 * entry has been indeed inserted */
bool nf_mptcp_hash_insert(struct mp_per_dir *mp, 
							u32 token)
{
	if (nf_mptcp_hash_find(token)) {
		/* already inserted, stop here */
		return false;
	}
	__nf_mptcp_hash_insert(mp, token);
	return true;
}


/* Remove both per-dir parts of the conntrack mpconn from the hashtable */
void nf_mptcp_hash_remove(struct nf_conn_mptcp *mpconn)
{
	write_lock_bh(&htb_lock);
	list_del(&mpconn->d[IP_CT_DIR_ORIGINAL].collide_tk);
	list_del(&mpconn->d[IP_CT_DIR_REPLY].collide_tk);
	write_unlock_bh(&htb_lock);
}

/* Remove all the MPTCP conntracks from the hashtable */
void nf_mptcp_hash_free(struct list_head *bucket)
{
	struct mp_per_dir *mp, *tmp;
	struct nf_conn_mptcp *mpct;
	list_for_each_entry_safe(mp, tmp, bucket, collide_tk) {
		mpct = nf_ct_perdir_to_conntrack(mp);
		/* the 2 parts of the conntracks must be removed from the hashtable
		 * before the freeing, else, we wouldn't have any reference left to
		 * remove it later */
		list_del(&mp->collide_tk);
		list_del(&mpct->d[!mp->dir].collide_tk);
		kfree(mpct);
	}
}
/* End of hashtable implem */



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

    mpj = (struct mp_join*)nf_mptcp_find_subtype(th, MPTCP_SUB_JOIN);
	return __nf_mptcp_get_token(mpj);
}


u64 __nf_mptcp_get_key(struct mp_capable * mpc)
{
	if (mpc && mpc->sender_key)
		return mpc->sender_key;
	return 0;
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

/* -- end of utility functions */
static unsigned int nf_ct_mptcp_timeout_no_subflow  __read_mostly = 10 * 60 * HZ;

/* STATES from the FSM */
/* Define states' names */ 
static const char *const mptcp_conntrack_names[] = {
	"M_NONE",
	"M_SYN_SENT",
	"M_SYN_RECV",
	"M_ESTABLISHED",
	"M_NO_SUBFLOW",
	"M_FINWAIT",
	"M_CLOSEWAIT",
	"M_LASTACK",
	"M_TIMEWAIT",
	"M_SYN_SENT2",
};
static const char *const mptcp_index_names[] = {
	"MPTCP_CAP_SYN",
	"MPTCP_CAP_SYNACK",
	"MPTCP_CAP_ACK",
	"MPTCP_DATA_FIN",
	"MPTCP_DATA_ACK",
	"MPTCP_FASTCLOSE",
	"MPTCP_INFINITE_MAPPING",
	"MPTCP_NOOPT",
};

#define sMNO MPTCP_CONNTRACK_NONE
#define sMSS MPTCP_CONNTRACK_SYN_SENT
#define sMS2 MPTCP_CONNTRACK_SYN_SENT2
#define	sMSR MPTCP_CONNTRACK_SYN_RECV
#define sMES MPTCP_CONNTRACK_ESTABLISHED
#define sMNS MPTCP_CONNTRACK_NO_SUBFLOW
#define sMFW MPTCP_CONNTRACK_FINWAIT
#define sMCW MPTCP_CONNTRACK_CLOSEWAIT
#define sMLA MPTCP_CONNTRACK_LASTACK
#define sMTW MPTCP_CONNTRACK_TIMEWAIT
#define sMIV MPTCP_CONNTRACK_MAX
#define sMIG MPTCP_CONNTRACK_IGNORE
#define sMFB MPTCP_CONNTRACK_FALLBACK

/* Possible packet types related to MPTCP connection */
enum mptcp_pkt_type {
	MPTCP_CAP_SYN,
	MPTCP_CAP_SYNACK,
	MPTCP_CAP_ACK,
	MPTCP_DATA_FIN,
	MPTCP_DATA_ACK,
	MPTCP_FASTCLOSE,
	MPTCP_INFINITE_MAP,
	MPTCP_NOOPT,
	MPTCP_PKT_INDEX_MAX,
	MPTCP_DATA_MAP, /* not part of the FSM */
	MPTCP_JOIN_SYN,
	MPTCP_JOIN_SYNACK,
	MPTCP_JOIN_ACK,
	MPTCP_FAIL,
	MPTCP_INVALID
};
	

/* Return the index of the packet-type corresponding to the packet seen
 * This refers to a value from enum mptcp_pkt_type 
 * Set a pointer mp to the considered option start address 
 *
 * This assumes that there is only one "indexable" mpoption by packet */
static enum mptcp_pkt_type __get_conntrack_index(const struct tcphdr *tcph, 
		struct mptcp_option **mp)
{
	u8 *opt; /*(struct mptcp_option*)(tcph + 1); skip the common tcp header */
	struct mp_dss *mpdss;
	unsigned int len;
	short subtype;
	
	/* iterates over the mptcp options until one matching packet-type is found */
	for_each_mpopt(opt, subtype, len, tcph) {
		pr_debug("nf_mptcp: get_index: opt=%p, subtype=%i, len=%u\n",opt,subtype,len);
		*mp = (struct mptcp_option*)opt;
		switch (subtype) {
		case MPTCP_SUB_JOIN:
			pr_debug("nf_mptcp JOIN: SYN=%u, ACK=%u\n",tcph->syn, tcph->ack); 
			if (tcph->syn) return (tcph->ack ? MPTCP_JOIN_SYNACK : MPTCP_JOIN_SYN);
			else if (tcph->ack) return MPTCP_JOIN_ACK;
			return MPTCP_INVALID;
		case MPTCP_SUB_CAPABLE:
			pr_debug("nf_mptcp CAP: SYN=%u, ACK=%u, senderkey=%llx, otherkey=%llx\n",tcph->syn, tcph->ack, 
					((struct mp_capable*)*mp)->sender_key, (~tcph->syn & tcph->ack)?((struct mp_capable*)*mp)->receiver_key:0);
			if (tcph->syn) return (tcph->ack ? MPTCP_CAP_SYNACK : MPTCP_CAP_SYN);
			else if (tcph->ack) return MPTCP_CAP_ACK;
			return MPTCP_INVALID;
		case MPTCP_SUB_FAIL:
			if (tcph->rst || tcph->ack) return MPTCP_FAIL;
			return MPTCP_INVALID;
		case MPTCP_SUB_FCLOSE:
			if (tcph->rst) return MPTCP_FASTCLOSE;
			return MPTCP_INVALID;
		case MPTCP_SUB_DSS:
			mpdss = (struct mp_dss*)*mp;
			pr_debug("nf_mptcp DSS: FIN=%u, ACK=%u (%ubits), MAP=%u (%ubits)\n",mpdss->F,
					mpdss->A, mpdss->a?64:32,
					mpdss->M, mpdss->m?64:32);
			if (mpdss->F) return MPTCP_DATA_FIN;
			else if (mpdss->A) return MPTCP_DATA_ACK;
			else if (mpdss->M) {
				if ( ntohs((u16)(*((u8*)mpdss + mptcp_sub_len_dss(mpdss, 0)-2))) == 0)
					return MPTCP_INFINITE_MAP;
				else
					return MPTCP_DATA_MAP;
			}
			return MPTCP_INVALID;
		default:
			break;
		}
	}

	pr_debug("nf_ct_mptcp_get_index: no mptcp option detected.\n");
	*mp = NULL;
	return MPTCP_NOOPT;
}

/* Special get_conntrack_index for use with MPTCP's FSM */
static enum mptcp_pkt_type _get_conntrack_index(const struct tcphdr *tcph,
		struct mptcp_option **mp) 
{
	enum mptcp_pkt_type type;
	type = __get_conntrack_index(tcph, mp);
	/* in case of index not in FSM, DO NOT take into account the
	 * option */
	if (type >= MPTCP_PKT_INDEX_MAX) {
		return MPTCP_NOOPT;
	}
	return type;
}

/* same as _get_conntrack_index when second arg is not needed */
static enum mptcp_pkt_type get_conntrack_index(const struct tcphdr *tcph) 
{
	struct mptcp_option *mp;
	return _get_conntrack_index(tcph, &mp);
}

/* same as __get_conntrack_index when second arg is not needed */
static enum mptcp_pkt_type mptcp_check_combination(const struct tcphdr *tcph)
{
	struct mptcp_option *mp;
	pr_debug("Checking MPTCP packet flags combination\n");
	return __get_conntrack_index(tcph, &mp);
}

/* MPTCP state transition table */
static const u8 mptcp_conntracks[2][MPTCP_PKT_INDEX_MAX][MPTCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL */
/*					sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpcap syn*/	   { sMSS, sMSS, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMSS, sMS2},
/*
 *	sMNO -> sMSS	Initialize a new connection
 *	sMSS -> sMSS	Retransmitted SYN
 *	sMS2 -> sMS2	Late retransmitted SYN
 *	sMSR -> sMIG
 *	sMES -> sMIG	
 *	sMNS -> sMIV	A new subflow must be created with a JOIN+SYN, not mpcap
 *	sMFW -> sMIG
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMSS	Reopened connection (RFC 1122).
 */
/*				 sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpcap synack*/{ sMIV, sMIV, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMIG, sMSR},
/*
 *	sMNO -> sMIV	Too late and no reason to do anything
 *	sMSS -> sMIV	Client can't send SYN and then SYN/ACK
 *	sMS2 -> sMSR	SYN/ACK sent to SYN2 in simultaneous open
 *	sMSR -> sMIG
 *	sMES -> sMIG	
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active, 
 *					but has been accepted so we're out of sync
 *	sMFW -> sMIG
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG
 */
/*	    	     sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpcap ack*/ { sMIV, sMIV, sMES, sMIG, sMIG, sMIV, sMIV, sMIV, sMIV, sMIV},
/*
 *	sMNO -> sMIV	Too late and no reason to do anything
 *	sMSS -> sMIV	Client should have received mpcap synack first.
 *	sMS2 -> sMIV	idem
 *	sMSR -> sMES	thats its purpose :)
 *	sMES -> sMIG	possible retransmission
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMIV
 *	sMCW -> sMIV
 *	sMLA -> sMIV
 *	sMTW -> sMIV
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*datafin*/    { sMIV, sMIV, sMFW, sMFW, sMIG, sMLA, sMLA, sMLA, sMTW, sMIV},
/*
 *	sMNO -> sMIV	Too late and no reason to do anything...
 *	sMSS -> sMIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sMS2 -> sMIV
 *	sMSR -> sMFW	Close started.
 *	sMES -> sMFW
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMLA	FIN seen in both directions, waiting for
 *			the last ACK.
 *			Migth be a retransmitted FIN as well...
 *	sMCW -> sMLA
 *	sMLA -> sMLA	Retransmitted FIN. Remain in the same state.
 *	sMTW -> sMTW
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*dataack*/	   { sMES, sMIV, sMIV, sMES, sMIG, sMCW, sMCW, sMTW, sMTW, sMIV},
/*
 *	sMNO -> sMES	Assumed.
 *	sMSS -> sMIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sMS2 -> sMIV
 *	sMSR -> sMIV	MPCAP should have been received before any dataack	
 *	sMES -> sMES	
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMCW	Normal close request answered by ACK.
 *	sMCW -> sMCW
 *	sMLA -> sMTW	Last ACK detected.
 *	sMTW -> sMTW	Retransmitted last ACK. Remain in the same state.
 */
/*
 *  */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*fclose*/    { sMIV, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW},
/*
 * a valid fclose always leads to a TIMEWAIT state: the connection is kept
 * alive until there's no more open subflow.
 */
/*				  sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/* inf mapping */{ sMFB, sMIV, sMIV, sMFB, sMFB, sMFB, sMFB, sMFB, sMFB, sMIV},
/*
 *	sMNO -> sMFB	Assumed established but it falls back
 *	sMSS -> sMIV	Can't be any DSS while synchronizing
 *	sMSR -> sMIV
 *	sMS2 -> sMIV
 *	sMES -> sMFB	Common case of fallback with a single subflow
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMFB	Fallback possible until connection closed
 *	sMCW -> sMFB
 *	sMLA -> sMFB	
 *	sMTW -> sMTW
 */
/*				  sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpnoopt */	 { sMNO, sMFB, sMFB, sMES, sMIG, sMFW, sMCW, sMLA, sMTW, sMFB}
/* packet without MPTCP option cannot affect the MPTCP conntrack, except for
 * falling back:
 *  sMSS -> sMFB
 *  sMSR -> sMFB
 *  sMS2 -> sMFB
 */
	},
	{
/* REPLY */
/*				sMNO, sMSS, sMSR, sMES, sMNF, sMFW, sMCW, sMLA, sMTW, sMS2*/
/*mpcapsyn*/	{ sMIV, sMS2, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV, sMS2},
/*
 *	sMNO -> sMIV	Never reached.
 *	sMSS -> sMS2	Simultaneous open
 *	sMS2 -> sMS2	Retransmitted simultaneous SYN
 *	sMSR -> sMIV	Invalid SYN packets sent by the server
 *	sMES -> sMIV
 *	sMNS -> sMIV	A new subflow must be created with a JOIN+SYN, not mpcap
 *	sMFW -> sMIV
 *	sMCW -> sMIV
 *	sMLA -> sMIV
 *	sMTW -> sMIV	Reopened connection, but server may not do it.
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpcapsynack*/ { sMIV, sMSR, sMIG, sMIG, sMIV, sMIG, sMIG, sMIG, sMIG, sMSR},
/*
 *	sMSS -> sMSR	Standard open.
 *	sMS2 -> sMSR	Simultaneous open
 *	sMSR -> sMIG	Retransmitted SYN/ACK, ignore it.
 *	sMES -> sMIG	Late retransmitted SYN/ACK?
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMIG	Might be SYN/ACK answering ignored SYN
 *	sMCW -> sMIG
 *	sMLA -> sMIG
 *	sMTW -> sMIG
 */
/*	    	     sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpcap ack*/ { sMIV, sMIV, sMES, sMIG, sMIV, sMIV, sMIV, sMIV, sMIV, sMIV},
/*
 *	sMNO -> sMIV	
 *	sMSS -> sMIV	
 *	sMS2 -> sMIV	ack cannot come before synack
 *	sMSR -> sMES	Simultaneous open
 *	sMES -> sMIG	retransmitted ack after simultaneous open	
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMIV
 *	sMCW -> sMIV
 *	sMLA -> sMIV
 *	sMTW -> sMIV
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*datafin*/    { sMIV, sMIV, sMFW, sMFW, sMIV, sMLA, sMLA, sMLA, sMTW, sMIV},
/*
 *	sMSS -> sMIV	Server might not send FIN in this state.
 *	sMS2 -> sMIV
 *	sMSR -> sMFW	Close started.
 *	sMES -> sMFW
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMLA	FIN seen in both directions.
 *	sMCW -> sMLA
 *	sMLA -> sMLA	Retransmitted FIN.
 *	sMTW -> sMTW
 */
/*				sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*dataack*/	   { sMIV, sMIG, sMSR, sMES, sMIV, sMCW, sMCW, sMTW, sMTW, sMIG},
/*
 *	sMSS -> sMIG	Might be a half-open connection.
 *	sMS2 -> sMIG
 *	sMSR -> sMSR	Might answer late resent SYN.
 *	sMES -> sMES	
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMCW	Normal close request answered by ACK.
 *	sMCW -> sMCW
 *	sMLA -> sMTW	Last ACK detected.
 *	sMTW -> sMTW	Retransmitted last ACK.
 */
/*				 sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpfastclose*/  { sMIV, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW, sMTW},
/* inf mapping */{ sMFB, sMIV, sMIV, sMFB, sMFB, sMFB, sMFB, sMFB, sMFB, sMIV},
/*
 *	sMNO -> sMFB	Assumed established but it falls back
 *	sMSS -> sMIV	Can't be any DSS while synchronizing
 *	sMSR -> sMIV
 *	sMS2 -> sMIV
 *	sMES -> sMFB	Common case of fallback with a single subflow
 *	sMNS -> sMIG	Unexpected packet while no subflow should be active
 *	sMFW -> sMFB	Fallback possible until connection closed
 *	sMCW -> sMFB
 *	sMLA -> sMFB	
 *	sMTW -> sMTW
 */
/*				  sMNO, sMSS, sMSR, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMS2 */
/*mpnoopt */	 { sMNO, sMFB, sMFB, sMES, sMNS, sMFW, sMCW, sMLA, sMTW, sMFB}
/* idem than ORIGINAL dir */
	}
};


void nf_mptcp_put(struct nf_conn_mptcp* mpct) {
	/* delete references from hashtable: there are 2, one for each token */
	pr_debug("= nf_mptcp_put(%p) === MPTCP conntrack dead\n", mpct);
	spin_lock_bh(&mpct->lock);
	nf_mptcp_hash_remove(mpct);
	spin_unlock_bh(&mpct->lock);
	kfree(mpct);
}

/* Called by timer at its expiration */
static void nf_mptcp_death_by_timeout(unsigned long ul_mpct) {
	pr_debug("nf_mptcp_death_by_timeout: mpct=%p\n",(void*)ul_mpct);
	nf_mptcp_put((struct nf_conn_mptcp*)ul_mpct);
}

void nf_mptcp_update_timer(struct nf_conn_mptcp *mpct) {
	BUG_ON(mpct->state != MPTCP_CONNTRACK_NO_SUBFLOW);
	/* adjust the timer or (re)activate it: mptcp conntrack will die whenever the 
	 * timeout associated to the current state expires*/
	mod_timer(&mpct->timeout, nf_ct_mptcp_timeout_no_subflow);
}

static void nf_mptcp_delete_timer(struct nf_conn_mptcp *mpct) {
	del_timer(&mpct->timeout);
}

/* Make the conntrack fall back to single path TCP.
 * mpct access must be locked. */
void nf_mptcp_fallback(struct nf_conn *ct, struct nf_conn_mptcp *mpct) {
	/* In case of MPTCP fallback, the MPTCP state can be deleted, that is,
	 * disassociate the subflow and destroy the MPTCP conntrack.
	 * 1) one MPCAP is invalid/absent
	 * 2) an infinite mapping is present in both directions 
	 *
	 */
	pr_debug("=======================================================\n");
	pr_debug("nf_ct_mptcp: falling back to single-path TCP tracking.\n");
	pr_debug("=======================================================\n");
	/* The subflow may outlive the data connection, ref to connection 
	 * must be deleted. */
	spin_lock_bh(&ct->lock);
	ct->proto.tcp.mpmaster = NULL;
	spin_unlock_bh(&ct->lock);
	nf_mptcp_put(mpct);
}

/* compute the token and idsn from key and fill the mp struct with them if
 * they don't differ from an eventual previous insertion. 
 * If the key is not different from a previous key, return true */
static bool nf_mptcp_init_key(u64 key, struct mp_per_dir *mp)
{
	u32 token;
	u64 idsn;
	if (mp->key) {
		if (key != mp->key)
			return false;
		else
			return true;
	}

	nf_mptcp_key_sha1(key, &token, &idsn);
	__nf_mptcp_hash_insert(mp, token);
	mp->key = key;
	mp->token = token;
	mp->last_dseq = idsn;
	return true;
}


/* called at the reception of a packet from a subflow unseen before*/
static bool mpcap_new(struct nf_conn *ct, const struct tcphdr *th, 
		struct mptcp_option* mptr)
{
	enum mptcp_ct_state new_state;
	struct nf_conn_mptcp *mpct = NULL;
	struct mp_per_dir *d, *d2;
	struct mptcp_subflow_info *mpsub;
	enum mptcp_pkt_type index;
	
	index = get_conntrack_index(th);
	/* look at the eventual transition that the packet would fire */
	new_state = mptcp_conntracks[0][index][MPTCP_CONNTRACK_NONE];

	/* Invalid connection attempt */
	if (new_state >= MPTCP_CONNTRACK_MAX) {
		pr_debug("nf_ct_mptcp new: invalid new connection attempt, deleting.\n");
		return false;
	}

	/* allocate the conntrack */
	if ((mpct = kmalloc(sizeof(struct nf_conn_mptcp), GFP_KERNEL)) == NULL) {
		pr_debug("nf_ct_mptcp new: cannot allocate the mptcp conntrack, "
				"the connection won't be tracked.\n");
		return false;
	}
	memset(mpct, 0, sizeof(struct nf_conn_mptcp));


	/* initialize the mpct state, only if a conntrack has been created */
	mpct->counter_sub = 1; /* the MPCAP stage always is the first subflow */
	/* init the lock protecting access to mptcp conntrack */
	spin_lock_init(&mpct->lock);
	/* setup the timer that will trigger the destruction of the conntrack*/
	setup_timer(&mpct->timeout, nf_mptcp_death_by_timeout, (unsigned long)mpct);

	mpsub = &ct->proto.tcp.mpflow;
	/* Fill subflow-related info as well */
	mpsub->addr_id = 0; /* first subflow is always 0 */
	/* relative direction is always ORIGINAL for original subflow by definition */
	mpsub->rel_dir = IP_CT_DIR_ORIGINAL; 
	/* Keep a ref to master mptcp connnection in every subflow conntrack */
	ct->proto.tcp.mpmaster = mpct;
	d = &mpct->d[IP_CT_DIR_ORIGINAL];
	d->dir = IP_CT_DIR_ORIGINAL;
	d2 = &mpct->d[IP_CT_DIR_REPLY];
	d2->dir = IP_CT_DIR_REPLY;
	switch (new_state){
	case MPTCP_CONNTRACK_SYN_SENT:
		if (index == MPTCP_CAP_SYN) {
			/* client is trying to establish an MPTCP conn */
			/* allocate and fill the mptcp connection struct */

			pr_debug("nf_ct_mptcp new: new mptcp connection mptcp=%p, created from "
					"subflow ct=%p\n", mpct, ct);
			d->key = ((struct mp_capable*)mptr)->sender_key;
			/* fill the structure */
			nf_mptcp_key_sha1(d->key, &d->token, &d->last_dseq);
			/* insert the conntrack in the hashtable, keyed by token */
			nf_mptcp_hash_insert(d, d->token);
		}
		break;

	case MPTCP_CONNTRACK_ESTABLISHED:
		if (index == MPTCP_CAP_ACK) {
			/* The connection is assumed, let's take our chance to populate our
			 * local structure about the connection, otherwise we'd need to stop tracking :( */
			pr_debug("nf_ct_mptcp new: new mptcp connection mptcp=%p, created from "
					"subflow ct=%p\n", mpct, ct);

			/* set keys */
			d->key = ((struct mp_capable*)mptr)->sender_key;
			/* for other direction too */
			d2->key = ((struct mp_capable*)mptr)->receiver_key;
			/* and fill the struct with them */
			nf_mptcp_key_sha1(d->key, &d->token, &d->last_dseq);
			nf_mptcp_key_sha1(d2->key, &d2->token, &d2->last_dseq);
			/* insert both entries of the conntrack in the hashtable, keyed by token */
			nf_mptcp_hash_insert(d, d->token);
			nf_mptcp_hash_insert(d2, d2->token);
		}
		break;
	default:
		/* Should never happen */
		BUG_ON(true);
		kfree(mpct);
		return false;

	}
	mpct->state = MPTCP_CONNTRACK_NONE; /* initial state */
	/* the transition to new state will be effectively fired later by mptcp_packet stage */ 
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
	enum ip_conntrack_dir dir, subdir;
	struct nf_conn_mptcp *mpct;
	struct mp_per_dir *mp;
	unsigned int index;
	struct net *net = nf_ct_net(ct);
	
	pr_debug("mptcp_packet: ENTERING MPTCP PACKET\n");
	
	mpct = ct->proto.tcp.mpmaster;
	if (mpct)
		pr_debug("mpct=%p for ct=%p: state=%i, token0=%x (key0=%llx), "
				"token1=%x (key1=%llx)\n", mpct,
				ct, mpct->state, mpct->d[0].token, 
				mpct->d[0].key, mpct->d[1].token, mpct->d[1].key);
	old_state = mpct->state;
	subdir = CTINFO2DIR(ctinfo);
	dir = nf_mptcp_subdir2dir(&ct->proto.tcp.mpflow, subdir);
	/* parse the packet to retrieve its type for the FSM */
	index = get_conntrack_index(th);
	/* look at the new state that it elicits */
	new_state = mptcp_conntracks[dir][index][old_state];
	/* retrieve the per-dir local info */
	tuple = &ct->tuplehash[dir].tuple;
	mp = &mpct->d[dir];
		
	pr_debug("nf_ct_mptcp_packet: received segmenttype %i, oldstate %s -> newstate %s\n",
			index, mptcp_conntrack_names[old_state], 
			(new_state<MPTCP_CONNTRACK_MAX)?mptcp_conntrack_names[new_state]:"(pseudostate)");
	

	switch (new_state) {
	case MPTCP_CONNTRACK_TIMEWAIT:
		pr_debug("nf_ct_mptcp_packet: waiting for subflows to close before"
				"removing the mpconntrack.\n");
		break;
	
	case MPTCP_CONNTRACK_SYN_RECV:
			/*if (index != MPTCP_CAP_SYN)
				break;*/
	case MPTCP_CONNTRACK_SYN_SENT2: /* opposite SYN in simultaneous open */
			if (index == MPTCP_CAP_SYN || index == MPTCP_CAP_SYNACK) {
				pr_debug("mptcp_packet: set key from  mpcap %s\n",(index==MPTCP_CAP_SYN)?"SYN":"SYNACK");
				/* set and check the key and cie for this direction too */
				if (!nf_mptcp_init_key(((struct mp_capable*)mptr)->sender_key, mp)) {
					pr_debug("mptcp_packet: already set key %llx != new key %llx\n", mp->key,((struct mp_capable*)mptr)->sender_key);
					/* already set key is different */
					if (LOG_INVALID(net, IPPROTO_TCP))
						nf_log_packet(pf, 0, skb, NULL, NULL, NULL,
								"nf_ct_mptcp: key from retransmitted SYN/SYNACK dont match: "
								"old=%llx new=%llx", mp->key, 
								((struct mp_capable*)mptr)->sender_key);
					return -NF_ACCEPT;
				}
				/* those do not need further window checking because the TCP conntracker is
				 * already handling it */
				goto inwindow;
			}

	case MPTCP_CONNTRACK_ESTABLISHED:
			if (old_state == MPTCP_CONNTRACK_SYN_RECV && index == MPTCP_CAP_ACK) {
				/* can be for both directions in case of simultaneous open */
				/* Check that the keys match the local data */
				if (!(((struct mp_capable*)mptr)->sender_key == mp->key && 
							((struct mp_capable*)mptr)->receiver_key == mpct->d[!dir].key)) {
					pr_debug("nf_ct_mptcp: keys from final MP_CAPABLE ACK don't match:"
							"local1=%llx, local2=%llx, remote1=%llx, remote2=%llx\n",
							mp->key, 
							((struct mp_capable*)mptr)->sender_key,
							mpct->d[!dir].key,
							((struct mp_capable*)mptr)->receiver_key);
					if (LOG_INVALID(net, IPPROTO_TCP))
						nf_log_packet(pf, 0, skb, NULL, NULL, NULL,
								"nf_ct_mptcp: keys from final MP_CAPABLE ACK don't match");
					return -NF_ACCEPT;
				}
				goto inwindow;
			}
			break;

	case MPTCP_CONNTRACK_FALLBACK:
		if (mpct->counter_sub == 1) {
		pr_debug("nf_ct_mptcp_packet: fallback detected, to be confirmed by seqnum\n");
			break;
		}
		pr_debug("nf_ct_mptcp_packet: unexpected packet, features a infinite fallback "
				"while several subflows in use.\n");
	case MPTCP_CONNTRACK_IGNORE:
			pr_debug("nf_ct_mptcp_pkt: unexpected state %u, ignoring packet...", new_state);
			new_state = old_state;
			break;
	case MPTCP_CONNTRACK_MAX:
			/* invalid packets */
			pr_debug("nf_ct_tcp: Invalid dir=%i index=%u ostate=%u\n",
					dir, get_conntrack_index(th), old_state);
			if (LOG_INVALID(net, IPPROTO_TCP))
				nf_log_packet(pf, 0, skb, NULL, NULL, NULL,
						"nf_ct_tcp: invalid state ");
			return -NF_ACCEPT;
	default:
			break;
	}

	/* Window checking should be performed here */

inwindow:
	pr_debug("mptcp_packet: in-window => going to be accepted\n");

	if (new_state == MPTCP_CONNTRACK_FALLBACK) {
		/* the single-subflow connection is going to fall back.
		 * we can destroy the conntrack at the MPTCP level */
		nf_mptcp_fallback(ct, mpct);
	}

updateState:
	/* Fire the transition */
	pr_debug("mptcp_packet: effective state update: %s\n", mptcp_conntrack_names[new_state]);
	mpct->state = new_state;

	return NF_ACCEPT;
}

int nf_ct_mptcp_error(struct net *net, struct nf_conn *tmpl,
		     struct sk_buff *skb,
		     unsigned int dataoff,
		     enum ip_conntrack_info *ctinfo,
		     u_int8_t pf,
		     unsigned int hooknum)
{
	int ret;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	
	pr_debug("=================== Packet ==================\n");

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);
	ret =  tcp_error(net, tmpl, skb, dataoff, ctinfo, pf, hooknum);
	pr_debug("mptcp_error: return of tcp_error=%i",ret);

	/* FIXME : doesnt check add_addr and remove_addr*/
	if (mptcp_check_combination(th) == MPTCP_INVALID) {
		pr_debug("nf_ct_mptcp_error: invalid TCP/MPTCP flag combination");
		if (LOG_INVALID(net, IPPROTO_TCP))
			nf_log_packet(pf, 0, skb, NULL, NULL, NULL,
				"nf_ct_mptcp: invalid TCP/MPTCP flag combination");
		return -NF_ACCEPT;
	}
	
	return ret;
}

/* TCP packet without connection tracker (new connections) */
bool nf_ct_mptcp_new(struct nf_conn *ct, const struct sk_buff *skb,
		    unsigned int dataoff)
{
	struct mptcp_option *mptr;
	int ret, ret_mp = 1;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	enum mptcp_pkt_type index;
	
	/* initiate subflow's conntrack as usual */
	ret = tcp_new(ct, skb, dataoff);
	
	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	BUG_ON(th == NULL);
    
	if (!(mptr = nf_mptcp_get_ptr(th))) {
		pr_debug("mptcp_new: no mptcp option\n");
		return ret; /* no mptcp option present */
	}

	index = _get_conntrack_index(th, &mptr);
	pr_debug("mptcp_new: transition index: %s\n", mptcp_index_names[index]);
	/* Get mptcp packet type and return a pointer mptr to the right option in
	 * skb */
	switch (index) {
	case MPTCP_CAP_SYN:
	case MPTCP_CAP_ACK:
		ret_mp = mpcap_new(ct, th, mptr);
		break;
	default:
		pr_debug("mptcp_new: index %u not handled by MPTCP FSM\n", index);
		/* FIXME */
		break;
	}
	pr_debug("mptcp_new: Ok, ret=%u, ret_mp=%u\n", ret, ret_mp);
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
	
	pr_debug("=== [Client %s Server]\n",CTINFO2DIR(ctinfo)?"<--":"-->");

	/* first handle as single path packet */
	ret = tcp_packet(ct, skb, dataoff, ctinfo, pf, hooknum);
	pr_debug("mptcp_packet: tcp_packet returned %i\n",ret);

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
	
	/* mpct cannot be modified by several subflows at the same time */
	spin_lock_bh(&mpct->lock);

	/* a packet part of the mptcp connection has been received, a subflow
	 * is alive, we are sure that the data connection must not die by timer*/
	nf_mptcp_delete_timer(mpct);
    
	/* dispatching */
	/* Get mptcp packet type and return a pointer mptr to the right option in
	 * skb */
	index = _get_conntrack_index(th, &mptr);
	pr_debug("mptcp_packet: transition index: %s\n", mptcp_index_names[index]);
	switch (index) {
	/* mptcp packet: only transitions from MPTCP's FSM */
	case MPTCP_NOOPT:
	case MPTCP_CAP_SYN:
	case MPTCP_CAP_SYNACK:
	case MPTCP_CAP_ACK:
	case MPTCP_DATA_ACK:
	case MPTCP_DATA_FIN:
	case MPTCP_FASTCLOSE:
	case MPTCP_INFINITE_MAP:
		/* actual MPTCP-level connection tracking */
		ret_mp = mptcp_packet(ct, th, ctinfo, pf, skb, mptr);
	default:
		break;
	}
	/* the spin must always be unlocked as the mpct can't die within it thanks
	 * to the timer */
	spin_unlock_bh(&mpct->lock);
	
	pr_debug("nf_ct_mptcp_packet: ret=%i, ret_mptcp=%i\n",ret, ret_mp);
	
	/* Take MPTCP decision into account only if negative */
	if (ret_mp > 0)
		return ret;
	return ret_mp;

}

/* MPTCP subflow tracking -related */
/* update the subflow counter when a subflow is added
 * Return true if the new counter is zero, else otherwise */
bool nf_mptcp_add_subflow(struct nf_conn_mptcp *mpct) {
	pr_debug("ct_mptcp: adding subflow\n");
	mpct->counter_sub += 1;
	BUG_ON(mpct->counter_sub <= 0);
	return !mpct->counter_sub;
}

/* Update the subflow counter when a subflow is removed
 * Return true if the new counter is zero, else otherwise
 */
bool nf_mptcp_remove_subflow(struct nf_conn_mptcp *mpct) {
	pr_debug("ct_mptcp: removing subflow --> counter=%u\n",mpct->counter_sub-1);
	mpct->counter_sub -= 1;
	BUG_ON(mpct->counter_sub < 0);
	return !mpct->counter_sub;
}

/* Update the state and the timers according to the (non)nullity of the
 * subflows counter 
 */
void nf_mptcp_update(struct nf_conn_mptcp *mpct, bool zero_counter) {
	switch (mpct->state) {
	case MPTCP_CONNTRACK_NO_SUBFLOW:
		if (!zero_counter) {
			pr_debug("ct_mptcp: NO_SUBFLOW -> ESTABLISHED\n");
			mpct->state = MPTCP_CONNTRACK_ESTABLISHED;
			nf_mptcp_delete_timer(mpct);
		}
		break;
	case MPTCP_CONNTRACK_ESTABLISHED:
		if (zero_counter) {
			pr_debug("ct_mptcp: ESTABLISHED -> NO_SUBFLOW\n");
			mpct->state = MPTCP_CONNTRACK_NO_SUBFLOW;
			nf_mptcp_update_timer(mpct);
		}
		break;
	case MPTCP_CONNTRACK_TIMEWAIT:
		if (zero_counter) {
			/* no more subflow on a closed MPTCP connection */
			nf_mptcp_put(mpct);
			return;
		}
	default:
		break;
	}
}

/* Called whenever a TCP conntrack is going to be destroyed */
void nf_ct_mptcp_destroy(struct nf_conn *ct) {
	struct nf_conn_mptcp *mpct;
	
	pr_debug("nf_ct_mptcp_destroy: DESTROY\n");

	if ((mpct = ct->proto.tcp.mpmaster) == NULL) {
		pr_debug("nf_ct_mptcp_destroy: nothing to do\n");
		return;
	}
	
	/* the mptcp conntrack does not need to die, it's only one subflow less,
	 * however, if it was the last subflow, trigger death after timeout */
	spin_lock_bh(&mpct->lock);
	nf_mptcp_update(mpct, nf_mptcp_remove_subflow(mpct));
	spin_unlock_bh(&mpct->lock);
}

static int __init nf_conntrack_mptcp_init(void)
{
	int i;

/*	nf_ct_mptcp_timeout_no_subflow = 10 * 60 * HZ;*/ /* 10 mins */

	/* hashtable init */
	for (i = 0; i < NF_MPTCP_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&mptcp_conn_htb[i]);
	}
	rwlock_init(&htb_lock);

	return 0;
}

module_init(nf_conntrack_mptcp_init);
MODULE_LICENSE("GPL");
