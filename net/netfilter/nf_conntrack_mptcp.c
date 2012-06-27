#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>

#include <net/netfilter/nf_conntrack_mptcp.h>


#ifdef CONFIG_NF_MPTCP
#define NF_MPTCP_HASH_SIZE 1024

/* Hashtable to retrieve nf_conn from token */
static struct list_head mptcp_conn_htb[NF_MPTCP_HASH_SIZE];
static rwlock_t htb_lock;	

static inline u32 nf_mptcp_hash_tk(u32 token)
{
	return token % NF_MPTCP_HASH_SIZE;
}

struct nf_mptcp_conn *nf_mptcp_hash_find(u32 token)
{
	u32 hash = nf_mptcp_hash_tk(token);
	struct nf_mptcp_conn *mptcp_conn;

	read_lock(&htb_lock);
	list_for_each_entry(mptcp_conn, &mptcp_conn_htb[hash], collide_tk) {
		if (token == mptcp_conn->token) { /*TODO: token in tuple ?*/
	        read_unlock(&htb_lock);
            return mptcp_conn;
        }
	}
	read_unlock(&htb_lock);
	return NULL;
}


void nf_mptcp_hash_insert(struct nf_mptcp_conn *mpconn, u32 token)
{
	u32 hash = nf_mptcp_hash_tk(token);

	write_lock_bh(&htb_lock);
	list_add(&mpconn->collide_tk, &mptcp_conn_htb[hash]);
	write_unlock_bh(&htb_lock);
}


void nf_mptcp_hash_remove(struct nf_mptcp_conn *mpconn)
{
	/* remove from the token hashtable */
	write_lock_bh(&htb_lock);
	list_del(&mpconn->collide_tk);
	write_unlock_bh(&htb_lock);
}

struct mp_join *mptcp_find_join(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	unsigned char *ptr;
	int length = (th->doff * 4) - sizeof(struct tcphdr);

	/* Jump through the options to check whether JOIN is there */
	ptr = (unsigned char *)(th + 1);
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
			if (opsize < 2)	/* "silly options" */
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


static int __init nf_conntrack_mptcp_init(void)
{
	int i;
	for (i = 0; i < NF_MPTCP_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&mptcp_token_htb[i]);
	}

	rwlock_init(&tk_hash_lock);
    return 0;
/*    FIXME: return value */
}

module_init(nf_conntrack_mptcp_init);

MODULE_LICENSE("GPL");
