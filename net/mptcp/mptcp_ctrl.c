/*
 *	MPTCP implementation - MPTCP-control
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	John Ronan <jronan@tssg.org>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <crypto/sha.h>

#include <net/inet_common.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/mptcp_v6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>

#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#if IS_ENABLED(CONFIG_IPV6)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#define AF_INET6_FAMILY(fam) ((fam) == AF_INET6)
#else
#define AF_INET_FAMILY(fam) 1
#define AF_INET6_FAMILY(fam) 0
#endif

static struct kmem_cache *mpcb_cache __read_mostly;

/* Sysctl data */

#ifdef CONFIG_SYSCTL

int sysctl_mptcp_mss __read_mostly = MPTCP_MSS;
int sysctl_mptcp_ndiffports __read_mostly = 1;
int sysctl_mptcp_enabled __read_mostly = 1;
int sysctl_mptcp_checksum __read_mostly = 1;
int sysctl_mptcp_debug __read_mostly = 0;
EXPORT_SYMBOL(sysctl_mptcp_debug);

static ctl_table mptcp_table[] = {
	{
		.procname = "mptcp_mss",
		.data = &sysctl_mptcp_mss,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_ndiffports",
		.data = &sysctl_mptcp_ndiffports,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_enabled",
		.data = &sysctl_mptcp_enabled,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_checksum",
		.data = &sysctl_mptcp_checksum,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{
		.procname = "mptcp_debug",
		.data = &sysctl_mptcp_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec
	},
	{ }
};

static ctl_table mptcp_net_table[] = {
	{
		.procname = "mptcp",
		.maxlen = 0,
		.mode = 0555,
		.child = mptcp_table
	},
	{ }
};

static ctl_table mptcp_root_table[] = {
	{
		.procname = "net",
		.mode = 0555,
		.child = mptcp_net_table
	},
	{ }
};
#endif

struct sock *mptcp_select_ack_sock(const struct mptcp_cb *mpcb, int copied)
{
	struct sock *sk, *subsk = NULL;
	struct tcp_sock *meta_tp = mpcb_meta_tp(mpcb);
	u32 max_data_seq = 0;
	/* max_data_seq initialized to correct compiler-warning.
	 * But the initialization is handled by max_data_seq_set */
	short max_data_seq_set = 0;
	u32 min_time = 0xffffffff;

	/* How do we select the subflow to send the window-update on?
	 *
	 * 1. He has to be in a state where he can send an ack.
	 * 2. He has to be one of those subflow who recently
	 *    contributed to the received stream
	 *    (this guarantees a working subflow)
	 *    a) its latest data_seq received is after the original
	 *       copied_seq.
	 *       We select the one with the lowest rtt, so that the
	 *       window-update reaches our peer the fastest.
	 *    b) if no subflow has this kind of data_seq (e.g., very
	 *       strange meta-level retransmissions going on), we take
	 *       the subflow who last sent the highest data_seq.
	 */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV |
					   TCPF_CLOSE | TCPF_LISTEN))
			continue;

		/* Select among those who contributed to the
		 * current receive-queue. */
		if (copied && after(tp->last_data_seq, meta_tp->copied_seq - copied)) {
			if (tp->srtt < min_time) {
				min_time = tp->srtt;
				subsk = sk;
				max_data_seq_set = 0;
			}
			continue;
		}

		if (!subsk && !max_data_seq_set) {
			max_data_seq = tp->last_data_seq;
			max_data_seq_set = 1;
			subsk = sk;
		}

		/* Otherwise, take the one with the highest data_seq */
		if ((!subsk || max_data_seq_set) &&
		    after(tp->last_data_seq, max_data_seq)) {
			max_data_seq = tp->last_data_seq;
			subsk = sk;
		}
	}

	if (!subsk) {
		mptcp_debug("%s subsk is null, copied %d, cseq %u\n", __func__,
			    copied, meta_tp->copied_seq);
		mptcp_for_each_sk(mpcb, sk) {
			struct tcp_sock *tp = tcp_sk(sk);
			mptcp_debug("%s pi %d state %u last_dseq %u\n",
				    __func__, tp->path_index, sk->sk_state,
				    tp->last_data_seq);
		}
	}

	return subsk;
}

void mptcp_sock_def_error_report(struct sock *sk)
{
	if (tcp_sk(sk)->mpc && !is_meta_sk(sk)) {
		sk->sk_err = 0;

		if (!sock_flag(sk, SOCK_DEAD))
			mptcp_sub_close(sk, 0);
		return;
	}

	sock_def_error_report(sk);
}

void mptcp_key_sha1(u64 key, u32 *token, u64 *idsn)
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

void mptcp_hmac_sha1(u8 *key_1, u8 *key_2, u8 *rand_1, u8 *rand_2,
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

static void mptcp_mpcb_inherit_sockopts(struct sock *meta_sk, struct sock *master_sk)
{
	/* Socket-options handled by mptcp_inherit_sk while creating the meta-sk.
	 * ======
	 * SO_SNDBUF, SO_SNDBUFFORCE, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT,
	 * SO_RCVTIMEO, SO_SNDTIMEO, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	 * TCP_NODELAY, TCP_CORK
	 *
	 * Socket-options handled in this function here
	 * ======
	 * SO_KEEPALIVE
	 * TCP_KEEP*
	 * TCP_DEFER_ACCEPT
	 *
	 * Socket-options on the todo-list
	 * ======
	 * SO_BINDTODEVICE - should probably prevent creation of new subsocks
	 * 		     across other devices. - what about the api-draft?
	 * SO_DEBUG
	 * SO_REUSEADDR - probably we don't care about this
	 * SO_DONTROUTE, SO_BROADCAST
	 * SO_OOBINLINE
	 * SO_LINGER
	 * SO_TIMESTAMP* - I don't think this is of concern for a SOCK_STREAM
	 * SO_PASSSEC - I don't think this is of concern for a SOCK_STREAM
	 * SO_RXQ_OVFL
	 * TCP_COOKIE_TRANSACTIONS
	 * TCP_MAXSEG
	 * TCP_THIN_* - Handled by mptcp_inherit_sk, but we need to support this
	 *		in mptcp_retransmit_timer. AND we need to check what is
	 *		about the subsockets.
	 * TCP_LINGER2
	 * TCP_WINDOW_CLAMP
	 * TCP_USER_TIMEOUT
	 * TCP_MD5SIG
	 *
	 * Socket-options of no concern for the meta-socket (but for the subsocket)
	 * ======
	 * SO_PRIORITY
	 * SO_MARK
	 * TCP_CONGESTION
	 * TCP_SYNCNT
	 * TCP_QUICKACK
	 */
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);

	/****** KEEPALIVE-handler ******/

	/* Keepalive-timer has been started in tcp_rcv_synsent_state_process or
	 * tcp_create_openreq_child */
	if (sock_flag(meta_sk, SOCK_KEEPOPEN)) {
		inet_csk_reset_keepalive_timer(meta_sk, keepalive_time_when(meta_tp));

		/* Prevent keepalive-reset in tcp_rcv_synsent_state_process */
		sock_reset_flag(master_sk, SOCK_KEEPOPEN);
	}

	/****** DEFER_ACCEPT-handler ******/

	/* DEFER_ACCEPT is not of concern for new subflows - we always accept
	 * them */
	inet_csk(meta_sk)->icsk_accept_queue.rskq_defer_accept = 0;
}

static void mptcp_sub_inherit_sockopts(struct sock *meta_sk, struct sock *sub_sk)
{
	/* Keepalive is handled at the meta-level */
	if (sock_flag(meta_sk, SOCK_KEEPOPEN))
		inet_csk_delete_keepalive_timer(sub_sk);
}

int mptcp_alloc_mpcb(struct sock *master_sk)
{
	struct mptcp_cb *mpcb;
	struct tcp_sock *meta_tp, *master_tp = tcp_sk(master_sk);
	struct sock *meta_sk;
	struct inet_connection_sock *meta_icsk;
	u64 idsn;

	mpcb = kmem_cache_alloc(mpcb_cache, GFP_ATOMIC);
	/* Memory allocation failed. Stopping here. */
	if (!mpcb)
		return -ENOBUFS;

	meta_sk = mpcb_meta_sk(mpcb);
	meta_tp = mpcb_meta_tp(mpcb);
	meta_icsk = inet_csk(meta_sk);

	memset(mpcb, 0, sizeof(struct mptcp_cb));

	/* meta_sk inherits master sk */
#if IS_ENABLED(CONFIG_IPV6)
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET6, GFP_ATOMIC);

	if (AF_INET_FAMILY(master_sk->sk_family)) {
		mpcb->icsk_af_ops_alt = &ipv6_specific;
		mpcb->sk_prot_alt = &tcpv6_prot;
	} else {
		mpcb->icsk_af_ops_alt = &ipv4_specific;
		mpcb->sk_prot_alt = &tcp_prot;
	}
#else
	mptcp_inherit_sk(master_sk, meta_sk, AF_INET, GFP_ATOMIC);
#endif /* CONFIG_IPV6 */

	/* Store the keys and generate the peer's token */
	mpcb->mptcp_loc_key = master_tp->mptcp_loc_key;
	mpcb->mptcp_loc_token = master_tp->mptcp_loc_token;

	/* Generate Initial data-sequence-numbers */
	mptcp_key_sha1(mpcb->mptcp_loc_key, NULL, &idsn);
	idsn = ntohll(idsn) + 1;
	mpcb->snd_high_order[0] = idsn >> 32;
	mpcb->snd_high_order[1] = mpcb->snd_high_order[0] - 1;
	meta_tp->write_seq = (u32)idsn;
	meta_tp->snd_sml = meta_tp->snd_una = meta_tp->snd_nxt = meta_tp->write_seq;

	mpcb->rx_opt.mptcp_rem_key = meta_tp->mptcp_rem_key;
	mptcp_key_sha1(mpcb->rx_opt.mptcp_rem_key,
		       &mpcb->rx_opt.mptcp_rem_token, &idsn);
	idsn = ntohll(idsn) + 1;
	mpcb->rcv_high_order[0] = idsn >> 32;
	mpcb->rcv_high_order[1] = mpcb->rcv_high_order[0] + 1;
	meta_tp->copied_seq = meta_tp->rcv_nxt = meta_tp->rcv_wup = (u32) idsn;

	meta_tp->packets_out = 0;
	meta_tp->snt_isn = meta_tp->write_seq; /* Initial data-sequence-number */
	meta_tp->window_clamp = tcp_sk(master_sk)->window_clamp;
	meta_tp->rcv_ssthresh = tcp_sk(master_sk)->rcv_ssthresh;
	meta_icsk->icsk_probes_out = 0;

	meta_tp->mss_cache = mptcp_sysctl_mss();

	meta_tp->mpcb = mpcb;
	meta_tp->mpc = 1;
	meta_tp->attached = 0;

	skb_queue_head_init(&mpcb->reinject_queue);
	skb_queue_head_init(&meta_tp->out_of_order_queue);

	mutex_init(&mpcb->mutex);

	/* Initialize workqueue-struct */
	INIT_WORK(&mpcb->work, mptcp_send_updatenotif_wq);

	/* Redefine function-pointers to wake up application */
	master_sk->sk_error_report = mptcp_sock_def_error_report;
	meta_sk->sk_error_report = mptcp_sock_def_error_report;

	/* Init the accept_queue structure, we support a queue of 32 pending
	 * connections, it does not need to be huge, since we only store
	 * here pending subflow creations.
	 */
	if (reqsk_queue_alloc(&meta_icsk->icsk_accept_queue, 32, GFP_ATOMIC))
		return -ENOMEM;

	master_tp->mpcb = mpcb;
	mpcb->master_sk = master_sk;

	/* Meta-level retransmit timer */
	meta_icsk->icsk_rto *= 2; /* Double of master - rto */
	tcp_init_xmit_timers(meta_sk);

	/* Adding the mpcb in the token hashtable */
	mptcp_hash_insert(mpcb, mpcb->mptcp_loc_token);

	mptcp_mpcb_inherit_sockopts(meta_sk, master_sk);

	mptcp_debug("%s: created mpcb with token %#x\n",
		    __func__, mpcb->mptcp_loc_token);

	return 0;
}

void mptcp_release_mpcb(struct mptcp_cb *mpcb)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);

	security_sk_free(meta_sk);

	mptcp_debug("%s: Will free mpcb %#x\n", __func__, mpcb->mptcp_loc_token);
	kmem_cache_free(mpcb_cache, mpcb);
}

void mptcp_release_sock(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = (struct mptcp_cb *)meta_sk;
	struct sock *sk_it;

	/* We need to do the following, because as far
	 * as the master-socket is locked, every received segment is
	 * put into the backlog queue.
	 */
	while (meta_sk->sk_backlog.tail ||
	       mptcp_test_any_sk(mpcb, sk_it, sk_it->sk_backlog.tail)) {
		/* process incoming join requests */
		if (meta_sk->sk_backlog.tail)
			__release_sock(meta_sk, mpcb);

		mptcp_for_each_sk(mpcb, sk_it) {
			if (sk_it->sk_backlog.tail)
				__release_sock(sk_it, mpcb);
		}
	}
}

static void mptcp_destroy_mpcb(struct mptcp_cb *mpcb)
{
	/* Detach the mpcb from the token hashtable */
	mptcp_hash_remove(mpcb);
	reqsk_queue_destroy(&((struct inet_connection_sock *)mpcb)->icsk_accept_queue);
}

void mptcp_add_sock(struct mptcp_cb *mpcb, struct tcp_sock *tp)
{
	struct sock *meta_sk = mpcb_meta_sk(mpcb);
	struct sock *sk = (struct sock *) tp;

	tp->mpcb = mpcb;

	/* The corresponding sock_put is in inet_sock_destruct(). It cannot be
	 * included in mptcp_del_sock(), because the mpcb must remain alive
	 * until the last subsocket is completely destroyed. */
	sock_hold(meta_sk);

	tp->next = mpcb->connection_list;
	mpcb->connection_list = tp;
	tp->attached = 1;

	mpcb->cnt_subflows++;
	mptcp_update_window_clamp(tcp_sk(meta_sk));
	atomic_add(atomic_read(&((struct sock *)tp)->sk_rmem_alloc),
		   &meta_sk->sk_rmem_alloc);

	/* The socket is already established if it was in the
	 * accept queue of the mpcb
	 */
	if (sk->sk_state == TCP_ESTABLISHED) {
		mpcb->cnt_established++;
		mptcp_update_sndbuf(mpcb);
		if ((1 << meta_sk->sk_state) &
		    (TCPF_SYN_SENT | TCPF_SYN_RECV))
			meta_sk->sk_state = TCP_ESTABLISHED;
	}

	mptcp_sub_inherit_sockopts(meta_sk, sk);
	INIT_DELAYED_WORK(&tp->work, mptcp_sub_close_wq);

	if (sk->sk_family == AF_INET)
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI4:%d dst_addr:"
				"%pI4:%d, cnt_subflows now %d\n", __func__ ,
				mpcb->mptcp_loc_token,
				tp->path_index,
				&((struct inet_sock *) tp)->inet_saddr,
				ntohs(((struct inet_sock *) tp)->inet_sport),
				&((struct inet_sock *) tp)->inet_daddr,
				ntohs(((struct inet_sock *) tp)->inet_dport),
				mpcb->cnt_subflows);
	else
		mptcp_debug("%s: token %#x pi %d, src_addr:%pI6:%d dst_addr:"
				"%pI6:%d, cnt_subflows now %d\n", __func__ ,
				mpcb->mptcp_loc_token,
				tp->path_index, &inet6_sk(sk)->saddr,
				ntohs(((struct inet_sock *) tp)->inet_sport),
				&inet6_sk(sk)->daddr,
				ntohs(((struct inet_sock *) tp)->inet_dport),
				mpcb->cnt_subflows);
}

void mptcp_del_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk), *tp_prev;
	struct mptcp_cb *mpcb;
	int done = 0;

	/* Need to check for protocol here, because we may enter here for
	 * non-tcp sockets. (coming from inet_csk_destroy_sock) */
	if (sk->sk_type != SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP ||
	    !tp->mpc || !tp->attached)
		return;

	mpcb = tp->mpcb;
	tp_prev = mpcb->connection_list;

	mptcp_debug("%s: Removing subsock tok %#x pi:%d state %d is_meta? %d\n",
		    __func__, mpcb->mptcp_loc_token, tp->path_index,
		    sk->sk_state, is_meta_sk(sk));

	if (tp_prev == tp) {
		mpcb->connection_list = tp->next;
		mpcb->cnt_subflows--;
		done = 1;
	} else {
		for (; tp_prev && tp_prev->next; tp_prev = tp_prev->next) {
			if (tp_prev->next == tp) {
				tp_prev->next = tp->next;
				mpcb->cnt_subflows--;
				done = 1;
				break;
			}
		}
	}

	tp->next = NULL;
	tp->attached = 0;
	mpcb->path_index_bits &= ~(1 << tp->path_index);

	if (!skb_queue_empty(&sk->sk_write_queue) && mpcb->cnt_established > 0)
		mptcp_reinject_data(sk, 0);

	if (is_master_tp(tp))
		mpcb->master_sk = NULL;
}

/**
 * Updates the metasocket ULID/port data, based on the given sock.
 * The argument sock must be the sock accessible to the application.
 * In this function, we update the meta socket info, based on the changes
 * in the application socket (bind, address allocation, ...)
 */
void mptcp_update_metasocket(struct sock *sk, struct mptcp_cb *mpcb)
{

	switch (sk->sk_family) {
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		/* If the socket is v4 mapped, we continue with v4 operations */
		if (!mptcp_v6_is_v4_mapped(sk)) {
			ipv6_addr_copy(&mpcb->addr6[0].addr, &inet6_sk(sk)->saddr);
			mpcb->addr6[0].id = 0;
			mpcb->addr6[0].port = 0;
			mpcb->addr6[0].low_prio = 0;
			mpcb->loc6_bits |= 1;
			mpcb->next_v6_index = 1;

			mptcp_v6_add_raddress(&mpcb->rx_opt,
					      &inet6_sk(sk)->daddr,
					      inet_sk(sk)->inet_dport, 0);
			mptcp_v6_set_init_addr_bit(mpcb, &inet6_sk(sk)->daddr);
			break;
		}
#endif
	case AF_INET:
		mpcb->addr4[0].addr.s_addr = inet_sk(sk)->inet_saddr;
		mpcb->addr4[0].id = 0;
		mpcb->addr4[0].port = 0;
		mpcb->addr4[0].low_prio = 0;
		mpcb->loc4_bits |= 1;
		mpcb->next_v4_index = 1;

		mptcp_v4_add_raddress(&mpcb->rx_opt,
				      (struct in_addr *)&inet_sk(sk)->inet_daddr,
				      inet_sk(sk)->inet_dport, 0);
		mptcp_v4_set_init_addr_bit(mpcb, inet_sk(sk)->inet_daddr);
		break;
	}

	mptcp_set_addresses(mpcb);

	switch (sk->sk_family) {
	case AF_INET:
		tcp_sk(sk)->low_prio = mpcb->addr4[0].low_prio;
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		tcp_sk(sk)->low_prio = mpcb->addr6[0].low_prio;
		break;
#endif
	}

	tcp_sk(sk)->send_mp_prio = tcp_sk(sk)->low_prio;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void mptcp_cleanup_rbuf(struct sock *meta_sk, int copied)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk, *subsk;
	int time_to_ack = 0;

	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		const struct inet_connection_sock *icsk = inet_csk(sk);
		if (!inet_csk_ack_scheduled(sk))
			continue;
		/* Delayed ACKs frequently hit locked sockets during bulk
		 * receive. */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 && ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2)
				|| ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED)
				&& !icsk->icsk_ack.pingpong))
				&& !atomic_read(&meta_sk->sk_rmem_alloc))) {
			time_to_ack = 1;
			tcp_send_ack(sk);
		}
	}

	if (time_to_ack)
		return;

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	if (copied > 0 && !time_to_ack
			&& !(meta_sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(meta_tp);

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2 * rcv_window_now <= meta_tp->window_clamp) {
			__u32 new_window;
			subsk = mptcp_select_ack_sock(mpcb, copied);
			if (!subsk)
				return;
			new_window = __tcp_select_window(subsk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than
			 * current one.
			 * "Lots" means "at least twice" here.
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}

	if (time_to_ack) {
		if (subsk)
			tcp_send_ack(subsk);
		else
			printk(KERN_ERR "%s did not find a subsk! "
					"Should not happen.\n", __func__);
	}
}

void mptcp_sub_close_wq(struct work_struct *work)
{
	struct tcp_sock *tp = container_of(work, struct tcp_sock, work.work);
	struct sock *sk = (struct sock *)tp;
	struct sock *meta_sk = mptcp_meta_sk(sk);

	mutex_lock(&tp->mpcb->mutex);
	lock_sock(meta_sk);

	if (sock_flag(sk, SOCK_DEAD))
		goto exit;

	if (meta_sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		tcp_close(sk, 0);
	else if (tcp_close_state(sk))
		tcp_send_fin(sk);

exit:
	release_sock(meta_sk);
	mutex_unlock(&tp->mpcb->mutex);
	sock_put(sk);
}

void mptcp_sub_close(struct sock *sk, unsigned long delay)
{
	struct delayed_work *work = &tcp_sk(sk)->work;

	/* Work already scheduled ? */
	if (work_pending(&work->work)) {
		/* Work present - who will be first ? */
		if (jiffies + delay > work->timer.expires)
			return;

		/* Try canceling - if it fails, work will be executed soon */
		if (!cancel_delayed_work(work))
			return;
		sock_put(sk);
	}

	if (!delay) {
		/* We directly send the FIN. Because it may take so a long time,
		 * untile the work-queue will get scheduled...
		 */
		tcp_shutdown(sk, SEND_SHUTDOWN);
	}

	sock_hold(sk);
	schedule_delayed_work(work, delay);
}

/**
 * At the moment we apply a simple addition algorithm.
 * We will complexify later
 */
void mptcp_update_window_clamp(struct tcp_sock *tp)
{
	struct sock *meta_sk, *sk;
	struct tcp_sock *meta_tp;
	struct mptcp_cb *mpcb;
	u32 new_clamp = 0, new_rcv_ssthresh = 0;
	int new_rcvbuf = 0;

	/* Can happen if called from non mpcb sock. */
	if (!tp->mpc)
		return;

	mpcb = tp->mpcb;
	meta_tp = mpcb_meta_tp(mpcb);
	meta_sk = mpcb_meta_sk(mpcb);

	mptcp_for_each_sk(mpcb, sk) {
		new_clamp += tcp_sk(sk)->window_clamp;
		new_rcv_ssthresh += tcp_sk(sk)->rcv_ssthresh;
		new_rcvbuf += sk->sk_rcvbuf;

		if (new_rcvbuf > sysctl_tcp_rmem[2] || new_rcvbuf < 0) {
			new_rcvbuf = sysctl_tcp_rmem[2];
			break;
		}
	}
	meta_tp->window_clamp = new_clamp;
	meta_tp->rcv_ssthresh = new_rcv_ssthresh;
	meta_sk->sk_rcvbuf = min(new_rcvbuf, sysctl_tcp_rmem[2]);
}

/**
 * Update the mpcb send window, based on the contributions
 * of each subflow
 */
void mptcp_update_sndbuf(struct mptcp_cb *mpcb)
{
	struct sock *meta_sk = (struct sock *) mpcb, *sk;
	int new_sndbuf = 0;
	mptcp_for_each_sk(mpcb, sk) {
		new_sndbuf += sk->sk_sndbuf;

		if (new_sndbuf > sysctl_tcp_wmem[2] || new_sndbuf < 0) {
			new_sndbuf = sysctl_tcp_wmem[2];
			break;
		}
	}
	meta_sk->sk_sndbuf = min(new_sndbuf, sysctl_tcp_wmem[2]);
}

/**
 * Sets the socket pointer of the meta_sk after an accept at the socket level
 * Set also the sk_wq pointer, because it has just been copied by
 * sock_graft()
 */
void mptcp_check_socket(struct sock *sk)
{
	if (sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP &&
	    tcp_sk(sk)->mpc) {
		struct sock *meta_sk = mpcb_meta_sk(tcp_sk(sk)->mpcb);
		sk_set_socket(meta_sk, sk->sk_socket);
		meta_sk->sk_wq = sk->sk_wq;
		sk->sk_socket->sk = meta_sk;
	}
}
EXPORT_SYMBOL(mptcp_check_socket);

void mptcp_close(struct sock *meta_sk, long timeout)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct sock *sk_it, *sk_tmp;
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	mptcp_debug("%s: Close of meta_sk with tok %#x\n", __func__,
			mpcb->mptcp_loc_token);

	mptcp_for_each_sk(mpcb, sk_it) {
		if (!is_master_tp(tcp_sk(sk_it)))
			sock_rps_reset_flow(sk_it);
	}

	mutex_lock(&mpcb->mutex);

	lock_sock(meta_sk);

	mptcp_destroy_mpcb(mpcb);

	meta_sk->sk_shutdown = SHUTDOWN_MASK;
	/* We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&meta_sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  (mptcp_is_data_fin(skb) ? 1 : 0);
		data_was_unread += len;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(meta_sk);

	/* If socket has been already reset (e.g. in tcp_reset()) - kill it. */
	if (meta_sk->sk_state == TCP_CLOSE) {
		mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp)
			mptcp_sub_close(sk_it, 0);
		goto adjudge_to_death;
	}

	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(meta_sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(meta_sk, TCP_CLOSE);
		tcp_send_active_reset(meta_sk, meta_sk->sk_allocation);
	} else if (tcp_close_state(meta_sk)) {
		mptcp_send_fin(meta_sk);
	} else if (meta_tp->snd_una == meta_tp->write_seq) {
		/* The DATA_FIN has been sent and acknowledged
		 * (e.g., by sk_shutdown). Close all the other subflows */
		mptcp_for_each_sk_safe(mpcb, sk_it, sk_tmp) {
			unsigned long delay = 0;
			/* If we are the passive closer, don't trigger
			 * subflow-fin until the subflow has been finned
			 * by the peer. - thus we add a delay */
			if (mpcb->passive_close && sk_it->sk_state == TCP_ESTABLISHED)
				delay = inet_csk(sk_it)->icsk_rto << 3;

			mptcp_sub_close(sk_it, delay);
		}
	}

	sk_stream_wait_close(meta_sk, timeout);

adjudge_to_death:
	state = meta_sk->sk_state;
	sock_hold(meta_sk);
	sock_orphan(meta_sk);

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(meta_sk);

	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(meta_sk);
	WARN_ON(sock_owned_by_user(meta_sk));

	percpu_counter_inc(meta_sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && meta_sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (meta_sk->sk_state == TCP_FIN_WAIT2) {
		if (meta_tp->linger2 < 0) {
			tcp_set_state(meta_sk, TCP_CLOSE);
			tcp_send_active_reset(meta_sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(meta_sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(meta_sk);

			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(meta_sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else {
				tcp_time_wait(meta_sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (meta_sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(meta_sk);
		if (tcp_too_many_orphans(meta_sk, 0)) {
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			tcp_set_state(meta_sk, TCP_CLOSE);
			tcp_send_active_reset(meta_sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(meta_sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}


	if (meta_sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(meta_sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(meta_sk);
	local_bh_enable();
	mutex_unlock(&mpcb->mutex);
	sock_put(meta_sk); /* Taken by sock_hold */
}

/**
 * When a listening sock is closed with established children still pending,
 * those children have created already an mpcb (tcp_check_req()).
 * Moreover, that mpcb has possibly received additional children,
 * from JOIN subflows. All this must be cleaned correctly, which is done
 * here. Later we should use a more generic approach, reusing more of
 * the regular TCP stack.
 */
void mptcp_detach_unused_child(struct sock *sk)
{
	struct mptcp_cb *mpcb;
	struct sock *child;
	if (!sk->sk_protocol == IPPROTO_TCP)
		return;
	mpcb = tcp_sk(sk)->mpcb;
	if (!mpcb)
		return;
	mptcp_destroy_mpcb(mpcb);
	/* Now all subflows of the mpcb are attached, so we can destroy them,
	 * being sure that the mpcb will be correctly destroyed last.
	 */
	mptcp_for_each_sk(mpcb, child) {
		if (child == sk)
			continue; /* master_sk will be freed last
				   * as part of the normal
				   * net_csk_listen_stop() function
				   */
		/* This section is copied from
		 * inet_csk_listen_stop()
		 */
		local_bh_disable();
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		percpu_counter_inc(sk->sk_prot->orphan_count);

		inet_csk_destroy_sock(child);

		local_bh_enable();
		sock_put(child);
	}
}

void mptcp_set_bw_est(struct tcp_sock *tp, u32 now)
{
	if (!tp->mpc)
		return;

	if (!tp->bw_est.time)
		goto new_bw_est;

	if (after(tp->snd_una, tp->bw_est.seq)) {
		if (now - tp->bw_est.time == 0) {
			/* The interval was to small - shift one more */
			tp->bw_est.shift++;
		} else {
			tp->cur_bw_est = (tp->snd_una -
				(tp->bw_est.seq - tp->bw_est.space)) /
				(now - tp->bw_est.time);
		}
		goto new_bw_est;
	}
	return;

new_bw_est:
	tp->bw_est.space = (tp->snd_cwnd * tp->mss_cache) << tp->bw_est.shift;
	tp->bw_est.seq = tp->snd_una + tp->bw_est.space;
	tp->bw_est.time = now;
}

/**
 * Returns 1 if we should enable MPTCP for that socket.
 */
int mptcp_doit(struct sock *sk)
{
	/* Socket may already be established (e.g., called from tcp_recvmsg) */
	if (tcp_sk(sk)->mpc || tcp_sk(sk)->request_mptcp)
		return 1;

	if (!sysctl_mptcp_enabled)
		return 0;

	/* Don't do mptcp over loopback or local addresses */
	if (sk->sk_family == AF_INET &&
	    (ipv4_is_loopback(inet_sk(sk)->inet_daddr) ||
	     ipv4_is_loopback(inet_sk(sk)->inet_saddr)))
		return 0;
	if (sk->sk_family == AF_INET6 &&
	    (ipv6_addr_loopback(&inet6_sk(sk)->daddr) ||
	     ipv6_addr_loopback(&inet6_sk(sk)->saddr)))
		return 0;
	if (mptcp_v6_is_v4_mapped(sk) && ipv4_is_loopback(inet_sk(sk)->inet_saddr))
		return 0;

	return 1;
}

void mptcp_set_state(struct sock *sk, int state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int oldstate = sk->sk_state;

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED && tp->mpc) {
			struct sock *meta_sk = mptcp_meta_sk(sk);
			tcp_sk(sk)->mpcb->cnt_established++;
			mptcp_update_sndbuf(tp->mpcb);
			if ((1 << meta_sk->sk_state) &
				(TCPF_SYN_SENT | TCPF_SYN_RECV))
				meta_sk->sk_state = TCP_ESTABLISHED;
		}
		break;
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		/* We set the mpcb state to SYN_SENT even if the peer
		 * has no support for MPTCP. This is the only option
		 * as we don't know yet if he is MP_CAPABLE.
		 */
		if (tp->mpcb && is_master_tp(tp))
			mptcp_meta_sk(sk)->sk_state = state;
		break;
	case TCP_CLOSE:
		if (tcp_sk(sk)->mpcb && oldstate != TCP_SYN_SENT &&
		    oldstate != TCP_SYN_RECV && oldstate != TCP_LISTEN)
			tcp_sk(sk)->mpcb->cnt_established--;
	}
}

int mptcp_check_req_master(struct sock *child, struct request_sock *req,
			   struct multipath_options *mopt)
{
	struct tcp_sock *child_tp = tcp_sk(child);

	/* Copy mptcp related info from req to child
	 * we do this here because this is shared between
	 * ipv4 and ipv6
	 */
	child_tp->rx_opt.saw_mpc = req->saw_mpc;
	if (child_tp->rx_opt.saw_mpc) {
		struct mptcp_cb *mpcb;

		child_tp->rx_opt.saw_mpc = 0;
		child_tp->slave_sk = 0;
		child_tp->path_index = 1;

		/* Just set this values to pass them to mptcp_alloc_mpcb */
		child_tp->mptcp_loc_key = req->mptcp_loc_key;
		child_tp->mptcp_loc_token = req->mptcp_loc_token;
		child_tp->mptcp_rem_key = req->mptcp_rem_key;

		if (mptcp_alloc_mpcb(child)) {
			/* The allocation of the mpcb failed!
			 * Destroy the child and go to listen_overflow
			 */
			sock_orphan(child);
			tcp_done(child);
			return -ENOBUFS;
		}
		child_tp->mpc = 1;
		mpcb = child_tp->mpcb;

		inet_sk(child)->loc_id = 0;
		inet_sk(child)->rem_id = 0;

		mptcp_add_sock(mpcb, child_tp);

		if (mopt->list_rcvd) {
			memcpy(&mpcb->rx_opt, mopt, sizeof(*mopt));
			mpcb->rx_opt.mptcp_rem_key = req->mptcp_rem_key;
		}

		mpcb->rx_opt.dss_csum = sysctl_mptcp_checksum || req->dss_csum;
		mpcb->rx_opt.mpcb = mpcb;

		mpcb->server_side = 1;
		/* Will be moved to ESTABLISHED by
		 * tcp_rcv_state_process()
		 */
		mpcb_meta_sk(mpcb)->sk_state = TCP_SYN_RECV;
		mptcp_update_metasocket(child, mpcb);

		/* Needs to be done here additionally, because when accepting a
		 * new connection we pass by __reqsk_free and not reqsk_free.
		 */
		mptcp_reqsk_remove_tk(req);

		 /* hold in mptcp_inherit_sk due to initialization to 2 */
		sock_put(mpcb_meta_sk(mpcb));
	} else {
		child_tp->mpcb = NULL;
	}

	return 0;
}

struct sock *mptcp_check_req_child(struct sock *meta_sk, struct sock *child,
				   struct request_sock *req,
				   struct request_sock **prev)
{
	struct tcp_sock *child_tp = tcp_sk(child);
	struct mptcp_cb *mpcb = req->mpcb;
	u8 hash_mac_check[20];

	if (!mpcb->rx_opt.mptcp_opt_type == MPTCP_MP_JOIN_TYPE_ACK)
		goto teardown;

	mptcp_hmac_sha1((u8 *)&mpcb->rx_opt.mptcp_rem_key,
			(u8 *)&mpcb->mptcp_loc_key,
			(u8 *)&req->mptcp_rem_nonce,
			(u8 *)&req->mptcp_loc_nonce,
			(u32 *)hash_mac_check);

	if (memcmp(hash_mac_check, (char *)&mpcb->rx_opt.mptcp_recv_mac, 20))
		goto teardown;

	child_tp->path_index = mptcp_set_new_pathindex(mpcb);
	/* No more space for more subflows? */
	if (!child_tp->path_index)
		goto teardown;

	/* The child is a clone of the meta socket, we must now reset
	 * some of the fields
	 */
	child_tp->mpc = 1;
	child_tp->slave_sk = 1;
	child_tp->bw_est.time = 0;
	child_tp->rx_opt.low_prio = req->low_prio;
	child->sk_sndmsg_page = NULL;

	inet_sk(child)->loc_id = mptcp_get_loc_addrid(mpcb, child);
	inet_sk(child)->rem_id = req->rem_id;

	/* Point it to the same struct socket and wq as the meta_sk */
	sk_set_socket(child, mpcb_meta_sk(mpcb)->sk_socket);
	child->sk_wq = mpcb_meta_sk(mpcb)->sk_wq;

	mptcp_add_sock(mpcb, child_tp);

	/* Subflows do not use the accept queue, as they
	 * are attached immediately to the mpcb.
	 */
	inet_csk_reqsk_queue_drop(meta_sk, req, prev);
	return child;

teardown:
	sock_orphan(child);
	tcp_done(child);
	return meta_sk;
}

/* General initialization of mptcp */
static int __init mptcp_init(void)
{
#ifdef CONFIG_SYSCTL
	register_sysctl_table(mptcp_root_table);
#endif
	mpcb_cache = kmem_cache_create("mptcp_mpcb", sizeof(struct mptcp_cb),
				       0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);
	mptcp_ofo_queue_init();
	return 0;
}
module_init(mptcp_init);

MODULE_LICENSE("GPL");
