#ifndef _NF_CONNTRACK_MPTCP_H
#define _NF_CONNTRACK_MPTCP_H

#include <linux/list.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>

#include <asm/byteorder.h>


#define NF_MPTCP_HASH_SIZE 1024

/* MPTCP options */
#define OPTION_TYPE_SYN		(1 << 0)
#define OPTION_TYPE_SYNACK	(1 << 1)
#define OPTION_TYPE_ACK		(1 << 2)
#define OPTION_MP_CAPABLE	(1 << 3)
#define OPTION_DATA_ACK		(1 << 4)
#define OPTION_ADD_ADDR		(1 << 5)
#define OPTION_MP_JOIN		(1 << 6)
#define OPTION_MP_FAIL		(1 << 7)
#define OPTION_MP_FCLOSE	(1 << 8)
#define OPTION_REMOVE_ADDR	(1 << 9)
#define OPTION_MP_PRIO		(1 << 10)

struct mptcp_option {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};


struct nf_mptcp_conn {
    struct nf_conn conn;
    u32 token; /* XXX not needed if token in tuple */
    struct list_head collide_tk; 
};

#endif /* _NF_CONNTRACK_MPTCP_H */
