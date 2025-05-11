/*
 * Minimal pfvar.h for compilation with PFVAR_NEW_STYLE on macOS
 */
#ifndef _NET_PFVAR_H_
#define _NET_PFVAR_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

union pf_rule_ptr {
	struct pf_rule		*ptr		__attribute__((aligned(8)));
	u_int32_t		 nr		__attribute__((aligned(8)));
};

struct pfioc_rule {
	u_int32_t	 action;
	u_int32_t	 ticket;
	u_int32_t	 pool_ticket;
	u_int32_t	 nr;
	char		 anchor[MAXPATHLEN];
	char		 anchor_call[MAXPATHLEN];
	struct pf_rule	 rule;
};

struct pfioc_pooladdr {
	u_int32_t		 action;
	u_int32_t		 ticket;
	u_int32_t		 nr;
	u_int32_t		 r_num;
	u_int32_t		 r_action;
	char			 r_path[MAXPATHLEN];
	struct pf_pooladdr	 addr;
};

struct pfioc_natlook {
	struct pf_addr	 saddr;
	struct pf_addr	 daddr;
	struct pf_addr	 rsaddr;
	struct pf_addr	 rdaddr;
	u_int16_t	 sport;
	u_int16_t	 dport;
	u_int16_t	 rsport;
	u_int16_t	 rdport;
	sa_family_t	 af;
	u_int8_t	 proto;
	u_int8_t	 direction;
};

struct pf_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		u_int8_t		addr8[16];
		u_int16_t		addr16[8];
		u_int32_t		addr32[4];
	} pfa;
};

#define addr8   pfa._addr8
#define addr16  pfa._addr16
#define addr32  pfa._addr32
#define v4      pfa.v4
#define v6      pfa.v6

/* PF device */
#define PFDEV		"/dev/pf"

/* DIOCNATLOOK/DIOCRDR status values */
#define DIOCRDR_SUCCESS	  0
#define DIOCRDR_NOTFOUND  1
#define DIOCRDR_BADAF	  2
#define DIOCRDR_NOROUTE	  3
#define DIOCRDR_BADROUTE  4
#define DIOCRDR_NOTSUPP   5
#define DIOCRDR_INUSE     6

/* ioctl operations */
#define DIOCADDRULE	_IOWR('D', 4, struct pfioc_rule)
#define DIOCGETRULES	_IOWR('D', 6, struct pfioc_rule)
#define DIOCGETRULE	_IOWR('D', 7, struct pfioc_rule)
#define DIOCNATLOOK	_IOWR('D', 23, struct pfioc_natlook)
#define DIOCSETLIMIT  _IOWR('D', 41, struct pfioc_limit) /* Not implemented */
#define DIOCADDRULEXP _IOWR('D', 45, struct pfioc_rulext) /* Not implemented */
#define DIOCGETRULEXP _IOWR('D', 46, struct pfioc_rulext) /* Not implemented */

#endif /* _NET_PFVAR_H_ */