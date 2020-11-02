#ifndef NFTABLES_TCPOPT_H
#define NFTABLES_TCPOPT_H

#include <proto.h>
#include <exthdr.h>
#include <statement.h>

extern struct expr *tcpopt_expr_alloc(const struct location *loc,
				      unsigned int kind, unsigned int field);

extern void tcpopt_init_raw(struct expr *expr, uint8_t type,
			    unsigned int offset, unsigned int len,
			    uint32_t flags);

extern bool tcpopt_find_template(struct expr *expr, const struct expr *mask,
				 unsigned int *shift);

/* TCP option numbers used on wire */
enum tcpopt_kind {
	TCPOPT_KIND_EOL = 0,
	TCPOPT_KIND_NOP = 1,
	TCPOPT_KIND_MAXSEG = 2,
	TCPOPT_KIND_WINDOW = 3,
	TCPOPT_KIND_SACK_PERMITTED = 4,
	TCPOPT_KIND_SACK = 5,
	TCPOPT_KIND_TIMESTAMP = 8,
	TCPOPT_KIND_ECHO = 8,
	__TCPOPT_KIND_MAX,

	/* extra oob info, internal to nft */
	TCPOPT_KIND_SACK1 = 256,
	TCPOPT_KIND_SACK2 = 257,
	TCPOPT_KIND_SACK3 = 258,
};

enum tcpopt_hdr_fields {
	TCPOPTHDR_FIELD_INVALID,
	TCPOPTHDR_FIELD_KIND,
	TCPOPTHDR_FIELD_LENGTH,
	TCPOPTHDR_FIELD_SIZE,
	TCPOPTHDR_FIELD_COUNT,
	TCPOPTHDR_FIELD_LEFT,
	TCPOPTHDR_FIELD_RIGHT,
	TCPOPTHDR_FIELD_TSVAL,
	TCPOPTHDR_FIELD_TSECR,
};

extern const struct exthdr_desc *tcpopt_protocols[__TCPOPT_KIND_MAX];

#endif /* NFTABLES_TCPOPT_H */
