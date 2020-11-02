#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <utils.h>
#include <headers.h>
#include <expression.h>
#include <tcpopt.h>

static const struct proto_hdr_template tcpopt_unknown_template =
	PROTO_HDR_TEMPLATE("unknown", &invalid_type, BYTEORDER_INVALID, 0, 0);

#define PHT(__token, __offset, __len) \
	PROTO_HDR_TEMPLATE(__token, &integer_type, BYTEORDER_BIG_ENDIAN, \
			   __offset, __len)
static const struct exthdr_desc tcpopt_eol = {
	.name		= "eol",
	.type		= TCPOPT_KIND_EOL,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",  0,    8),
	},
};

static const struct exthdr_desc tcpopt_nop = {
	.name		= "noop",
	.type		= TCPOPT_KIND_NOP,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,   8),
	},
};

static const struct exthdr_desc tcptopt_maxseg = {
	.name		= "maxseg",
	.type		= TCPOPT_KIND_MAXSEG,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_SIZE]		= PHT("size",  16, 16),
	},
};

static const struct exthdr_desc tcpopt_window = {
	.name		= "window",
	.type		= TCPOPT_KIND_WINDOW,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_COUNT]		= PHT("count", 16,  8),
	},
};

static const struct exthdr_desc tcpopt_sack_permitted = {
	.name		= "sack-perm",
	.type		= TCPOPT_KIND_SACK_PERMITTED,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0, 8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8, 8),
	},
};

static const struct exthdr_desc tcpopt_sack = {
	.name		= "sack",
	.type		= TCPOPT_KIND_SACK,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,   8),
		[TCPOPTHDR_FIELD_LENGTH]		= PHT("length", 8,   8),
		[TCPOPTHDR_FIELD_LEFT]		= PHT("left",  16,  32),
		[TCPOPTHDR_FIELD_RIGHT]		= PHT("right", 48,  32),
	},
};

static const struct exthdr_desc tcpopt_timestamp = {
	.name		= "timestamp",
	.type		= TCPOPT_KIND_TIMESTAMP,
	.templates	= {
		[TCPOPTHDR_FIELD_KIND]		= PHT("kind",   0,  8),
		[TCPOPTHDR_FIELD_LENGTH]	= PHT("length", 8,  8),
		[TCPOPTHDR_FIELD_TSVAL]		= PHT("tsval",  16, 32),
		[TCPOPTHDR_FIELD_TSECR]		= PHT("tsecr",  48, 32),
	},
};
#undef PHT

const struct exthdr_desc *tcpopt_protocols[] = {
	[TCPOPT_KIND_EOL]		= &tcpopt_eol,
	[TCPOPT_KIND_NOP]		= &tcpopt_nop,
	[TCPOPT_KIND_MAXSEG]		= &tcptopt_maxseg,
	[TCPOPT_KIND_WINDOW]		= &tcpopt_window,
	[TCPOPT_KIND_SACK_PERMITTED]	= &tcpopt_sack_permitted,
	[TCPOPT_KIND_SACK]		= &tcpopt_sack,
	[TCPOPT_KIND_TIMESTAMP]		= &tcpopt_timestamp,
};

static unsigned int calc_offset(const struct exthdr_desc *desc,
				const struct proto_hdr_template *tmpl,
				unsigned int num)
{
	if (!desc || tmpl == &tcpopt_unknown_template)
		return 0;

	switch (desc->type) {
	case TCPOPT_SACK:
		/* Make sure, offset calculations only apply to left and right
		 * fields
		 */
		return (tmpl->offset < 16) ? 0 : num * 64;
	default:
		return 0;
	}
}


static unsigned int calc_offset_reverse(const struct exthdr_desc *desc,
					const struct proto_hdr_template *tmpl,
					unsigned int offset)
{
	if (!desc || tmpl == &tcpopt_unknown_template)
		return offset;

	switch (desc->type) {
	case TCPOPT_SACK:
		/* We can safely ignore the first left/right field */
		return offset < 80 ? offset : (offset % 64);
	default:
		return offset;
	}
}

struct expr *tcpopt_expr_alloc(const struct location *loc,
			       unsigned int kind,
			       unsigned int field)
{
	const struct proto_hdr_template *tmpl;
	const struct exthdr_desc *desc;
	uint8_t optnum = 0;
	struct expr *expr;

	switch (kind) {
	case TCPOPT_KIND_SACK1:
		kind = TCPOPT_KIND_SACK;
		optnum = 1;
		break;
	case TCPOPT_KIND_SACK2:
		kind = TCPOPT_KIND_SACK;
		optnum = 2;
		break;
	case TCPOPT_KIND_SACK3:
		kind = TCPOPT_KIND_SACK;
		optnum = 3;
	}

	desc = tcpopt_protocols[kind];
	tmpl = &desc->templates[field];
	if (!tmpl)
		return NULL;

	expr = expr_alloc(loc, EXPR_EXTHDR, tmpl->dtype,
			  BYTEORDER_BIG_ENDIAN, tmpl->len);
	expr->exthdr.desc   = desc;
	expr->exthdr.tmpl   = tmpl;
	expr->exthdr.op     = NFT_EXTHDR_OP_TCPOPT;
	expr->exthdr.offset = calc_offset(desc, tmpl, optnum);

	return expr;
}

void tcpopt_init_raw(struct expr *expr, uint8_t type, unsigned int offset,
		     unsigned int len, uint32_t flags)
{
	const struct proto_hdr_template *tmpl;
	unsigned int i, off;

	assert(expr->etype == EXPR_EXTHDR);

	expr->len = len;
	expr->exthdr.flags = flags;
	expr->exthdr.offset = offset;

	assert(type < array_size(tcpopt_protocols));
	expr->exthdr.desc = tcpopt_protocols[type];
	expr->exthdr.flags = flags;
	assert(expr->exthdr.desc != NULL);

	for (i = 0; i < array_size(expr->exthdr.desc->templates); ++i) {
		tmpl = &expr->exthdr.desc->templates[i];
		/* We have to reverse calculate the offset for the sack options
		 * at this point
		 */
		off = calc_offset_reverse(expr->exthdr.desc, tmpl, offset);
		if (tmpl->offset != off || tmpl->len != len)
			continue;

		if (flags & NFT_EXTHDR_F_PRESENT)
			datatype_set(expr, &boolean_type);
		else
			datatype_set(expr, tmpl->dtype);
		expr->exthdr.tmpl = tmpl;
		expr->exthdr.op   = NFT_EXTHDR_OP_TCPOPT;
		break;
	}
}

bool tcpopt_find_template(struct expr *expr, const struct expr *mask,
			  unsigned int *shift)
{
	if (expr->exthdr.tmpl != &tcpopt_unknown_template)
		return false;

	tcpopt_init_raw(expr, expr->exthdr.desc->type, expr->exthdr.offset,
			expr->len, 0);

	if (expr->exthdr.tmpl == &tcpopt_unknown_template)
		return false;

	return true;
}
