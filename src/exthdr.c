/*
 * Exthdr expression protocol and type definitions and related functions.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <utils.h>
#include <headers.h>
#include <expression.h>
#include <statement.h>

static void exthdr_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	if (expr->exthdr.op == NFT_EXTHDR_OP_TCPOPT) {
		/* Offset calculation is a bit hacky at this point.
		 * There might be a tcp option one day with another
		 * multiplicator
		 */
		unsigned int offset = expr->exthdr.offset / 64;

		nft_print(octx, "tcp option %s", expr->exthdr.desc->name);
		if (expr->exthdr.flags & NFT_EXTHDR_F_PRESENT)
			return;
		if (offset)
			nft_print(octx, "%d", offset);
		nft_print(octx, " %s", expr->exthdr.tmpl->token);
	} else if (expr->exthdr.op == NFT_EXTHDR_OP_IPV4) {
		nft_print(octx, "ip option %s", expr->exthdr.desc->name);
		if (expr->exthdr.flags & NFT_EXTHDR_F_PRESENT)
			return;
		nft_print(octx, " %s", expr->exthdr.tmpl->token);
	} else {
		if (expr->exthdr.flags & NFT_EXTHDR_F_PRESENT)
			nft_print(octx, "exthdr %s", expr->exthdr.desc->name);
		else {
			nft_print(octx, "%s %s",
				  expr->exthdr.desc ? expr->exthdr.desc->name : "unknown-exthdr",
				  expr->exthdr.tmpl->token);
		}
	}
}

static bool exthdr_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->exthdr.desc == e2->exthdr.desc &&
	       e1->exthdr.tmpl == e2->exthdr.tmpl &&
	       e1->exthdr.op == e2->exthdr.op &&
	       e1->exthdr.flags == e2->exthdr.flags;
}

static void exthdr_expr_clone(struct expr *new, const struct expr *expr)
{
	new->exthdr.desc = expr->exthdr.desc;
	new->exthdr.tmpl = expr->exthdr.tmpl;
	new->exthdr.offset = expr->exthdr.offset;
	new->exthdr.op = expr->exthdr.op;
	new->exthdr.flags = expr->exthdr.flags;
}

const struct expr_ops exthdr_expr_ops = {
	.type		= EXPR_EXTHDR,
	.name		= "exthdr",
	.print		= exthdr_expr_print,
	.json		= exthdr_expr_json,
	.cmp		= exthdr_expr_cmp,
	.clone		= exthdr_expr_clone,
};

static const struct proto_hdr_template exthdr_unknown_template =
	PROTO_HDR_TEMPLATE("unknown", &invalid_type, BYTEORDER_INVALID, 0, 0);

struct expr *exthdr_expr_alloc(const struct location *loc,
			       const struct exthdr_desc *desc,
			       uint8_t type)
{
	const struct proto_hdr_template *tmpl;
	struct expr *expr;

	if (desc != NULL)
		tmpl = &desc->templates[type];
	else
		tmpl = &exthdr_unknown_template;

	expr = expr_alloc(loc, EXPR_EXTHDR, tmpl->dtype,
			  BYTEORDER_BIG_ENDIAN, tmpl->len);
	expr->exthdr.desc = desc;
	expr->exthdr.tmpl = tmpl;
	return expr;
}

static void exthdr_stmt_print(const struct stmt *stmt, struct output_ctx *octx)
{
	expr_print(stmt->exthdr.expr, octx);
	nft_print(octx, " set ");
	expr_print(stmt->exthdr.val, octx);
}

static void exthdr_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->exthdr.expr);
	expr_free(stmt->exthdr.val);
}

static const struct stmt_ops exthdr_stmt_ops = {
	.type		= STMT_EXTHDR,
	.name		= "exthdr",
	.print		= exthdr_stmt_print,
	.json		= exthdr_stmt_json,
	.destroy	= exthdr_stmt_destroy,
};

struct stmt *exthdr_stmt_alloc(const struct location *loc,
				struct expr *expr, struct expr *val)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &exthdr_stmt_ops);
	stmt->exthdr.expr = expr;
	stmt->exthdr.val  = val;
	return stmt;
}

static const struct exthdr_desc *exthdr_protocols[IPPROTO_MAX] = {
	[IPPROTO_HOPOPTS]	= &exthdr_hbh,
	[IPPROTO_ROUTING]	= &exthdr_rt,
	[IPPROTO_FRAGMENT]	= &exthdr_frag,
	[IPPROTO_DSTOPTS]	= &exthdr_dst,
	[IPPROTO_MH]		= &exthdr_mh,
};

const struct exthdr_desc *exthdr_find_proto(uint8_t proto)
{
	assert(exthdr_protocols[proto]);

	return exthdr_protocols[proto];
}

static const struct proto_hdr_template *
exthdr_rt_find(struct expr *expr, const struct exthdr_desc *desc)
{
	const struct proto_hdr_template *tmpl;
	unsigned int i;

	for (i = 0; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset == expr->exthdr.offset &&
		    tmpl->len == expr->len) {
			expr->exthdr.desc = desc;
			return tmpl;
		}
	}

	return NULL;
}

void exthdr_init_raw(struct expr *expr, uint8_t type,
		     unsigned int offset, unsigned int len,
		     enum nft_exthdr_op op, uint32_t flags)
{
	const struct proto_hdr_template *tmpl = &exthdr_unknown_template;
	unsigned int i;

	assert(expr->etype == EXPR_EXTHDR);
	if (op == NFT_EXTHDR_OP_TCPOPT)
		return tcpopt_init_raw(expr, type, offset, len, flags);
	if (op == NFT_EXTHDR_OP_IPV4)
		return ipopt_init_raw(expr, type, offset, len, flags, true);

	expr->len = len;
	expr->exthdr.flags = flags;
	expr->exthdr.offset = offset;
	expr->exthdr.desc = NULL;

	if (type < array_size(exthdr_protocols))
		expr->exthdr.desc = exthdr_protocols[type];

	if (expr->exthdr.desc == NULL)
		goto out;

	for (i = 0; i < array_size(expr->exthdr.desc->templates); i++) {
		tmpl = &expr->exthdr.desc->templates[i];
		if (tmpl->offset == offset && tmpl->len == len)
			goto out;
	}

	if (expr->exthdr.desc == &exthdr_rt) {
		tmpl = exthdr_rt_find(expr, &exthdr_rt4);
		if (tmpl)
			goto out;
		tmpl = exthdr_rt_find(expr, &exthdr_rt0);
		if (tmpl)
			goto out;
		tmpl =	exthdr_rt_find(expr, &exthdr_rt2);
		if (tmpl)
			goto out;
	}

	tmpl = &exthdr_unknown_template;
 out:
	expr->exthdr.tmpl = tmpl;
	if (flags & NFT_EXTHDR_F_PRESENT)
		datatype_set(expr, &boolean_type);
	else
		datatype_set(expr, tmpl->dtype);
}

static unsigned int mask_length(const struct expr *mask)
{
	unsigned long off = mpz_scan1(mask->value, 0);

	return mpz_scan0(mask->value, off + 1);
}

bool exthdr_find_template(struct expr *expr, const struct expr *mask, unsigned int *shift)
{
	unsigned int off, mask_offset, mask_len;

	if (expr->exthdr.op != NFT_EXTHDR_OP_IPV4 &&
	    expr->exthdr.tmpl != &exthdr_unknown_template)
		return false;

	/* In case we are handling tcp options instead of the default ipv6
	 * extension headers.
	 */
	if (expr->exthdr.op == NFT_EXTHDR_OP_TCPOPT)
		return tcpopt_find_template(expr, mask, shift);

	mask_offset = mpz_scan1(mask->value, 0);
	mask_len = mask_length(mask);

	off = expr->exthdr.offset;
	off += round_up(mask->len, BITS_PER_BYTE) - mask_len;

	/* Handle ip options after the offset and mask have been calculated. */
	if (expr->exthdr.op == NFT_EXTHDR_OP_IPV4) {
		if (ipopt_find_template(expr, off, mask_len - mask_offset)) {
			*shift = mask_offset;
			return true;
		} else {
			return false;
		}
	}

	exthdr_init_raw(expr, expr->exthdr.desc->type,
			off, mask_len - mask_offset, expr->exthdr.op, 0);

	/* still failed to find a template... Bug. */
	if (expr->exthdr.tmpl == &exthdr_unknown_template)
		return false;

	*shift = mask_offset;
	return true;
}

#define HDR_TEMPLATE(__name, __dtype, __type, __member)			\
	PROTO_HDR_TEMPLATE(__name, __dtype,				\
			   BYTEORDER_BIG_ENDIAN,			\
			   offsetof(__type, __member) * 8,		\
			   field_sizeof(__type, __member) * 8)

/*
 * Hop-by-hop options
 */

#define HBH_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_hbh, __member)

const struct exthdr_desc exthdr_hbh = {
	.name		= "hbh",
	.type		= IPPROTO_HOPOPTS,
	.templates	= {
		[HBHHDR_NEXTHDR]	= HBH_FIELD("nexthdr", ip6h_nxt, &inet_protocol_type),
		[HBHHDR_HDRLENGTH]	= HBH_FIELD("hdrlength", ip6h_len, &integer_type),
	},
};

/*
 * Routing header
 */

const struct exthdr_desc exthdr_rt2 = {
	.name           = "rt2",
	.type           = IPPROTO_ROUTING,
	.proto_key	= 2,
	.templates	= {
		[RT2HDR_RESERVED]	= {},
		[RT2HDR_ADDR]		= {},
	},
};

#define RT0_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_rthdr0, __member)

const struct exthdr_desc exthdr_rt0 = {
	.name           = "rt0",
	.type           = IPPROTO_ROUTING,
	.proto_key      = 0,
	.templates	= {
		[RT0HDR_RESERVED]	= RT0_FIELD("reserved", ip6r0_reserved, &integer_type),
		[RT0HDR_ADDR_1]		= RT0_FIELD("addr[1]", ip6r0_addr[0], &ip6addr_type),
		[RT0HDR_ADDR_1 + 1]	= RT0_FIELD("addr[2]", ip6r0_addr[1], &ip6addr_type),
		// ...
	},
};

#define RT4_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_rt4, __member)

const struct exthdr_desc exthdr_rt4 = {
	.name		= "srh",
	.type		= IPPROTO_ROUTING,
	.proto_key	= 4,
	.templates      = {
		[RT4HDR_LASTENT]	= RT4_FIELD("last-entry", ip6r4_last_entry, &integer_type),
		[RT4HDR_FLAGS]		= RT4_FIELD("flags", ip6r4_flags, &integer_type),
		[RT4HDR_TAG]		= RT4_FIELD("tag", ip6r4_tag, &integer_type),
		[RT4HDR_SID_1]		= RT4_FIELD("sid[1]", ip6r4_segments[0], &ip6addr_type),
		[RT4HDR_SID_1 + 1]	= RT4_FIELD("sid[2]", ip6r4_segments[1], &ip6addr_type),
		// ...
	},
};


#define RT_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_rthdr, __member)

const struct exthdr_desc exthdr_rt = {
	.name		= "rt",
	.type		= IPPROTO_ROUTING,
	.proto_key      = -1,
#if 0
	.protocol_key	= RTHDR_TYPE,
	.protocols	= {
		[0]	= &exthdr_rt0,
		[2]	= &exthdr_rt2,
	},
#endif
	.templates	= {
		[RTHDR_NEXTHDR]		= RT_FIELD("nexthdr", ip6r_nxt, &inet_protocol_type),
		[RTHDR_HDRLENGTH]	= RT_FIELD("hdrlength", ip6r_len, &integer_type),
		[RTHDR_TYPE]		= RT_FIELD("type", ip6r_type, &integer_type),
		[RTHDR_SEG_LEFT]	= RT_FIELD("seg-left", ip6r_segleft, &integer_type),
	},
};

/*
 * Fragment header
 */

#define FRAG_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_frag, __member)

const struct exthdr_desc exthdr_frag = {
	.name		= "frag",
	.type		= IPPROTO_FRAGMENT,
	.templates	= {
		[FRAGHDR_NEXTHDR]	= FRAG_FIELD("nexthdr", ip6f_nxt, &inet_protocol_type),
		[FRAGHDR_RESERVED]	= FRAG_FIELD("reserved", ip6f_reserved, &integer_type),
		[FRAGHDR_FRAG_OFF]	= PROTO_HDR_TEMPLATE("frag-off", &integer_type,
							  BYTEORDER_BIG_ENDIAN,
							  16, 13),
		[FRAGHDR_RESERVED2]	= PROTO_HDR_TEMPLATE("reserved2", &integer_type,
							  BYTEORDER_BIG_ENDIAN,
							  29, 2),
		[FRAGHDR_MFRAGS]	= PROTO_HDR_TEMPLATE("more-fragments", &integer_type,
							  BYTEORDER_BIG_ENDIAN,
							  31, 1),
		[FRAGHDR_ID]		= FRAG_FIELD("id", ip6f_ident, &integer_type),
	},
};

/*
 * DST options
 */

#define DST_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_dest, __member)

const struct exthdr_desc exthdr_dst = {
	.name		= "dst",
	.type		= IPPROTO_DSTOPTS,
	.templates	= {
		[DSTHDR_NEXTHDR]	= DST_FIELD("nexthdr", ip6d_nxt, &inet_protocol_type),
		[DSTHDR_HDRLENGTH]	= DST_FIELD("hdrlength", ip6d_len, &integer_type),
	},
};

/*
 * Mobility header
 */

#define MH_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_mh, __member)

static const struct symbol_table mh_type_tbl = {
	.base		= BASE_DECIMAL,
	.symbols	= {
		SYMBOL("binding-refresh-request",	IP6_MH_TYPE_BRR),
		SYMBOL("home-test-init",		IP6_MH_TYPE_HOTI),
		SYMBOL("careof-test-init",		IP6_MH_TYPE_COTI),
		SYMBOL("home-test",			IP6_MH_TYPE_HOT),
		SYMBOL("careof-test",			IP6_MH_TYPE_COT),
		SYMBOL("binding-update",		IP6_MH_TYPE_BU),
		SYMBOL("binding-acknowledgement",	IP6_MH_TYPE_BACK),
		SYMBOL("binding-error",			IP6_MH_TYPE_BERROR),
		SYMBOL("fast-binding-update",		IP6_MH_TYPE_FBU),
		SYMBOL("fast-binding-acknowledgement",	IP6_MH_TYPE_FBACK),
		SYMBOL("fast-binding-advertisement",	IP6_MH_TYPE_FNA),
		SYMBOL("experimental-mobility-header",	IP6_MH_TYPE_EMH),
		SYMBOL("home-agent-switch-message",	IP6_MH_TYPE_HASM),
		SYMBOL_LIST_END
	},
};

const struct datatype mh_type_type = {
	.type		= TYPE_MH_TYPE,
	.name		= "mh_type",
	.desc		= "Mobility Header Type",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &mh_type_tbl,
};

const struct exthdr_desc exthdr_mh = {
	.name		= "mh",
	.type		= IPPROTO_MH,
	.templates	= {
		[MHHDR_NEXTHDR]		= MH_FIELD("nexthdr", ip6mh_proto, &inet_protocol_type),
		[MHHDR_HDRLENGTH]	= MH_FIELD("hdrlength", ip6mh_hdrlen, &integer_type),
		[MHHDR_TYPE]		= MH_FIELD("type", ip6mh_type, &mh_type_type),
		[MHHDR_RESERVED]	= MH_FIELD("reserved", ip6mh_reserved, &integer_type),
		[MHHDR_CHECKSUM]	= MH_FIELD("checksum", ip6mh_cksum, &integer_type),
	},
};
