/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/netfilter/nf_tables.h>

#include <string.h>
#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <netlink.h>
#include <gmputil.h>
#include <utils.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <libnftnl/udata.h>


struct netlink_linearize_ctx {
	struct nftnl_rule	*nlr;
	unsigned int		reg_low;
};

static void netlink_put_register(struct nftnl_expr *nle,
				 uint32_t attr, uint32_t reg)
{
	/* Convert to 128 bit register numbers if possible for compatibility */
	if (reg != NFT_REG_VERDICT) {
		reg -= NFT_REG_1;
		if (reg % (NFT_REG_SIZE / NFT_REG32_SIZE) == 0)
			reg = NFT_REG_1 + reg / (NFT_REG_SIZE / NFT_REG32_SIZE);
		else
			reg += NFT_REG32_00;
	}

	nftnl_expr_set_u32(nle, attr, reg);
}

static enum nft_registers __get_register(struct netlink_linearize_ctx *ctx,
					 unsigned int size)
{
	unsigned int reg, n;

	n = netlink_register_space(size);
	if (ctx->reg_low + n > NFT_REG_1 + NFT_REG32_15 - NFT_REG32_00 + 1)
		BUG("register reg_low %u invalid\n", ctx->reg_low);

	reg = ctx->reg_low;
	ctx->reg_low += n;
	return reg;
}

static void __release_register(struct netlink_linearize_ctx *ctx,
			       unsigned int size)
{
	unsigned int n;

	n = netlink_register_space(size);
	if (ctx->reg_low < NFT_REG_1 + n)
		BUG("register reg_low %u invalid\n", ctx->reg_low);

	ctx->reg_low -= n;
}

static enum nft_registers get_register(struct netlink_linearize_ctx *ctx,
				       const struct expr *expr)
{
	if (expr && expr->etype == EXPR_CONCAT)
		return __get_register(ctx, expr->len);
	else
		return __get_register(ctx, NFT_REG_SIZE * BITS_PER_BYTE);
}

static void release_register(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr)
{
	if (expr && expr->etype == EXPR_CONCAT)
		__release_register(ctx, expr->len);
	else
		__release_register(ctx, NFT_REG_SIZE * BITS_PER_BYTE);
}

static void netlink_gen_expr(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg);

static void netlink_gen_concat(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	const struct expr *i;

	list_for_each_entry(i, &expr->expressions, list) {
		netlink_gen_expr(ctx, i, dreg);
		dreg += netlink_register_space(i->len);
	}
}

static void netlink_gen_fib(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("fib");
	netlink_put_register(nle, NFTNL_EXPR_FIB_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_FIB_RESULT, expr->fib.result);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_FIB_FLAGS, expr->fib.flags);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_hash(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	enum nft_registers sreg;
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("hash");

	if (expr->hash.expr) {
		sreg = get_register(ctx, expr->hash.expr);
		netlink_gen_expr(ctx, expr->hash.expr, sreg);
		release_register(ctx, expr->hash.expr);
		netlink_put_register(nle, NFTNL_EXPR_HASH_SREG, sreg);

		nftnl_expr_set_u32(nle, NFTNL_EXPR_HASH_LEN,
				   div_round_up(expr->hash.expr->len,
						BITS_PER_BYTE));
	}
	netlink_put_register(nle, NFTNL_EXPR_HASH_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_HASH_MODULUS, expr->hash.mod);
	if (expr->hash.seed_set)
		nftnl_expr_set_u32(nle, NFTNL_EXPR_HASH_SEED, expr->hash.seed);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_HASH_OFFSET, expr->hash.offset);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_HASH_TYPE, expr->hash.type);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_payload(struct netlink_linearize_ctx *ctx,
				const struct expr *expr,
				enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("payload");
	netlink_put_register(nle, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_BASE,
			   expr->payload.base - 1);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_OFFSET,
			   expr->payload.offset / BITS_PER_BYTE);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_LEN,
			   div_round_up(expr->len, BITS_PER_BYTE));

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_exthdr(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	unsigned int offset = expr->exthdr.tmpl->offset + expr->exthdr.offset;
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("exthdr");
	netlink_put_register(nle, NFTNL_EXPR_EXTHDR_DREG, dreg);
	nftnl_expr_set_u8(nle, NFTNL_EXPR_EXTHDR_TYPE,
			  expr->exthdr.desc->type);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_OFFSET, offset / BITS_PER_BYTE);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_LEN,
			   div_round_up(expr->len, BITS_PER_BYTE));
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_OP, expr->exthdr.op);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_FLAGS, expr->exthdr.flags);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("meta");
	netlink_put_register(nle, NFTNL_EXPR_META_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_META_KEY, expr->meta.key);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_rt(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("rt");
	netlink_put_register(nle, NFTNL_EXPR_RT_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_RT_KEY, expr->rt.key);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_socket(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("socket");
	netlink_put_register(nle, NFTNL_EXPR_SOCKET_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_SOCKET_KEY, expr->socket.key);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_osf(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("osf");
	netlink_put_register(nle, NFTNL_EXPR_OSF_DREG, dreg);
	nftnl_expr_set_u8(nle, NFTNL_EXPR_OSF_TTL, expr->osf.ttl);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_OSF_FLAGS, expr->osf.flags);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_numgen(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("numgen");
	netlink_put_register(nle, NFTNL_EXPR_NG_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_NG_TYPE, expr->numgen.type);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_NG_MODULUS, expr->numgen.mod);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_NG_OFFSET, expr->numgen.offset);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_ct(struct netlink_linearize_ctx *ctx,
			   const struct expr *expr,
			   enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("ct");
	netlink_put_register(nle, NFTNL_EXPR_CT_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CT_KEY, expr->ct.key);
	if (expr->ct.direction >= 0)
		nftnl_expr_set_u8(nle, NFTNL_EXPR_CT_DIR,
				  expr->ct.direction);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_map(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg;
	int regspace = 0;

	assert(expr->mappings->etype == EXPR_SET_REF);

	if (dreg == NFT_REG_VERDICT)
		sreg = get_register(ctx, expr->map);
	else
		sreg = dreg;

	/* suppress assert in netlink_gen_expr */
	if (expr->map->etype == EXPR_CONCAT) {
		regspace = netlink_register_space(expr->map->len);
		ctx->reg_low += regspace;
	}

	netlink_gen_expr(ctx, expr->map, sreg);
	ctx->reg_low -= regspace;

	nle = alloc_nft_expr("lookup");
	netlink_put_register(nle, NFTNL_EXPR_LOOKUP_SREG, sreg);
	netlink_put_register(nle, NFTNL_EXPR_LOOKUP_DREG, dreg);
	nftnl_expr_set_str(nle, NFTNL_EXPR_LOOKUP_SET,
			   expr->mappings->set->handle.set.name);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_LOOKUP_SET_ID,
			   expr->mappings->set->handle.set_id);

	if (dreg == NFT_REG_VERDICT)
		release_register(ctx, expr->map);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_lookup(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg;

	assert(expr->right->etype == EXPR_SET_REF);
	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx, expr->left);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr("lookup");
	netlink_put_register(nle, NFTNL_EXPR_LOOKUP_SREG, sreg);
	nftnl_expr_set_str(nle, NFTNL_EXPR_LOOKUP_SET,
			   expr->right->set->handle.set.name);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_LOOKUP_SET_ID,
			   expr->right->set->handle.set_id);
	if (expr->op == OP_NEQ)
		nftnl_expr_set_u32(nle, NFTNL_EXPR_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);

	release_register(ctx, expr->left);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static enum nft_cmp_ops netlink_gen_cmp_op(enum ops op)
{
	switch (op) {
	case OP_EQ:
	case OP_IMPLICIT:
		return NFT_CMP_EQ;
	case OP_NEQ:
		return NFT_CMP_NEQ;
	case OP_LT:
		return NFT_CMP_LT;
	case OP_GT:
		return NFT_CMP_GT;
	case OP_LTE:
		return NFT_CMP_LTE;
	case OP_GTE:
		return NFT_CMP_GTE;
	default:
		BUG("invalid comparison operation %u\n", op);
	}
}

static struct expr *netlink_gen_prefix(struct netlink_linearize_ctx *ctx,
				       const struct expr *expr,
				       enum nft_registers sreg)
{
	struct nft_data_linearize nld, zero = {};
	struct nftnl_expr *nle;
	mpz_t mask;

	mpz_init(mask);
	mpz_prefixmask(mask, expr->right->len, expr->right->prefix_len);
	netlink_gen_raw_data(mask, expr->right->byteorder,
			     expr->right->len / BITS_PER_BYTE, &nld);
	mpz_clear(mask);

	zero.len = nld.len;

	nle = alloc_nft_expr("bitwise");
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_SREG, sreg);
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_DREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BITWISE_LEN, nld.len);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_MASK, &nld.value, nld.len);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_XOR, &zero.value, zero.len);
	nftnl_rule_add_expr(ctx->nlr, nle);

	return expr->right->prefix;
}

static void netlink_gen_range(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct expr *range = expr->right;
	struct nftnl_expr *nle;
	enum nft_registers sreg;
	struct nft_data_linearize nld;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx, expr->left);
	netlink_gen_expr(ctx, expr->left, sreg);

	switch (expr->op) {
	case OP_NEQ:
		nle = alloc_nft_expr("range");
		netlink_put_register(nle, NFTNL_EXPR_RANGE_SREG, sreg);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_RANGE_OP, NFT_RANGE_NEQ);
		netlink_gen_data(range->left, &nld);
		nftnl_expr_set(nle, NFTNL_EXPR_RANGE_FROM_DATA,
			       nld.value, nld.len);
		netlink_gen_data(range->right, &nld);
		nftnl_expr_set(nle, NFTNL_EXPR_RANGE_TO_DATA,
			       nld.value, nld.len);
		nftnl_rule_add_expr(ctx->nlr, nle);
		break;
	case OP_EQ:
	case OP_IMPLICIT:
		nle = alloc_nft_expr("cmp");
		netlink_put_register(nle, NFTNL_EXPR_CMP_SREG, sreg);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_CMP_OP,
				   netlink_gen_cmp_op(OP_GTE));
		netlink_gen_data(range->left, &nld);
		nftnl_expr_set(nle, NFTNL_EXPR_CMP_DATA, nld.value, nld.len);
		nftnl_rule_add_expr(ctx->nlr, nle);

		nle = alloc_nft_expr("cmp");
		netlink_put_register(nle, NFTNL_EXPR_CMP_SREG, sreg);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_CMP_OP,
				   netlink_gen_cmp_op(OP_LTE));
		netlink_gen_data(range->right, &nld);
		nftnl_expr_set(nle, NFTNL_EXPR_CMP_DATA, nld.value, nld.len);
		nftnl_rule_add_expr(ctx->nlr, nle);
		break;
	default:
		BUG("invalid range operation %u\n", expr->op);

	}

	release_register(ctx, expr->left);
}

static void netlink_gen_flagcmp(struct netlink_linearize_ctx *ctx,
				const struct expr *expr,
				enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	struct nft_data_linearize nld, nld2;
	enum nft_registers sreg;
	unsigned int len;
	mpz_t zero;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx, expr->left);
	netlink_gen_expr(ctx, expr->left, sreg);
	len = div_round_up(expr->left->len, BITS_PER_BYTE);

	mpz_init_set_ui(zero, 0);

	netlink_gen_raw_data(zero, expr->right->byteorder, len, &nld);
	netlink_gen_data(expr->right, &nld2);

	nle = alloc_nft_expr("bitwise");
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_SREG, sreg);
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_DREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BITWISE_LEN, len);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_MASK, &nld2.value, nld2.len);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_XOR, &nld.value, nld.len);
	nftnl_rule_add_expr(ctx->nlr, nle);

	nle = alloc_nft_expr("cmp");
	netlink_put_register(nle, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CMP_OP, NFT_CMP_NEQ);
	nftnl_expr_set(nle, NFTNL_EXPR_CMP_DATA, nld.value, nld.len);
	nftnl_rule_add_expr(ctx->nlr, nle);

	mpz_clear(zero);
	release_register(ctx, expr->left);
}

static void netlink_gen_relational(struct netlink_linearize_ctx *ctx,
				   const struct expr *expr,
				   enum nft_registers dreg)
{
	struct nft_data_linearize nld;
	struct nftnl_expr *nle;
	enum nft_registers sreg;
	struct expr *right;
	int len;

	assert(dreg == NFT_REG_VERDICT);

	switch (expr->op) {
	case OP_IMPLICIT:
	case OP_EQ:
	case OP_NEQ:
	case OP_LT:
	case OP_GT:
	case OP_LTE:
	case OP_GTE:
		break;
	default:
		BUG("invalid relational operation %u\n", expr->op);
	}

	switch (expr->right->etype) {
	case EXPR_RANGE:
		return netlink_gen_range(ctx, expr, dreg);
	case EXPR_SET:
	case EXPR_SET_REF:
		return netlink_gen_lookup(ctx, expr, dreg);
	case EXPR_LIST:
		return netlink_gen_flagcmp(ctx, expr, dreg);
	case EXPR_PREFIX:
		sreg = get_register(ctx, expr->left);
		if (expr_basetype(expr->left)->type != TYPE_STRING) {
			len = div_round_up(expr->right->len, BITS_PER_BYTE);
			netlink_gen_expr(ctx, expr->left, sreg);
			right = netlink_gen_prefix(ctx, expr, sreg);
		} else {
			len = div_round_up(expr->right->prefix_len, BITS_PER_BYTE);
			right = expr->right->prefix;
			expr->left->len = expr->right->prefix_len;
			netlink_gen_expr(ctx, expr->left, sreg);
		}
		break;
	default:
		if (expr->op == OP_IMPLICIT &&
		    expr->right->dtype->basetype != NULL &&
		    expr->right->dtype->basetype->type == TYPE_BITMASK)
			return netlink_gen_flagcmp(ctx, expr, dreg);

		sreg = get_register(ctx, expr->left);
		len = div_round_up(expr->right->len, BITS_PER_BYTE);
		right = expr->right;
		netlink_gen_expr(ctx, expr->left, sreg);
		break;
	}

	nle = alloc_nft_expr("cmp");
	netlink_put_register(nle, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CMP_OP,
			   netlink_gen_cmp_op(expr->op));
	netlink_gen_data(right, &nld);
	nftnl_expr_set(nle, NFTNL_EXPR_CMP_DATA, nld.value, len);
	release_register(ctx, expr->left);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void combine_binop(mpz_t mask, mpz_t xor, const mpz_t m, const mpz_t x)
{
	/* xor = x ^ (xor & m) */
	mpz_and(xor, xor, m);
	mpz_xor(xor, x, xor);
	/* mask &= m */
	mpz_and(mask, mask, m);
}

static void netlink_gen_binop(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	struct nft_data_linearize nld;
	struct expr *left, *i;
	struct expr *binops[16];
	mpz_t mask, xor, val, tmp;
	unsigned int len;
	int n = 0;

	mpz_init(mask);
	mpz_init(xor);
	mpz_init(val);
	mpz_init(tmp);

	binops[n++] = left = (void *)expr;
	while (left->etype == EXPR_BINOP && left->left != NULL)
		binops[n++] = left = left->left;
	n--;

	netlink_gen_expr(ctx, binops[n--], dreg);

	mpz_bitmask(mask, expr->len);
	mpz_set_ui(xor, 0);
	for (; n >= 0; n--) {
		i = binops[n];
		mpz_set(val, i->right->value);

		switch (i->op) {
		case OP_AND:
			mpz_set_ui(tmp, 0);
			combine_binop(mask, xor, val, tmp);
			break;
		case OP_OR:
			mpz_com(tmp, val);
			combine_binop(mask, xor, tmp, val);
			break;
		case OP_XOR:
			mpz_bitmask(tmp, expr->len);
			combine_binop(mask, xor, tmp, val);
			break;
		default:
			BUG("invalid binary operation %u\n", i->op);
		}
	}

	len = div_round_up(expr->len, BITS_PER_BYTE);

	nle = alloc_nft_expr("bitwise");
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_SREG, dreg);
	netlink_put_register(nle, NFTNL_EXPR_BITWISE_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BITWISE_LEN, len);

	netlink_gen_raw_data(mask, expr->byteorder, len, &nld);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_MASK, nld.value, nld.len);
	netlink_gen_raw_data(xor, expr->byteorder, len, &nld);
	nftnl_expr_set(nle, NFTNL_EXPR_BITWISE_XOR, nld.value, nld.len);

	mpz_clear(tmp);
	mpz_clear(val);
	mpz_clear(xor);
	mpz_clear(mask);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static enum nft_byteorder_ops netlink_gen_unary_op(enum ops op)
{
	switch (op) {
	case OP_HTON:
		return NFT_BYTEORDER_HTON;
	case OP_NTOH:
		return NFT_BYTEORDER_NTOH;
	default:
		BUG("invalid unary operation %u\n", op);
	}
}

static void netlink_gen_unary(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	int byte_size;

	if ((expr->arg->len % 64) == 0)
		byte_size = 8;
	else if ((expr->arg->len % 32) == 0)
		byte_size = 4;
	else
		byte_size = 2;

	netlink_gen_expr(ctx, expr->arg, dreg);

	nle = alloc_nft_expr("byteorder");
	netlink_put_register(nle, NFTNL_EXPR_BYTEORDER_SREG, dreg);
	netlink_put_register(nle, NFTNL_EXPR_BYTEORDER_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BYTEORDER_LEN,
			   expr->len / BITS_PER_BYTE);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BYTEORDER_SIZE,
			   byte_size);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_BYTEORDER_OP,
			   netlink_gen_unary_op(expr->op));
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_immediate(struct netlink_linearize_ctx *ctx,
				  const struct expr *expr,
				  enum nft_registers dreg)
{
	struct nftnl_expr *nle;
	struct nft_data_linearize nld;

	nle = alloc_nft_expr("immediate");
	netlink_put_register(nle, NFTNL_EXPR_IMM_DREG, dreg);
	netlink_gen_data(expr, &nld);
	switch (expr->etype) {
	case EXPR_VALUE:
		nftnl_expr_set(nle, NFTNL_EXPR_IMM_DATA, nld.value, nld.len);
		break;
	case EXPR_VERDICT:
		if ((expr->chain != NULL) &&
		    !nftnl_expr_is_set(nle, NFTNL_EXPR_IMM_CHAIN)) {
			nftnl_expr_set_str(nle, NFTNL_EXPR_IMM_CHAIN,
					   nld.chain);
		}
		nftnl_expr_set_u32(nle, NFTNL_EXPR_IMM_VERDICT, nld.verdict);
		break;
	default:
		break;
	}
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_xfrm(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("xfrm");
	netlink_put_register(nle, NFTNL_EXPR_XFRM_DREG, dreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_XFRM_KEY, expr->xfrm.key);
	nftnl_expr_set_u8(nle, NFTNL_EXPR_XFRM_DIR, expr->xfrm.direction);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_XFRM_SPNUM, expr->xfrm.spnum);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_expr(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	assert(dreg < ctx->reg_low);

	switch (expr->etype) {
	case EXPR_VERDICT:
	case EXPR_VALUE:
		return netlink_gen_immediate(ctx, expr, dreg);
	case EXPR_UNARY:
		return netlink_gen_unary(ctx, expr, dreg);
	case EXPR_BINOP:
		return netlink_gen_binop(ctx, expr, dreg);
	case EXPR_RELATIONAL:
		return netlink_gen_relational(ctx, expr, dreg);
	case EXPR_CONCAT:
		return netlink_gen_concat(ctx, expr, dreg);
	case EXPR_MAP:
		return netlink_gen_map(ctx, expr, dreg);
	case EXPR_PAYLOAD:
		return netlink_gen_payload(ctx, expr, dreg);
	case EXPR_EXTHDR:
		return netlink_gen_exthdr(ctx, expr, dreg);
	case EXPR_META:
		return netlink_gen_meta(ctx, expr, dreg);
	case EXPR_RT:
		return netlink_gen_rt(ctx, expr, dreg);
	case EXPR_CT:
		return netlink_gen_ct(ctx, expr, dreg);
	case EXPR_SET_ELEM:
		return netlink_gen_expr(ctx, expr->key, dreg);
	case EXPR_NUMGEN:
		return netlink_gen_numgen(ctx, expr, dreg);
	case EXPR_HASH:
		return netlink_gen_hash(ctx, expr, dreg);
	case EXPR_FIB:
		return netlink_gen_fib(ctx, expr, dreg);
	case EXPR_SOCKET:
		return netlink_gen_socket(ctx, expr, dreg);
	case EXPR_OSF:
		return netlink_gen_osf(ctx, expr, dreg);
	case EXPR_XFRM:
		return netlink_gen_xfrm(ctx, expr, dreg);
	default:
		BUG("unknown expression type %s\n", expr_name(expr));
	}
}

static void netlink_gen_objref_stmt(struct netlink_linearize_ctx *ctx,
				    const struct stmt *stmt)
{
	struct expr *expr = stmt->objref.expr;
	struct nft_data_linearize nld;
	struct nftnl_expr *nle;
	uint32_t sreg_key;

	nle = alloc_nft_expr("objref");
	switch (expr->etype) {
	case EXPR_MAP:
		sreg_key = get_register(ctx, expr->map);
		netlink_gen_expr(ctx, expr->map, sreg_key);
		release_register(ctx, expr->map);

		nftnl_expr_set_u32(nle, NFTNL_EXPR_OBJREF_SET_SREG, sreg_key);
		nftnl_expr_set_str(nle, NFTNL_EXPR_OBJREF_SET_NAME,
				   expr->mappings->set->handle.set.name);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_OBJREF_SET_ID,
				   expr->mappings->set->handle.set_id);
		break;
	case EXPR_VALUE:
		netlink_gen_data(stmt->objref.expr, &nld);
		nftnl_expr_set(nle, NFTNL_EXPR_OBJREF_IMM_NAME,
			       nld.value, nld.len);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_OBJREF_IMM_TYPE,
				   stmt->objref.type);
		break;
	default:
		BUG("unsupported expression %u\n", expr->etype);
	}
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static struct nftnl_expr *
netlink_gen_connlimit_stmt(struct netlink_linearize_ctx *ctx,
			   const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("connlimit");
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CONNLIMIT_COUNT,
			   stmt->connlimit.count);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CONNLIMIT_FLAGS,
			   stmt->connlimit.flags);

	return nle;
}

static struct nftnl_expr *
netlink_gen_counter_stmt(struct netlink_linearize_ctx *ctx,
			 const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("counter");
	if (stmt->counter.packets) {
		nftnl_expr_set_u64(nle, NFTNL_EXPR_CTR_PACKETS,
				   stmt->counter.packets);
	}
	if (stmt->counter.bytes) {
		nftnl_expr_set_u64(nle, NFTNL_EXPR_CTR_BYTES,
				   stmt->counter.bytes);
	}

	return nle;
}

static struct nftnl_expr *
netlink_gen_limit_stmt(struct netlink_linearize_ctx *ctx,
		       const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("limit");
	nftnl_expr_set_u64(nle, NFTNL_EXPR_LIMIT_RATE, stmt->limit.rate);
	nftnl_expr_set_u64(nle, NFTNL_EXPR_LIMIT_UNIT, stmt->limit.unit);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_LIMIT_TYPE, stmt->limit.type);
	if (stmt->limit.burst > 0)
		nftnl_expr_set_u32(nle, NFTNL_EXPR_LIMIT_BURST,
				   stmt->limit.burst);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_LIMIT_FLAGS, stmt->limit.flags);

	return nle;
}

static struct nftnl_expr *
netlink_gen_quota_stmt(struct netlink_linearize_ctx *ctx,
		       const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("quota");
	nftnl_expr_set_u64(nle, NFTNL_EXPR_QUOTA_BYTES, stmt->quota.bytes);
	nftnl_expr_set_u64(nle, NFTNL_EXPR_QUOTA_CONSUMED, stmt->quota.used);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_QUOTA_FLAGS, stmt->quota.flags);

	return nle;
}

static struct nftnl_expr *
netlink_gen_stmt_stateful(struct netlink_linearize_ctx *ctx,
			  const struct stmt *stmt)
{
	switch (stmt->ops->type) {
	case STMT_CONNLIMIT:
		return netlink_gen_connlimit_stmt(ctx, stmt);
	case STMT_COUNTER:
		return netlink_gen_counter_stmt(ctx, stmt);
	case STMT_LIMIT:
		return netlink_gen_limit_stmt(ctx, stmt);
	case STMT_QUOTA:
		return netlink_gen_quota_stmt(ctx, stmt);
	default:
		BUG("unknown stateful statement type %s\n", stmt->ops->name);
	}
}

static void netlink_gen_verdict_stmt(struct netlink_linearize_ctx *ctx,
				     const struct stmt *stmt)
{
	return netlink_gen_expr(ctx, stmt->expr, NFT_REG_VERDICT);
}

static bool payload_needs_l4csum_update_pseudohdr(const struct expr *expr,
						  const struct proto_desc *desc)
{
	int i;

	for (i = 0; i < PROTO_HDRS_MAX; i++) {
		if (payload_hdr_field(expr) == desc->pseudohdr[i])
			return true;
	}
	return false;
}

static void netlink_gen_exthdr_stmt(struct netlink_linearize_ctx *ctx,
				    const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	const struct expr *expr;
	enum nft_registers sreg;
	unsigned int offset;

	sreg = get_register(ctx, stmt->exthdr.val);
	netlink_gen_expr(ctx, stmt->exthdr.val, sreg);
	release_register(ctx, stmt->exthdr.val);

	expr = stmt->exthdr.expr;

	offset = expr->exthdr.tmpl->offset + expr->exthdr.offset;

	nle = alloc_nft_expr("exthdr");
	netlink_put_register(nle, NFTNL_EXPR_EXTHDR_SREG, sreg);
	nftnl_expr_set_u8(nle, NFTNL_EXPR_EXTHDR_TYPE,
			  expr->exthdr.desc->type);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_OFFSET, offset / BITS_PER_BYTE);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_LEN,
			   div_round_up(expr->len, BITS_PER_BYTE));
	nftnl_expr_set_u32(nle, NFTNL_EXPR_EXTHDR_OP, expr->exthdr.op);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_payload_stmt(struct netlink_linearize_ctx *ctx,
				     const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	const struct proto_desc *desc;
	const struct expr *expr;
	enum nft_registers sreg;
	unsigned int csum_off;

	sreg = get_register(ctx, stmt->payload.val);
	netlink_gen_expr(ctx, stmt->payload.val, sreg);
	release_register(ctx, stmt->payload.val);

	expr = stmt->payload.expr;

	csum_off = 0;
	desc = expr->payload.desc;
	if (desc != NULL && desc->checksum_key)
		csum_off = desc->templates[desc->checksum_key].offset;

	nle = alloc_nft_expr("payload");
	netlink_put_register(nle, NFTNL_EXPR_PAYLOAD_SREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_BASE,
			   expr->payload.base - 1);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_OFFSET,
			   expr->payload.offset / BITS_PER_BYTE);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_LEN,
			   expr->len / BITS_PER_BYTE);
	if (csum_off) {
		nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_CSUM_TYPE,
				   NFT_PAYLOAD_CSUM_INET);
		nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_CSUM_OFFSET,
				   csum_off / BITS_PER_BYTE);
	}
	if (expr->payload.base == PROTO_BASE_NETWORK_HDR &&
	    payload_needs_l4csum_update_pseudohdr(expr, desc))
		nftnl_expr_set_u32(nle, NFTNL_EXPR_PAYLOAD_FLAGS,
				   NFT_PAYLOAD_L4CSUM_PSEUDOHDR);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta_stmt(struct netlink_linearize_ctx *ctx,
				  const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg;

	sreg = get_register(ctx, stmt->meta.expr);
	netlink_gen_expr(ctx, stmt->meta.expr, sreg);
	release_register(ctx, stmt->meta.expr);

	nle = alloc_nft_expr("meta");
	netlink_put_register(nle, NFTNL_EXPR_META_SREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_META_KEY, stmt->meta.key);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_log_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("log");
	if (stmt->log.prefix != NULL) {
		nftnl_expr_set_str(nle, NFTNL_EXPR_LOG_PREFIX,
				      stmt->log.prefix);
	}
	if (stmt->log.flags & STMT_LOG_GROUP) {
		nftnl_expr_set_u16(nle, NFTNL_EXPR_LOG_GROUP, stmt->log.group);
		if (stmt->log.flags & STMT_LOG_SNAPLEN)
			nftnl_expr_set_u32(nle, NFTNL_EXPR_LOG_SNAPLEN,
					   stmt->log.snaplen);
		if (stmt->log.flags & STMT_LOG_QTHRESHOLD)
			nftnl_expr_set_u16(nle, NFTNL_EXPR_LOG_QTHRESHOLD,
					   stmt->log.qthreshold);
	} else {
		if (stmt->log.flags & STMT_LOG_LEVEL)
			nftnl_expr_set_u32(nle, NFTNL_EXPR_LOG_LEVEL,
					   stmt->log.level);
		if (stmt->log.logflags)
			nftnl_expr_set_u32(nle, NFTNL_EXPR_LOG_FLAGS,
					   stmt->log.logflags);
	}
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_reject_stmt(struct netlink_linearize_ctx *ctx,
				    const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("reject");
	nftnl_expr_set_u32(nle, NFTNL_EXPR_REJECT_TYPE, stmt->reject.type);
	if (stmt->reject.icmp_code != -1)
		nftnl_expr_set_u8(nle, NFTNL_EXPR_REJECT_CODE,
				  stmt->reject.icmp_code);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_nat_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers amin_reg, amax_reg;
	enum nft_registers pmin_reg, pmax_reg;
	int registers = 0;
	int family;
	int nftnl_flag_attr;
	int nftnl_reg_pmin, nftnl_reg_pmax;

	switch (stmt->nat.type) {
	case NFT_NAT_SNAT:
	case NFT_NAT_DNAT:
		nle = alloc_nft_expr("nat");
		nftnl_expr_set_u32(nle, NFTNL_EXPR_NAT_TYPE, stmt->nat.type);

		family = stmt->nat.family;
		nftnl_expr_set_u32(nle, NFTNL_EXPR_NAT_FAMILY, family);

		nftnl_flag_attr = NFTNL_EXPR_NAT_FLAGS;
		nftnl_reg_pmin = NFTNL_EXPR_NAT_REG_PROTO_MIN;
		nftnl_reg_pmax = NFTNL_EXPR_NAT_REG_PROTO_MAX;
		break;
	case NFT_NAT_MASQ:
		nle = alloc_nft_expr("masq");

		nftnl_flag_attr = NFTNL_EXPR_MASQ_FLAGS;
		nftnl_reg_pmin = NFTNL_EXPR_MASQ_REG_PROTO_MIN;
		nftnl_reg_pmax = NFTNL_EXPR_MASQ_REG_PROTO_MAX;
		break;
	case NFT_NAT_REDIR:
		nle = alloc_nft_expr("redir");

		nftnl_flag_attr = NFTNL_EXPR_REDIR_FLAGS;
		nftnl_reg_pmin = NFTNL_EXPR_REDIR_REG_PROTO_MIN;
		nftnl_reg_pmax = NFTNL_EXPR_REDIR_REG_PROTO_MAX;
		break;
	default:
		BUG("unknown nat type %d\n", stmt->nat.type);
		break;
	}

	if (stmt->nat.flags != 0)
		nftnl_expr_set_u32(nle, nftnl_flag_attr, stmt->nat.flags);

	if (stmt->nat.addr) {
		amin_reg = get_register(ctx, NULL);
		registers++;

		if (stmt->nat.addr->etype == EXPR_RANGE) {
			amax_reg = get_register(ctx, NULL);
			registers++;

			netlink_gen_expr(ctx, stmt->nat.addr->left, amin_reg);
			netlink_gen_expr(ctx, stmt->nat.addr->right, amax_reg);
			netlink_put_register(nle, NFTNL_EXPR_NAT_REG_ADDR_MIN,
					     amin_reg);
			netlink_put_register(nle, NFTNL_EXPR_NAT_REG_ADDR_MAX,
					     amax_reg);
		} else {
			netlink_gen_expr(ctx, stmt->nat.addr, amin_reg);
			netlink_put_register(nle, NFTNL_EXPR_NAT_REG_ADDR_MIN,
					     amin_reg);
		}

	}

	if (stmt->nat.proto) {
		pmin_reg = get_register(ctx, NULL);
		registers++;

		if (stmt->nat.proto->etype == EXPR_RANGE) {
			pmax_reg = get_register(ctx, NULL);
			registers++;

			netlink_gen_expr(ctx, stmt->nat.proto->left, pmin_reg);
			netlink_gen_expr(ctx, stmt->nat.proto->right, pmax_reg);
			netlink_put_register(nle, nftnl_reg_pmin, pmin_reg);
			netlink_put_register(nle, nftnl_reg_pmax, pmax_reg);
		} else {
			netlink_gen_expr(ctx, stmt->nat.proto, pmin_reg);
			netlink_put_register(nle, nftnl_reg_pmin, pmin_reg);
		}
	}

	while (registers > 0) {
		release_register(ctx, NULL);
		registers--;
	}

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_tproxy_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers addr_reg;
	enum nft_registers port_reg;
	int registers = 0;
	const int family = stmt->tproxy.family;
	int nftnl_reg_port;

	nle = alloc_nft_expr("tproxy");

	nftnl_expr_set_u32(nle, NFTNL_EXPR_TPROXY_FAMILY, family);

	nftnl_reg_port = NFTNL_EXPR_TPROXY_REG_PORT;

	if (stmt->tproxy.addr) {
		addr_reg = get_register(ctx, NULL);
		registers++;
		netlink_gen_expr(ctx, stmt->tproxy.addr, addr_reg);
		netlink_put_register(nle, NFTNL_EXPR_TPROXY_REG_ADDR,
				     addr_reg);
	}

	if (stmt->tproxy.port) {
		port_reg = get_register(ctx, NULL);
		registers++;
		netlink_gen_expr(ctx, stmt->tproxy.port, port_reg);
		netlink_put_register(nle, nftnl_reg_port, port_reg);
	}

	while (registers > 0) {
		release_register(ctx, NULL);
		registers--;
	}

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_synproxy_stmt(struct netlink_linearize_ctx *ctx,
				      const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("synproxy");
	nftnl_expr_set_u16(nle, NFTNL_EXPR_SYNPROXY_MSS, stmt->synproxy.mss);
	nftnl_expr_set_u8(nle, NFTNL_EXPR_SYNPROXY_WSCALE,
			  stmt->synproxy.wscale);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_SYNPROXY_FLAGS,
			   stmt->synproxy.flags);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_dup_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg1, sreg2;

	nle = alloc_nft_expr("dup");

	if (stmt->dup.to != NULL) {
		if (stmt->dup.to->dtype == &ifindex_type) {
			sreg1 = get_register(ctx, stmt->dup.to);
			netlink_gen_expr(ctx, stmt->dup.to, sreg1);
			netlink_put_register(nle, NFTNL_EXPR_DUP_SREG_DEV, sreg1);
		} else {
			sreg1 = get_register(ctx, stmt->dup.to);
			netlink_gen_expr(ctx, stmt->dup.to, sreg1);
			netlink_put_register(nle, NFTNL_EXPR_DUP_SREG_ADDR, sreg1);
		}
	}
	if (stmt->dup.dev != NULL) {
		sreg2 = get_register(ctx, stmt->dup.dev);
		netlink_gen_expr(ctx, stmt->dup.dev, sreg2);
		netlink_put_register(nle, NFTNL_EXPR_DUP_SREG_DEV, sreg2);
		release_register(ctx, stmt->dup.dev);
	}
	if (stmt->dup.to != NULL)
		release_register(ctx, stmt->dup.to);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_fwd_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	enum nft_registers sreg1, sreg2;
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("fwd");

	sreg1 = get_register(ctx, stmt->fwd.dev);
	netlink_gen_expr(ctx, stmt->fwd.dev, sreg1);
	netlink_put_register(nle, NFTNL_EXPR_FWD_SREG_DEV, sreg1);

	if (stmt->fwd.addr != NULL) {
		sreg2 = get_register(ctx, stmt->fwd.addr);
		netlink_gen_expr(ctx, stmt->fwd.addr, sreg2);
		netlink_put_register(nle, NFTNL_EXPR_FWD_SREG_ADDR, sreg2);
		release_register(ctx, stmt->fwd.addr);
	}
	release_register(ctx, stmt->fwd.dev);

	if (stmt->fwd.family)
		nftnl_expr_set_u32(nle, NFTNL_EXPR_FWD_NFPROTO,
				   stmt->fwd.family);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_queue_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	uint16_t total_queues;
	mpz_t low, high;

	mpz_init2(low, 16);
	mpz_init2(high, 16);
	if (stmt->queue.queue != NULL) {
		range_expr_value_low(low, stmt->queue.queue);
		range_expr_value_high(high, stmt->queue.queue);
	}
	total_queues = mpz_get_uint16(high) - mpz_get_uint16(low) + 1;

	nle = alloc_nft_expr("queue");
	nftnl_expr_set_u16(nle, NFTNL_EXPR_QUEUE_NUM, mpz_get_uint16(low));
	nftnl_expr_set_u16(nle, NFTNL_EXPR_QUEUE_TOTAL, total_queues);
	if (stmt->queue.flags)
		nftnl_expr_set_u16(nle, NFTNL_EXPR_QUEUE_FLAGS,
				   stmt->queue.flags);

	nftnl_rule_add_expr(ctx->nlr, nle);

	mpz_clear(low);
	mpz_clear(high);
}

static void netlink_gen_ct_stmt(struct netlink_linearize_ctx *ctx,
				  const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg;

	sreg = get_register(ctx, stmt->ct.expr);
	netlink_gen_expr(ctx, stmt->ct.expr, sreg);
	release_register(ctx, stmt->ct.expr);

	nle = alloc_nft_expr("ct");
	netlink_put_register(nle, NFTNL_EXPR_CT_SREG, sreg);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_CT_KEY, stmt->ct.key);
	if (stmt->ct.direction >= 0)
		nftnl_expr_set_u8(nle, NFTNL_EXPR_CT_DIR,
				  stmt->ct.direction);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_notrack_stmt(struct netlink_linearize_ctx *ctx,
				     const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("notrack");
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_flow_offload_stmt(struct netlink_linearize_ctx *ctx,
					  const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	nle = alloc_nft_expr("flow_offload");
	nftnl_expr_set_str(nle, NFTNL_EXPR_FLOW_TABLE_NAME,
			   stmt->flow.table_name);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_set_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct set *set = stmt->meter.set->set;
	struct nftnl_expr *nle;
	enum nft_registers sreg_key;

	sreg_key = get_register(ctx, stmt->set.key->key);
	netlink_gen_expr(ctx, stmt->set.key->key, sreg_key);
	release_register(ctx, stmt->set.key->key);

	nle = alloc_nft_expr("dynset");
	netlink_put_register(nle, NFTNL_EXPR_DYNSET_SREG_KEY, sreg_key);
	if (stmt->set.key->timeout > 0)
		nftnl_expr_set_u64(nle, NFTNL_EXPR_DYNSET_TIMEOUT,
				   stmt->set.key->timeout);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_OP, stmt->set.op);
	nftnl_expr_set_str(nle, NFTNL_EXPR_DYNSET_SET_NAME, set->handle.set.name);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_SET_ID, set->handle.set_id);
	nftnl_rule_add_expr(ctx->nlr, nle);

	if (stmt->set.stmt)
		nftnl_expr_set(nle, NFTNL_EXPR_DYNSET_EXPR,
			       netlink_gen_stmt_stateful(ctx, stmt->set.stmt), 0);
}

static void netlink_gen_map_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct set *set = stmt->map.set->set;
	enum nft_registers sreg_data;
	enum nft_registers sreg_key;
	struct nftnl_expr *nle;

	sreg_key = get_register(ctx, stmt->map.key);
	netlink_gen_expr(ctx, stmt->map.key, sreg_key);

	sreg_data = get_register(ctx, stmt->map.data);
	netlink_gen_expr(ctx, stmt->map.data, sreg_data);

	release_register(ctx, stmt->map.key);
	release_register(ctx, stmt->map.data);

	nle = alloc_nft_expr("dynset");
	netlink_put_register(nle, NFTNL_EXPR_DYNSET_SREG_KEY, sreg_key);
	netlink_put_register(nle, NFTNL_EXPR_DYNSET_SREG_DATA, sreg_data);

	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_OP, stmt->map.op);
	nftnl_expr_set_str(nle, NFTNL_EXPR_DYNSET_SET_NAME, set->handle.set.name);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_SET_ID, set->handle.set_id);

	if (stmt->map.stmt)
		nftnl_expr_set(nle, NFTNL_EXPR_DYNSET_EXPR,
			       netlink_gen_stmt_stateful(ctx, stmt->map.stmt), 0);

	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meter_stmt(struct netlink_linearize_ctx *ctx,
				   const struct stmt *stmt)
{
	struct nftnl_expr *nle;
	enum nft_registers sreg_key;
	enum nft_dynset_ops op;
	struct set *set;

	sreg_key = get_register(ctx, stmt->meter.key->key);
	netlink_gen_expr(ctx, stmt->meter.key->key, sreg_key);
	release_register(ctx, stmt->meter.key->key);

	set = stmt->meter.set->set;
	if (stmt->meter.key->timeout)
		op = NFT_DYNSET_OP_UPDATE;
	else
		op = NFT_DYNSET_OP_ADD;

	nle = alloc_nft_expr("dynset");
	netlink_put_register(nle, NFTNL_EXPR_DYNSET_SREG_KEY, sreg_key);
	if (stmt->meter.key->timeout)
		nftnl_expr_set_u64(nle, NFTNL_EXPR_DYNSET_TIMEOUT,
				   stmt->meter.key->timeout);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_OP, op);
	nftnl_expr_set_str(nle, NFTNL_EXPR_DYNSET_SET_NAME, set->handle.set.name);
	nftnl_expr_set_u32(nle, NFTNL_EXPR_DYNSET_SET_ID, set->handle.set_id);
	nftnl_expr_set(nle, NFTNL_EXPR_DYNSET_EXPR,
		       netlink_gen_stmt_stateful(ctx, stmt->meter.stmt), 0);
	nftnl_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_stmt(struct netlink_linearize_ctx *ctx,
			     const struct stmt *stmt)
{
	struct nftnl_expr *nle;

	switch (stmt->ops->type) {
	case STMT_EXPRESSION:
		return netlink_gen_expr(ctx, stmt->expr, NFT_REG_VERDICT);
	case STMT_VERDICT:
		return netlink_gen_verdict_stmt(ctx, stmt);
	case STMT_METER:
		return netlink_gen_meter_stmt(ctx, stmt);
	case STMT_EXTHDR:
		return netlink_gen_exthdr_stmt(ctx, stmt);
	case STMT_PAYLOAD:
		return netlink_gen_payload_stmt(ctx, stmt);
	case STMT_META:
		return netlink_gen_meta_stmt(ctx, stmt);
	case STMT_LOG:
		return netlink_gen_log_stmt(ctx, stmt);
	case STMT_REJECT:
		return netlink_gen_reject_stmt(ctx, stmt);
	case STMT_NAT:
		return netlink_gen_nat_stmt(ctx, stmt);
	case STMT_TPROXY:
		return netlink_gen_tproxy_stmt(ctx, stmt);
	case STMT_SYNPROXY:
		return netlink_gen_synproxy_stmt(ctx, stmt);
	case STMT_DUP:
		return netlink_gen_dup_stmt(ctx, stmt);
	case STMT_QUEUE:
		return netlink_gen_queue_stmt(ctx, stmt);
	case STMT_CT:
		return netlink_gen_ct_stmt(ctx, stmt);
	case STMT_SET:
		return netlink_gen_set_stmt(ctx, stmt);
	case STMT_FWD:
		return netlink_gen_fwd_stmt(ctx, stmt);
	case STMT_CONNLIMIT:
	case STMT_COUNTER:
	case STMT_LIMIT:
	case STMT_QUOTA:
		nle = netlink_gen_stmt_stateful(ctx, stmt);
		nftnl_rule_add_expr(ctx->nlr, nle);
		break;
	case STMT_NOTRACK:
		return netlink_gen_notrack_stmt(ctx, stmt);
	case STMT_FLOW_OFFLOAD:
		return netlink_gen_flow_offload_stmt(ctx, stmt);
	case STMT_OBJREF:
		return netlink_gen_objref_stmt(ctx, stmt);
	case STMT_MAP:
		return netlink_gen_map_stmt(ctx, stmt);
	default:
		BUG("unknown statement type %s\n", stmt->ops->name);
	}
}

void netlink_linearize_rule(struct netlink_ctx *ctx, struct nftnl_rule *nlr,
			    const struct rule *rule)
{
	struct netlink_linearize_ctx lctx;
	const struct stmt *stmt;

	memset(&lctx, 0, sizeof(lctx));
	lctx.reg_low = NFT_REG_1;
	lctx.nlr = nlr;

	list_for_each_entry(stmt, &rule->stmts, list)
		netlink_gen_stmt(&lctx, stmt);

	if (rule->comment) {
		struct nftnl_udata_buf *udata;

		udata = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
		if (!udata)
			memory_allocation_error();

		if (!nftnl_udata_put_strz(udata, NFTNL_UDATA_RULE_COMMENT,
					  rule->comment))
			memory_allocation_error();
		nftnl_rule_set_data(nlr, NFTNL_RULE_USERDATA,
				    nftnl_udata_buf_data(udata),
				    nftnl_udata_buf_len(udata));

		nftnl_udata_buf_free(udata);
	}

	netlink_dump_rule(nlr, ctx);
}
