/*
 * Socket expression/statement related definition and types.
 *
 * Copyright (c) 2018 Máté Eckl <ecklm94@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <nftables.h>
#include <expression.h>
#include <socket.h>
#include <json.h>

const struct socket_template socket_templates[] = {
	[NFT_SOCKET_TRANSPARENT] = {
		.token		= "transparent",
		.dtype		= &integer_type,
		.len		= BITS_PER_BYTE,
		.byteorder	= BYTEORDER_HOST_ENDIAN,
	},
	[NFT_SOCKET_MARK] = {
		.token		= "mark",
		.dtype		= &mark_type,
		.len		= 4 * BITS_PER_BYTE,
		.byteorder	= BYTEORDER_HOST_ENDIAN,
	},
};

static void socket_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	nft_print(octx, "socket %s", socket_templates[expr->socket.key].token);
}

static bool socket_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->socket.key == e2->socket.key;
}

static void socket_expr_clone(struct expr *new, const struct expr *expr)
{
	new->socket.key = expr->socket.key;
}

const struct expr_ops socket_expr_ops = {
	.type		= EXPR_SOCKET,
	.name		= "socket",
	.print		= socket_expr_print,
	.json		= socket_expr_json,
	.cmp		= socket_expr_cmp,
	.clone		= socket_expr_clone,
};

struct expr *socket_expr_alloc(const struct location *loc, enum nft_socket_keys key)
{
	const struct socket_template *tmpl = &socket_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, EXPR_SOCKET, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->socket.key = key;

	return expr;
}
