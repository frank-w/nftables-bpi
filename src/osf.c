#include <nftables.h>
#include <expression.h>
#include <utils.h>
#include <string.h>
#include <osf.h>

static void osf_expr_print(const struct expr *expr, struct output_ctx *octx)
{
	nft_print(octx, "osf name");
}

static void osf_expr_clone(struct expr *new, const struct expr *expr)
{
}

static const struct expr_ops osf_expr_ops = {
	.type		= EXPR_OSF,
	.name		= "osf",
	.print		= osf_expr_print,
	.clone		= osf_expr_clone,
};

struct expr *osf_expr_alloc(const struct location *loc)
{
	unsigned int len = NFT_OSF_MAXGENRELEN * BITS_PER_BYTE;
	const struct datatype *type = &string_type;
	struct expr *expr;

	expr = expr_alloc(loc, &osf_expr_ops, type,
			  BYTEORDER_HOST_ENDIAN, len);

	return expr;
}
