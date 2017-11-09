/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <nftables/nftables.h>
#include <erec.h>
#include <mnl.h>
#include <parser.h>
#include <utils.h>
#include <iface.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int nft_netlink(struct nft_ctx *nft,
		       struct parser_state *state, struct list_head *msgs,
		       struct mnl_socket *nf_sock)
{
	uint32_t batch_seqnum, seqnum = 0;
	struct nftnl_batch *batch;
	struct netlink_ctx ctx;
	struct cmd *cmd;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	bool batch_supported = netlink_batch_supported(nf_sock, &seqnum);
	int ret = 0;

	batch = mnl_batch_init();

	batch_seqnum = mnl_batch_begin(batch, mnl_seqnum_alloc(&seqnum));
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc(&seqnum);
		ctx.batch = batch;
		ctx.batch_supported = batch_supported;
		ctx.octx = &nft->output;
		ctx.nf_sock = nf_sock;
		ctx.cache = &nft->cache;
		ctx.debug_mask = nft->debug_mask;
		init_list_head(&ctx.list);
		ret = do_command(&ctx, cmd);
		if (ret < 0)
			goto out;
	}
	if (!nft->check)
		mnl_batch_end(batch, mnl_seqnum_alloc(&seqnum));

	if (!mnl_batch_ready(batch))
		goto out;

	ret = netlink_batch_send(&ctx, &err_list);

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &state->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == batch_seqnum) {
				netlink_io_error(&ctx, &cmd->location,
						 "Could not process rule: %s",
						 strerror(err->err));
				errno = err->err;
				if (err->seqnum == cmd->seqnum) {
					mnl_err_list_free(err);
					break;
				}
			}
		}
	}
out:
	mnl_batch_reset(batch);
	return ret;
}

static int nft_run(struct nft_ctx *nft, struct mnl_socket *nf_sock,
		   void *scanner, struct parser_state *state,
		   struct list_head *msgs)
{
	struct cmd *cmd, *next;
	int ret;

	ret = nft_parse(nft, scanner, state);
	if (ret != 0 || state->nerrs > 0) {
		ret = -1;
		goto err1;
	}

	list_for_each_entry(cmd, &state->cmds, list)
		nft_cmd_expand(cmd);

	ret = nft_netlink(nft, state, msgs, nf_sock);
err1:
	list_for_each_entry_safe(cmd, next, &state->cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}

	return ret;
}

static void nft_init(void)
{
	mark_table_init();
	realm_table_rt_init();
	devgroup_table_init();
	realm_table_meta_init();
	ct_label_table_init();
	gmp_init();
#ifdef HAVE_LIBXTABLES
	xt_init();
#endif
}

static void nft_exit(void)
{
	ct_label_table_exit();
	realm_table_rt_exit();
	devgroup_table_exit();
	realm_table_meta_exit();
	mark_table_exit();
}

int nft_ctx_add_include_path(struct nft_ctx *ctx, const char *path)
{
	char **tmp;
	int pcount = ctx->num_include_paths;

	tmp = realloc(ctx->include_paths, (pcount + 1) * sizeof(char *));
	if (!tmp)
		return -1;

	ctx->include_paths = tmp;

	if (asprintf(&ctx->include_paths[pcount], "%s", path) < 0)
		return -1;

	ctx->num_include_paths++;
	return 0;
}

void nft_ctx_clear_include_paths(struct nft_ctx *ctx)
{
	while (ctx->num_include_paths)
		xfree(ctx->include_paths[--ctx->num_include_paths]);

	xfree(ctx->include_paths);
	ctx->include_paths = NULL;
}

static void nft_ctx_netlink_init(struct nft_ctx *ctx)
{
	ctx->nf_sock = netlink_open_sock();
}

struct nft_ctx *nft_ctx_new(uint32_t flags)
{
	struct nft_ctx *ctx;

	nft_init();
	ctx = xzalloc(sizeof(struct nft_ctx));

	nft_ctx_add_include_path(ctx, DEFAULT_INCLUDE_PATH);
	ctx->parser_max_errors	= 10;
	init_list_head(&ctx->cache.list);
	ctx->flags = flags;

	if (flags == NFT_CTX_DEFAULT)
		nft_ctx_netlink_init(ctx);

	return ctx;
}

void nft_ctx_free(struct nft_ctx *ctx)
{
	if (ctx->nf_sock)
		netlink_close_sock(ctx->nf_sock);

	iface_cache_release();
	cache_release(&ctx->cache);
	nft_ctx_clear_include_paths(ctx);
	xfree(ctx);
	nft_exit();
}

FILE *nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp)
{
	FILE *old = ctx->output.output_fp;

	ctx->output.output_fp = fp;

	return old;
}

bool nft_ctx_get_dry_run(struct nft_ctx *ctx)
{
	return ctx->check;
}

void nft_ctx_set_dry_run(struct nft_ctx *ctx, bool dry)
{
	ctx->check = dry;
}

enum nft_numeric_level nft_ctx_output_get_numeric(struct nft_ctx *ctx)
{
	return ctx->output.numeric;
}

void nft_ctx_output_set_numeric(struct nft_ctx *ctx,
				enum nft_numeric_level level)
{
	ctx->output.numeric = level;
}

bool nft_ctx_output_get_stateless(struct nft_ctx *ctx)
{
	return ctx->output.stateless;
}

void nft_ctx_output_set_stateless(struct nft_ctx *ctx, bool val)
{
	ctx->output.stateless = val;
}

bool nft_ctx_output_get_ip2name(struct nft_ctx *ctx)
{
	return ctx->output.ip2name;
}

void nft_ctx_output_set_ip2name(struct nft_ctx *ctx, bool val)
{
	ctx->output.ip2name = val;
}

unsigned int nft_ctx_output_get_debug(struct nft_ctx *ctx)
{
	return ctx->debug_mask;
}
void nft_ctx_output_set_debug(struct nft_ctx *ctx, unsigned int mask)
{
	ctx->debug_mask = mask;
}

bool nft_ctx_output_get_handle(struct nft_ctx *ctx)
{
	return ctx->output.handle;
}

void nft_ctx_output_set_handle(struct nft_ctx *ctx, bool val)
{
	ctx->output.handle = val;
}

bool nft_ctx_output_get_echo(struct nft_ctx *ctx)
{
	return ctx->output.echo;
}

void nft_ctx_output_set_echo(struct nft_ctx *ctx, bool val)
{
	ctx->output.echo = val;
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

int nft_run_cmd_from_buffer(struct nft_ctx *nft, char *buf, size_t buflen)
{
	int rc = NFT_EXIT_SUCCESS;
	struct parser_state state;
	LIST_HEAD(msgs);
	void *scanner;
	FILE *fp;

	parser_init(nft->nf_sock, &nft->cache, &state,
		    &msgs, nft->debug_mask, &nft->output);
	scanner = scanner_init(&state);
	scanner_push_buffer(scanner, &indesc_cmdline, buf);

	if (nft_run(nft, nft->nf_sock, scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;

	fp = nft_ctx_set_output(nft, stderr);
	erec_print_list(&nft->output, &msgs, nft->debug_mask);
	nft_ctx_set_output(nft, fp);
	scanner_destroy(scanner);
	iface_cache_release();

	return rc;
}

int nft_run_cmd_from_filename(struct nft_ctx *nft, const char *filename)
{
	struct parser_state state;
	LIST_HEAD(msgs);
	void *scanner;
	int rc;
	FILE *fp;

	rc = cache_update(nft->nf_sock, &nft->cache, CMD_INVALID, &msgs,
			  nft->debug_mask, &nft->output);
	if (rc < 0)
		return NFT_EXIT_FAILURE;

	parser_init(nft->nf_sock, &nft->cache, &state,
		    &msgs, nft->debug_mask, &nft->output);
	scanner = scanner_init(&state);
	if (scanner_read_file(scanner, filename, &internal_location) < 0) {
		rc = NFT_EXIT_FAILURE;
		goto err;
	}

	if (nft_run(nft, nft->nf_sock, scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;
err:
	fp = nft_ctx_set_output(nft, stderr);
	erec_print_list(&nft->output, &msgs, nft->debug_mask);
	nft_ctx_set_output(nft, fp);
	scanner_destroy(scanner);
	iface_cache_release();

	return rc;
}

int nft_print(struct output_ctx *octx, const char *fmt, ...)
{
	int ret;
	va_list arg;

	if (!octx->output_fp)
		return -1;

	va_start(arg, fmt);
	ret = vfprintf(octx->output_fp, fmt, arg);
	va_end(arg);
	fflush(octx->output_fp);

	return ret;
}

int nft_gmp_print(struct output_ctx *octx, const char *fmt, ...)
{
	int ret;
	va_list arg;

	if (!octx->output_fp)
		return -1;

	va_start(arg, fmt);
	ret = gmp_vfprintf(octx->output_fp, fmt, arg);
	va_end(arg);
	fflush(octx->output_fp);

	return ret;
}

