/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <nftables/libnftables.h>
#include <erec.h>
#include <mnl.h>
#include <parser.h>
#include <utils.h>
#include <iface.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int nft_netlink(struct nft_ctx *nft,
		       struct list_head *cmds, struct list_head *msgs,
		       struct mnl_socket *nf_sock)
{
	uint32_t batch_seqnum, seqnum = 0, num_cmds = 0;
	struct netlink_ctx ctx = {
		.nft  = nft,
		.msgs = msgs,
		.list = LIST_HEAD_INIT(ctx.list),
		.batch = mnl_batch_init(),
	};
	struct cmd *cmd;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	int ret = 0;

	if (list_empty(cmds))
		return 0;

	batch_seqnum = mnl_batch_begin(ctx.batch, mnl_seqnum_alloc(&seqnum));
	list_for_each_entry(cmd, cmds, list) {
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc(&seqnum);
		ret = do_command(&ctx, cmd);
		if (ret < 0) {
			netlink_io_error(&ctx, &cmd->location,
					 "Could not process rule: %s",
					 strerror(errno));
			goto out;
		}
		num_cmds++;
	}
	if (!nft->check)
		mnl_batch_end(ctx.batch, mnl_seqnum_alloc(&seqnum));

	if (!mnl_batch_ready(ctx.batch))
		goto out;

	ret = mnl_batch_talk(&ctx, &err_list, num_cmds);
	if (ret < 0) {
		netlink_io_error(&ctx, NULL,
				 "Could not process rule: %s", strerror(errno));
		goto out;
	}

	if (!list_empty(&err_list))
		ret = -1;

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, cmds, list) {
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
	mnl_batch_reset(ctx.batch);
	return ret;
}

static void nft_init(struct nft_ctx *ctx)
{
	mark_table_init(ctx);
	realm_table_rt_init(ctx);
	devgroup_table_init(ctx);
	ct_label_table_init(ctx);
}

static void nft_exit(struct nft_ctx *ctx)
{
	ct_label_table_exit(ctx);
	realm_table_rt_exit(ctx);
	devgroup_table_exit(ctx);
	mark_table_exit(ctx);
}

EXPORT_SYMBOL(nft_ctx_add_include_path);
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

EXPORT_SYMBOL(nft_ctx_clear_include_paths);
void nft_ctx_clear_include_paths(struct nft_ctx *ctx)
{
	while (ctx->num_include_paths)
		xfree(ctx->include_paths[--ctx->num_include_paths]);

	xfree(ctx->include_paths);
	ctx->include_paths = NULL;
}

static void nft_ctx_netlink_init(struct nft_ctx *ctx)
{
	ctx->nf_sock = nft_mnl_socket_open();
}

EXPORT_SYMBOL(nft_ctx_new);
struct nft_ctx *nft_ctx_new(uint32_t flags)
{
	static bool init_once;
	struct nft_ctx *ctx;

	if (!init_once) {
		init_once = true;
		gmp_init();
#ifdef HAVE_LIBXTABLES
		xt_init();
#endif
	}

	ctx = xzalloc(sizeof(struct nft_ctx));
	nft_init(ctx);

	ctx->state = xzalloc(sizeof(struct parser_state));
	nft_ctx_add_include_path(ctx, DEFAULT_INCLUDE_PATH);
	ctx->parser_max_errors	= 10;
	init_list_head(&ctx->cache.list);
	ctx->flags = flags;
	ctx->output.output_fp = stdout;
	ctx->output.error_fp = stderr;

	if (flags == NFT_CTX_DEFAULT)
		nft_ctx_netlink_init(ctx);

	return ctx;
}

static ssize_t cookie_write(void *cptr, const char *buf, size_t buflen)
{
	struct cookie *cookie = cptr;

	if (!cookie->buflen) {
		cookie->buflen = buflen + 1;
		cookie->buf = xmalloc(cookie->buflen);
	} else if (cookie->pos + buflen >= cookie->buflen) {
		size_t newlen = cookie->buflen * 2;

		while (newlen <= cookie->pos + buflen)
			newlen *= 2;

		cookie->buf = xrealloc(cookie->buf, newlen);
		cookie->buflen = newlen;
	}
	memcpy(cookie->buf + cookie->pos, buf, buflen);
	cookie->pos += buflen;
	cookie->buf[cookie->pos] = '\0';

	return buflen;
}

static int init_cookie(struct cookie *cookie)
{
	cookie_io_functions_t cookie_fops = {
		.write = cookie_write,
	};

	if (cookie->orig_fp) { /* just rewind buffer */
		if (cookie->buflen) {
			cookie->pos = 0;
			cookie->buf[0] = '\0';
		}
		return 0;
	}

	cookie->orig_fp = cookie->fp;

	cookie->fp = fopencookie(cookie, "w", cookie_fops);
	if (!cookie->fp) {
		cookie->fp = cookie->orig_fp;
		cookie->orig_fp = NULL;
		return 1;
	}

	return 0;
}

static int exit_cookie(struct cookie *cookie)
{
	if (!cookie->orig_fp)
		return 1;

	fclose(cookie->fp);
	cookie->fp = cookie->orig_fp;
	cookie->orig_fp = NULL;
	free(cookie->buf);
	cookie->buf = NULL;
	cookie->buflen = 0;
	cookie->pos = 0;
	return 0;
}

EXPORT_SYMBOL(nft_ctx_buffer_output);
int nft_ctx_buffer_output(struct nft_ctx *ctx)
{
	return init_cookie(&ctx->output.output_cookie);
}

EXPORT_SYMBOL(nft_ctx_unbuffer_output);
int nft_ctx_unbuffer_output(struct nft_ctx *ctx)
{
	return exit_cookie(&ctx->output.output_cookie);
}

EXPORT_SYMBOL(nft_ctx_buffer_error);
int nft_ctx_buffer_error(struct nft_ctx *ctx)
{
	return init_cookie(&ctx->output.error_cookie);
}

EXPORT_SYMBOL(nft_ctx_unbuffer_error);
int nft_ctx_unbuffer_error(struct nft_ctx *ctx)
{
	return exit_cookie(&ctx->output.error_cookie);
}

static const char *get_cookie_buffer(struct cookie *cookie)
{
	fflush(cookie->fp);

	/* This is a bit tricky: Rewind the buffer for future use and return
	 * the old content at the same time. Therefore return an empty string
	 * if buffer position is zero, otherwise just rewind buffer position
	 * and return the unmodified buffer. */

	if (!cookie->pos)
		return "";

	cookie->pos = 0;
	return cookie->buf;
}

EXPORT_SYMBOL(nft_ctx_get_output_buffer);
const char *nft_ctx_get_output_buffer(struct nft_ctx *ctx)
{
	return get_cookie_buffer(&ctx->output.output_cookie);
}

EXPORT_SYMBOL(nft_ctx_get_error_buffer);
const char *nft_ctx_get_error_buffer(struct nft_ctx *ctx)
{
	return get_cookie_buffer(&ctx->output.error_cookie);
}

EXPORT_SYMBOL(nft_ctx_free);
void nft_ctx_free(struct nft_ctx *ctx)
{
	if (ctx->nf_sock)
		mnl_socket_close(ctx->nf_sock);

	exit_cookie(&ctx->output.output_cookie);
	exit_cookie(&ctx->output.error_cookie);
	iface_cache_release();
	cache_release(&ctx->cache);
	nft_ctx_clear_include_paths(ctx);
	xfree(ctx->state);
	xfree(ctx);
	nft_exit(ctx);
}

EXPORT_SYMBOL(nft_ctx_set_output);
FILE *nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp)
{
	FILE *old = ctx->output.output_fp;

	if (!fp || ferror(fp))
		return NULL;

	ctx->output.output_fp = fp;

	return old;
}

EXPORT_SYMBOL(nft_ctx_set_error);
FILE *nft_ctx_set_error(struct nft_ctx *ctx, FILE *fp)
{
	FILE *old = ctx->output.error_fp;

	if (!fp || ferror(fp))
		return NULL;

	ctx->output.error_fp = fp;

	return old;
}

EXPORT_SYMBOL(nft_ctx_get_dry_run);
bool nft_ctx_get_dry_run(struct nft_ctx *ctx)
{
	return ctx->check;
}

EXPORT_SYMBOL(nft_ctx_set_dry_run);
void nft_ctx_set_dry_run(struct nft_ctx *ctx, bool dry)
{
	ctx->check = dry;
}

EXPORT_SYMBOL(nft_ctx_output_get_flags);
unsigned int nft_ctx_output_get_flags(struct nft_ctx *ctx)
{
	return ctx->output.flags;
}

EXPORT_SYMBOL(nft_ctx_output_set_flags);
void nft_ctx_output_set_flags(struct nft_ctx *ctx, unsigned int flags)
{
	ctx->output.flags = flags;
}

EXPORT_SYMBOL(nft_ctx_output_get_debug);
unsigned int nft_ctx_output_get_debug(struct nft_ctx *ctx)
{
	return ctx->debug_mask;
}
EXPORT_SYMBOL(nft_ctx_output_set_debug);
void nft_ctx_output_set_debug(struct nft_ctx *ctx, unsigned int mask)
{
	ctx->debug_mask = mask;
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

static int nft_parse_bison_buffer(struct nft_ctx *nft, const char *buf,
				  struct list_head *msgs, struct list_head *cmds)
{
	int ret;

	parser_init(nft, nft->state, msgs, cmds);
	nft->scanner = scanner_init(nft->state);
	scanner_push_buffer(nft->scanner, &indesc_cmdline, buf);

	ret = nft_parse(nft, nft->scanner, nft->state);
	if (ret != 0 || nft->state->nerrs > 0)
		return -1;

	return 0;
}

static int nft_parse_bison_filename(struct nft_ctx *nft, const char *filename,
				    struct list_head *msgs, struct list_head *cmds)
{
	int ret;

	parser_init(nft, nft->state, msgs, cmds);
	nft->scanner = scanner_init(nft->state);
	if (scanner_read_file(nft, filename, &internal_location) < 0)
		return -1;

	ret = nft_parse(nft, nft->scanner, nft->state);
	if (ret != 0 || nft->state->nerrs > 0)
		return -1;

	return 0;
}

static int nft_evaluate(struct nft_ctx *nft, struct list_head *msgs,
			struct list_head *cmds)
{
	unsigned int flags;
	struct cmd *cmd;

	flags = cache_evaluate(nft, cmds);
	if (cache_update(nft, flags, msgs) < 0)
		return -1;

	list_for_each_entry(cmd, cmds, list) {
		struct eval_ctx ectx = {
			.nft	= nft,
			.msgs	= msgs,
		};
		if (cmd_evaluate(&ectx, cmd) < 0 &&
		    ++nft->state->nerrs == nft->parser_max_errors)
			return -1;
	}

	if (nft->state->nerrs)
		return -1;

	list_for_each_entry(cmd, cmds, list)
		nft_cmd_expand(cmd);

	return 0;
}

EXPORT_SYMBOL(nft_run_cmd_from_buffer);
int nft_run_cmd_from_buffer(struct nft_ctx *nft, const char *buf)
{
	int rc = -EINVAL, parser_rc;
	struct cmd *cmd, *next;
	LIST_HEAD(msgs);
	LIST_HEAD(cmds);
	char *nlbuf;

	nlbuf = xzalloc(strlen(buf) + 2);
	sprintf(nlbuf, "%s\n", buf);

	if (nft_output_json(&nft->output))
		rc = nft_parse_json_buffer(nft, nlbuf, &msgs, &cmds);
	if (rc == -EINVAL)
		rc = nft_parse_bison_buffer(nft, nlbuf, &msgs, &cmds);

	parser_rc = rc;

	rc = nft_evaluate(nft, &msgs, &cmds);
	if (rc < 0)
		goto err;

	if (parser_rc) {
		rc = parser_rc;
		goto err;
	}

	if (nft_netlink(nft, &cmds, &msgs, nft->nf_sock) != 0)
		rc = -1;
err:
	erec_print_list(&nft->output, &msgs, nft->debug_mask);
	list_for_each_entry_safe(cmd, next, &cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}
	iface_cache_release();
	if (nft->scanner) {
		scanner_destroy(nft);
		nft->scanner = NULL;
	}
	free(nlbuf);

	if (!rc &&
	    nft_output_json(&nft->output) &&
	    nft_output_echo(&nft->output))
		json_print_echo(nft);
	if (rc)
		cache_release(&nft->cache);
	return rc;
}

EXPORT_SYMBOL(nft_run_cmd_from_filename);
int nft_run_cmd_from_filename(struct nft_ctx *nft, const char *filename)
{
	struct cmd *cmd, *next;
	int rc, parser_rc;
	LIST_HEAD(msgs);
	LIST_HEAD(cmds);

	if (!strcmp(filename, "-"))
		filename = "/dev/stdin";

	rc = -EINVAL;
	if (nft_output_json(&nft->output))
		rc = nft_parse_json_filename(nft, filename, &msgs, &cmds);
	if (rc == -EINVAL)
		rc = nft_parse_bison_filename(nft, filename, &msgs, &cmds);

	parser_rc = rc;

	rc = nft_evaluate(nft, &msgs, &cmds);
	if (rc < 0)
		goto err;

	if (parser_rc) {
		rc = parser_rc;
		goto err;
	}

	if (nft_netlink(nft, &cmds, &msgs, nft->nf_sock) != 0)
		rc = -1;
err:
	erec_print_list(&nft->output, &msgs, nft->debug_mask);
	list_for_each_entry_safe(cmd, next, &cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}
	iface_cache_release();
	if (nft->scanner) {
		scanner_destroy(nft);
		nft->scanner = NULL;
	}

	if (!rc &&
	    nft_output_json(&nft->output) &&
	    nft_output_echo(&nft->output))
		json_print_echo(nft);
	if (rc)
		cache_release(&nft->cache);
	return rc;
}
