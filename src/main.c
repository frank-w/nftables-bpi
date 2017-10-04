/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>

#include <nftables.h>
#include <utils.h>
#include <parser.h>
#include <rule.h>
#include <netlink.h>
#include <erec.h>
#include <mnl.h>
#include <iface.h>
#include <cli.h>

static struct nft_ctx *nft;

enum opt_vals {
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_CHECK		= 'c',
	OPT_FILE		= 'f',
	OPT_INTERACTIVE		= 'i',
	OPT_INCLUDEPATH		= 'I',
	OPT_NUMERIC		= 'n',
	OPT_STATELESS		= 's',
	OPT_IP2NAME		= 'N',
	OPT_DEBUG		= 'd',
	OPT_HANDLE_OUTPUT	= 'a',
	OPT_ECHO		= 'e',
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvcf:iI:vnsNae"

static const struct option options[] = {
	{
		.name		= "help",
		.val		= OPT_HELP,
	},
	{
		.name		= "version",
		.val		= OPT_VERSION,
	},
	{
		.name		= "check",
		.val		= OPT_CHECK,
	},
	{
		.name		= "file",
		.val		= OPT_FILE,
		.has_arg	= 1,
	},
	{
		.name		= "interactive",
		.val		= OPT_INTERACTIVE,
	},
	{
		.name		= "numeric",
		.val		= OPT_NUMERIC,
	},
	{
		.name		= "stateless",
		.val		= OPT_STATELESS,
	},
	{
		.name		= "reversedns",
		.val		= OPT_IP2NAME,
	},
	{
		.name		= "includepath",
		.val		= OPT_INCLUDEPATH,
		.has_arg	= 1,
	},
	{
		.name		= "debug",
		.val		= OPT_DEBUG,
		.has_arg	= 1,
	},
	{
		.name		= "handle",
		.val		= OPT_HANDLE_OUTPUT,
	},
	{
		.name		= "echo",
		.val		= OPT_ECHO,
	},
	{
		.name		= NULL
	}
};

static void show_help(const char *name)
{
	printf(
"Usage: %s [ options ] [ cmds... ]\n"
"\n"
"Options:\n"
"  -h, --help			Show this help\n"
"  -v, --version			Show version information\n"
"\n"
"  -c, --check			Check commands validity without actually applying the changes.\n"
"  -f, --file <filename>		Read input from <filename>\n"
"  -i, --interactive		Read input from interactive CLI\n"
"\n"
"  -n, --numeric			When specified once, show network addresses numerically (default behaviour).\n"
"  				Specify twice to also show Internet services (port numbers) numerically.\n"
"				Specify three times to also show protocols, user IDs, and group IDs numerically.\n"
"  -s, --stateless		Omit stateful information of ruleset.\n"
"  -N				Translate IP addresses to names.\n"
"  -a, --handle			Output rule handle.\n"
"  -e, --echo			Echo what has been added, inserted or replaced.\n"
"  -I, --includepath <directory>	Add <directory> to the paths searched for include files. Default is: %s\n"
"  --debug <level [,level...]>	Specify debugging level (scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all)\n"
"\n",
	name, DEFAULT_INCLUDE_PATH);
}

static const struct {
	const char		*name;
	enum debug_level	level;
} debug_param[] = {
	{
		.name		= "scanner",
		.level		= DEBUG_SCANNER,
	},
	{
		.name		= "parser",
		.level		= DEBUG_PARSER,
	},
	{
		.name		= "eval",
		.level		= DEBUG_EVALUATION,
	},
	{
		.name		= "netlink",
		.level		= DEBUG_NETLINK,
	},
	{
		.name		= "mnl",
		.level		= DEBUG_MNL,
	},
	{
		.name		= "proto-ctx",
		.level		= DEBUG_PROTO_CTX,
	},
	{
		.name		= "segtree",
		.level		= DEBUG_SEGTREE,
	},
	{
		.name		= "all",
		.level		= ~0,
	},
};

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

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

int nft_run(struct nft_ctx *nft, struct mnl_socket *nf_sock,
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

static void nft_ctx_netlink_init(struct nft_ctx *ctx)
{
	ctx->nf_sock = netlink_open_sock();
}

static struct nft_ctx *nft_ctx_new(uint32_t flags)
{
	struct nft_ctx *ctx;

	nft_init();
	ctx = xzalloc(sizeof(struct nft_ctx));

	ctx->include_paths[0]	= DEFAULT_INCLUDE_PATH;
	ctx->num_include_paths	= 1;
	ctx->parser_max_errors	= 10;
	init_list_head(&ctx->cache.list);
	ctx->flags = flags;

	if (flags == NFT_CTX_DEFAULT)
		nft_ctx_netlink_init(ctx);

	return ctx;
}

static void nft_ctx_free(const struct nft_ctx *ctx)
{
	if (ctx->nf_sock)
		netlink_close_sock(ctx->nf_sock);

	iface_cache_release();
	cache_release(&nft->cache);
	xfree(ctx);
	nft_exit();
}

static FILE *nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp)
{
	FILE *old = ctx->output.output_fp;

	ctx->output.output_fp = fp;

	return old;
}

static int nft_run_cmd_from_buffer(struct nft_ctx *nft,
				   char *buf, size_t buflen)
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

	return rc;
}

static int nft_run_cmd_from_filename(struct nft_ctx *nft, const char *filename)
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

int main(int argc, char * const *argv)
{
	char *buf = NULL, *filename = NULL;
	unsigned int len;
	bool interactive = false;
	struct parser_state state;
	int i, val, rc;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	nft_ctx_set_output(nft, stdout);

	while (1) {
		val = getopt_long(argc, argv, OPTSTRING, options, NULL);
		if (val == -1)
			break;

		switch (val) {
		case OPT_HELP:
			show_help(argv[0]);
			exit(NFT_EXIT_SUCCESS);
		case OPT_VERSION:
			printf("%s v%s (%s)\n",
			       PACKAGE_NAME, PACKAGE_VERSION, RELEASE_NAME);
			exit(NFT_EXIT_SUCCESS);
		case OPT_CHECK:
			nft->check = true;
			break;
		case OPT_FILE:
			filename = optarg;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_INCLUDEPATH:
			if (nft->num_include_paths >= INCLUDE_PATHS_MAX) {
				fprintf(stderr, "Too many include paths "
						"specified, max. %u\n",
					INCLUDE_PATHS_MAX - 1);
				exit(NFT_EXIT_FAILURE);
			}
			nft->include_paths[nft->num_include_paths++] = optarg;
			break;
		case OPT_NUMERIC:
			if (++nft->output.numeric > NUMERIC_ALL) {
				fprintf(stderr, "Too many numeric options "
						"used, max. %u\n",
					NUMERIC_ALL);
				exit(NFT_EXIT_FAILURE);
			}
			break;
		case OPT_STATELESS:
			nft->output.stateless++;
			break;
		case OPT_IP2NAME:
			nft->output.ip2name++;
			break;
		case OPT_DEBUG:
			for (;;) {
				unsigned int i;
				char *end;

				end = strchr(optarg, ',');
				if (end)
					*end = '\0';

				for (i = 0; i < array_size(debug_param); i++) {
					if (strcmp(debug_param[i].name, optarg))
						continue;
					nft->debug_mask |= debug_param[i].level;
					break;
				}

				if (i == array_size(debug_param)) {
					fprintf(stderr, "invalid debug parameter `%s'\n",
						optarg);
					exit(NFT_EXIT_FAILURE);
				}

				if (end == NULL)
					break;
				optarg = end + 1;
			}
			break;
		case OPT_HANDLE_OUTPUT:
			nft->output.handle++;
			break;
		case OPT_ECHO:
			nft->output.echo++;
			break;
		case OPT_INVALID:
			exit(NFT_EXIT_FAILURE);
		}
	}

	if (optind != argc) {
		for (len = 0, i = optind; i < argc; i++)
			len += strlen(argv[i]) + strlen(" ");

		buf = xzalloc(len + 2);
		for (i = optind; i < argc; i++) {
			strcat(buf, argv[i]);
			if (i + 1 < argc)
				strcat(buf, " ");
		}
		strcat(buf, "\n");
		rc = nft_run_cmd_from_buffer(nft, buf, len + 2);
	} else if (filename != NULL) {
		rc = nft_run_cmd_from_filename(nft, filename);
	} else if (interactive) {
		if (cli_init(nft, nft->nf_sock, &state) < 0) {
			fprintf(stderr, "%s: interactive CLI not supported in this build\n",
				argv[0]);
			exit(NFT_EXIT_FAILURE);
		}
		return 0;
	} else {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		exit(NFT_EXIT_FAILURE);
	}

	xfree(buf);
	nft_ctx_free(nft);

	return rc;
}
