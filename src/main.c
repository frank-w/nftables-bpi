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

#include <nftables/libnftables.h>
#include <utils.h>
#include <cli.h>

static struct nft_ctx *nft;

enum opt_vals {
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_CHECK		= 'c',
	OPT_FILE		= 'f',
	OPT_INTERACTIVE		= 'i',
	OPT_INCLUDEPATH		= 'I',
	OPT_JSON		= 'j',
	OPT_NUMERIC		= 'n',
	OPT_STATELESS		= 's',
	OPT_IP2NAME		= 'N',
	OPT_DEBUG		= 'd',
	OPT_HANDLE_OUTPUT	= 'a',
	OPT_ECHO		= 'e',
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvcf:iI:jvnsNae"

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
		.name		= "json",
		.val		= OPT_JSON,
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
"  -j, --json			Format output in JSON\n"
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
	enum nft_debug_level	level;
} debug_param[] = {
	{
		.name		= "scanner",
		.level		= NFT_DEBUG_SCANNER,
	},
	{
		.name		= "parser",
		.level		= NFT_DEBUG_PARSER,
	},
	{
		.name		= "eval",
		.level		= NFT_DEBUG_EVALUATION,
	},
	{
		.name		= "netlink",
		.level		= NFT_DEBUG_NETLINK,
	},
	{
		.name		= "mnl",
		.level		= NFT_DEBUG_MNL,
	},
	{
		.name		= "proto-ctx",
		.level		= NFT_DEBUG_PROTO_CTX,
	},
	{
		.name		= "segtree",
		.level		= NFT_DEBUG_SEGTREE,
	},
	{
		.name		= "all",
		.level		= ~0,
	},
};

int main(int argc, char * const *argv)
{
	char *buf = NULL, *filename = NULL;
	enum nft_numeric_level numeric;
	bool interactive = false;
	unsigned int debug_mask;
	unsigned int len;
	int i, val, rc;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);

	while (1) {
		val = getopt_long(argc, argv, OPTSTRING, options, NULL);
		if (val == -1)
			break;

		switch (val) {
		case OPT_HELP:
			show_help(argv[0]);
			exit(EXIT_SUCCESS);
		case OPT_VERSION:
			printf("%s v%s (%s)\n",
			       PACKAGE_NAME, PACKAGE_VERSION, RELEASE_NAME);
			exit(EXIT_SUCCESS);
		case OPT_CHECK:
			nft_ctx_set_dry_run(nft, true);
			break;
		case OPT_FILE:
			filename = optarg;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_INCLUDEPATH:
			if (nft_ctx_add_include_path(nft, optarg)) {
				fprintf(stderr,
					"Failed to add include path '%s'\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case OPT_NUMERIC:
			numeric = nft_ctx_output_get_numeric(nft);
			if (numeric == NFT_NUMERIC_ALL) {
				fprintf(stderr, "Too many numeric options "
						"used, max. %u\n",
					NFT_NUMERIC_ALL);
				exit(EXIT_FAILURE);
			}
			nft_ctx_output_set_numeric(nft, numeric + 1);
			break;
		case OPT_STATELESS:
			nft_ctx_output_set_stateless(nft, true);
			break;
		case OPT_IP2NAME:
			nft_ctx_output_set_ip2name(nft, true);
			break;
		case OPT_DEBUG:
			debug_mask = nft_ctx_output_get_debug(nft);
			for (;;) {
				unsigned int i;
				char *end;

				end = strchr(optarg, ',');
				if (end)
					*end = '\0';

				for (i = 0; i < array_size(debug_param); i++) {
					if (strcmp(debug_param[i].name, optarg))
						continue;
					debug_mask |= debug_param[i].level;
					break;
				}

				if (i == array_size(debug_param)) {
					fprintf(stderr, "invalid debug parameter `%s'\n",
						optarg);
					exit(EXIT_FAILURE);
				}

				if (end == NULL)
					break;
				optarg = end + 1;
			}
			nft_ctx_output_set_debug(nft, debug_mask);
			break;
		case OPT_HANDLE_OUTPUT:
			nft_ctx_output_set_handle(nft, true);
			break;
		case OPT_ECHO:
			nft_ctx_output_set_echo(nft, true);
			break;
		case OPT_JSON:
			nft_ctx_output_set_json(nft, true);
			break;
		case OPT_INVALID:
			exit(EXIT_FAILURE);
		}
	}

	if (optind != argc) {
		for (len = 0, i = optind; i < argc; i++)
			len += strlen(argv[i]) + strlen(" ");

		buf = xzalloc(len);
		for (i = optind; i < argc; i++) {
			strcat(buf, argv[i]);
			if (i + 1 < argc)
				strcat(buf, " ");
		}
		rc = !!nft_run_cmd_from_buffer(nft, buf);
	} else if (filename != NULL) {
		rc = !!nft_run_cmd_from_filename(nft, filename);
	} else if (interactive) {
		if (cli_init(nft) < 0) {
			fprintf(stderr, "%s: interactive CLI not supported in this build\n",
				argv[0]);
			exit(EXIT_FAILURE);
		}
		return EXIT_SUCCESS;
	} else {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	xfree(buf);
	nft_ctx_free(nft);

	return rc;
}
