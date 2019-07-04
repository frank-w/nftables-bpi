/*
 * Asynchronous readline-based interactive interface
 *
 * Actually not asynchronous so far, but intended to be.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <cli.h>
#include <list.h>

#define CMDLINE_HISTFILE	".nft.history"

static struct nft_ctx *cli_nft;
static char histfile[PATH_MAX];
static char *multiline;

static char *cli_append_multiline(char *line)
{
	size_t len = strlen(line);
	bool complete = false;
	char *s;

	if (len == 0)
		return NULL;

	if (line[len - 1] == '\\') {
		line[len - 1] = '\0';
		len--;
	} else if (multiline == NULL)
		return line;
	else
		complete = 1;

	if (multiline == NULL) {
		multiline = line;
		rl_save_prompt();
		rl_clear_message();
		rl_set_prompt(".... ");
	} else {
		len += strlen(multiline);
		s = malloc(len + 1);
		if (!s) {
			fprintf(stderr, "%s:%u: Memory allocation failure\n",
				__FILE__, __LINE__);
			cli_exit();
			exit(EXIT_FAILURE);
		}
		snprintf(s, len + 1, "%s%s", multiline, line);
		free(multiline);
		multiline = s;
	}
	line = NULL;

	if (complete) {
		line = multiline;
		multiline = NULL;
		rl_restore_prompt();
	}
	return line;
}

static void cli_complete(char *line)
{
	const HIST_ENTRY *hist;
	const char *c;
	LIST_HEAD(msgs);

	if (line == NULL) {
		printf("\n");
		cli_exit();
		exit(0);
	}

	line = cli_append_multiline(line);
	if (line == NULL)
		return;

	for (c = line; *c != '\0'; c++)
		if (!isspace(*c))
			break;
	if (*c == '\0')
		return;

	if (!strcmp(line, "quit")) {
		cli_exit();
		exit(0);
	}

	/* avoid duplicate history entries */
	hist = history_get(history_length);
	if (hist == NULL || strcmp(hist->line, line))
		add_history(line);

	nft_run_cmd_from_buffer(cli_nft, line);
	free(line);
}

static char **cli_completion(const char *text, int start, int end)
{
	return NULL;
}

int cli_init(struct nft_ctx *nft)
{
	const char *home;

	cli_nft = nft;
	rl_readline_name = "nft";
	rl_instream  = stdin;
	rl_outstream = stdout;

	rl_callback_handler_install("nft> ", cli_complete);
	rl_attempted_completion_function = cli_completion;

	home = getenv("HOME");
	if (home == NULL)
		home = "";
	snprintf(histfile, sizeof(histfile), "%s/%s", home, CMDLINE_HISTFILE);

	read_history(histfile);
	history_set_pos(history_length);

	while (true)
		rl_callback_read_char();
	return 0;
}

void cli_exit(void)
{
	rl_callback_handler_remove();
	rl_deprep_terminal();
	write_history(histfile);
}
