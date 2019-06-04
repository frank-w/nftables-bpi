/*
 * Copyright (c) 2019 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (or any
 * later) as published by the Free Software Foundation.
 */

#include <expression.h>
#include <statement.h>
#include <rule.h>
#include <erec.h>
#include <utils.h>

static unsigned int evaluate_cache_add(struct cmd *cmd)
{
	unsigned int completeness = CMD_INVALID;

	switch (cmd->obj) {
	case CMD_OBJ_SETELEM:
	case CMD_OBJ_SET:
	case CMD_OBJ_CHAIN:
	case CMD_OBJ_FLOWTABLE:
		completeness = cmd->op;
		break;
	case CMD_OBJ_RULE:
		/* XXX index is set to zero unless this handle_merge() call is
		 * invoked, this handle_merge() call is done from the
		 * evaluation, which is too late.
		 */
		handle_merge(&cmd->rule->handle, &cmd->handle);

		if (cmd->rule->handle.index.id)
			completeness = CMD_LIST;
		break;
	default:
		break;
	}

	return completeness;
}

static unsigned int evaluate_cache_del(struct cmd *cmd)
{
	unsigned int completeness = CMD_INVALID;

	switch (cmd->obj) {
	case CMD_OBJ_SETELEM:
		completeness = cmd->op;
		break;
	default:
		break;
	}

	return completeness;
}

static unsigned int evaluate_cache_flush(struct cmd *cmd)
{
	unsigned int completeness = CMD_INVALID;

	switch (cmd->obj) {
	case CMD_OBJ_SET:
	case CMD_OBJ_MAP:
	case CMD_OBJ_METER:
		completeness = cmd->op;
		break;
	default:
		break;
	}

	return completeness;
}

static unsigned int evaluate_cache_rename(struct cmd *cmd)
{
	unsigned int completeness = CMD_INVALID;

	switch (cmd->obj) {
	case CMD_OBJ_CHAIN:
		completeness = cmd->op;
		break;
	default:
		break;
	}

	return completeness;
}

int cache_evaluate(struct nft_ctx *nft, struct list_head *cmds)
{
	unsigned int echo_completeness = CMD_INVALID;
	unsigned int completeness = CMD_INVALID;
	struct cmd *cmd;

	list_for_each_entry(cmd, cmds, list) {
		switch (cmd->op) {
		case CMD_ADD:
		case CMD_INSERT:
		case CMD_REPLACE:
			if (nft_output_echo(&nft->output))
				echo_completeness = cmd->op;

			/* Fall through */
		case CMD_CREATE:
			completeness = evaluate_cache_add(cmd);
			break;
		case CMD_DELETE:
			completeness = evaluate_cache_del(cmd);
			break;
		case CMD_GET:
		case CMD_LIST:
		case CMD_RESET:
		case CMD_EXPORT:
		case CMD_MONITOR:
			completeness = cmd->op;
			break;
		case CMD_FLUSH:
			completeness = evaluate_cache_flush(cmd);
			break;
		case CMD_RENAME:
			completeness = evaluate_cache_rename(cmd);
			break;
		case CMD_DESCRIBE:
		case CMD_IMPORT:
			break;
		default:
			break;
		}
	}

	return max(completeness, echo_completeness);
}
