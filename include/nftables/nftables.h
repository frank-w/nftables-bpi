/*
 * Copyright (c) 2017 Eric Leblond <eric@regit.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef LIB_NFTABLES_H
#define LIB_NFTABLES_H

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

struct nft_ctx;

enum debug_level {
	DEBUG_SCANNER		= 0x1,
	DEBUG_PARSER		= 0x2,
	DEBUG_EVALUATION	= 0x4,
	DEBUG_NETLINK		= 0x8,
	DEBUG_MNL		= 0x10,
	DEBUG_PROTO_CTX		= 0x20,
	DEBUG_SEGTREE		= 0x40,
};

enum numeric_level {
	NUMERIC_NONE,
	NUMERIC_ADDR,
	NUMERIC_PORT,
	NUMERIC_ALL,
};

/**
 * Possible flags to pass to nft_ctx_new()
 */
#define NFT_CTX_DEFAULT		0

/**
 * Exit codes returned by nft_run_cmd_from_*()
 */
enum nftables_exit_codes {
	NFT_EXIT_SUCCESS	= 0,
	NFT_EXIT_FAILURE	= 1,
	NFT_EXIT_NOMEM		= 2,
	NFT_EXIT_NONL		= 3,
};

struct nft_ctx *nft_ctx_new(uint32_t flags);
void nft_ctx_free(struct nft_ctx *ctx);
FILE *nft_ctx_set_output(struct nft_ctx *ctx, FILE *fp);
void nft_ctx_flush_cache(struct nft_ctx *ctx);

int nft_run_cmd_from_buffer(struct nft_ctx *nft, char *buf, size_t buflen);
int nft_run_cmd_from_filename(struct nft_ctx *nft, const char *filename);

#endif /* LIB_NFTABLES_H */
