#ifndef _NFT_CLI_H_
#define _NFT_CLI_H_

#include <nftables/libnftables.h>
#include <config.h>

struct parser_state;
#ifdef HAVE_LIBREADLINE
extern int cli_init(struct nft_ctx *nft);
#else
static inline int cli_init(struct nft_ctx *nft)
{
        return -1;
}
#endif
extern void cli_exit(void);

#endif
