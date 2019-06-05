#ifndef NFTABLES_PARSER_H
#define NFTABLES_PARSER_H

#include <list.h>
#include <rule.h> // FIXME
#include <nftables.h>

#define TABSIZE				8

#define YYLTYPE				struct location
#define YYLTYPE_IS_TRIVIAL		0
#define YYENABLE_NLS			0

#define SCOPE_NEST_MAX			3

struct parser_state {
	struct input_descriptor		*indesc;
	struct input_descriptor		*indescs[MAX_INCLUDE_DEPTH];
	unsigned int			indesc_idx;
	struct list_head		indesc_list;

	struct list_head		*msgs;
	unsigned int			nerrs;

	struct scope			top_scope;
	struct scope			*scopes[SCOPE_NEST_MAX];
	unsigned int			scope;

	struct list_head		*cmds;
};

struct mnl_socket;

extern void parser_init(struct nft_ctx *nft, struct parser_state *state,
			struct list_head *msgs, struct list_head *cmds);
extern int nft_parse(struct nft_ctx *ctx, void *, struct parser_state *state);

extern void *scanner_init(struct parser_state *state);
extern void scanner_destroy(struct nft_ctx *nft);

extern int scanner_read_file(struct nft_ctx *nft, const char *filename,
			     const struct location *loc);
extern int scanner_include_file(struct nft_ctx *ctx, void *scanner,
				const char *filename,
				const struct location *loc);
extern void scanner_push_buffer(void *scanner,
				const struct input_descriptor *indesc,
				const char *buffer);

#endif /* NFTABLES_PARSER_H */
