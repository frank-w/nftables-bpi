#ifndef NFTABLES_NETLINK_H
#define NFTABLES_NETLINK_H

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/flowtable.h>

#include <linux/netlink.h>
#include <linux/netfilter/nf_tables.h>

#include <rule.h>

#define MAX_REGS	(1 + NFT_REG32_15 - NFT_REG32_00)

struct netlink_parse_ctx {
	struct list_head	*msgs;
	struct table		*table;
	struct rule		*rule;
	struct stmt		*stmt;
	struct expr		*registers[MAX_REGS + 1];
	unsigned int		debug_mask;
};

struct rule_pp_ctx {
	struct proto_ctx	pctx;
	struct payload_dep_ctx	pdctx;
	struct stmt		*stmt;
};

extern const struct input_descriptor indesc_netlink;
extern const struct location netlink_location;

/** 
 * struct netlink_ctx
 *
 * @nft:	nftables context
 * @msgs:	message queue
 * @list:	list of parsed rules/chains/tables
 * @set:	current set
 * @data:	pointer to pass data to callback
 * @seqnum:	sequence number
 */
struct netlink_ctx {
	struct nft_ctx		*nft;
	struct list_head	*msgs;
	struct list_head	list;
	struct set		*set;
	const void		*data;
	uint32_t		seqnum;
	struct nftnl_batch	*batch;
};

extern struct nftnl_expr *alloc_nft_expr(const char *name);
extern void alloc_setelem_cache(const struct expr *set, struct nftnl_set *nls);

extern struct nftnl_table *netlink_table_alloc(const struct nlmsghdr *nlh);
extern struct nftnl_chain *netlink_chain_alloc(const struct nlmsghdr *nlh);
extern struct nftnl_set *netlink_set_alloc(const struct nlmsghdr *nlh);
extern struct nftnl_obj *netlink_obj_alloc(const struct nlmsghdr *nlh);
extern struct nftnl_rule *netlink_rule_alloc(const struct nlmsghdr *nlh);

struct nft_data_linearize {
	uint32_t	len;
	uint32_t	value[4];
	char		chain[NFT_CHAIN_MAXNAMELEN];
	int		verdict;
};

struct nft_data_delinearize {
	uint32_t	len;
	const uint32_t	*value;
	const char	*chain;
	int		verdict;
};

static inline unsigned int netlink_register_space(unsigned int size)
{
	return div_round_up(size, NFT_REG32_SIZE * BITS_PER_BYTE);
}

static inline unsigned int netlink_padded_len(unsigned int size)
{
	return netlink_register_space(size) * NFT_REG32_SIZE * BITS_PER_BYTE;
}

static inline unsigned int netlink_padding_len(unsigned int size)
{
	return netlink_padded_len(size) - size;
}

extern void netlink_gen_data(const struct expr *expr,
			     struct nft_data_linearize *data);
extern void netlink_gen_raw_data(const mpz_t value, enum byteorder byteorder,
				 unsigned int len,
				 struct nft_data_linearize *data);

extern struct expr *netlink_alloc_value(const struct location *loc,
				        const struct nft_data_delinearize *nld);
extern struct expr *netlink_alloc_data(const struct location *loc,
				       const struct nft_data_delinearize *nld,
				       enum nft_registers dreg);

extern int netlink_list_rules(struct netlink_ctx *ctx, const struct handle *h);
extern void netlink_linearize_rule(struct netlink_ctx *ctx,
				   struct nftnl_rule *nlr,
				   const struct rule *rule);
extern struct rule *netlink_delinearize_rule(struct netlink_ctx *ctx,
					     struct nftnl_rule *r);

extern int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h);
extern struct chain *netlink_delinearize_chain(struct netlink_ctx *ctx,
					       const struct nftnl_chain *nlc);

extern int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h);
extern struct table *netlink_delinearize_table(struct netlink_ctx *ctx,
					       const struct nftnl_table *nlt);

extern int netlink_list_sets(struct netlink_ctx *ctx, const struct handle *h);
extern struct set *netlink_delinearize_set(struct netlink_ctx *ctx,
					   const struct nftnl_set *nls);

extern struct stmt *netlink_parse_set_expr(const struct set *set,
					   const struct nft_cache *cache,
					   const struct nftnl_expr *nle);

extern int netlink_list_setelems(struct netlink_ctx *ctx,
				 const struct handle *h, struct set *set);
extern int netlink_get_setelem(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc, struct table *table,
			       struct set *set, struct expr *init);
extern int netlink_delinearize_setelem(struct nftnl_set_elem *nlse,
				       const struct set *set,
				       struct nft_cache *cache);

extern int netlink_list_objs(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_reset_objs(struct netlink_ctx *ctx, const struct cmd *cmd,
			      uint32_t type, bool dump);
extern struct obj *netlink_delinearize_obj(struct netlink_ctx *ctx,
					   struct nftnl_obj *nlo);

extern int netlink_list_flowtables(struct netlink_ctx *ctx,
				   const struct handle *h);

extern void netlink_dump_chain(const struct nftnl_chain *nlc,
			       struct netlink_ctx *ctx);
extern void netlink_dump_rule(const struct nftnl_rule *nlr,
			      struct netlink_ctx *ctx);
extern void netlink_dump_expr(const struct nftnl_expr *nle,
			      FILE *fp, unsigned int debug_mask);
extern void netlink_dump_set(const struct nftnl_set *nls,
			     struct netlink_ctx *ctx);
extern void netlink_dump_obj(struct nftnl_obj *nlo, struct netlink_ctx *ctx);
extern void netlink_dump_flowtable(struct nftnl_flowtable *flo, struct netlink_ctx *ctx);

#define netlink_abi_error()	\
	__netlink_abi_error(__FILE__, __LINE__, strerror(errno));
extern void __noreturn __netlink_abi_error(const char *file, int line, const char *reason);
extern int netlink_io_error(struct netlink_ctx *ctx,
			    const struct location *loc, const char *fmt, ...);
#define netlink_init_error()	\
	__netlink_init_error(__FILE__, __LINE__, strerror(errno));
extern void __noreturn __netlink_init_error(const char *file, int line, const char *reason);

struct netlink_mon_handler {
	uint32_t		monitor_flags;
	uint32_t		format;
	struct netlink_ctx	*ctx;
	const struct location	*loc;
	unsigned int		debug_mask;
	bool			cache_needed;
	struct nft_cache	*cache;
};

extern int netlink_monitor(struct netlink_mon_handler *monhandler,
			    struct mnl_socket *nf_sock);
int netlink_echo_callback(const struct nlmsghdr *nlh, void *data);

struct ruleset_parse {
	struct netlink_ctx      *nl_ctx;
	struct cmd              *cmd;
};

struct nftnl_parse_ctx;

int netlink_events_trace_cb(const struct nlmsghdr *nlh, int type,
			    struct netlink_mon_handler *monh);

enum nft_data_types dtype_map_to_kernel(const struct datatype *dtype);
const struct datatype *dtype_map_from_kernel(enum nft_data_types type);

#endif /* NFTABLES_NETLINK_H */
