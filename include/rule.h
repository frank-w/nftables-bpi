#ifndef NFTABLES_RULE_H
#define NFTABLES_RULE_H

#include <stdint.h>
#include <nftables.h>
#include <list.h>
#include <netinet/in.h>
#include <libnftnl/object.h>	/* For NFTNL_CTTIMEOUT_ARRAY_MAX. */
#include <linux/netfilter/nf_tables.h>

/**
 * struct handle_spec - handle ID
 *
 * @location:	location this handle was defined at
 * @id:		handle ID value
 */
struct handle_spec {
	struct location		location;
	uint64_t		id;
};

/**
 * struct position_spec - position ID
 *
 * @location:	location this position was defined at
 * @id:		position ID value
 */
struct position_spec {
	struct location		location;
	uint64_t		id;
};

struct table_spec {
	struct location		location;
	const char		*name;
};

struct chain_spec {
	struct location		location;
	const char		*name;
};

struct set_spec {
	struct location		location;
	const char		*name;
};

struct obj_spec {
	struct location		location;
	const char		*name;
};

/**
 * struct handle - handle for tables, chains, rules and sets
 *
 * @family:	protocol family
 * @table:	table name
 * @chain:	chain name (chains and rules only)
 * @set:	set name (sets only)
 * @obj:	stateful object name (stateful object only)
 * @flowtable:	flow table name (flow table only)
 * @handle:	rule handle (rules only)
 * @position:	rule position (rules only)
 * @set_id:	set ID (sets only)
 */
struct handle {
	uint32_t		family;
	struct table_spec	table;
	struct chain_spec	chain;
	struct set_spec		set;
	struct obj_spec		obj;
	const char		*flowtable;
	struct handle_spec	handle;
	struct position_spec	position;
	struct position_spec	index;
	uint32_t		set_id;
	uint32_t		rule_id;
	uint32_t		position_id;
};

extern void handle_merge(struct handle *dst, const struct handle *src);
extern void handle_free(struct handle *h);

/**
 * struct scope
 *
 * @parent:	pointer to parent scope
 * @symbols:	symbols bound in the scope
 */
struct scope {
	const struct scope	*parent;
	struct list_head	symbols;
};

extern struct scope *scope_init(struct scope *scope, const struct scope *parent);
extern void scope_release(const struct scope *scope);

/**
 * struct symbol
 *
 * @list:	scope symbol list node
 * @identifier:	identifier
 * @expr:	initializer
 * @refcnt:	reference counter
 */
struct symbol {
	struct list_head	list;
	const char		*identifier;
	struct expr		*expr;
	int			refcnt;
};

extern void symbol_bind(struct scope *scope, const char *identifier,
			struct expr *expr);
extern int symbol_unbind(const struct scope *scope, const char *identifier);
extern struct symbol *symbol_lookup(const struct scope *scope,
				    const char *identifier);
struct symbol *symbol_lookup_fuzzy(const struct scope *scope,
				   const char *identifier);
struct symbol *symbol_get(const struct scope *scope, const char *identifier);

enum table_flags {
	TABLE_F_DORMANT		= (1 << 0),
};
#define TABLE_FLAGS_MAX 1

extern const char *table_flags_name[TABLE_FLAGS_MAX];

/**
 * struct table - nftables table
 *
 * @list:	list node
 * @handle:	table handle
 * @location:	location the table was defined at
 * @chains:	chains contained in the table
 * @sets:	sets contained in the table
 * @objs:	stateful objects contained in the table
 * @flowtables:	flow tables contained in the table
 * @flags:	table flags
 * @refcnt:	table reference counter
 */
struct table {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct scope		scope;
	struct list_head	chains;
	struct list_head	sets;
	struct list_head	objs;
	struct list_head	flowtables;
	enum table_flags 	flags;
	unsigned int		refcnt;
};

extern struct table *table_alloc(void);
extern struct table *table_get(struct table *table);
extern void table_free(struct table *table);
extern void table_add_hash(struct table *table, struct nft_cache *cache);
extern struct table *table_lookup(const struct handle *h,
				  const struct nft_cache *cache);
extern struct table *table_lookup_fuzzy(const struct handle *h,
					const struct nft_cache *cache);

/**
 * enum chain_flags - chain flags
 *
 * @CHAIN_F_BASECHAIN:	chain is a base chain
 */
enum chain_flags {
	CHAIN_F_BASECHAIN	= 0x1,
};

/**
 * struct prio_spec - extendend priority specification for mixed
 *                    textual/numerical parsing.
 *
 * @expr:  expr of the standard priority value
 */
struct prio_spec {
	struct location loc;
	struct expr	*expr;
};

/**
 * struct chain - nftables chain
 *
 * @list:	list node in table list
 * @handle:	chain handle
 * @location:	location the chain was defined at
 * @refcnt:	reference counter
 * @flags:	chain flags
 * @hookstr:	unified and human readable hook name (base chains)
 * @hooknum:	hook number (base chains)
 * @priority:	hook priority (base chains)
 * @policy:	default chain policy (base chains)
 * @type:	chain type
 * @dev:	device (if any)
 * @rules:	rules contained in the chain
 */
struct chain {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	unsigned int		refcnt;
	uint32_t		flags;
	const char		*hookstr;
	unsigned int		hooknum;
	struct prio_spec	priority;
	struct expr		*policy;
	const char		*type;
	const char		*dev;
	struct scope		scope;
	struct list_head	rules;
};

#define STD_PRIO_BUFSIZE 100
extern int std_prio_lookup(const char *std_prio_name, int family, int hook);
extern const char *chain_type_name_lookup(const char *name);
extern const char *chain_hookname_lookup(const char *name);
extern struct chain *chain_alloc(const char *name);
extern struct chain *chain_get(struct chain *chain);
extern void chain_free(struct chain *chain);
extern void chain_add_hash(struct chain *chain, struct table *table);
extern struct chain *chain_lookup(const struct table *table,
				  const struct handle *h);
extern struct chain *chain_lookup_fuzzy(const struct handle *h,
					const struct nft_cache *cache,
					const struct table **table);

extern const char *family2str(unsigned int family);
extern const char *hooknum2str(unsigned int family, unsigned int hooknum);
extern const char *chain_policy2str(uint32_t policy);
extern void chain_print_plain(const struct chain *chain,
			      struct output_ctx *octx);

/**
 * struct rule - nftables rule
 *
 * @list:	list node in chain list
 * @handle:	rule handle
 * @location:	location the rule was defined at
 * @stmt:	list of statements
 * @num_stmts:	number of statements in stmts list
 * @comment:	comment
 * @refcnt:	rule reference counter
 */
struct rule {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct list_head	stmts;
	unsigned int		num_stmts;
	const char		*comment;
	unsigned int		refcnt;
};

extern struct rule *rule_alloc(const struct location *loc,
			       const struct handle *h);
extern struct rule *rule_get(struct rule *rule);
extern void rule_free(struct rule *rule);
extern void rule_print(const struct rule *rule, struct output_ctx *octx);
extern struct rule *rule_lookup(const struct chain *chain, uint64_t handle);
extern struct rule *rule_lookup_by_index(const struct chain *chain,
					 uint64_t index);

/**
 * struct set - nftables set
 *
 * @list:	table set list node
 * @handle:	set handle
 * @location:	location the set was defined/declared at
 * @refcnt:	reference count
 * @flags:	bitmask of set flags
 * @gc_int:	garbage collection interval
 * @timeout:	default timeout value
 * @key:	key expression (data type, length))
 * @datatype:	mapping data type
 * @datalen:	mapping data len
 * @objtype:	mapping object type
 * @init:	initializer
 * @rg_cache:	cached range element (left)
 * @policy:	set mechanism policy
 * @automerge:	merge adjacents and overlapping elements, if possible
 * @desc:	set mechanism desc
 */
struct set {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	unsigned int		refcnt;
	uint32_t		flags;
	uint32_t		gc_int;
	uint64_t		timeout;
	struct expr		*key;
	const struct datatype	*datatype;
	unsigned int		datalen;
	uint32_t		objtype;
	struct expr		*init;
	struct expr		*rg_cache;
	uint32_t		policy;
	bool			automerge;
	struct {
		uint32_t	size;
	} desc;
};

extern struct set *set_alloc(const struct location *loc);
extern struct set *set_get(struct set *set);
extern void set_free(struct set *set);
extern struct set *set_clone(const struct set *set);
extern void set_add_hash(struct set *set, struct table *table);
extern struct set *set_lookup(const struct table *table, const char *name);
extern struct set *set_lookup_global(uint32_t family, const char *table,
				     const char *name, struct nft_cache *cache);
extern struct set *set_lookup_fuzzy(const char *set_name,
				    const struct nft_cache *cache,
				    const struct table **table);
extern const char *set_policy2str(uint32_t policy);
extern void set_print(const struct set *set, struct output_ctx *octx);
extern void set_print_plain(const struct set *s, struct output_ctx *octx);

static inline bool set_is_datamap(uint32_t set_flags)
{
	return set_flags & NFT_SET_MAP;
}

static inline bool set_is_objmap(uint32_t set_flags)
{
	return set_flags & NFT_SET_OBJECT;
}

static inline bool set_is_map(uint32_t set_flags)
{
	return set_is_datamap(set_flags) || set_is_objmap(set_flags);
}

static inline bool set_is_anonymous(uint32_t set_flags)
{
	return set_flags & NFT_SET_ANONYMOUS;
}

static inline bool set_is_literal(uint32_t set_flags)
{
	return !(set_is_anonymous(set_flags) || set_is_map(set_flags));
}

static inline bool map_is_literal(uint32_t set_flags)
{
	return !(set_is_anonymous(set_flags) || !set_is_map(set_flags));
}

#include <statement.h>

struct counter {
	uint64_t	packets;
	uint64_t	bytes;
};

struct quota {
	uint64_t	bytes;
	uint64_t	used;
	uint32_t	flags;
};

struct ct_helper {
	char name[16];
	uint16_t l3proto;
	uint8_t l4proto;
};

struct timeout_state {
	struct list_head head;
	struct location location;
	uint8_t timeout_index;
	const char *timeout_str;
	unsigned int timeout_value;
};

struct ct_timeout {
	uint16_t l3proto;
	uint8_t l4proto;
	uint32_t timeout[NFTNL_CTTIMEOUT_ARRAY_MAX];
	struct list_head timeout_list;
};

struct ct_expect {
	uint16_t l3proto;
	uint8_t l4proto;
	uint16_t dport;
	uint32_t timeout;
	uint8_t size;
};

struct limit {
	uint64_t	rate;
	uint64_t	unit;
	uint32_t	burst;
	uint32_t	type;
	uint32_t	flags;
};

struct secmark {
	char		ctx[NFT_SECMARK_CTX_MAXLEN];
};

/**
 * struct obj - nftables stateful object statement
 *
 * @list:	table set list node
 * @location:	location the stateful object was defined/declared at
 * @handle:	counter handle
 * @type:	type of stateful object
 * @refcnt:	object reference counter
 */
struct obj {
	struct list_head		list;
	struct location			location;
	struct handle			handle;
	uint32_t			type;
	unsigned int			refcnt;
	union {
		struct counter		counter;
		struct quota		quota;
		struct ct_helper	ct_helper;
		struct limit		limit;
		struct ct_timeout	ct_timeout;
		struct secmark		secmark;
		struct ct_expect	ct_expect;
	};
};

struct obj *obj_alloc(const struct location *loc);
extern struct obj *obj_get(struct obj *obj);
void obj_free(struct obj *obj);
void obj_add_hash(struct obj *obj, struct table *table);
struct obj *obj_lookup(const struct table *table, const char *name,
		       uint32_t type);
struct obj *obj_lookup_fuzzy(const char *obj_name,
			     const struct nft_cache *cache,
			     const struct table **t);
void obj_print(const struct obj *n, struct output_ctx *octx);
void obj_print_plain(const struct obj *obj, struct output_ctx *octx);
const char *obj_type_name(uint32_t type);
uint32_t obj_type_to_cmd(uint32_t type);

struct flowtable {
	struct list_head	list;
	struct handle		handle;
	struct scope		scope;
	struct location		location;
	const char *		hookstr;
	unsigned int		hooknum;
	struct prio_spec	priority;
	const char		**dev_array;
	struct expr		*dev_expr;
	int			dev_array_len;
	unsigned int		refcnt;
};

extern struct flowtable *flowtable_alloc(const struct location *loc);
extern struct flowtable *flowtable_get(struct flowtable *flowtable);
extern void flowtable_free(struct flowtable *flowtable);
extern void flowtable_add_hash(struct flowtable *flowtable, struct table *table);

void flowtable_print(const struct flowtable *n, struct output_ctx *octx);

/**
 * enum cmd_ops - command operations
 *
 * @CMD_INVALID:	invalid
 * @CMD_ADD:		add object (non-exclusive)
 * @CMD_REPLACE,	replace object
 * @CMD_CREATE:		create object (exclusive)
 * @CMD_INSERT:		insert object
 * @CMD_DELETE:		delete object
 * @CMD_GET:		get object
 * @CMD_LIST:		list container
 * @CMD_RESET:		reset container
 * @CMD_FLUSH:		flush container
 * @CMD_RENAME:		rename object
 * @CMD_IMPORT:		import a ruleset in a given format
 * @CMD_EXPORT:		export the ruleset in a given format
 * @CMD_MONITOR:	event listener
 * @CMD_DESCRIBE:	describe an expression
 */
enum cmd_ops {
	CMD_INVALID,
	CMD_ADD,
	CMD_REPLACE,
	CMD_CREATE,
	CMD_INSERT,
	CMD_DELETE,
	CMD_GET,
	CMD_LIST,
	CMD_RESET,
	CMD_FLUSH,
	CMD_RENAME,
	CMD_IMPORT,
	CMD_EXPORT,
	CMD_MONITOR,
	CMD_DESCRIBE,
};

/**
 * enum cmd_obj - command objects
 *
 * @CMD_OBJ_INVALID:	invalid
 * @CMD_OBJ_SETELEM:	set element(s)
 * @CMD_OBJ_SET:	set
 * @CMD_OBJ_SETS:	multiple sets
 * @CMD_OBJ_RULE:	rule
 * @CMD_OBJ_CHAIN:	chain
 * @CMD_OBJ_CHAINS:	multiple chains
 * @CMD_OBJ_TABLE:	table
 * @CMD_OBJ_FLOWTABLE:	flowtable
 * @CMD_OBJ_FLOWTABLES:	flowtables
 * @CMD_OBJ_RULESET:	ruleset
 * @CMD_OBJ_EXPR:	expression
 * @CMD_OBJ_MONITOR:	monitor
 * @CMD_OBJ_MARKUP:    import/export
 * @CMD_OBJ_METER:	meter
 * @CMD_OBJ_METERS:	meters
 * @CMD_OBJ_COUNTER:	counter
 * @CMD_OBJ_COUNTERS:	multiple counters
 * @CMD_OBJ_QUOTA:	quota
 * @CMD_OBJ_QUOTAS:	multiple quotas
 * @CMD_OBJ_LIMIT:	limit
 * @CMD_OBJ_LIMITS:	multiple limits
 * @CMD_OBJ_FLOWTABLES:	flow tables
 * @CMD_OBJ_SECMARK:	secmark
 * @CMD_OBJ_SECMARKS:	multiple secmarks
 */
enum cmd_obj {
	CMD_OBJ_INVALID,
	CMD_OBJ_SETELEM,
	CMD_OBJ_SET,
	CMD_OBJ_SETS,
	CMD_OBJ_RULE,
	CMD_OBJ_CHAIN,
	CMD_OBJ_CHAINS,
	CMD_OBJ_TABLE,
	CMD_OBJ_RULESET,
	CMD_OBJ_EXPR,
	CMD_OBJ_MONITOR,
	CMD_OBJ_MARKUP,
	CMD_OBJ_METER,
	CMD_OBJ_METERS,
	CMD_OBJ_MAP,
	CMD_OBJ_MAPS,
	CMD_OBJ_COUNTER,
	CMD_OBJ_COUNTERS,
	CMD_OBJ_QUOTA,
	CMD_OBJ_QUOTAS,
	CMD_OBJ_CT_HELPER,
	CMD_OBJ_CT_HELPERS,
	CMD_OBJ_LIMIT,
	CMD_OBJ_LIMITS,
	CMD_OBJ_FLOWTABLE,
	CMD_OBJ_FLOWTABLES,
	CMD_OBJ_CT_TIMEOUT,
	CMD_OBJ_SECMARK,
	CMD_OBJ_SECMARKS,
	CMD_OBJ_CT_EXPECT,
};

struct markup {
	uint32_t	format;
};

struct markup *markup_alloc(uint32_t format);
void markup_free(struct markup *m);

enum {
	CMD_MONITOR_OBJ_ANY,
	CMD_MONITOR_OBJ_TABLES,
	CMD_MONITOR_OBJ_CHAINS,
	CMD_MONITOR_OBJ_RULES,
	CMD_MONITOR_OBJ_SETS,
	CMD_MONITOR_OBJ_ELEMS,
	CMD_MONITOR_OBJ_RULESET,
	CMD_MONITOR_OBJ_TRACE,
	CMD_MONITOR_OBJ_MAX
};

struct monitor {
	struct location	location;
	uint32_t	format;
	uint32_t	flags;
	uint32_t	type;
	const char	*event;
};

struct monitor *monitor_alloc(uint32_t format, uint32_t type, const char *event);
void monitor_free(struct monitor *m);

/**
 * struct cmd - command statement
 *
 * @list:	list node
 * @location:	location of the statement
 * @op:		operation
 * @obj:	object type to perform operation on
 * @handle:	handle for operations working without full objects
 * @seqnum:	sequence number to match netlink errors
 * @union:	object
 * @arg:	argument data
 */
struct cmd {
	struct list_head	list;
	struct location		location;
	enum cmd_ops		op;
	enum cmd_obj		obj;
	struct handle		handle;
	uint32_t		seqnum;
	union {
		void		*data;
		struct expr	*expr;
		struct set	*set;
		struct rule	*rule;
		struct chain	*chain;
		struct table	*table;
		struct flowtable *flowtable;
		struct monitor	*monitor;
		struct markup	*markup;
		struct obj	*object;
	};
	const void		*arg;
};

extern struct cmd *cmd_alloc(enum cmd_ops op, enum cmd_obj obj,
			     const struct handle *h, const struct location *loc,
			     void *data);
extern void nft_cmd_expand(struct cmd *cmd);
extern struct cmd *cmd_alloc_obj_ct(enum cmd_ops op, int type,
				    const struct handle *h,
				    const struct location *loc, struct obj *obj);
extern void cmd_free(struct cmd *cmd);

#include <payload.h>
#include <expression.h>

/**
 * struct eval_ctx - evaluation context
 *
 * @nft:	nftables context
 * @msgs:	message queue
 * @cmd:	current command
 * @table:	current table
 * @rule:	current rule
 * @set:	current set
 * @stmt:	current statement
 * @cache:	cache context
 * @debug_mask: debugging bitmask
 * @ectx:	expression context
 * @pctx:	payload context
 */
struct eval_ctx {
	struct nft_ctx		*nft;
	struct list_head	*msgs;
	struct cmd		*cmd;
	struct table		*table;
	struct rule		*rule;
	struct set		*set;
	struct stmt		*stmt;
	struct expr_ctx		ectx;
	struct proto_ctx	pctx;
};

extern int cmd_evaluate(struct eval_ctx *ctx, struct cmd *cmd);

extern struct error_record *rule_postprocess(struct rule *rule);

struct netlink_ctx;
extern int do_command(struct netlink_ctx *ctx, struct cmd *cmd);

extern unsigned int cache_evaluate(struct nft_ctx *nft, struct list_head *cmds);
extern int cache_update(struct nft_ctx *ctx, enum cmd_ops cmd,
			struct list_head *msgs);
extern bool cache_needs_update(struct nft_cache *cache);
extern void cache_release(struct nft_cache *cache);

struct timeout_protocol {
	uint32_t array_size;
	const char *const *state_to_name;
	uint32_t *dflt_timeout;
};

extern struct timeout_protocol timeout_protocol[IPPROTO_MAX];
extern int timeout_str2num(uint16_t l4proto, struct timeout_state *ts);

#endif /* NFTABLES_RULE_H */
