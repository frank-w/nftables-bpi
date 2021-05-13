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
#include <cache.h>
#include <netlink.h>
#include <mnl.h>
#include <libnftnl/chain.h>
#include <linux/netfilter.h>

static unsigned int evaluate_cache_add(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_CHAIN:
	case CMD_OBJ_SET:
	case CMD_OBJ_COUNTER:
	case CMD_OBJ_QUOTA:
	case CMD_OBJ_LIMIT:
	case CMD_OBJ_SECMARK:
	case CMD_OBJ_CT_HELPER:
	case CMD_OBJ_CT_TIMEOUT:
	case CMD_OBJ_CT_EXPECT:
	case CMD_OBJ_SYNPROXY:
	case CMD_OBJ_FLOWTABLE:
		flags |= NFT_CACHE_TABLE;
		break;
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_CHAIN |
			 NFT_CACHE_SET |
			 NFT_CACHE_OBJECT |
			 NFT_CACHE_SETELEM;
		break;
	case CMD_OBJ_RULE:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_CHAIN |
			 NFT_CACHE_SET |
			 NFT_CACHE_OBJECT |
			 NFT_CACHE_FLOWTABLE;

		if (cmd->handle.index.id ||
		    cmd->handle.position.id)
			flags |= NFT_CACHE_RULE | NFT_CACHE_UPDATE;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_del(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_SETELEM;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_get(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_ELEMENTS:
		flags |= NFT_CACHE_TABLE |
			 NFT_CACHE_SET |
			 NFT_CACHE_SETELEM;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_flush(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_SET:
	case CMD_OBJ_MAP:
	case CMD_OBJ_METER:
		flags |= NFT_CACHE_SET;
		break;
	case CMD_OBJ_RULESET:
		flags |= NFT_CACHE_FLUSHED;
		break;
	default:
		break;
	}

	return flags;
}

static unsigned int evaluate_cache_rename(struct cmd *cmd, unsigned int flags)
{
	switch (cmd->obj) {
	case CMD_OBJ_CHAIN:
		flags |= NFT_CACHE_CHAIN;
		break;
	default:
		break;
	}

	return flags;
}

unsigned int nft_cache_evaluate(struct nft_ctx *nft, struct list_head *cmds)
{
	unsigned int flags = NFT_CACHE_EMPTY;
	struct cmd *cmd;

	list_for_each_entry(cmd, cmds, list) {
		switch (cmd->op) {
		case CMD_ADD:
		case CMD_INSERT:
		case CMD_CREATE:
			flags = evaluate_cache_add(cmd, flags);
			if (nft_output_echo(&nft->output))
				flags |= NFT_CACHE_FULL;
			break;
		case CMD_REPLACE:
			flags = NFT_CACHE_FULL;
			break;
		case CMD_DELETE:
			flags |= NFT_CACHE_TABLE |
				 NFT_CACHE_CHAIN |
				 NFT_CACHE_SET |
				 NFT_CACHE_FLOWTABLE |
				 NFT_CACHE_OBJECT;

			flags = evaluate_cache_del(cmd, flags);
			break;
		case CMD_GET:
			flags = evaluate_cache_get(cmd, flags);
			break;
		case CMD_RESET:
			flags |= NFT_CACHE_TABLE;
			break;
		case CMD_LIST:
		case CMD_EXPORT:
			flags |= NFT_CACHE_FULL | NFT_CACHE_REFRESH;
			break;
		case CMD_MONITOR:
			flags |= NFT_CACHE_FULL;
			break;
		case CMD_FLUSH:
			flags = evaluate_cache_flush(cmd, flags);
			break;
		case CMD_RENAME:
			flags = evaluate_cache_rename(cmd, flags);
			break;
		case CMD_DESCRIBE:
		case CMD_IMPORT:
			break;
		default:
			break;
		}
	}

	return flags;
}

void table_cache_add(struct table *table, struct nft_cache *cache)
{
	uint32_t hash;

	hash = djb_hash(table->handle.table.name) % NFT_CACHE_HSIZE;
	cache_add(&table->cache, &cache->table_cache, hash);
}

void table_cache_del(struct table *table)
{
	cache_del(&table->cache);
}

struct table *table_cache_find(const struct cache *cache,
			       const char *name, uint32_t family)
{
	struct table *table;
	uint32_t hash;

	if (!name)
		return NULL;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(table, &cache->ht[hash], cache.hlist) {
		if (table->handle.family == family &&
		    !strcmp(table->handle.table.name, name))
			return table;
	}

	return NULL;
}

struct chain_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int chain_cache_cb(struct nftnl_chain *nlc, void *arg)
{
	struct chain_cache_dump_ctx *ctx = arg;
	const char *chain_name, *table_name;
	uint32_t hash, family;
	struct chain *chain;

	table_name = nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE);
	chain_name = nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME);
	family = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);

	if (strcmp(table_name, ctx->table->handle.table.name) ||
	    family != ctx->table->handle.family)
		return 0;

	hash = djb_hash(chain_name) % NFT_CACHE_HSIZE;
	chain = netlink_delinearize_chain(ctx->nlctx, nlc);

	if (chain->flags & CHAIN_F_BINDING) {
		list_add_tail(&chain->cache.list, &ctx->table->chain_bindings);
	} else {
		cache_add(&chain->cache, &ctx->table->chain_cache, hash);
	}

	nftnl_chain_list_del(nlc);
	nftnl_chain_free(nlc);

	return 0;
}

static int chain_cache_init(struct netlink_ctx *ctx, struct table *table,
			    struct nftnl_chain_list *chain_list)
{
	struct chain_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_chain_list_foreach(chain_list, chain_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_chain_list *chain_cache_dump(struct netlink_ctx *ctx,
						 int *err)
{
	struct nftnl_chain_list *chain_list;

	chain_list = mnl_nft_chain_dump(ctx, AF_UNSPEC);
	if (chain_list == NULL) {
		if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return chain_list;
}

void chain_cache_add(struct chain *chain, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(chain->handle.chain.name) % NFT_CACHE_HSIZE;
	cache_add(&chain->cache, &table->chain_cache, hash);
}

void chain_cache_del(struct chain *chain)
{
	cache_del(&chain->cache);
}

struct chain *chain_cache_find(const struct table *table, const char *name)
{
	struct chain *chain;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(chain, &table->chain_cache.ht[hash], cache.hlist) {
		if (!strcmp(chain->handle.chain.name, name))
			return chain;
	}

	return NULL;
}

struct set_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int set_cache_cb(struct nftnl_set *nls, void *arg)
{
	struct set_cache_dump_ctx *ctx = arg;
	const char *set_name;
	struct set *set;
	uint32_t hash;

	set = netlink_delinearize_set(ctx->nlctx, nls);
	if (!set)
		return -1;

	set_name = nftnl_set_get_str(nls, NFTNL_SET_NAME);
	hash = djb_hash(set_name) % NFT_CACHE_HSIZE;
	cache_add(&set->cache, &ctx->table->set_cache, hash);

	return 0;
}

static int set_cache_init(struct netlink_ctx *ctx, struct table *table,
			  struct nftnl_set_list *set_list)
{
	struct set_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_set_list_foreach(set_list, set_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_set_list *set_cache_dump(struct netlink_ctx *ctx,
					     const struct table *table,
					     int *err)
{
	struct nftnl_set_list *set_list;

	set_list = mnl_nft_set_dump(ctx, table->handle.family,
				    table->handle.table.name);
	if (!set_list) {
                if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return set_list;
}

void set_cache_add(struct set *set, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(set->handle.set.name) % NFT_CACHE_HSIZE;
	cache_add(&set->cache, &table->set_cache, hash);
}

void set_cache_del(struct set *set)
{
	cache_del(&set->cache);
}

struct set *set_cache_find(const struct table *table, const char *name)
{
	struct set *set;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(set, &table->set_cache.ht[hash], cache.hlist) {
		if (!strcmp(set->handle.set.name, name))
			return set;
	}

	return NULL;
}

struct obj_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int obj_cache_cb(struct nftnl_obj *nlo, void *arg)
{
	struct obj_cache_dump_ctx *ctx = arg;
	const char *obj_name;
	struct obj *obj;
	uint32_t hash;

	obj = netlink_delinearize_obj(ctx->nlctx, nlo);
	if (!obj)
		return -1;

	obj_name = nftnl_obj_get_str(nlo, NFTNL_OBJ_NAME);
	hash = djb_hash(obj_name) % NFT_CACHE_HSIZE;
	cache_add(&obj->cache, &ctx->table->obj_cache, hash);

	return 0;
}

static int obj_cache_init(struct netlink_ctx *ctx, struct table *table,
			  struct nftnl_obj_list *obj_list)
{
	struct obj_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_obj_list_foreach(obj_list, obj_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_obj_list *obj_cache_dump(struct netlink_ctx *ctx,
					     const struct table *table,
					     int *err)
{
	struct nftnl_obj_list *obj_list;

	obj_list = mnl_nft_obj_dump(ctx, table->handle.family,
				    table->handle.table.name, NULL,
				    0, true, false);
	if (!obj_list) {
                if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return obj_list;
}

void obj_cache_add(struct obj *obj, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(obj->handle.obj.name) % NFT_CACHE_HSIZE;
	cache_add(&obj->cache, &table->obj_cache, hash);
}

void obj_cache_del(struct obj *obj)
{
	cache_del(&obj->cache);
}

struct obj *obj_cache_find(const struct table *table, const char *name,
			   uint32_t obj_type)
{
	struct obj *obj;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(obj, &table->obj_cache.ht[hash], cache.hlist) {
		if (!strcmp(obj->handle.obj.name, name) &&
		    obj->type == obj_type)
			return obj;
	}

	return NULL;
}

struct ft_cache_dump_ctx {
	struct netlink_ctx	*nlctx;
	struct table		*table;
};

static int ft_cache_cb(struct nftnl_flowtable *nlf, void *arg)
{
	struct ft_cache_dump_ctx *ctx = arg;
	const char *ft_name;
	struct flowtable *ft;
	uint32_t hash;

	ft = netlink_delinearize_flowtable(ctx->nlctx, nlf);
	if (!ft)
		return -1;

	ft_name = nftnl_flowtable_get_str(nlf, NFTNL_FLOWTABLE_NAME);
	hash = djb_hash(ft_name) % NFT_CACHE_HSIZE;
	cache_add(&ft->cache, &ctx->table->ft_cache, hash);

	return 0;
}

static int ft_cache_init(struct netlink_ctx *ctx, struct table *table,
			 struct nftnl_flowtable_list *ft_list)
{
	struct ft_cache_dump_ctx dump_ctx = {
		.nlctx	= ctx,
		.table	= table,
	};
	nftnl_flowtable_list_foreach(ft_list, ft_cache_cb, &dump_ctx);

	return 0;
}

static struct nftnl_flowtable_list *ft_cache_dump(struct netlink_ctx *ctx,
						  const struct table *table,
						  int *err)
{
	struct nftnl_flowtable_list *ft_list;

	ft_list = mnl_nft_flowtable_dump(ctx, table->handle.family,
					 table->handle.table.name);
	if (!ft_list) {
                if (errno == EINTR) {
			*err = -1;
			return NULL;
		}
		*err = 0;
		return NULL;
	}

	return ft_list;
}

void ft_cache_add(struct flowtable *ft, struct table *table)
{
	uint32_t hash;

	hash = djb_hash(ft->handle.flowtable.name) % NFT_CACHE_HSIZE;
	cache_add(&ft->cache, &table->ft_cache, hash);
}

void ft_cache_del(struct flowtable *ft)
{
	cache_del(&ft->cache);
}

struct flowtable *ft_cache_find(const struct table *table, const char *name)
{
	struct flowtable *ft;
	uint32_t hash;

	hash = djb_hash(name) % NFT_CACHE_HSIZE;
	list_for_each_entry(ft, &table->ft_cache.ht[hash], cache.hlist) {
		if (!strcmp(ft->handle.flowtable.name, name))
			return ft;
	}

	return NULL;
}

static int cache_init_tables(struct netlink_ctx *ctx, struct handle *h,
			     struct nft_cache *cache)
{
	struct table *table, *next;
	int ret;

	ret = netlink_list_tables(ctx, h);
	if (ret < 0)
		return -1;

	list_for_each_entry_safe(table, next, &ctx->list, list) {
		list_del(&table->list);
		table_cache_add(table, cache);
	}

	return 0;
}

static int cache_init_objects(struct netlink_ctx *ctx, unsigned int flags)
{
	struct nftnl_flowtable_list *ft_list = NULL;
	struct nftnl_chain_list *chain_list = NULL;
	struct nftnl_set_list *set_list = NULL;
	struct nftnl_obj_list *obj_list;
	struct rule *rule, *nrule;
	struct table *table;
	struct chain *chain;
	struct set *set;
	int ret = 0;

	if (flags & NFT_CACHE_CHAIN_BIT) {
		chain_list = chain_cache_dump(ctx, &ret);
		if (!chain_list)
			return -1;
	}

	list_for_each_entry(table, &ctx->nft->cache.table_cache.list, cache.list) {
		if (flags & NFT_CACHE_SET_BIT) {
			set_list = set_cache_dump(ctx, table, &ret);
			if (!set_list) {
				ret = -1;
				goto cache_fails;
			}
			ret = set_cache_init(ctx, table, set_list);

			nftnl_set_list_free(set_list);

			if (ret < 0) {
				ret = -1;
				goto cache_fails;
			}
		}
		if (flags & NFT_CACHE_SETELEM_BIT) {
			list_for_each_entry(set, &table->set_cache.list, cache.list) {
				ret = netlink_list_setelems(ctx, &set->handle,
							    set);
				if (ret < 0) {
					ret = -1;
					goto cache_fails;
				}
			}
		}
		if (flags & NFT_CACHE_CHAIN_BIT) {
			ret = chain_cache_init(ctx, table, chain_list);
			if (ret < 0) {
				ret = -1;
				goto cache_fails;
			}
		}
		if (flags & NFT_CACHE_FLOWTABLE_BIT) {
			ft_list = ft_cache_dump(ctx, table, &ret);
			if (!ft_list) {
				ret = -1;
				goto cache_fails;
			}
			ret = ft_cache_init(ctx, table, ft_list);

			nftnl_flowtable_list_free(ft_list);

			if (ret < 0) {
				ret = -1;
				goto cache_fails;
			}
		}
		if (flags & NFT_CACHE_OBJECT_BIT) {
			obj_list = obj_cache_dump(ctx, table, &ret);
			if (!obj_list) {
				ret = -1;
				goto cache_fails;
			}
			ret = obj_cache_init(ctx, table, obj_list);

			nftnl_obj_list_free(obj_list);

			if (ret < 0) {
				ret = -1;
				goto cache_fails;
			}
		}

		if (flags & NFT_CACHE_RULE_BIT) {
			ret = netlink_list_rules(ctx, &table->handle);
			list_for_each_entry_safe(rule, nrule, &ctx->list, list) {
				chain = chain_cache_find(table, rule->handle.chain.name);
				if (!chain)
					chain = chain_binding_lookup(table,
							rule->handle.chain.name);
				if (!chain) {
					ret = -1;
					goto cache_fails;
				}

				list_move_tail(&rule->list, &chain->rules);
			}
			if (ret < 0) {
				ret = -1;
				goto cache_fails;
			}
		}
	}

cache_fails:
	if (flags & NFT_CACHE_CHAIN_BIT)
		nftnl_chain_list_free(chain_list);

	return ret;
}

static int nft_cache_init(struct netlink_ctx *ctx, unsigned int flags)
{
	struct handle handle = {
		.family = NFPROTO_UNSPEC,
	};
	int ret;

	if (flags == NFT_CACHE_EMPTY)
		return 0;

	/* assume NFT_CACHE_TABLE is always set. */
	ret = cache_init_tables(ctx, &handle, &ctx->nft->cache);
	if (ret < 0)
		return ret;
	ret = cache_init_objects(ctx, flags);
	if (ret < 0)
		return ret;

	return 0;
}

static bool nft_cache_is_complete(struct nft_cache *cache, unsigned int flags)
{
	return (cache->flags & flags) == flags;
}

static bool nft_cache_needs_refresh(struct nft_cache *cache)
{
	return cache->flags & NFT_CACHE_REFRESH;
}

static bool nft_cache_is_updated(struct nft_cache *cache, uint16_t genid)
{
	return genid && genid == cache->genid;
}

bool nft_cache_needs_update(struct nft_cache *cache)
{
	return cache->flags & NFT_CACHE_UPDATE;
}

int nft_cache_update(struct nft_ctx *nft, unsigned int flags,
		     struct list_head *msgs)
{
	struct netlink_ctx ctx = {
		.list		= LIST_HEAD_INIT(ctx.list),
		.nft		= nft,
		.msgs		= msgs,
	};
	struct nft_cache *cache = &nft->cache;
	uint32_t genid, genid_stop, oldflags;
	int ret;
replay:
	ctx.seqnum = cache->seqnum++;
	genid = mnl_genid_get(&ctx);
	if (!nft_cache_needs_refresh(cache) &&
	    nft_cache_is_complete(cache, flags) &&
	    nft_cache_is_updated(cache, genid))
		return 0;

	if (cache->genid)
		nft_cache_release(cache);

	if (flags & NFT_CACHE_FLUSHED) {
		oldflags = flags;
		flags = NFT_CACHE_EMPTY;
		if (oldflags & NFT_CACHE_UPDATE)
			flags |= NFT_CACHE_UPDATE;
		goto skip;
	}

	ret = nft_cache_init(&ctx, flags);
	if (ret < 0) {
		if (errno == EINTR) {
			nft_cache_release(cache);
			goto replay;
		}

		nft_cache_release(cache);
		return -1;
	}

	genid_stop = mnl_genid_get(&ctx);
	if (genid != genid_stop) {
		nft_cache_release(cache);
		goto replay;
	}
skip:
	cache->genid = genid;
	cache->flags = flags;
	return 0;
}

static void nft_cache_flush(struct cache *table_cache)
{
	struct table *table, *next;

	list_for_each_entry_safe(table, next, &table_cache->list, cache.list) {
		table_cache_del(table);
		table_free(table);
	}
}

void nft_cache_release(struct nft_cache *cache)
{
	nft_cache_flush(&cache->table_cache);
	cache->genid = 0;
	cache->flags = NFT_CACHE_EMPTY;
}

void cache_init(struct cache *cache)
{
	int i;

	cache->ht = xmalloc(sizeof(struct list_head) * NFT_CACHE_HSIZE);
	for (i = 0; i < NFT_CACHE_HSIZE; i++)
		init_list_head(&cache->ht[i]);

	init_list_head(&cache->list);
}

void cache_free(struct cache *cache)
{
	xfree(cache->ht);
}

void cache_add(struct cache_item *item, struct cache *cache, uint32_t hash)
{
	list_add_tail(&item->hlist, &cache->ht[hash]);
	list_add_tail(&item->list, &cache->list);
}

void cache_del(struct cache_item *item)
{
	list_del(&item->hlist);
	list_del(&item->list);
}
