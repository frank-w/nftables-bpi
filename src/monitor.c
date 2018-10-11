/*
 * Copyright (c) 2015 Arturo Borrero Gonzalez <arturo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>

#include <libnftnl/table.h>
#include <libnftnl/trace.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/object.h>
#include <libnftnl/set.h>
#include <libnftnl/flowtable.h>
#include <libnftnl/udata.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <netlink.h>
#include <mnl.h>
#include <expression.h>
#include <statement.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>
#include <iface.h>

#define nft_mon_print(monh, ...) nft_print(monh->ctx->octx, __VA_ARGS__)

static struct nftnl_table *netlink_table_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;

	nlt = nftnl_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();
	if (nftnl_table_nlmsg_parse(nlh, nlt) < 0)
		netlink_abi_error();

	return nlt;
}

static struct nftnl_chain *netlink_chain_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_chain *nlc;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();
	if (nftnl_chain_nlmsg_parse(nlh, nlc) < 0)
		netlink_abi_error();

	return nlc;
}

static struct nftnl_set *netlink_set_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_set *nls;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();
	if (nftnl_set_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nftnl_set *netlink_setelem_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_set *nls;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();
	if (nftnl_set_elems_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nftnl_rule *netlink_rule_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_rule *nlr;

	nlr = nftnl_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();
	if (nftnl_rule_nlmsg_parse(nlh, nlr) < 0)
		netlink_abi_error();

	return nlr;
}

static struct nftnl_obj *netlink_obj_alloc(const struct nlmsghdr *nlh)
{
	struct nftnl_obj *nlo;

	nlo = nftnl_obj_alloc();
	if (nlo == NULL)
		memory_allocation_error();
	if (nftnl_obj_nlmsg_parse(nlh, nlo) < 0)
		netlink_abi_error();

	return nlo;
}

static uint32_t netlink_msg2nftnl_of(uint32_t msg)
{
	switch (msg) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_NEWRULE:
		return NFTNL_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
	case NFT_MSG_DELRULE:
		return NFTNL_OF_EVENT_DEL;
	}

	return 0;
}

static void nlr_for_each_set(struct nftnl_rule *nlr,
			     void (*cb)(struct set *s, void *data),
			     void *data, struct nft_cache *cache)
{
	struct nftnl_expr_iter *nlrei;
	struct nftnl_expr *nlre;
	const char *set_name, *table;
	const char *name;
	struct set *s;
	uint32_t family;

	nlrei = nftnl_expr_iter_create(nlr);
	if (nlrei == NULL)
		memory_allocation_error();

	family = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
	table = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);

	nlre = nftnl_expr_iter_next(nlrei);
	while (nlre != NULL) {
		name = nftnl_expr_get_str(nlre, NFTNL_EXPR_NAME);
		if (strcmp(name, "lookup") != 0)
			goto next;

		set_name = nftnl_expr_get_str(nlre, NFTNL_EXPR_LOOKUP_SET);
		s = set_lookup_global(family, table, set_name, cache);
		if (s == NULL)
			goto next;

		cb(s, data);
next:
		nlre = nftnl_expr_iter_next(nlrei);
	}
	nftnl_expr_iter_destroy(nlrei);
}

static int netlink_events_table_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct nftnl_table *nlt;
	uint32_t family;

	nlt = netlink_table_alloc(nlh);

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		if (type == NFT_MSG_NEWTABLE) {
			nft_mon_print(monh, "add table ");
		} else {
			nft_mon_print(monh, "delete table ");
		}

		family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);

		nft_mon_print(monh, "%s %s", family2str(family),
		       nftnl_table_get_str(nlt, NFTNL_TABLE_NAME));
		if (monh->ctx->octx->handle > 0)
			nft_mon_print(monh, " # handle %" PRIu64 "",
				      nftnl_table_get_u64(nlt, NFTNL_TABLE_HANDLE));
		nft_mon_print(monh, "\n");
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_table_fprintf(monh->ctx->octx->output_fp, nlt,
				    monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}

	nftnl_table_free(nlt);
	return MNL_CB_OK;
}

static int netlink_events_chain_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct nftnl_chain *nlc;
	struct chain *c;
	uint32_t family;

	nlc = netlink_chain_alloc(nlh);

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWCHAIN:
			nft_mon_print(monh, "add ");

			c = netlink_delinearize_chain(monh->ctx, nlc);
			chain_print_plain(c, monh->ctx->octx);
			chain_free(c);
			break;
		case NFT_MSG_DELCHAIN:
			family = nftnl_chain_get_u32(nlc, NFTNL_CHAIN_FAMILY);
			nft_mon_print(monh, "delete chain %s %s %s\n", family2str(family),
			       nftnl_chain_get_str(nlc, NFTNL_CHAIN_TABLE),
			       nftnl_chain_get_str(nlc, NFTNL_CHAIN_NAME));
			break;
		}
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_chain_fprintf(monh->ctx->octx->output_fp, nlc,
				    monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}

	nftnl_chain_free(nlc);
	return MNL_CB_OK;
}

static int netlink_events_set_cb(const struct nlmsghdr *nlh, int type,
				 struct netlink_mon_handler *monh)
{
	struct nftnl_set *nls;
	struct set *set;
	uint32_t family, flags;

	nls = netlink_set_alloc(nlh);
	flags = nftnl_set_get_u32(nls, NFTNL_SET_FLAGS);
	if (flags & NFT_SET_ANONYMOUS)
		goto out;

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWSET:
			nft_mon_print(monh, "add ");
			set = netlink_delinearize_set(monh->ctx, nls);
			if (set == NULL) {
				nftnl_set_free(nls);
				return MNL_CB_ERROR;
			}
			set_print_plain(set, monh->ctx->octx);
			set_free(set);
			nft_mon_print(monh, "\n");
			break;
		case NFT_MSG_DELSET:
			family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
			nft_mon_print(monh, "delete set %s %s %s\n",
			       family2str(family),
			       nftnl_set_get_str(nls, NFTNL_SET_TABLE),
			       nftnl_set_get_str(nls, NFTNL_SET_NAME));
			break;
		}
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_set_fprintf(monh->ctx->octx->output_fp, nls,
				  monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}
out:
	nftnl_set_free(nls);
	return MNL_CB_OK;
}

/* returns true if the event should be ignored (i.e. null element) */
static bool netlink_event_ignore_range_event(struct nftnl_set_elem *nlse)
{
        uint32_t flags = 0;

	if (nftnl_set_elem_is_set(nlse, NFTNL_SET_ELEM_FLAGS))
		flags = nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_FLAGS);
	if (!(flags & NFT_SET_ELEM_INTERVAL_END))
		return false;

	if (nftnl_set_elem_get_u32(nlse, NFTNL_SET_ELEM_KEY) != 0)
		return false;

	return true;
}

static bool set_elem_is_open_interval(struct expr *elem)
{
	switch (elem->ops->type) {
	case EXPR_SET_ELEM:
		return elem->elem_flags & SET_ELEM_F_INTERVAL_OPEN;
	case EXPR_MAPPING:
		return set_elem_is_open_interval(elem->left);
	default:
		return false;
	}
}

/* returns true if the we cached the range element */
static bool netlink_event_range_cache(struct set *cached_set,
				      struct set *dummyset)
{
	struct expr *elem;

	/* not an interval ? */
	if (!(cached_set->flags & NFT_SET_INTERVAL))
		return false;

	/* if cache exists, dummyset must contain the other end of the range */
	if (cached_set->rg_cache) {
		compound_expr_add(dummyset->init, cached_set->rg_cache);
		cached_set->rg_cache = NULL;
		goto out_decompose;
	}

	/* don't cache half-open range elements */
	elem = list_entry(dummyset->init->expressions.prev, struct expr, list);
	if (!set_elem_is_open_interval(elem)) {
		cached_set->rg_cache = expr_clone(elem);
		return true;
	}

out_decompose:
	interval_map_decompose(dummyset->init);
	return false;
}

static int netlink_events_setelem_cb(const struct nlmsghdr *nlh, int type,
				     struct netlink_mon_handler *monh)
{
	struct nftnl_set_elems_iter *nlsei;
	struct nftnl_set_elem *nlse;
	struct nftnl_set *nls;
	struct set *dummyset;
	struct set *set;
	const char *setname, *table;
	uint32_t family;

	nls = netlink_setelem_alloc(nlh);
	table = nftnl_set_get_str(nls, NFTNL_SET_TABLE);
	setname = nftnl_set_get_str(nls, NFTNL_SET_NAME);
	family = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);

	set = set_lookup_global(family, table, setname, monh->cache);
	if (set == NULL) {
		fprintf(stderr, "W: Received event for an unknown set.");
		goto out;
	}

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		if (set->flags & NFT_SET_ANONYMOUS)
			goto out;

		/* we want to 'delinearize' the set_elem, but don't
		 * modify the original cached set. This path is only
		 * used by named sets, so use a dummy set.
		 */
		dummyset = set_alloc(monh->loc);
		dummyset->key = expr_clone(set->key);
		dummyset->datatype = set->datatype;
		dummyset->flags = set->flags;
		dummyset->init = set_expr_alloc(monh->loc, set);

		nlsei = nftnl_set_elems_iter_create(nls);
		if (nlsei == NULL)
			memory_allocation_error();

		nlse = nftnl_set_elems_iter_next(nlsei);
		while (nlse != NULL) {
			if (netlink_event_ignore_range_event(nlse)) {
				set_free(dummyset);
				nftnl_set_elems_iter_destroy(nlsei);
				goto out;
			}
			if (netlink_delinearize_setelem(nlse, dummyset,
							monh->cache) < 0) {
				set_free(dummyset);
				nftnl_set_elems_iter_destroy(nlsei);
				goto out;
			}
			nlse = nftnl_set_elems_iter_next(nlsei);
		}
		nftnl_set_elems_iter_destroy(nlsei);

		if (netlink_event_range_cache(set, dummyset)) {
			set_free(dummyset);
			goto out;
		}

		switch (type) {
		case NFT_MSG_NEWSETELEM:
			nft_mon_print(monh, "add ");
			break;
		case NFT_MSG_DELSETELEM:
			nft_mon_print(monh, "delete ");
			break;
		default:
			set_free(dummyset);
			goto out;
		}
		nft_mon_print(monh, "element %s %s %s ", family2str(family), table, setname);
		expr_print(dummyset->init, monh->ctx->octx);
		nft_mon_print(monh, "\n");

		set_free(dummyset);
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_set_fprintf(monh->ctx->octx->output_fp, nls,
				  monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}
out:
	nftnl_set_free(nls);
	return MNL_CB_OK;
}

static int netlink_events_obj_cb(const struct nlmsghdr *nlh, int type,
				 struct netlink_mon_handler *monh)
{
	struct nftnl_obj *nlo;
	uint32_t family;
	struct obj *obj;

	nlo = netlink_obj_alloc(nlh);

	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWOBJ:
			nft_mon_print(monh, "add ");
			obj = netlink_delinearize_obj(monh->ctx, nlo);
			if (obj == NULL) {
				nftnl_obj_free(nlo);
				return MNL_CB_ERROR;
			}
			obj_print_plain(obj, monh->ctx->octx);
			obj_free(obj);
			nft_mon_print(monh, "\n");
			break;
		case NFT_MSG_DELOBJ:
			family = nftnl_obj_get_u32(nlo, NFTNL_OBJ_FAMILY);
			nft_mon_print(monh, "delete %s %s %s %s\n",
			       obj_type_name(nftnl_obj_get_u32(nlo, NFTNL_OBJ_TYPE)),
			       family2str(family),
			       nftnl_obj_get_str(nlo, NFTNL_OBJ_TABLE),
			       nftnl_obj_get_str(nlo, NFTNL_OBJ_NAME));
			break;
		}
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_obj_fprintf(monh->ctx->octx->output_fp, nlo,
				  monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}

	nftnl_obj_free(nlo);
	return MNL_CB_OK;
}

static void rule_map_decompose_cb(struct set *s, void *data)
{
	if (s->flags & NFT_SET_INTERVAL)
		interval_map_decompose(s->init);
}

static int netlink_events_rule_cb(const struct nlmsghdr *nlh, int type,
				  struct netlink_mon_handler *monh)
{
	struct nftnl_rule *nlr;
	const char *family;
	const char *table;
	const char *chain;
	struct rule *r;
	uint64_t handle;
	uint32_t fam;

	nlr = netlink_rule_alloc(nlh);
	switch (monh->format) {
	case NFTNL_OUTPUT_DEFAULT:
		fam = nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY);
		family = family2str(fam);
		table = nftnl_rule_get_str(nlr, NFTNL_RULE_TABLE);
		chain = nftnl_rule_get_str(nlr, NFTNL_RULE_CHAIN);
		handle = nftnl_rule_get_u64(nlr, NFTNL_RULE_HANDLE);

		switch (type) {
		case NFT_MSG_NEWRULE:
			r = netlink_delinearize_rule(monh->ctx, nlr);
			nlr_for_each_set(nlr, rule_map_decompose_cb, NULL,
					 monh->cache);

			nft_mon_print(monh, "add rule %s %s %s ", family, table, chain);
			rule_print(r, monh->ctx->octx);
			nft_mon_print(monh, "\n");

			rule_free(r);
			break;
		case NFT_MSG_DELRULE:
			nft_mon_print(monh, "delete rule %s %s %s handle %u\n",
			       family, table, chain, (unsigned int)handle);
			break;
		}
		break;
	case NFTNL_OUTPUT_JSON:
		nftnl_rule_fprintf(monh->ctx->octx->output_fp, nlr,
				   monh->format, netlink_msg2nftnl_of(type));
		nft_mon_print(monh, "\n");
		break;
	}

	nftnl_rule_free(nlr);
	return MNL_CB_OK;
}

static void netlink_events_cache_addtable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;
	struct table *t;

	nlt = netlink_table_alloc(nlh);
	t = netlink_delinearize_table(monh->ctx, nlt);
	nftnl_table_free(nlt);

	table_add_hash(t, monh->cache);
}

static void netlink_events_cache_deltable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct nftnl_table *nlt;
	struct table *t;
	struct handle h;

	nlt      = netlink_table_alloc(nlh);
	h.family = nftnl_table_get_u32(nlt, NFTNL_TABLE_FAMILY);
	h.table.name  = nftnl_table_get_str(nlt, NFTNL_TABLE_NAME);

	t = table_lookup(&h, monh->cache);
	if (t == NULL)
		goto out;

	list_del(&t->list);
	table_free(t);
out:
	nftnl_table_free(nlt);
}

static void netlink_events_cache_addset(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh)
{
	struct netlink_ctx set_tmpctx;
	struct nftnl_set *nls;
	struct table *t;
	struct set *s;
	LIST_HEAD(msgs);

	memset(&set_tmpctx, 0, sizeof(set_tmpctx));
	init_list_head(&set_tmpctx.list);
	init_list_head(&msgs);
	set_tmpctx.msgs = &msgs;

	nls = netlink_set_alloc(nlh);
	s = netlink_delinearize_set(&set_tmpctx, nls);
	if (s == NULL)
		goto out;
	s->init = set_expr_alloc(monh->loc, s);

	t = table_lookup(&s->handle, monh->cache);
	if (t == NULL) {
		fprintf(stderr, "W: Unable to cache set: table not found.\n");
		set_free(s);
		goto out;
	}

	set_add_hash(s, t);
out:
	nftnl_set_free(nls);
}

static void netlink_events_cache_addsetelem(struct netlink_mon_handler *monh,
					    const struct nlmsghdr *nlh)
{
	struct nftnl_set_elems_iter *nlsei;
	struct nftnl_set_elem *nlse;
	struct nftnl_set *nls;
	struct set *set;
	const char *table, *setname;
	uint32_t family;

	nls     = netlink_setelem_alloc(nlh);
	family  = nftnl_set_get_u32(nls, NFTNL_SET_FAMILY);
	table   = nftnl_set_get_str(nls, NFTNL_SET_TABLE);
	setname = nftnl_set_get_str(nls, NFTNL_SET_NAME);

	set = set_lookup_global(family, table, setname, monh->cache);
	if (set == NULL) {
		fprintf(stderr,
			"W: Unable to cache set_elem. Set not found.\n");
		goto out;
	}

	nlsei = nftnl_set_elems_iter_create(nls);
	if (nlsei == NULL)
		memory_allocation_error();

	nlse = nftnl_set_elems_iter_next(nlsei);
	while (nlse != NULL) {
		if (netlink_delinearize_setelem(nlse, set, monh->cache) < 0) {
			fprintf(stderr,
				"W: Unable to cache set_elem. "
				"Delinearize failed.\n");
			nftnl_set_elems_iter_destroy(nlsei);
			goto out;
		}
		nlse = nftnl_set_elems_iter_next(nlsei);
	}
	nftnl_set_elems_iter_destroy(nlsei);
out:
	nftnl_set_free(nls);
}

static void netlink_events_cache_delset_cb(struct set *s,
					   void *data)
{
	list_del(&s->list);
	set_free(s);
}

static void netlink_events_cache_delsets(struct netlink_mon_handler *monh,
					 const struct nlmsghdr *nlh)
{
	struct nftnl_rule *nlr = netlink_rule_alloc(nlh);

	nlr_for_each_set(nlr, netlink_events_cache_delset_cb, NULL,
			 monh->cache);
	nftnl_rule_free(nlr);
}

static void netlink_events_cache_addobj(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh)
{
	struct netlink_ctx obj_tmpctx;
	struct nftnl_obj *nlo;
	struct table *t;
	struct obj *obj;
	LIST_HEAD(msgs);

	memset(&obj_tmpctx, 0, sizeof(obj_tmpctx));
	init_list_head(&obj_tmpctx.list);
	init_list_head(&msgs);
	obj_tmpctx.msgs = &msgs;

	nlo = netlink_obj_alloc(nlh);
	obj = netlink_delinearize_obj(&obj_tmpctx, nlo);
	if (obj == NULL)
		goto out;

	t = table_lookup(&obj->handle, monh->cache);
	if (t == NULL) {
		fprintf(stderr, "W: Unable to cache object: table not found.\n");
		obj_free(obj);
		goto out;
	}

	obj_add_hash(obj, t);
out:
	nftnl_obj_free(nlo);
}

static void netlink_events_cache_delobj(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh)
{
	struct nftnl_obj *nlo;
	const char *name;
	struct obj *obj;
	struct handle h;
	struct table *t;
	uint32_t type;

	nlo      = netlink_obj_alloc(nlh);
	h.family = nftnl_obj_get_u32(nlo, NFTNL_OBJ_FAMILY);
	h.table.name  = nftnl_obj_get_str(nlo, NFTNL_OBJ_TABLE);

	name     = nftnl_obj_get_str(nlo, NFTNL_OBJ_NAME);
	type	 = nftnl_obj_get_u32(nlo, NFTNL_OBJ_TYPE);
	h.handle.id	= nftnl_obj_get_u64(nlo, NFTNL_OBJ_HANDLE);

	t = table_lookup(&h, monh->cache);
	if (t == NULL) {
		fprintf(stderr, "W: Unable to cache object: table not found.\n");
		goto out;
	}

	obj = obj_lookup(t, name, type);
	if (obj == NULL) {
		fprintf(stderr, "W: Unable to find object in cache\n");
		goto out;
	}

	list_del(&obj->list);
	obj_free(obj);
out:
	nftnl_obj_free(nlo);
}

static void netlink_events_cache_update(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh, int type)
{
	if (!monh->cache_needed)
		return;

	switch (type) {
	case NFT_MSG_NEWTABLE:
		netlink_events_cache_addtable(monh, nlh);
		break;
	case NFT_MSG_DELTABLE:
		netlink_events_cache_deltable(monh, nlh);
		break;
	case NFT_MSG_NEWSET:
		netlink_events_cache_addset(monh, nlh);
		break;
	case NFT_MSG_NEWSETELEM:
		netlink_events_cache_addsetelem(monh, nlh);
		break;
	case NFT_MSG_DELRULE:
		/* there are no notification for anon-set deletion */
		netlink_events_cache_delsets(monh, nlh);
		break;
	case NFT_MSG_NEWOBJ:
		netlink_events_cache_addobj(monh, nlh);
		break;
	case NFT_MSG_DELOBJ:
		netlink_events_cache_delobj(monh, nlh);
		break;
	}
}

/* only those which could be useful listening to events */
static const char *const nftnl_msg_types[NFT_MSG_MAX] = {
	[NFT_MSG_NEWTABLE]	= "NFT_MSG_NEWTABLE",
	[NFT_MSG_DELTABLE]	= "NFT_MSG_DELTABLE",
	[NFT_MSG_NEWCHAIN]	= "NFT_MSG_NEWCHAIN",
	[NFT_MSG_DELCHAIN]	= "NFT_MSG_DELCHAIN",
	[NFT_MSG_NEWSET]	= "NFT_MSG_NEWSET",
	[NFT_MSG_DELSET]	= "NFT_MSG_DELSET",
	[NFT_MSG_NEWSETELEM]	= "NFT_MSG_NEWSETELEM",
	[NFT_MSG_DELSETELEM]	= "NFT_MSG_DELSETELEM",
	[NFT_MSG_NEWRULE]	= "NFT_MSG_NEWRULE",
	[NFT_MSG_DELRULE]	= "NFT_MSG_DELRULE",
	[NFT_MSG_TRACE]		= "NFT_MSG_TRACE",
	[NFT_MSG_NEWGEN]	= "NFT_MSG_NEWGEN",
	[NFT_MSG_NEWOBJ]	= "NFT_MSG_NEWOBJ",
	[NFT_MSG_DELOBJ]	= "NFT_MSG_DELOBJ",
};

static const char *nftnl_msgtype2str(uint16_t type)
{
	if (type >= NFT_MSG_MAX || !nftnl_msg_types[type])
		return "unknown";

	return nftnl_msg_types[type];
}

static void netlink_events_debug(uint16_t type, unsigned int debug_mask)
{
	if (!(debug_mask & NFT_DEBUG_NETLINK))
		return;

	printf("netlink event: %s\n", nftnl_msgtype2str(type));
}

static int netlink_events_newgen_cb(const struct nlmsghdr *nlh, int type,
				    struct netlink_mon_handler *monh)
{
	const struct nlattr *attr;
	char name[256] = "";
	int genid = -1, pid = -1;

	mnl_attr_for_each(attr, nlh, sizeof(struct nfgenmsg)) {
		switch (mnl_attr_get_type(attr)) {
		case NFTA_GEN_ID:
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				break;
			genid = ntohl(mnl_attr_get_u32(attr));
			break;
		case NFTA_GEN_PROC_NAME:
			if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
				break;
			snprintf(name, sizeof(name), "%s", mnl_attr_get_str(attr));
			break;
		case NFTA_GEN_PROC_PID:
			if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
				break;
			pid = ntohl(mnl_attr_get_u32(attr));
			break;
		}
	}
	if (genid >= 0) {
		nft_mon_print(monh, "# new generation %d", genid);
		if (pid >= 0) {
			nft_mon_print(monh, " by process %d", pid);
			if (!monh->ctx->octx->numeric)
				nft_mon_print(monh, " (%s)", name);
		}
		nft_mon_print(monh, "\n");
	}

	return MNL_CB_OK;
}

static int netlink_events_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret = MNL_CB_OK;
	uint16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	struct netlink_mon_handler *monh = (struct netlink_mon_handler *)data;

	netlink_events_debug(type, monh->debug_mask);
	netlink_events_cache_update(monh, nlh, type);

	if (!(monh->monitor_flags & (1 << type)))
		return ret;

	switch (type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = netlink_events_table_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = netlink_events_chain_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:		/* nft {add|delete} set */
		ret = netlink_events_set_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:	/* nft {add|delete} element */
		ret = netlink_events_setelem_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = netlink_events_rule_cb(nlh, type, monh);
		break;
	case NFT_MSG_TRACE:
		ret = netlink_events_trace_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWOBJ:
	case NFT_MSG_DELOBJ:
		ret = netlink_events_obj_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWGEN:
		ret = netlink_events_newgen_cb(nlh, type, monh);
		break;
	}

	return ret;
}

int netlink_echo_callback(const struct nlmsghdr *nlh, void *data)
{
	struct netlink_ctx *ctx = data;
	struct netlink_mon_handler echo_monh = {
		.format = NFTNL_OUTPUT_DEFAULT,
		.ctx = ctx,
		.loc = &netlink_location,
		.monitor_flags = 0xffffffff,
		.cache_needed = true,
		.cache = ctx->cache,
		.debug_mask = ctx->debug_mask,
	};

	if (!echo_monh.ctx->octx->echo)
		return MNL_CB_OK;

	return netlink_events_cb(nlh, &echo_monh);
}

int netlink_monitor(struct netlink_mon_handler *monhandler,
		    struct mnl_socket *nf_sock)
{
	int group;

	if (monhandler->monitor_flags & (1 << NFT_MSG_TRACE)) {
		group = NFNLGRP_NFTRACE;
		if (mnl_socket_setsockopt(nf_sock, NETLINK_ADD_MEMBERSHIP,
					  &group, sizeof(int)) < 0)
			return -1;
	}
	if (monhandler->monitor_flags & ~(1 << NFT_MSG_TRACE)) {
		group = NFNLGRP_NFTABLES;
		if (mnl_socket_setsockopt(nf_sock, NETLINK_ADD_MEMBERSHIP,
					  &group, sizeof(int)) < 0)
			return -1;
	}

	return mnl_nft_event_listener(nf_sock, monhandler->debug_mask,
				      monhandler->ctx->octx, netlink_events_cb,
				      monhandler);
}
