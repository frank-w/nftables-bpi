/*
 * Copyright (c) 2013-2017 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <libmnl/libmnl.h>
#include <libnftnl/common.h>
#include <libnftnl/ruleset.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/flowtable.h>
#include <libnftnl/batch.h>
#include <libnftnl/udata.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <mnl.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <utils.h>
#include <nftables.h>

struct mnl_socket *nft_mnl_socket_open(void)
{
	struct mnl_socket *nf_sock;

	nf_sock = mnl_socket_open(NETLINK_NETFILTER);
	if (!nf_sock)
		netlink_init_error();

	if (fcntl(mnl_socket_get_fd(nf_sock), F_SETFL, O_NONBLOCK))
		netlink_init_error();

	return nf_sock;
}

struct mnl_socket *nft_mnl_socket_reopen(struct mnl_socket *nf_sock)
{
	mnl_socket_close(nf_sock);

	return nft_mnl_socket_open();
}

uint32_t mnl_seqnum_alloc(unsigned int *seqnum)
{
	return (*seqnum)++;
}

/* The largest nf_tables netlink message is the set element message, which
 * contains the NFTA_SET_ELEM_LIST_ELEMENTS attribute. This attribute is
 * a nest that describes the set elements. Given that the netlink attribute
 * length (nla_len) is 16 bits, the largest message is a bit larger than
 * 64 KBytes.
 */
#define NFT_NLMSG_MAXSIZE (UINT16_MAX + getpagesize())

static int
nft_mnl_recv(struct netlink_ctx *ctx, uint32_t portid,
	     int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[NFT_NLMSG_MAXSIZE];
	int ret;

	ret = mnl_socket_recvfrom(ctx->nft->nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, ctx->seqnum, portid, cb, cb_data);
		if (ret <= 0)
			goto out;

		ret = mnl_socket_recvfrom(ctx->nft->nf_sock, buf, sizeof(buf));
	}
out:
	if (ret < 0 && errno == EAGAIN)
		return 0;

	return ret;
}

int
nft_mnl_talk(struct netlink_ctx *ctx, const void *data, unsigned int len,
	     int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	uint32_t portid = mnl_socket_get_portid(ctx->nft->nf_sock);

	if (ctx->nft->debug_mask & NFT_DEBUG_MNL)
		mnl_nlmsg_fprintf(ctx->nft->output.output_fp, data, len,
				  sizeof(struct nfgenmsg));

	if (mnl_socket_sendto(ctx->nft->nf_sock, data, len) < 0)
		return -1;

	return nft_mnl_recv(ctx, portid, cb, cb_data);
}

/*
 * Rule-set consistency check across several netlink dumps
 */
static uint32_t nft_genid;

static int genid_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfh = mnl_nlmsg_get_payload(nlh);

	nft_genid = ntohs(nfh->res_id);

	return MNL_CB_OK;
}

uint32_t mnl_genid_get(struct netlink_ctx *ctx)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETGEN, AF_UNSPEC, 0, ctx->seqnum);
	/* Skip error checking, old kernels sets res_id field to zero. */
	nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, genid_cb, NULL);

	return nft_genid;
}

static uint16_t nft_genid_u16(uint32_t genid)
{
	return genid & 0xffff;
}

static int check_genid(const struct nlmsghdr *nlh)
{
	struct nfgenmsg *nfh = mnl_nlmsg_get_payload(nlh);

	if (nft_genid_u16(nft_genid) != ntohs(nfh->res_id)) {
		errno = EINTR;
		return -1;
	}
	return 0;
}

/*
 * Batching
 */

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

struct nftnl_batch *mnl_batch_init(void)
{
	struct nftnl_batch *batch;

	batch = nftnl_batch_alloc(BATCH_PAGE_SIZE, NFT_NLMSG_MAXSIZE);
	if (batch == NULL)
		memory_allocation_error();

	return batch;
}

static void mnl_nft_batch_continue(struct nftnl_batch *batch)
{
	if (nftnl_batch_update(batch) < 0)
		memory_allocation_error();
}

uint32_t mnl_batch_begin(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_begin(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);

	return seqnum;
}

void mnl_batch_end(struct nftnl_batch *batch, uint32_t seqnum)
{
	nftnl_batch_end(nftnl_batch_buffer(batch), seqnum);
	mnl_nft_batch_continue(batch);
}

bool mnl_batch_ready(struct nftnl_batch *batch)
{
	/* Check if the batch only contains the initial and trailing batch
	 * messages. In that case, the batch is empty.
	 */
	return nftnl_batch_buffer_len(batch) !=
	       (NLMSG_HDRLEN + sizeof(struct nfgenmsg)) * 2;
}

void mnl_batch_reset(struct nftnl_batch *batch)
{
	nftnl_batch_free(batch);
}

static void mnl_err_list_node_add(struct list_head *err_list, int error,
				  int seqnum)
{
	struct mnl_err *err = xmalloc(sizeof(struct mnl_err));

	err->seqnum = seqnum;
	err->err = error;
	list_add_tail(&err->head, err_list);
}

void mnl_err_list_free(struct mnl_err *err)
{
	list_del(&err->head);
	xfree(err);
}

static int nlbuffsiz;

static void mnl_set_sndbuffer(const struct mnl_socket *nl,
			      struct nftnl_batch *batch)
{
	int newbuffsiz;

	if (nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = nftnl_batch_iovec_len(batch) * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static unsigned int nlsndbufsiz;

static int mnl_set_rcvbuffer(const struct mnl_socket *nl, socklen_t bufsiz)
{
	socklen_t len = sizeof(nlsndbufsiz);
	int ret;

	if (!nlsndbufsiz) {
		getsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUF,
			   &nlsndbufsiz, &len);
	}

	if (nlsndbufsiz >= bufsiz)
		return 0;

	ret = setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUFFORCE,
			 &bufsiz, sizeof(socklen_t));
	if (ret < 0) {
		/* If this doesn't work, try to reach the system wide maximum
		 * (or whatever the user requested).
		 */
		ret = setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUF,
				 &bufsiz, sizeof(socklen_t));
	}

	return ret;
}

static size_t mnl_nft_batch_to_msg(struct netlink_ctx *ctx, struct msghdr *msg,
				   const struct sockaddr_nl *snl,
				   struct iovec *iov, unsigned int iov_len)
{
	unsigned int i;
	size_t len = 0;

	msg->msg_name		= (struct sockaddr_nl *)snl;
	msg->msg_namelen	= sizeof(*snl);
	msg->msg_iov		= iov;
	msg->msg_iovlen		= iov_len;

	nftnl_batch_iovec(ctx->batch, iov, iov_len);

	for (i = 0; i < iov_len; i++)
		len += msg->msg_iov[i].iov_len;

	return len;
}

static ssize_t mnl_nft_socket_sendmsg(struct netlink_ctx *ctx,
				      const struct msghdr *msg)
{
	uint32_t iov_len = msg->msg_iovlen;
	struct iovec *iov = msg->msg_iov;
	unsigned int i;

	if (ctx->nft->debug_mask & NFT_DEBUG_MNL) {
		for (i = 0; i < iov_len; i++) {
			mnl_nlmsg_fprintf(ctx->nft->output.output_fp,
					  iov[i].iov_base, iov[i].iov_len,
					  sizeof(struct nfgenmsg));
		}
	}

	return sendmsg(mnl_socket_get_fd(ctx->nft->nf_sock), msg, 0);
}

int mnl_batch_talk(struct netlink_ctx *ctx, struct list_head *err_list,
		   uint32_t num_cmds)
{
	struct mnl_socket *nl = ctx->nft->nf_sock;
	int ret, fd = mnl_socket_get_fd(nl), portid = mnl_socket_get_portid(nl);
	uint32_t iov_len = nftnl_batch_iovec_len(ctx->batch);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int enobuf_restarts = 0;
	size_t avg_msg_size, batch_size;
	const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};
	struct iovec iov[iov_len];
	unsigned int scale = 4;
	struct msghdr msg = {};
	fd_set readfds;

	mnl_set_sndbuffer(ctx->nft->nf_sock, ctx->batch);

	batch_size = mnl_nft_batch_to_msg(ctx, &msg, &snl, iov, iov_len);
	avg_msg_size = div_round_up(batch_size, num_cmds);

restart:
	mnl_set_rcvbuffer(ctx->nft->nf_sock, num_cmds * avg_msg_size * scale);

	ret = mnl_nft_socket_sendmsg(ctx, &msg);
	if (ret == -1)
		return -1;

	/* receive and digest all the acknowledgments from the kernel. */
	while (true) {
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		ret = select(fd + 1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			return -1;

		if (!FD_ISSET(fd, &readfds))
			break;

		ret = mnl_socket_recvfrom(nl, rcv_buf, sizeof(rcv_buf));
		if (ret == -1) {
			if (errno == ENOBUFS && enobuf_restarts++ < 3) {
				scale *= 2;
				goto restart;
			}
			return -1;
		}

		ret = mnl_cb_run(rcv_buf, ret, 0, portid, &netlink_echo_callback, ctx);
		/* Continue on error, make sure we get all acknowledgments */
		if (ret == -1) {
			struct nlmsghdr *nlh = (struct nlmsghdr *)rcv_buf;

			mnl_err_list_node_add(err_list, errno, nlh->nlmsg_seq);
		}
	}
	return 0;
}

int mnl_nft_rule_add(struct netlink_ctx *ctx, const struct cmd *cmd,
		     unsigned int flags)
{
	struct rule *rule = cmd->rule;
	struct handle *h = &rule->handle;
	struct nftnl_rule *nlr;
	struct nlmsghdr *nlh;

	nlr = nftnl_rule_alloc();
	if (!nlr)
		memory_allocation_error();

	nftnl_rule_set_u32(nlr, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set_str(nlr, NFTNL_RULE_TABLE, h->table.name);
	nftnl_rule_set_str(nlr, NFTNL_RULE_CHAIN, h->chain.name);
	if (h->position.id)
		nftnl_rule_set_u64(nlr, NFTNL_RULE_POSITION, h->position.id);
	if (h->rule_id)
		nftnl_rule_set_u32(nlr, NFTNL_RULE_ID, h->rule_id);
	if (h->position_id)
		nftnl_rule_set_u32(nlr, NFTNL_RULE_POSITION_ID, h->position_id);

	netlink_linearize_rule(ctx, nlr, rule);
	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWRULE,
				    cmd->handle.family,
				    NLM_F_CREATE | flags, ctx->seqnum);
	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	nftnl_rule_free(nlr);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_rule_replace(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	struct rule *rule = cmd->rule;
	struct handle *h = &rule->handle;
	unsigned int flags = 0;
	struct nftnl_rule *nlr;
	struct nlmsghdr *nlh;

	if (nft_output_echo(&ctx->nft->output))
		flags |= NLM_F_ECHO;

	nlr = nftnl_rule_alloc();
	if (!nlr)
		memory_allocation_error();

	nftnl_rule_set_u32(nlr, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set_str(nlr, NFTNL_RULE_TABLE, h->table.name);
	nftnl_rule_set_str(nlr, NFTNL_RULE_CHAIN, h->chain.name);
	nftnl_rule_set_u64(nlr, NFTNL_RULE_HANDLE, h->handle.id);

	netlink_linearize_rule(ctx, nlr, rule);
	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWRULE,
				    cmd->handle.family,
				    NLM_F_REPLACE | flags, ctx->seqnum);
	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	nftnl_rule_free(nlr);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_rule_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_rule *nlr;
	struct nlmsghdr *nlh;

	nlr = nftnl_rule_alloc();
	if (!nlr)
		memory_allocation_error();

	nftnl_rule_set_u32(nlr, NFTNL_RULE_FAMILY, h->family);
	nftnl_rule_set_str(nlr, NFTNL_RULE_TABLE, h->table.name);
	if (h->chain.name)
		nftnl_rule_set_str(nlr, NFTNL_RULE_CHAIN, h->chain.name);
	if (h->handle.id)
		nftnl_rule_set_u64(nlr, NFTNL_RULE_HANDLE, h->handle.id);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELRULE,
				    nftnl_rule_get_u32(nlr, NFTNL_RULE_FAMILY),
				    0, ctx->seqnum);
	nftnl_rule_nlmsg_build_payload(nlh, nlr);
	nftnl_rule_free(nlr);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

/*
 * Rule
 */

static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_rule_list *nlr_list = data;
	struct nftnl_rule *r;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	r = nftnl_rule_alloc();
	if (r == NULL)
		memory_allocation_error();

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
		goto err_free;

	nftnl_rule_list_add_tail(r, nlr_list);
	return MNL_CB_OK;

err_free:
	nftnl_rule_free(r);
	return MNL_CB_OK;
}

struct nftnl_rule_list *mnl_nft_rule_dump(struct netlink_ctx *ctx,
					  int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_rule_list *nlr_list;
	struct nlmsghdr *nlh;
	int ret;

	nlr_list = nftnl_rule_list_alloc();
	if (nlr_list == NULL)
		memory_allocation_error();

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
				    NLM_F_DUMP, ctx->seqnum);

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, rule_cb, nlr_list);
	if (ret < 0)
		goto err;

	return nlr_list;
err:
	nftnl_rule_list_free(nlr_list);
	return NULL;
}

/*
 * Chain
 */
int mnl_nft_chain_add(struct netlink_ctx *ctx, const struct cmd *cmd,
		      unsigned int flags)
{
	struct nftnl_chain *nlc;
	struct nlmsghdr *nlh;
	int priority;
	int policy;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	nftnl_chain_set_u32(nlc, NFTNL_CHAIN_FAMILY, cmd->handle.family);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_TABLE, cmd->handle.table.name);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME, cmd->handle.chain.name);

	if (cmd->chain) {
		if (cmd->chain->flags & CHAIN_F_BASECHAIN) {
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_HOOKNUM,
					    cmd->chain->hooknum);
			mpz_export_data(&priority,
					cmd->chain->priority.expr->value,
					BYTEORDER_HOST_ENDIAN, sizeof(int));
			nftnl_chain_set_s32(nlc, NFTNL_CHAIN_PRIO, priority);
			nftnl_chain_set_str(nlc, NFTNL_CHAIN_TYPE,
					    cmd->chain->type);
		}
		if (cmd->chain->policy) {
			mpz_export_data(&policy, cmd->chain->policy->value,
					BYTEORDER_HOST_ENDIAN, sizeof(int));
			nftnl_chain_set_u32(nlc, NFTNL_CHAIN_POLICY, policy);
		}
		if (cmd->chain->dev != NULL)
			nftnl_chain_set_str(nlc, NFTNL_CHAIN_DEV,
					    cmd->chain->dev);
	}
	netlink_dump_chain(nlc, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWCHAIN,
				    cmd->handle.family,
				    NLM_F_CREATE | flags, ctx->seqnum);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);
	nftnl_chain_free(nlc);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_chain_rename(struct netlink_ctx *ctx, const struct cmd *cmd,
			 const struct chain *chain)
{
	const char *name = cmd->arg;
	struct nftnl_chain *nlc;
	struct nlmsghdr *nlh;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	nftnl_chain_set_u32(nlc, NFTNL_CHAIN_FAMILY, cmd->handle.family);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_TABLE, cmd->handle.table.name);
	nftnl_chain_set_u64(nlc, NFTNL_CHAIN_HANDLE, chain->handle.handle.id);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME, name);

	netlink_dump_chain(nlc, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWCHAIN,
				    cmd->handle.family,
				    0, ctx->seqnum);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);
	nftnl_chain_free(nlc);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_chain_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	struct nftnl_chain *nlc;
	struct nlmsghdr *nlh;

	nlc = nftnl_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	nftnl_chain_set_u32(nlc, NFTNL_CHAIN_FAMILY, cmd->handle.family);
	nftnl_chain_set_str(nlc, NFTNL_CHAIN_TABLE, cmd->handle.table.name);
	if (cmd->handle.chain.name)
		nftnl_chain_set_str(nlc, NFTNL_CHAIN_NAME,
				    cmd->handle.chain.name);
	else if (cmd->handle.handle.id)
		nftnl_chain_set_u64(nlc, NFTNL_CHAIN_HANDLE,
				    cmd->handle.handle.id);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELCHAIN,
				    cmd->handle.family,
				    0, ctx->seqnum);
	nftnl_chain_nlmsg_build_payload(nlh, nlc);
	nftnl_chain_free(nlc);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_chain_list *nlc_list = data;
	struct nftnl_chain *c;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	c = nftnl_chain_alloc();
	if (c == NULL)
		memory_allocation_error();

	if (nftnl_chain_nlmsg_parse(nlh, c) < 0)
		goto err_free;

	nftnl_chain_list_add_tail(c, nlc_list);
	return MNL_CB_OK;

err_free:
	nftnl_chain_free(c);
	return MNL_CB_OK;
}

struct nftnl_chain_list *mnl_nft_chain_dump(struct netlink_ctx *ctx,
					    int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_chain_list *nlc_list;
	struct nlmsghdr *nlh;
	int ret;

	nlc_list = nftnl_chain_list_alloc();
	if (nlc_list == NULL)
		memory_allocation_error();

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
				    NLM_F_DUMP, ctx->seqnum);

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, chain_cb, nlc_list);
	if (ret < 0)
		goto err;

	return nlc_list;
err:
	nftnl_chain_list_free(nlc_list);
	return NULL;
}

/*
 * Table
 */
int mnl_nft_table_add(struct netlink_ctx *ctx, const struct cmd *cmd,
		      unsigned int flags)
{
	struct nftnl_table *nlt;
	struct nlmsghdr *nlh;

	nlt = nftnl_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();

	nftnl_table_set_u32(nlt, NFTNL_TABLE_FAMILY, cmd->handle.family);
	nftnl_table_set(nlt, NFTNL_TABLE_NAME, cmd->handle.table.name);
	if (cmd->table)
		nftnl_table_set_u32(nlt, NFTNL_TABLE_FLAGS, cmd->table->flags);
	else
		nftnl_table_set_u32(nlt, NFTNL_TABLE_FLAGS, 0);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWTABLE,
				    cmd->handle.family,
				    flags, ctx->seqnum);
	nftnl_table_nlmsg_build_payload(nlh, nlt);
	nftnl_table_free(nlt);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_table_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	struct nftnl_table *nlt;
	struct nlmsghdr *nlh;

	nlt = nftnl_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();

	nftnl_table_set_u32(nlt, NFTNL_TABLE_FAMILY, cmd->handle.family);
	if (cmd->handle.table.name)
		nftnl_table_set(nlt, NFTNL_TABLE_NAME, cmd->handle.table.name);
	else if (cmd->handle.handle.id)
		nftnl_table_set_u64(nlt, NFTNL_TABLE_HANDLE,
				    cmd->handle.handle.id);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELTABLE,
				    cmd->handle.family,
				    0, ctx->seqnum);
	nftnl_table_nlmsg_build_payload(nlh, nlt);
	nftnl_table_free(nlt);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_table_list *nlt_list = data;
	struct nftnl_table *t;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	t = nftnl_table_alloc();
	if (t == NULL)
		memory_allocation_error();

	if (nftnl_table_nlmsg_parse(nlh, t) < 0)
		goto err_free;

	nftnl_table_list_add_tail(t, nlt_list);
	return MNL_CB_OK;

err_free:
	nftnl_table_free(t);
	return MNL_CB_OK;
}

struct nftnl_table_list *mnl_nft_table_dump(struct netlink_ctx *ctx,
					    int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_table_list *nlt_list;
	struct nlmsghdr *nlh;
	int ret;

	nlt_list = nftnl_table_list_alloc();
	if (nlt_list == NULL)
		return NULL;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family,
				    NLM_F_DUMP, ctx->seqnum);

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, table_cb, nlt_list);
	if (ret < 0)
		goto err;

	return nlt_list;
err:
	nftnl_table_list_free(nlt_list);
	return NULL;
}

/*
 * Set
 */
int mnl_nft_set_add(struct netlink_ctx *ctx, const struct cmd *cmd,
		    unsigned int flags)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_udata_buf *udbuf;
	struct set *set = cmd->set;
	struct nftnl_set *nls;
	struct nlmsghdr *nlh;

	nls = nftnl_set_alloc();
	if (!nls)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	nftnl_set_set_u32(nls, NFTNL_SET_ID, h->set_id);

	nftnl_set_set_u32(nls, NFTNL_SET_FLAGS, set->flags);
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_TYPE,
			  dtype_map_to_kernel(set->key->dtype));
	nftnl_set_set_u32(nls, NFTNL_SET_KEY_LEN,
			  div_round_up(set->key->len, BITS_PER_BYTE));
	if (set_is_datamap(set->flags)) {
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_TYPE,
				  dtype_map_to_kernel(set->datatype));
		nftnl_set_set_u32(nls, NFTNL_SET_DATA_LEN,
				  set->datalen / BITS_PER_BYTE);
	}
	if (set_is_objmap(set->flags))
		nftnl_set_set_u32(nls, NFTNL_SET_OBJ_TYPE, set->objtype);

	if (set->timeout)
		nftnl_set_set_u64(nls, NFTNL_SET_TIMEOUT, set->timeout);
	if (set->gc_int)
		nftnl_set_set_u32(nls, NFTNL_SET_GC_INTERVAL, set->gc_int);

	nftnl_set_set_u32(nls, NFTNL_SET_ID, set->handle.set_id);

	if (!(set->flags & NFT_SET_CONSTANT)) {
		if (set->policy != NFT_SET_POL_PERFORMANCE)
			nftnl_set_set_u32(nls, NFTNL_SET_POLICY, set->policy);

		if (set->desc.size != 0)
			nftnl_set_set_u32(nls, NFTNL_SET_DESC_SIZE,
					  set->desc.size);
	} else if (set->init) {
		nftnl_set_set_u32(nls, NFTNL_SET_DESC_SIZE, set->init->size);
	}

	udbuf = nftnl_udata_buf_alloc(NFT_USERDATA_MAXLEN);
	if (!udbuf)
		memory_allocation_error();
	if (!nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_KEYBYTEORDER,
				 set->key->byteorder))
		memory_allocation_error();

	if (set_is_datamap(set->flags) &&
	    !nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_DATABYTEORDER,
				 set->datatype->byteorder))
		memory_allocation_error();

	if (set->automerge &&
	    !nftnl_udata_put_u32(udbuf, NFTNL_UDATA_SET_MERGE_ELEMENTS,
				 set->automerge))
		memory_allocation_error();

	nftnl_set_set_data(nls, NFTNL_SET_USERDATA, nftnl_udata_buf_data(udbuf),
			   nftnl_udata_buf_len(udbuf));
	nftnl_udata_buf_free(udbuf);

	netlink_dump_set(nls, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWSET,
				    h->family,
				    NLM_F_CREATE | flags, ctx->seqnum);
	nftnl_set_nlmsg_build_payload(nlh, nls);
	nftnl_set_free(nls);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_set_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_set *nls;
	struct nlmsghdr *nlh;

	nls = nftnl_set_alloc();
	if (!nls)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	if (h->set.name)
		nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	else if (h->handle.id)
		nftnl_set_set_u64(nls, NFTNL_SET_HANDLE, h->handle.id);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELSET,
				    h->family,
				    0, ctx->seqnum);
	nftnl_set_nlmsg_build_payload(nlh, nls);
	nftnl_set_free(nls);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_set_list *nls_list = data;
	struct nftnl_set *s;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	s = nftnl_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	if (nftnl_set_nlmsg_parse(nlh, s) < 0)
		goto err_free;

	nftnl_set_list_add_tail(s, nls_list);
	return MNL_CB_OK;

err_free:
	nftnl_set_free(s);
	return MNL_CB_OK;
}

struct nftnl_set_list *
mnl_nft_set_dump(struct netlink_ctx *ctx, int family, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_set_list *nls_list;
	struct nlmsghdr *nlh;
	struct nftnl_set *s;
	int ret;

	s = nftnl_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				    NLM_F_DUMP, ctx->seqnum);
	if (table != NULL)
		nftnl_set_set(s, NFTNL_SET_TABLE, table);
	nftnl_set_nlmsg_build_payload(nlh, s);
	nftnl_set_free(s);

	nls_list = nftnl_set_list_alloc();
	if (nls_list == NULL)
		memory_allocation_error();

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, set_cb, nls_list);
	if (ret < 0)
		goto err;

	return nls_list;
err:
	nftnl_set_list_free(nls_list);
	return NULL;
}

int mnl_nft_obj_add(struct netlink_ctx *ctx, const struct cmd *cmd,
		    unsigned int flags)
{
	struct obj *obj = cmd->object;
	struct nftnl_obj *nlo;
	struct nlmsghdr *nlh;

	nlo = nftnl_obj_alloc();
	if (!nlo)
		memory_allocation_error();

	nftnl_obj_set_u32(nlo, NFTNL_OBJ_FAMILY, cmd->handle.family);
	nftnl_obj_set_str(nlo, NFTNL_OBJ_TABLE, cmd->handle.table.name);
	nftnl_obj_set_str(nlo, NFTNL_OBJ_NAME, cmd->handle.obj.name);
	nftnl_obj_set_u32(nlo, NFTNL_OBJ_TYPE, obj->type);

	switch (obj->type) {
	case NFT_OBJECT_COUNTER:
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_CTR_PKTS,
				  obj->counter.packets);
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_CTR_BYTES,
				  obj->counter.bytes);
                break;
	case NFT_OBJECT_QUOTA:
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_QUOTA_BYTES,
				  obj->quota.bytes);
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_QUOTA_CONSUMED,
				  obj->quota.used);
		nftnl_obj_set_u32(nlo, NFTNL_OBJ_QUOTA_FLAGS,
				  obj->quota.flags);
		break;
	case NFT_OBJECT_LIMIT:
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_LIMIT_RATE, obj->limit.rate);
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_LIMIT_UNIT, obj->limit.unit);
		nftnl_obj_set_u32(nlo, NFTNL_OBJ_LIMIT_BURST, obj->limit.burst);
		nftnl_obj_set_u32(nlo, NFTNL_OBJ_LIMIT_TYPE, obj->limit.type);
		nftnl_obj_set_u32(nlo, NFTNL_OBJ_LIMIT_FLAGS, obj->limit.flags);
		break;
	case NFT_OBJECT_CT_HELPER:
		nftnl_obj_set_str(nlo, NFTNL_OBJ_CT_HELPER_NAME,
				  obj->ct_helper.name);
		nftnl_obj_set_u8(nlo, NFTNL_OBJ_CT_HELPER_L4PROTO,
				 obj->ct_helper.l4proto);
		if (obj->ct_helper.l3proto)
			nftnl_obj_set_u16(nlo, NFTNL_OBJ_CT_HELPER_L3PROTO,
					  obj->ct_helper.l3proto);
		break;
	case NFT_OBJECT_CT_TIMEOUT:
		nftnl_obj_set_u8(nlo, NFTNL_OBJ_CT_TIMEOUT_L4PROTO,
				 obj->ct_timeout.l4proto);
		if (obj->ct_timeout.l3proto)
			nftnl_obj_set_u16(nlo, NFTNL_OBJ_CT_TIMEOUT_L3PROTO,
					  obj->ct_timeout.l3proto);
		nftnl_obj_set(nlo, NFTNL_OBJ_CT_TIMEOUT_ARRAY,
			      obj->ct_timeout.timeout);
		break;
	case NFT_OBJECT_CT_EXPECT:
		if (obj->ct_expect.l3proto)
			nftnl_obj_set_u16(nlo, NFTNL_OBJ_CT_EXPECT_L3PROTO,
					  obj->ct_expect.l3proto);
		nftnl_obj_set_u8(nlo, NFTNL_OBJ_CT_EXPECT_L4PROTO,
				 obj->ct_expect.l4proto);
		nftnl_obj_set_u16(nlo, NFTNL_OBJ_CT_EXPECT_DPORT,
				  obj->ct_expect.dport);
		nftnl_obj_set_u32(nlo, NFTNL_OBJ_CT_EXPECT_TIMEOUT,
				  obj->ct_expect.timeout);
		nftnl_obj_set_u8(nlo, NFTNL_OBJ_CT_EXPECT_SIZE,
				 obj->ct_expect.size);
		break;
	case NFT_OBJECT_SECMARK:
		nftnl_obj_set_str(nlo, NFTNL_OBJ_SECMARK_CTX,
				  obj->secmark.ctx);
		break;
	default:
		BUG("Unknown type %d\n", obj->type);
		break;
	}
	netlink_dump_obj(nlo, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWOBJ, cmd->handle.family,
				    NLM_F_CREATE | flags, ctx->seqnum);
	nftnl_obj_nlmsg_build_payload(nlh, nlo);
	nftnl_obj_free(nlo);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_obj_del(struct netlink_ctx *ctx, const struct cmd *cmd, int type)
{
	struct nftnl_obj *nlo;
	struct nlmsghdr *nlh;

	nlo = nftnl_obj_alloc();
	if (!nlo)
		memory_allocation_error();

	nftnl_obj_set_u32(nlo, NFTNL_OBJ_FAMILY, cmd->handle.family);
	nftnl_obj_set_str(nlo, NFTNL_OBJ_TABLE, cmd->handle.table.name);
	nftnl_obj_set_u32(nlo, NFTNL_OBJ_TYPE, type);
	if (cmd->handle.obj.name)
		nftnl_obj_set_str(nlo, NFTNL_OBJ_NAME, cmd->handle.obj.name);
	else if (cmd->handle.handle.id)
		nftnl_obj_set_u64(nlo, NFTNL_OBJ_HANDLE, cmd->handle.handle.id);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELOBJ, cmd->handle.family,
				    0, ctx->seqnum);
	nftnl_obj_nlmsg_build_payload(nlh, nlo);
	nftnl_obj_free(nlo);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

static int obj_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_obj_list *nln_list = data;
	struct nftnl_obj *n;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	n = nftnl_obj_alloc();
	if (n == NULL)
		memory_allocation_error();

	if (nftnl_obj_nlmsg_parse(nlh, n) < 0)
		goto err_free;

	nftnl_obj_list_add_tail(n, nln_list);
	return MNL_CB_OK;

err_free:
	nftnl_obj_free(n);
	return MNL_CB_OK;
}


struct nftnl_obj_list *
mnl_nft_obj_dump(struct netlink_ctx *ctx, int family,
		 const char *table, const char *name,  uint32_t type, bool dump,
		 bool reset)
{
	uint16_t nl_flags = dump ? NLM_F_DUMP : NLM_F_ACK;
	struct nftnl_obj_list *nln_list;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nftnl_obj *n;
	int msg_type, ret;

	if (reset)
		msg_type = NFT_MSG_GETOBJ_RESET;
	else
		msg_type = NFT_MSG_GETOBJ;

	n = nftnl_obj_alloc();
	if (n == NULL)
		memory_allocation_error();

	nlh = nftnl_nlmsg_build_hdr(buf, msg_type, family,
				    nl_flags, ctx->seqnum);
	if (table != NULL)
		nftnl_obj_set_str(n, NFTNL_OBJ_TABLE, table);
	if (name != NULL)
		nftnl_obj_set_str(n, NFTNL_OBJ_NAME, name);
	if (type != NFT_OBJECT_UNSPEC)
		nftnl_obj_set_u32(n, NFTNL_OBJ_TYPE, type);
	nftnl_obj_nlmsg_build_payload(nlh, n);
	nftnl_obj_free(n);

	nln_list = nftnl_obj_list_alloc();
	if (nln_list == NULL)
		memory_allocation_error();

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, obj_cb, nln_list);
	if (ret < 0)
		goto err;

	return nln_list;
err:
	nftnl_obj_list_free(nln_list);
	return NULL;
}

/*
 * Set elements
 */
static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	nftnl_set_elems_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

static int mnl_nft_setelem_batch(struct nftnl_set *nls,
				 struct nftnl_batch *batch,
				 enum nf_tables_msg_types cmd,
				 unsigned int flags, uint32_t seqnum)
{
	struct nlmsghdr *nlh;
	struct nftnl_set_elems_iter *iter;
	int ret;

	iter = nftnl_set_elems_iter_create(nls);
	if (iter == NULL)
		memory_allocation_error();

	if (cmd == NFT_MSG_NEWSETELEM)
		flags |= NLM_F_CREATE;

	while (nftnl_set_elems_iter_cur(iter)) {
		nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(batch), cmd,
					    nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
					    flags, seqnum);
		ret = nftnl_set_elems_nlmsg_build_payload_iter(nlh, iter);
		mnl_nft_batch_continue(batch);
		if (ret <= 0)
			break;
	}

	nftnl_set_elems_iter_destroy(iter);

	return 0;
}

int mnl_nft_setelem_add(struct netlink_ctx *ctx, const struct set *set,
			const struct expr *expr, unsigned int flags)
{
	const struct handle *h = &set->handle;
	struct nftnl_set *nls;
	int err;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	if (h->set_id)
		nftnl_set_set_u32(nls, NFTNL_SET_ID, h->set_id);

	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls, ctx);

	err = mnl_nft_setelem_batch(nls, ctx->batch, NFT_MSG_NEWSETELEM, flags,
				    ctx->seqnum);
	nftnl_set_free(nls);

	return err;
}

int mnl_nft_setelem_flush(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_set *nls;
	struct nlmsghdr *nlh;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	if (h->handle.id)
		nftnl_set_set_u64(nls, NFTNL_SET_HANDLE, h->handle.id);

	netlink_dump_set(nls, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELSETELEM,
				    h->family,
				    0, ctx->seqnum);
	nftnl_set_elems_nlmsg_build_payload(nlh, nls);
	nftnl_set_free(nls);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_setelem_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	const struct handle *h = &cmd->handle;
	struct nftnl_set *nls;
	int err;

	nls = nftnl_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nftnl_set_set_u32(nls, NFTNL_SET_FAMILY, h->family);
	nftnl_set_set_str(nls, NFTNL_SET_TABLE, h->table.name);
	if (h->set.name)
		nftnl_set_set_str(nls, NFTNL_SET_NAME, h->set.name);
	else if (h->handle.id)
		nftnl_set_set_u64(nls, NFTNL_SET_HANDLE, h->handle.id);

	if (cmd->expr)
		alloc_setelem_cache(cmd->expr, nls);
	netlink_dump_set(nls, ctx);

	err = mnl_nft_setelem_batch(nls, ctx->batch, NFT_MSG_DELSETELEM, 0,
				    ctx->seqnum);
	nftnl_set_free(nls);

	return err;
}

struct nftnl_set *mnl_nft_setelem_get_one(struct netlink_ctx *ctx,
					  struct nftnl_set *nls_in)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_set *nls_out;
	struct nlmsghdr *nlh;
	int err;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
				    nftnl_set_get_u32(nls_in, NFTNL_SET_FAMILY),
				    NLM_F_ACK, ctx->seqnum);
	nftnl_set_elems_nlmsg_build_payload(nlh, nls_in);

	nls_out = nftnl_set_alloc();
	if (!nls_out)
		return NULL;

	nftnl_set_set_str(nls_out, NFTNL_SET_TABLE,
			  nftnl_set_get_str(nls_in, NFTNL_SET_TABLE));
	nftnl_set_set_str(nls_out, NFTNL_SET_NAME,
			  nftnl_set_get_str(nls_in, NFTNL_SET_NAME));

	err = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, set_elem_cb, nls_out);
	if (err < 0) {
		nftnl_set_free(nls_out);
		return NULL;
	}

	return nls_out;
}

int mnl_nft_setelem_get(struct netlink_ctx *ctx, struct nftnl_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
				    nftnl_set_get_u32(nls, NFTNL_SET_FAMILY),
				    NLM_F_DUMP, ctx->seqnum);
	nftnl_set_elems_nlmsg_build_payload(nlh, nls);

	return nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}

static int flowtable_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nftnl_flowtable_list *nln_list = data;
	struct nftnl_flowtable *n;

	if (check_genid(nlh) < 0)
		return MNL_CB_ERROR;

	n = nftnl_flowtable_alloc();
	if (n == NULL)
		memory_allocation_error();

	if (nftnl_flowtable_nlmsg_parse(nlh, n) < 0)
		goto err_free;

	nftnl_flowtable_list_add_tail(n, nln_list);
	return MNL_CB_OK;

err_free:
	nftnl_flowtable_free(n);
	return MNL_CB_OK;
}

struct nftnl_flowtable_list *
mnl_nft_flowtable_dump(struct netlink_ctx *ctx, int family, const char *table)
{
	struct nftnl_flowtable_list *nln_list;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nftnl_flowtable *n;
	struct nlmsghdr *nlh;
	int ret;

	n = nftnl_flowtable_alloc();
	if (n == NULL)
		memory_allocation_error();

	nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETFLOWTABLE, family,
				    NLM_F_DUMP, ctx->seqnum);
	if (table != NULL)
		nftnl_flowtable_set_str(n, NFTNL_FLOWTABLE_TABLE, table);
	nftnl_flowtable_nlmsg_build_payload(nlh, n);
	nftnl_flowtable_free(n);

	nln_list = nftnl_flowtable_list_alloc();
	if (nln_list == NULL)
		memory_allocation_error();

	ret = nft_mnl_talk(ctx, nlh, nlh->nlmsg_len, flowtable_cb, nln_list);
	if (ret < 0)
		goto err;

	return nln_list;
err:
	nftnl_flowtable_list_free(nln_list);
	return NULL;
}

int mnl_nft_flowtable_add(struct netlink_ctx *ctx, const struct cmd *cmd,
			  unsigned int flags)
{
	struct nftnl_flowtable *flo;
	const char *dev_array[8];
	struct nlmsghdr *nlh;
	struct expr *expr;
	int priority;
	int i = 0;

	flo = nftnl_flowtable_alloc();
	if (!flo)
		memory_allocation_error();

	nftnl_flowtable_set_u32(flo, NFTNL_FLOWTABLE_FAMILY,
				cmd->handle.family);
	nftnl_flowtable_set_str(flo, NFTNL_FLOWTABLE_TABLE,
				cmd->handle.table.name);
	nftnl_flowtable_set_str(flo, NFTNL_FLOWTABLE_NAME,
				cmd->handle.flowtable);
	nftnl_flowtable_set_u32(flo, NFTNL_FLOWTABLE_HOOKNUM,
				cmd->flowtable->hooknum);
	mpz_export_data(&priority, cmd->flowtable->priority.expr->value,
			BYTEORDER_HOST_ENDIAN, sizeof(int));
	nftnl_flowtable_set_u32(flo, NFTNL_FLOWTABLE_PRIO, priority);

	list_for_each_entry(expr, &cmd->flowtable->dev_expr->expressions, list)
		dev_array[i++] = expr->identifier;

	dev_array[i] = NULL;
	nftnl_flowtable_set(flo, NFTNL_FLOWTABLE_DEVICES, dev_array);

	netlink_dump_flowtable(flo, ctx);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_NEWFLOWTABLE, cmd->handle.family,
				    NLM_F_CREATE | flags, ctx->seqnum);
	nftnl_flowtable_nlmsg_build_payload(nlh, flo);
	nftnl_flowtable_free(flo);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

int mnl_nft_flowtable_del(struct netlink_ctx *ctx, const struct cmd *cmd)
{
	struct nftnl_flowtable *flo;
	struct nlmsghdr *nlh;

	flo = nftnl_flowtable_alloc();
	if (!flo)
		memory_allocation_error();

	nftnl_flowtable_set_u32(flo, NFTNL_FLOWTABLE_FAMILY,
				cmd->handle.family);
	nftnl_flowtable_set_str(flo, NFTNL_FLOWTABLE_TABLE,
				cmd->handle.table.name);
	nftnl_flowtable_set_str(flo, NFTNL_FLOWTABLE_NAME,
				cmd->handle.flowtable);

	nlh = nftnl_nlmsg_build_hdr(nftnl_batch_buffer(ctx->batch),
				    NFT_MSG_DELFLOWTABLE, cmd->handle.family,
				    0, ctx->seqnum);
	nftnl_flowtable_nlmsg_build_payload(nlh, flo);
	nftnl_flowtable_free(flo);

	mnl_nft_batch_continue(ctx->batch);

	return 0;
}

/*
 * events
 */
#define NFTABLES_NLEVENT_BUFSIZ	(1 << 24)

int mnl_nft_event_listener(struct mnl_socket *nf_sock, unsigned int debug_mask,
			   struct output_ctx *octx,
			   int (*cb)(const struct nlmsghdr *nlh, void *data),
			   void *cb_data)
{
	/* Set netlink socket buffer size to 16 Mbytes to reduce chances of
 	 * message loss due to ENOBUFS.
	 */
	unsigned int bufsiz = NFTABLES_NLEVENT_BUFSIZ;
	int fd = mnl_socket_get_fd(nf_sock);
	char buf[NFT_NLMSG_MAXSIZE];
	fd_set readfds;
	int ret;

	ret = mnl_set_rcvbuffer(nf_sock, bufsiz);
	if (ret < 0)
		nft_print(octx, "# Cannot set up netlink receive socket buffer size to %u bytes, falling back to %u bytes\n",
			  NFTABLES_NLEVENT_BUFSIZ, bufsiz);

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);

		ret = select(fd + 1, &readfds, NULL, NULL, NULL);
		if (ret < 0)
			return -1;

		if (FD_ISSET(fd, &readfds)) {
			ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
			if (ret < 0) {
				if (errno == ENOBUFS) {
					nft_print(octx, "# ERROR: We lost some netlink events!\n");
					continue;
				}
				nft_print(octx, "# ERROR: %s\n",
					  strerror(errno));
				break;
			}
		}

		if (debug_mask & NFT_DEBUG_MNL) {
			mnl_nlmsg_fprintf(octx->output_fp, buf, sizeof(buf),
					  sizeof(struct nfgenmsg));
		}
		ret = mnl_cb_run(buf, ret, 0, 0, cb, cb_data);
		if (ret <= 0)
			break;
	}
	return ret;
}
