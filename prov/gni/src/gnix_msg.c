/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gnix.h"
#include "gnix_cm_nic.h"
#include "gnix_nic.h"
#include "gnix_util.h"
#include "gnix_ep.h"
#include "gnix_hashtable.h"
#include "gnix_vc.h"
#include "gnix_cntr.h"
#include "gnix_av.h"

/*******************************************************************************
 * helper functions
 ******************************************************************************/

/*
 * search the posted receive queue to find a match
 * against an incoming SMSG message hdr.  If no
 * match found, add to the end of the unexpected queue.
 */
static int __gnix_smsg_hdr_match(struct gnix_fid_ep *ep,
				 struct gnix_address addr,
				 uint64_t sflags, uint64_t tag,
				 struct gnix_fab_req **req_ptr,
				 int *matched)
{
	int ret = FI_SUCCESS;
	struct gnix_fab_req *req;
	struct gnix_address *addr_ptr;
	struct gnix_tag_storage *unexp_queue;
	struct gnix_tag_storage *posted_queue;
	fastlock_t *queue_lock;

	/*
	 * we have to keep this lock till either we find a match
	 * or we add the request to the tail of the unexpected queue
	 */

	if (likely(sflags & GNIX_MSG_TAGGED)) {
		queue_lock = &ep->tagged_queue_lock;
		unexp_queue = &ep->tagged_unexp_recv_queue;
		posted_queue = &ep->tagged_posted_recv_queue;
	} else {
		queue_lock = &ep->recv_queue_lock;
		unexp_queue = &ep->unexp_recv_queue;
		posted_queue = &ep->posted_recv_queue;
	}

	addr_ptr = (struct gnix_address *)&addr;
	fastlock_acquire(queue_lock);

	/* context param is null here because there wouldn't be any context
	 * associated with it yet
	 */
	req = _gnix_match_tag(posted_queue, tag, 0, 0, NULL, addr_ptr);
	if (req) {
		req->modes |= GNIX_FAB_RQ_M_MATCHED;
		*req_ptr = req;
		*matched = 1;
	} else {
		req = _gnix_fr_alloc(ep);
		if (req == NULL) {
			ret = -FI_ENOMEM;
			goto err;
		}

		req->modes = GNIX_FAB_RQ_M_UNEXPECTED;
		req->type = GNIX_FAB_RQ_RECV;
		*matched = 0;
		*req_ptr = req;

		/* ignore bits don't matter in the unexpected queue,
		 * so it doesn't matter what is passed in
		 */
		_gnix_insert_tag(unexp_queue, tag, req, ~0);
	}

err:
	fastlock_release(queue_lock);
	return ret;
}

/*******************************************************************************
 * GNI SMSG callbacks invoked upon completion of an SMSG message at the sender.
 ******************************************************************************/

static int __comp_eager_msg_w_data(void *data)
{
	int ret = FI_SUCCESS;
	struct gnix_tx_descriptor *tdesc;
	struct gnix_fid_ep *ep;
	struct gnix_fid_cq *cq;
	ssize_t cq_len;
	struct gnix_fab_req *req;

	tdesc = (struct gnix_tx_descriptor *)data;
	req = tdesc->desc.req;

	ep = tdesc->desc.ep;
	assert(ep != NULL);

	cq = ep->send_cq;
	assert(cq != NULL);

	cq_len = _gnix_cq_add_event(cq,
				    req->user_context,
				    FI_SEND | FI_MSG,
				    0,
				    0,
				    0,
				    0);
	if (cq_len != FI_SUCCESS)  {
		GNIX_WARN((FI_LOG_CQ | FI_LOG_EP_DATA),
			  "_gnix_cq_add_event returned %d\n",
			   cq_len);
		ret = (int)cq_len; /* ugh */
	}

	if (ep->send_cntr) {
		ret = _gnix_cntr_inc(ep->send_cntr);
		if (ret != FI_SUCCESS)
			GNIX_WARN(FI_LOG_CQ,
			  "_gnix_cntr_inc returned %d\n",
			   ret);
	}

	atomic_dec(&req->vc->outstanding_tx_reqs);

	/* We could have requests waiting for TXDs or FI_FENCE operations.
	 * Schedule this VC to push any such TXs. */
	_gnix_vc_schedule_tx(req->vc);

	_gnix_fr_free(ep, req);

	return ret;
}

static int __comp_eager_msg_w_data_ack(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_eager_msg_data_at_src_ack(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rts(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_rtr(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_cookie(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_send_done(void *data)
{
	return -FI_ENOSYS;
}

static int __comp_rndzv_msg_recv_done(void *data)
{
	return -FI_ENOSYS;
}

smsg_completer_fn_t gnix_ep_smsg_completers[] = {
	[GNIX_SMSG_T_EGR_W_DATA] = __comp_eager_msg_w_data,
	[GNIX_SMSG_T_EGR_W_DATA_ACK] = __comp_eager_msg_w_data_ack,
	[GNIX_SMSG_T_EGR_GET] = __comp_eager_msg_data_at_src,
	[GNIX_SMSG_T_EGR_GET_ACK] = __comp_eager_msg_data_at_src_ack,
	[GNIX_SMSG_T_RNDZV_RTS] = __comp_rndzv_msg_rts,
	[GNIX_SMSG_T_RNDZV_RTR] = __comp_rndzv_msg_rtr,
	[GNIX_SMSG_T_RNDZV_COOKIE] = __comp_rndzv_msg_cookie,
	[GNIX_SMSG_T_RNDZV_SDONE] = __comp_rndzv_msg_send_done,
	[GNIX_SMSG_T_RNDZV_RDONE] = __comp_rndzv_msg_recv_done
};


/*******************************************************************************
 * GNI SMSG callbacks invoked upon receipt of an SMSG message.
 * These callback functions are invoked with the lock for the nic
 * associated with the vc already held.
 ******************************************************************************/

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_W_DATA
 */

static int __smsg_eager_msg_w_data(void *data, void *msg)
{
	int ret = FI_SUCCESS;
	int matched = 0;
	gni_return_t status;
	struct gnix_vc *vc = (struct gnix_vc *)data;
	struct gnix_smsg_hdr *hdr = (struct gnix_smsg_hdr *)msg;
	struct gnix_fid_ep *ep;
	struct gnix_fid_cq *cq;
	struct gnix_fab_req *req = NULL;
	ssize_t cq_len;
	void *data_ptr;

	ep = vc->ep;
	assert(ep);

	cq = ep->recv_cq;
	assert(cq != NULL);

	/*
	 * where the sender data is
	 */
	data_ptr = (void *)((char *)msg + sizeof(*hdr));

	/*
	 * the msg data must be consumed either by matching
	 * a message or allocating a buffer and putting
	 * on unexpected queue.
	 */

	ret = __gnix_smsg_hdr_match(ep,
				    vc->peer_addr,
				    hdr->flags,
				    hdr->msg_tag,
				    &req,
				    &matched);
	if (ret != FI_SUCCESS)
		GNIX_WARN(FI_LOG_EP_DATA,
				"__gnix_smsg_hdr_match returned %d\n",
				ret);

	if (matched) {
		/*
		 * very exciting, a match, copy the user data (which is behind
		 * the hdr) into the receive buffer.
		 *
		 * TODO: handle -FI_ETRUNC error
		 */

		memcpy((void *)req->loc_addr, data_ptr,
			MIN(req->len, hdr->len));
		req->addr = vc->peer_addr;
		req->imm = hdr->imm;
		req->len = MIN(req->len, hdr->len);
		req->modes |= GNIX_FAB_RQ_M_COMPLETE;

		/*
		 * if no previously posted receives that are pending
		 * completion, we can go ahead and post CQ to
		 * libfabric cq for this ep.  This check is required
		 * to make sure the SAS ordering GNI provider promises
		 * actually is obeyed on the receiving end.
		 */
		fastlock_acquire(&ep->recv_comp_lock);
		if (slist_empty(&ep->pending_recv_comp_queue)) {

			/*
			 * TODO: eventually need to deal with
			 * FI_SELECTIVE_COMPLETION
			 */
			cq_len = _gnix_cq_add_event(cq,
						    req->user_context,
						    hdr->flags |
							FI_RECV | FI_MSG,
						    req->len,
						    (void *)req->loc_addr,
						    req->imm,
						    0);
			if (cq_len != FI_SUCCESS)  {
				GNIX_WARN((FI_LOG_CQ | FI_LOG_EP_DATA),
					  "_gnix_cq_add_event returned %d\n",
					   cq_len);
				ret = (int)cq_len; /* ugh */
			}

			if (ep->recv_cntr) {
				ret = _gnix_cntr_inc(ep->recv_cntr);
				if (ret != FI_SUCCESS)
					GNIX_WARN(FI_LOG_CQ,
					  "_gnix_cntr_inc() failed: %d\n", ret);
			}

			_gnix_fr_free(ep, req);

		} else
			gnix_slist_insert_tail(&req->slist,
					       &ep->pending_recv_comp_queue);
		fastlock_release(&ep->recv_comp_lock);

	} else {

		/*
		 * TODO: if the malloc fails to allocate space for the
		 * unexpected message this probably means the endpoint is
		 * getting flooded with messages.  We should eventually add
		 * either a flow control method or else at least fail with a
		 * more useful error message.
		 */
		req->loc_addr = (uint64_t)malloc(hdr->len);
		if (unlikely(req->loc_addr == 0UL)) {
			_gnix_fr_free(ep, req);
			ret = -FI_ENOMEM;
			GNIX_WARN(FI_LOG_EP_DATA,
				"malloc returned NULL while handling"
				" an unexpected message\n");
		} else {
			memcpy((void *)req->loc_addr, data_ptr, hdr->len);
			req->addr = vc->peer_addr;
			req->imm = hdr->imm;
			req->len = hdr->len;
			req->cq_flags = hdr->flags;
			req->modes |= GNIX_FAB_RQ_M_COMPLETE;
		}
	}

	status = GNI_SmsgRelease(vc->gni_ep);
	if (unlikely(status != GNI_RC_SUCCESS)) {
		GNIX_WARN(FI_LOG_EP_DATA,
				"GNI_SmsgRelease returned %s\n",
				gni_err_str[status]);
		ret = gnixu_to_fi_errno(status);
	}

	return ret;
}

/*
 * this function will probably not be used unless we need
 * some kind of explicit flow control to handle unexpected
 * receives
 */

static int __smsg_eager_msg_w_data_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_GET
 */
static int __smsg_eager_msg_data_at_src(void *data, void *msg)
{
	return -FI_ENOSYS;
}

/*
 * Handle SMSG message with tag GNIX_SMSG_T_EGR_GET_ACK
 */
static int  __smsg_eager_msg_data_at_src_ack(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rts(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_rtr(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_cookie(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_send_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

static int __smsg_rndzv_msg_recv_done(void *data, void *msg)
{
	return -FI_ENOSYS;
}

smsg_callback_fn_t gnix_ep_smsg_callbacks[] = {
	[GNIX_SMSG_T_EGR_W_DATA] = __smsg_eager_msg_w_data,
	[GNIX_SMSG_T_EGR_W_DATA_ACK] = __smsg_eager_msg_w_data_ack,
	[GNIX_SMSG_T_EGR_GET] = __smsg_eager_msg_data_at_src,
	[GNIX_SMSG_T_EGR_GET_ACK] = __smsg_eager_msg_data_at_src_ack,
	[GNIX_SMSG_T_RNDZV_RTS] = __smsg_rndzv_msg_rts,
	[GNIX_SMSG_T_RNDZV_RTR] = __smsg_rndzv_msg_rtr,
	[GNIX_SMSG_T_RNDZV_COOKIE] = __smsg_rndzv_msg_cookie,
	[GNIX_SMSG_T_RNDZV_SDONE] = __smsg_rndzv_msg_send_done,
	[GNIX_SMSG_T_RNDZV_RDONE] = __smsg_rndzv_msg_recv_done
};

/*******************************************************************************
 * Generic EP recv handling
 ******************************************************************************/

static struct gnix_fab_req *__gnix_recv_match(struct gnix_fid_ep *ep,
		struct gnix_address *addr,
		uint64_t flags, uint64_t tag,
		uint64_t ignore, void *context,
		struct gnix_tag_storage *unexp_queue)
{
	struct gnix_fab_req *req = NULL;
	uint64_t match_flags = flags & (FI_CLAIM | FI_PEEK | FI_DISCARD);
	/* Search the EP's unexpected list for a match. */
	uint64_t match_ignore = ignore;

	/* if FI_EP_MSG, take the first element off of the unexpected list. */
	if (ep->type == FI_EP_MSG)
		match_ignore = ~0;

	req = _gnix_match_tag(unexp_queue, tag, match_ignore,
			match_flags, context, addr);
	if (req) {
		req->modes |= GNIX_FAB_RQ_M_MATCHED;
	}

	return req;
}

ssize_t _gnix_recv(struct gnix_fid_ep *ep, uint64_t buf, size_t len, void *desc,
		   uint64_t src_addr, void *context, uint64_t flags,
		   uint64_t tag, uint64_t ignore)
{
	int ret = FI_SUCCESS;
	int sched_req = 0;
	struct gnix_fid_cq *cq;
	struct gnix_fid_av *av;
	struct gnix_fab_req *req = NULL;
	ssize_t cq_len;
	struct gnix_address *addr_ptr = NULL;
	fi_addr_t real_addr;
	fastlock_t *queue_lock = NULL;
	struct gnix_tag_storage *posted_queue = NULL;
	struct gnix_tag_storage *unexp_queue = NULL;
	uint64_t r_tag = tag, r_ignore = ignore, r_flags;

	r_flags = flags & (FI_CLAIM | FI_DISCARD | FI_PEEK);

	/* TODO make generic address lookup function */
	/* TODO ignore src_addr unless FI_DIRECT_RECV */
	if (ep->type == FI_EP_RDM) {
		av = ep->av;
		assert(av != NULL);
		ret = _gnix_av_addr_retrieve(av, src_addr, &real_addr);
		if (ret != FI_SUCCESS) {
			GNIX_WARN(FI_LOG_AV,
				"_gnix_av_addr_retrieve returned %d\n",
				ret);
			return ret;
		}
		addr_ptr = (struct gnix_address *)&real_addr;
	} else {
		addr_ptr = (struct gnix_address *)&src_addr;
	}
	assert(addr_ptr != NULL);


	if (likely(flags & GNIX_MSG_TAGGED)) {
		queue_lock = &ep->tagged_queue_lock;
		posted_queue = &ep->tagged_posted_recv_queue;
		unexp_queue = &ep->tagged_unexp_recv_queue;
	} else {
		queue_lock = &ep->recv_queue_lock;
		posted_queue = &ep->posted_recv_queue;
		unexp_queue = &ep->unexp_recv_queue;
		r_tag = 0;
		r_ignore = ~0;
	}

	fastlock_acquire(queue_lock);
	req = __gnix_recv_match(ep, addr_ptr, r_flags,
			r_tag, r_ignore, context, unexp_queue);

	/* special case for fi_recvmsg */
	if ((flags & GNIX_MSG_TAGGED) &&
			(flags & (FI_PEEK | FI_CLAIM | FI_DISCARD))) {

		ret = -FI_EOPNOTSUPP;
		goto err;

		/* if there is no message and we are peeking, exit */
		if (!req && (flags & FI_PEEK)) {
			ret = -FI_ENOMSG;
			goto err;
		}
	}


	if (req) {
		if (req->modes & GNIX_FAB_RQ_M_COMPLETE) {
			memcpy((void *)buf, (void *)req->loc_addr,
			       MIN(req->len, len));
			free((void *)req->loc_addr);
			req->loc_addr = 0UL;
		}

		cq = ep->recv_cq;
		assert(cq != NULL);

		fastlock_acquire(&ep->recv_comp_lock);
		if (slist_empty(&ep->pending_recv_comp_queue) &&
			(req->modes & GNIX_FAB_RQ_M_COMPLETE)) {

			/*
			 * TODO: eventually need to deal with
			 * FI_SELECTIVE_COMPLETION
			 */
			cq_len = _gnix_cq_add_event(cq,
						    context,
						    req->cq_flags |
							FI_RECV | FI_MSG,
						    MIN(req->len, len),
						    (void *)buf,
						    req->imm,
						    0);
			if (cq_len != FI_SUCCESS)  {
				GNIX_WARN((FI_LOG_CQ | FI_LOG_EP_DATA),
					  "_gnix_cq_add_event returned %d\n",
					   cq_len);
				ret = (int)cq_len; /* ugh */
			}

			if (ep->recv_cntr) {
				ret = _gnix_cntr_inc(ep->recv_cntr);
				if (ret != FI_SUCCESS)
					GNIX_WARN(FI_LOG_CQ,
					  "_gnix_cntr_inc() failed: %d\n", ret);
			}

			_gnix_fr_free(ep, req);
		} else {
			gnix_slist_insert_tail(&req->slist,
					&ep->pending_recv_comp_queue);
			sched_req = 1;
		}
		fastlock_release(&ep->recv_comp_lock);

	} else {

		req = _gnix_fr_alloc(ep);
		if (req == NULL) {
			ret = -FI_EAGAIN;
			goto err;
		}

		req->addr = *addr_ptr;
		req->len = len;
		req->loc_addr = (uint64_t)buf;
		req->type = GNIX_FAB_RQ_RECV;
		req->user_context = context;

		_gnix_insert_tag(posted_queue, r_tag, req, r_ignore);
	}

err:
	fastlock_release(queue_lock);
	if (sched_req) {
		/*
		 * TODO: schedule completion of req if not completed
		 */
	}

	return ret;
}

/*******************************************************************************
 * Generic EP send handling
 ******************************************************************************/

static int _gnix_send_req(void *data)
{
	struct gnix_fab_req *req = (struct gnix_fab_req *)data;
	struct gnix_nic *nic;
	struct gnix_fid_ep *ep;
	struct gnix_tx_descriptor *tdesc;
	gni_return_t status;
	int rc;
	int rendezvous = !!(req->flags & GNIX_MSG_RENDEZVOUS);
	int len;

	ep = req->gnix_ep;
	assert(ep != NULL);

	nic = ep->nic;
	assert(nic != NULL);

	rc = _gnix_nic_tx_alloc(nic, &tdesc);
	if (rc != FI_SUCCESS) {
		GNIX_INFO(FI_LOG_EP_DATA, "_gnix_nic_tx_alloc() failed: %d\n",
			  rc);
		return -FI_EAGAIN;
	}
	assert(rc == FI_SUCCESS);

	tdesc->desc.req = req;
	tdesc->desc.ep = ep;
	tdesc->desc.completer_fn =
			gnix_ep_smsg_completers[GNIX_SMSG_T_EGR_W_DATA];

	if (rendezvous) {
		/* Fill SMSG header with local buffer info. */

		len = 0;
		assert(0);
	} else {
		tdesc->desc.smsg_desc.hdr.len = req->len;
		tdesc->desc.smsg_desc.hdr.flags = 0;
		tdesc->desc.smsg_desc.buf = (void *)req->loc_addr;
		len = req->len;
	}

	/*
	 * Fill in tag information if necessary
	 */
	if (req->flags & GNIX_MSG_TAGGED) {
		tdesc->desc.smsg_desc.hdr.msg_tag = req->tag;
		tdesc->desc.smsg_desc.hdr.flags |= GNIX_MSG_TAGGED;
	}

	fastlock_acquire(&nic->lock);

	status = GNI_SmsgSendWTag(req->vc->gni_ep,
			&tdesc->desc.smsg_desc.hdr,
			sizeof(struct gnix_smsg_hdr),
			(void *)req->loc_addr, len,
			tdesc->desc.id,
			GNIX_SMSG_T_EGR_W_DATA);

	fastlock_release(&nic->lock);

	if (status == GNI_RC_NOT_DONE) {
		_gnix_nic_tx_free(nic, tdesc);
		GNIX_INFO(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	} else if (status != GNI_RC_SUCCESS) {
		_gnix_nic_tx_free(nic, tdesc);
		GNIX_WARN(FI_LOG_EP_DATA,
			  "GNI_SmsgSendWTag returned %s\n",
			  gni_err_str[status]);
	}

	return gnixu_to_fi_errno(status);
}

ssize_t _gnix_send(struct gnix_fid_ep *ep, uint64_t loc_addr, size_t len,
		   void *mdesc, uint64_t dest_addr, void *context,
		   uint64_t flags, uint64_t data, uint64_t tag)
{
	int ret = FI_SUCCESS;
	struct gnix_vc *vc = NULL;
	struct gnix_fab_req *req;
	struct gnix_fid_mem_desc *md = NULL;
	int rendezvous;

	if (!ep) {
		return -FI_EINVAL;
	}

	if ((flags & FI_INJECT) && (len > GNIX_INJECT_SIZE)) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "Send length %d exceeds inject max size: %d\n",
			  len, GNIX_INJECT_SIZE);
		return -FI_EINVAL;
	}

	rendezvous = len >= ep->domain->params.msg_rendezvous_thresh;

	/* need a memory descriptor for large sends */
	if (rendezvous && !mdesc) {
		GNIX_INFO(FI_LOG_EP_DATA,
			  "Send of length %d requires memory descriptor\n",
			  len);
		return -FI_EINVAL;
	}

	ret = _gnix_ep_get_vc(ep, dest_addr, &vc);
	if (ret) {
		return ret;
	}

	req = _gnix_fr_alloc(ep);
	if (req == NULL)
		return -FI_EAGAIN;

	req->type = GNIX_FAB_RQ_SEND;
	req->gnix_ep = ep;
	req->vc = vc;
	req->user_context = context;
	req->send_fn = _gnix_send_req;
	req->tag = tag;

	if (mdesc) {
		md = container_of(mdesc, struct gnix_fid_mem_desc, mr_fid);
	}
	req->loc_md = (void *)md;

	req->len = len;
	req->flags = flags;

	if (req->flags & FI_INJECT) {
		memcpy(req->inject_buf, (void *)loc_addr, len);
		req->loc_addr = (uint64_t)req->inject_buf;
	} else {
		req->loc_addr = loc_addr;
	}

	if (rendezvous) {
		req->flags |= GNIX_MSG_RENDEZVOUS;
	}

	return _gnix_vc_queue_tx_req(req);
}

