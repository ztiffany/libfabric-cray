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

//
// Endpoint common code
//
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gnix.h"
#include "gnix_cm_nic.h"
#include "gnix_util.h"
#include "gnix_ep.h"
#include "gnix_ep_rdm.h"
#include "gnix_ep_msg.h"

atomic_t gnix_id_counter;

/*
 * Prototypes for method structs below
 */

static int gnix_ep_close(fid_t fid);
static int gnix_ep_bind(fid_t fid, struct fid *bfid, uint64_t flags);

static struct fi_ops gnix_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_ep_close,
	.bind = gnix_ep_bind,
	.control = fi_no_control
};

static struct fi_ops_ep gnix_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

/*
 * EP messaging ops
 */

static const recv_func_t const recv_method[] = {
					[FI_EP_MSG] = gnix_ep_recv_msg,
					[FI_EP_RDM] = gnix_ep_recv_rdm,
					};

static ssize_t gnix_ep_recv(struct fid_ep *ep, void *buf, size_t len,
			    void *desc, fi_addr_t src_addr, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return recv_method[ep_priv->type](ep,
					  buf,
					  len,
					  desc,
					  src_addr,
					  context);
}

static const recvv_func_t const recvv_method[] = {
					[FI_EP_MSG] = gnix_ep_recvv_msg,
					[FI_EP_RDM] = gnix_ep_recvv_rdm,
					};

static ssize_t gnix_ep_recvv(struct fid_ep *ep, const struct iovec *iov,
			     void **desc, size_t count, fi_addr_t src_addr,
			     void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return recvv_method[ep_priv->type](ep,
					   iov,
					   desc,
					   count,
					   src_addr,
					   context);
}

static const recvmsg_func_t const recvmsg_method[] = {
					[FI_EP_MSG] = gnix_ep_recvmsg_msg,
					[FI_EP_RDM] = gnix_ep_recvmsg_rdm,
					};

static ssize_t gnix_ep_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
			uint64_t flags)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return recvmsg_method[ep_priv->type](ep,
					     msg,
					     flags);

}

static const send_func_t const send_method[] = {
					[FI_EP_MSG] =  gnix_ep_send_msg,
					[FI_EP_RDM] =  gnix_ep_send_rdm,
					};

static ssize_t gnix_ep_send(struct fid_ep *ep, const void *buf, size_t len,
			    void *desc, fi_addr_t dest_addr, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return send_method[ep_priv->type](ep,
					  buf,
					  len,
					  desc,
					  dest_addr,
					  context);
}

static const sendv_func_t const sendv_method[] = {
					[FI_EP_MSG] = gnix_ep_sendv_msg,
					[FI_EP_RDM] = gnix_ep_sendv_rdm,
					};

static ssize_t gnix_ep_sendv(struct fid_ep *ep, const struct iovec *iov,
			     void **desc, size_t count, fi_addr_t dest_addr,
			     void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return sendv_method[ep_priv->type](ep,
					   iov,
					   desc,
					   count,
					   dest_addr,
					   context);
}

static const sendmsg_func_t const sendmsg_method[] = {
					[FI_EP_MSG] = gnix_ep_sendmsg_msg,
					[FI_EP_RDM] = gnix_ep_sendmsg_rdm,
					};

static ssize_t gnix_ep_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
			uint64_t flags)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return sendmsg_method[ep_priv->type](ep,
					     msg,
					     flags);
}

static const msg_inject_func_t const msg_inject_method[] = {
					  [FI_EP_MSG] = gnix_ep_msg_inject_msg,
					  [FI_EP_RDM] = gnix_ep_msg_inject_rdm,
					};

static ssize_t gnix_ep_msg_inject(struct fid_ep *ep, const void *buf,
				  size_t len, fi_addr_t dest_addr)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return msg_inject_method[ep_priv->type](ep,
						buf,
						len,
						dest_addr);
}

ssize_t gnix_ep_senddata(struct fid_ep *ep, const void *buf, size_t len,
				uint64_t data, fi_addr_t dest_addr)
{
	return -FI_ENOSYS;
}

static struct fi_ops_msg gnix_ep_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = gnix_ep_recv,
	.recvv = gnix_ep_recvv,
	.recvmsg = gnix_ep_recvmsg,
	.send = gnix_ep_send,
	.sendv = gnix_ep_sendv,
	.sendmsg = gnix_ep_sendmsg,
	.inject = gnix_ep_msg_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

/*
 * EP rma ops
 */

static ssize_t gnix_ep_read(struct fid_ep *ep, void *buf, size_t len,
			    void *desc, fi_addr_t src_addr, uint64_t addr,
			    uint64_t key, void *context)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_readv(struct fid_ep *ep, const struct iovec *iov,
				void **desc, size_t count, fi_addr_t src_addr,
				uint64_t addr, uint64_t key, void *context)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_readmsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
				uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
				fi_addr_t dest_addr, uint64_t addr, uint64_t key,
				void *context)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_writev(struct fid_ep *ep, const struct iovec *iov,
				void **desc, size_t count, fi_addr_t dest_addr,
				uint64_t addr, uint64_t key, void *context)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
				uint64_t flags)
{
	return -FI_ENOSYS;
}

static ssize_t gnix_ep_rma_inject(struct fid_ep *ep, const void *buf, size_t len,
			fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	return -FI_ENOSYS;
}


static struct fi_ops_rma gnix_ep_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = gnix_ep_read,
	.readv = gnix_ep_readv,
	.readmsg = gnix_ep_readmsg,
	.write = gnix_ep_write,
	.writev = gnix_ep_writev,
	.writemsg = gnix_ep_writemsg,
	.inject = gnix_ep_rma_inject,
	.writedata = fi_no_rma_writedata,
	.injectdata = fi_no_rma_injectdata,
};

/*
 * EP tag matching ops
 */

static const trecv_func_t const trecv_method[] = {
					[FI_EP_MSG] = gnix_ep_trecv_msg,
					[FI_EP_RDM] = gnix_ep_trecv_rdm,
					};

static ssize_t gnix_ep_trecv(struct fid_ep *ep, void *buf, size_t len,
			     void *desc, fi_addr_t src_addr, uint64_t tag,
			     uint64_t ignore, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return trecv_method[ep_priv->type](ep,
					  buf,
					  len,
					  desc,
					  src_addr,
					  tag,
					  ignore,
					  context);
}

static const trecvv_func_t const trecvv_method[] = {
					[FI_EP_MSG] = gnix_ep_trecvv_msg,
					[FI_EP_RDM] = gnix_ep_trecvv_rdm,
					};

static ssize_t gnix_ep_trecvv(struct fid_ep *ep, const struct iovec *iov,
			      void **desc, size_t count, fi_addr_t src_addr,
			      uint64_t tag, uint64_t ignore, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return trecvv_method[ep_priv->type](ep,
					    iov,
					    desc,
					    count,
					    src_addr,
					    tag,
					    ignore,
					    context);
}

static const trecvmsg_func_t const trecvmsg_method[] = {
					[FI_EP_MSG] = gnix_ep_trecvmsg_msg,
					[FI_EP_RDM] = gnix_ep_trecvmsg_rdm,
					};

static ssize_t gnix_ep_trecvmsg(struct fid_ep *ep,
				const struct fi_msg_tagged *msg, uint64_t flags)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return trecvmsg_method[ep_priv->type](ep,
					      msg,
					      flags);
}

static const tsend_func_t const tsend_method[] = {
					[FI_EP_MSG] = gnix_ep_tsend_msg,
					[FI_EP_RDM] = gnix_ep_tsend_rdm,
					};

static ssize_t gnix_ep_tsend(struct fid_ep *ep, const void *buf, size_t len, void *desc,
			fi_addr_t dest_addr, uint64_t tag, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return tsend_method[ep_priv->type](ep,
					   buf,
					   len,
					   desc,
					   dest_addr,
					   tag,
					   context);
}

static const tsendv_func_t const tsendv_method[] = {
					[FI_EP_MSG] = gnix_ep_tsendv_msg,
					[FI_EP_RDM] = gnix_ep_tsendv_rdm,
					};

static ssize_t gnix_ep_tsendv(struct fid_ep *ep, const struct iovec *iov,
			      void **desc, size_t count, fi_addr_t dest_addr,
			      uint64_t tag, void *context)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return tsendv_method[ep_priv->type](ep,
					    iov,
					    desc,
					    count,
					    dest_addr,
					    tag,
					    context);
}

static const tsendmsg_func_t const tsendmsg_method[] = {
					[FI_EP_MSG] = gnix_ep_tsendmsg_msg,
					[FI_EP_RDM] = gnix_ep_tsendmsg_rdm,
					};

static ssize_t gnix_ep_tsendmsg(struct fid_ep *ep,
				const struct fi_msg_tagged *msg, uint64_t flags)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return tsendmsg_method[ep_priv->type](ep,
					      msg,
					      flags);
}

static const tinject_func_t const tinject_method[] = {
					[FI_EP_MSG] = gnix_ep_tinject_msg,
					[FI_EP_RDM] = gnix_ep_tinject_rdm,
					};

static ssize_t gnix_ep_tinject(struct fid_ep *ep, const void *buf, size_t len,
				fi_addr_t dest_addr, uint64_t tag)
{
	struct gnix_fid_ep *ep_priv;

	ep_priv = container_of(ep, struct gnix_fid_ep, ep_fid);
	assert((ep_priv->type == FI_EP_RDM) || (ep_priv->type == FI_EP_MSG));

	return tinject_method[ep_priv->type](ep,
					     buf,
					     len,
					     dest_addr,
					     tag);
}

ssize_t gnix_ep_tsenddata(struct fid_ep *ep, const void *buf, size_t len,
			void *desc, uint64_t data, fi_addr_t dest_addr,
			uint64_t tag, void *context)
{
	return -FI_ENOSYS;
}

ssize_t gnix_ep_tsearch(struct fid_ep *ep, uint64_t *tag, uint64_t ignore,
			uint64_t flags, fi_addr_t *src_addr, size_t *len,
			void *context)
{
	return -FI_ENOSYS;
}

struct fi_ops_tagged gnix_ep_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = gnix_ep_trecv,
	.recvv = gnix_ep_trecvv,
	.recvmsg = gnix_ep_trecvmsg,
	.send = gnix_ep_tsend,
	.sendv = gnix_ep_tsendv,
	.sendmsg = gnix_ep_tsendmsg,
	.inject = gnix_ep_tinject,
	.senddata = fi_no_tagged_senddata,
	.senddata = gnix_ep_tsenddata,
	.injectdata = fi_no_tagged_injectdata,
	.search = gnix_ep_tsearch,
};

static int gnix_ep_close(fid_t fid)
{
	struct gnix_fid_ep *ep;
	struct gnix_fid_domain *domain;
	struct gnix_nic *nic;
	struct gnix_cm_nic *cm_nic;

	ep = container_of(fid, struct gnix_fid_ep, ep_fid.fid);
	/* TODO: lots more stuff to do here */

	domain = ep->domain;
	assert(domain != NULL);
	atomic_dec(&domain->ref_cnt);
	assert(atomic_get(&domain->ref_cnt) > 0);

	cm_nic = ep->cm_nic;
	assert(cm_nic != NULL);
	gnix_cm_nic_free(cm_nic);

	nic = ep->nic;
	assert(nic != NULL);
	atomic_dec(&nic->ref_cnt);
	assert(atomic_get(&nic->ref_cnt) > 0);

	free(ep);

	return FI_SUCCESS;
}

static int gnix_ep_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	int ret = FI_SUCCESS;
	struct gnix_fid_ep  *ep;
	struct gnix_fid_av  *av;
	struct gnix_fid_cq  *cq;

	ep = container_of(fid, struct gnix_fid_ep, ep_fid.fid);

	if (!bfid)
		return -FI_EINVAL;

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		ret = -FI_ENOSYS;
		goto err;
		break;
	case FI_CLASS_CQ:
		cq = container_of(bfid, struct gnix_fid_cq, cq_fid.fid);
		if (ep->domain != cq->domain) {
			ret = -FI_EINVAL;
			break;
		}
		if (flags & FI_SEND) {
			ep->send_cq = cq;
		}
		if (flags & FI_RECV) {
			ep->recv_cq = cq;
		}
		if (flags & FI_COMPLETION) {
			ep->no_want_cqes = 1;
		}
		atomic_inc(&cq->ref_cnt);
		break;
	case FI_CLASS_AV:
		av = container_of(bfid, struct gnix_fid_av, av_fid.fid);
		if (ep->domain != av->domain) {
			ret = -FI_EINVAL;
			break;
		}
		ep->av = av;
		atomic_inc(&av->ref_cnt);
		break;
	case FI_CLASS_MR:/*TODO: got to figure this one out */
	case FI_CLASS_CNTR: /* TODO: need to support cntrs someday */
	default:
		ret = -FI_ENOSYS;
		break;
	}

err:
	return ret;
}

int gnix_ep_open(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **ep, void *context)
{
	int ret = FI_SUCCESS;
	struct gnix_fid_domain *domain_priv;
	struct gnix_fid_ep *ep_priv = NULL;
	struct gnix_nic *elem, *nic = NULL;
	gni_return_t status;
	uint32_t device_addr;
	uint32_t fake_cdm_id;

	if ((domain == NULL) || (info == NULL) || (ep == NULL))
		return -FI_EINVAL;

	if (info->ep_attr->type != FI_EP_RDM)
		return -FI_ENOSYS;

	domain_priv = container_of(domain, struct gnix_fid_domain, domain_fid);

	ep_priv = calloc(1, sizeof *ep_priv);
	if (!ep_priv)
		return -FI_ENOMEM;

	ep_priv->ep_fid.fid.fclass = FI_CLASS_EP;
	ep_priv->ep_fid.fid.context = context;

	ep_priv->ep_fid.fid.ops = &gnix_ep_fi_ops;
	ep_priv->ep_fid.ops = &gnix_ep_ops;
	ep_priv->domain = domain_priv;
	ep_priv->type = info->ep_attr->type;
	atomic_init(&ep_priv->active_fab_reqs, 0);

	ep_priv->ep_fid.msg = &gnix_ep_msg_ops;
	ep_priv->ep_fid.rma = &gnix_ep_rma_ops;
	ep_priv->ep_fid.tagged = &gnix_ep_tagged_ops;
	ep_priv->ep_fid.atomic = NULL;

	ep_priv->ep_fid.cm = &gnix_cm_ops;

	/*
	 * TODO, initialize vc hash table
	 */
	if (ep_priv->type == FI_EP_RDM) {
		ep_priv->vc_hash_hndl = NULL;
		ret = gnix_cm_nic_alloc(domain_priv,
					 &ep_priv->cm_nic);
		if (ret != FI_SUCCESS)
			goto err_w_ep;
	} else {
		ep_priv->vc = NULL;
	}

	/*
	 * TODO: hookup the progress functions
	 */

	ep_priv->progress_fn = NULL;
	ep_priv->rx_progress_fn = NULL;

	/*
	 * If we've maxed out the number of nics for this domain/ptag,
	 * search the list of existing nics.  Take the gnix_nic_list_lock
	 * here since the gnix_nic_list will be manipulated whether or
	 * not we attach to an existing nic or create a new one.
	 *
	 * Should not matter much that this is a pretty fat critical section
	 * since endpoint setup for RDM type will typically occur near
	 * app startup, likely in a single threaded region, and for the
	 * case of MSG, where there will likely be many 100s of EPs, after
	 * a few initial slow times through this section when nics are created,
	 * max nic count for the ptag will be reached and only the first part
	 * of the critical section - iteration over existing nics - will be
	 * happening.
	 */

	pthread_mutex_lock(&gnix_nic_list_lock);

	if (gnix_nics_per_ptag[domain_priv->ptag] ==
					gnix_def_max_nics_per_ptag) {
		list_for_each(&gnix_nic_list, elem, gnix_nic_list) {
			if ((elem->ptag == domain_priv->ptag) &&
				(elem->cookie == domain_priv->cookie)) {
				nic = elem;
				break;
			}
		}

		/*
		 * nic found, balance use by removing from head and
		 * positioning at end
		 */

		if (nic) {
			gnix_list_del_init(&nic->gnix_nic_list);
			list_add_tail(&gnix_nic_list, &nic->gnix_nic_list);
		}
	}

	/*
	 * no nic found create a cdm and attach
	 */
	if (!nic) {

		nic = calloc(1,sizeof(struct gnix_nic));
		if (nic == NULL) {
			ret = -FI_ENOMEM;
			goto err_w_lock;
		}

		ret = gnix_get_new_cdm_id(domain_priv, &fake_cdm_id);
		if (ret != FI_SUCCESS)
			goto err_w_lock;

		status = GNI_CdmCreate(fake_cdm_id,
					domain_priv->ptag,
					domain_priv->cookie,
					gnix_cdm_modes,
					&nic->gni_cdm_hndl);
		if (status != GNI_RC_SUCCESS) {
			GNIX_ERR(FI_LOG_EP_CTRL, "GNI_CdmCreate returned %s\n",
				 gni_err_str[status]);
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		/*
		 * Okay, now go for the attach
		*/
		status = GNI_CdmAttach(nic->gni_cdm_hndl,
					0,
					&device_addr,
					&nic->gni_nic_hndl);
		if (status != GNI_RC_SUCCESS) {
			GNIX_ERR(FI_LOG_EP_CTRL, "GNI_CdmAttach returned %s\n",
				 gni_err_str[status]);
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		/*
		 * create TX CQs - first polling, then blocking
		 */

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain_priv->gni_tx_cq_size,
					0,                    /* no delay count */
					GNI_CQ_NOBLOCK |
						domain_priv->gni_cq_modes,
					NULL,                 /* useless handler */
					NULL,                 /* useless handler context */
					&nic->tx_cq);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);

			goto err_w_inc;
		}

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain_priv->gni_tx_cq_size,
					0,                    /* no delay count */
					GNI_CQ_BLOCKING |
						domain_priv->gni_cq_modes,
					NULL,                 /* useless handler */
					NULL,                 /* useless handler context */
					&nic->tx_cq_blk);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		/*
		 * create RX CQs - first polling, then blocking
		 */

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain_priv->gni_rx_cq_size,
					0,                    /* no delay count */
					GNI_CQ_NOBLOCK |
						domain_priv->gni_cq_modes,
					NULL,                 /* useless handler */
					NULL,                 /* useless handler context */
					&nic->rx_cq);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
		goto err_w_inc;
		}

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain_priv->gni_rx_cq_size,
					0,                    /* no delay count */
					GNI_CQ_BLOCKING |
					domain_priv->gni_cq_modes,
					NULL,                 /* useless handler */
					NULL,                 /* useless handler context */
					&nic->rx_cq_blk);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		nic->device_addr = device_addr;
		nic->ptag = domain_priv->ptag;
		nic->cookie = domain_priv->cookie;

		/*
		 * TODO: set up work queue
		 */

		atomic_init(&nic->ref_cnt, 0);
		atomic_init(&nic->outstanding_fab_reqs_nic, 0);

		list_add_tail(&gnix_nic_list, &nic->gnix_nic_list);
		++gnix_nics_per_ptag[domain_priv->ptag];

		list_add_tail(&domain_priv->nic_list, &nic->list);
	}

	pthread_mutex_unlock(&gnix_nic_list_lock);

	ep_priv->nic = nic;
	atomic_inc(&nic->ref_cnt);

	atomic_inc(&domain_priv->ref_cnt);
	*ep = &ep_priv->ep_fid;
	return ret;

err_w_inc:
	atomic_dec(&gnix_id_counter);
err_w_lock:
	if (nic != NULL) {
		if (nic->rx_cq_blk != NULL) {
			GNI_CqDestroy(nic->rx_cq_blk);
		}
		if (nic->rx_cq != NULL) {
			GNI_CqDestroy(nic->rx_cq);
		}
		if (nic->tx_cq_blk != NULL) {
			GNI_CqDestroy(nic->tx_cq_blk);
		}
		if (nic->tx_cq != NULL) {
			GNI_CqDestroy(nic->tx_cq);
		}
		if (nic->gni_cdm_hndl != NULL) {
			GNI_CdmDestroy(nic->gni_cdm_hndl);
		}
	}

	if (nic != NULL)
		free(nic);
	pthread_mutex_unlock(&gnix_nic_list_lock);
err_w_ep:
	if (ep_priv != NULL) {
		if (ep_priv->cm_nic != NULL)
			gnix_cm_nic_free(ep_priv->cm_nic);
		free(ep_priv);
	}
	return ret;
}
