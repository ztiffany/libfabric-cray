/*
 * Copyright (c) 2015 Cray Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_prov.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>

#include "gnix.h"
#include "gnix_datagram.h"
#include "gnix_util.h"


/*
 * function to pack data into datagram in/out buffers.
 * On success, returns number of bytes packed in to the buffer,
 * otherwise -FI errno.
 */
ssize_t _gnix_dgram_pack_buf(struct gnix_datagram *d, enum gnix_dgram_buf buf,
			 void *data, uint32_t nbytes)
{
	char *dptr;
	uint32_t index;

	assert(d != NULL);
	if (buf == GNIX_DGRAM_IN_BUF) {
		index = d->index_in_buf;
		dptr = &d->dgram_in_buf[index];
	} else {
		index = d->index_out_buf;
		dptr = &d->dgram_out_buf[index];
	}

	/*
	 * make sure there's room
	 */
	if ((index + nbytes) > GNI_DATAGRAM_MAXSIZE)
		return -FI_ENOSPC;

	memcpy(dptr, data, nbytes);

	if (buf == GNIX_DGRAM_IN_BUF)
		d->index_in_buf += nbytes;
	else
		d->index_out_buf += nbytes;

	return nbytes;
}


/*
 * function to unpack data fromdatagram in/out buffers.
 * On success, returns number of bytes unpacked,
 * otherwise -FI errno.
 */
ssize_t _gnix_dgram_unpack_buf(struct gnix_datagram *d, enum gnix_dgram_buf buf,
			   void *data, uint32_t nbytes)
{
	char *dptr;
	uint32_t index, bytes_left;

	assert(d != NULL);
	if (buf == GNIX_DGRAM_IN_BUF) {
		index = d->index_in_buf;
		dptr = &d->dgram_in_buf[index];
	} else {
		index = d->index_out_buf;
		dptr = &d->dgram_out_buf[index];
	}

	/*
	 * only copy out up to GNI_DATAGRAM_MAXSIZE
	 */

	bytes_left = GNI_DATAGRAM_MAXSIZE - index;

	nbytes = (nbytes > bytes_left) ? bytes_left : nbytes;

	memcpy(data, dptr, nbytes);

	if (buf == GNIX_DGRAM_IN_BUF)
		d->index_in_buf += nbytes;
	else
		d->index_out_buf += nbytes;

	return nbytes;
}

/*
 * function to rewind the internal pointers to
 * datagram in/out buffers.
 */
int _gnix_dgram_rewind_buf(struct gnix_datagram *d, enum gnix_dgram_buf buf)
{
	assert(d != NULL);
	if (buf == GNIX_DGRAM_IN_BUF)
		d->index_in_buf = 0;
	else
		d->index_out_buf = 0;
	return FI_SUCCESS;
}

int _gnix_dgram_alloc(struct gnix_dgram_hndl *hndl, enum gnix_dgram_type type,
			struct gnix_datagram **d_ptr)
{
	int ret = -FI_ENOMEM;
	struct gnix_datagram *d = NULL;
	struct list_head *the_free_list;
	struct list_head *the_active_list;

	if (type == GNIX_DGRAM_WC) {
		the_free_list = &hndl->wc_dgram_free_list;
		the_active_list = &hndl->wc_dgram_active_list;
	} else {
		the_free_list = &hndl->bnd_dgram_free_list;
		the_active_list = &hndl->bnd_dgram_active_list;
	}

	if (!list_empty(the_free_list)) {
		d = list_top(the_free_list, struct gnix_datagram, list);
		if (d != NULL) {
			gnix_list_del_init(&d->list);
			list_add(the_active_list, &d->list);
			d->type = type;
			ret = FI_SUCCESS;
		}
	}

	if (d != NULL)
		d->index_in_buf = d->index_out_buf = 0;

	*d_ptr = d;
	return ret;
}

int _gnix_dgram_free(struct gnix_datagram *d)
{
	int ret = 0;
	gni_return_t status;

	if (d->type == GNIX_DGRAM_BND) {
		status = GNI_EpUnbind(d->gni_ep);
		if (status != GNI_RC_SUCCESS)
			assert(0);
			/* TODO: have to handle this */
	}

	gnix_list_del_init(&d->list);
	d->state = GNIX_DGRAM_STATE_FREE;
	list_add(d->free_list_head, &d->list);
	return ret;
}

int _gnix_dgram_wc_post(struct gnix_datagram *d, gni_return_t *status_ptr)
{
	int ret = FI_SUCCESS;
	gni_return_t status;

	GNIX_TRACE(FI_LOG_EP_CTRL, "\n");

	status = GNI_EpPostDataWId(d->gni_ep,
				   d->dgram_in_buf,
				   GNI_DATAGRAM_MAXSIZE,
				   d->dgram_out_buf,
				   GNI_DATAGRAM_MAXSIZE,
				   (uint64_t)d);
	if (status != GNI_RC_SUCCESS) {
		ret = gnixu_to_fi_errno(status);
	} else {
		/*
		 * datagram is active now, listening
		 */
		d->state = GNIX_DGRAM_STATE_LISTENING;
	}

	return ret;
}

int _gnix_dgram_bnd_post(struct gnix_datagram *d, gni_return_t *status_ptr)
{
	gni_return_t status;
	int ret = FI_SUCCESS;

	GNIX_TRACE(FI_LOG_EP_CTRL, "\n");

	/*
	 * bind the datagram ep
	 */

	status = GNI_EpBind(d->gni_ep,
			    d->target_addr.device_addr,
			    d->target_addr.cdm_id);
	if (status != GNI_RC_SUCCESS) {
		ret = gnixu_to_fi_errno(status);
		goto err;
	}

	/*
	 * if we get GNI_RC_ERROR_RESOURCE status return from
	 * GNI_EpPostDataWId  that means that a previously posted wildcard
	 * datagram has matched up with an incoming connect
	 * request from the rank we are trying to send a connect
	 * request to.  Don't treat this case as an error.
	 */

	fastlock_acquire(&d->nic->lock);
	status = GNI_EpPostDataWId(d->gni_ep,
				   d->dgram_in_buf,
				   GNI_DATAGRAM_MAXSIZE,
				   d->dgram_out_buf,
				   GNI_DATAGRAM_MAXSIZE,
				   (uint64_t)d);
	fastlock_release(&d->nic->lock);
	if ((status != GNI_RC_SUCCESS) &&
		(status != GNI_RC_ERROR_RESOURCE)) {
			ret = gnixu_to_fi_errno(status);
			goto err;
	}

	if (status_ptr != NULL)
		*status_ptr = status;

	/*
	 * datagram is active now, connecting
	 */
	if (status == GNI_RC_SUCCESS)
		d->state = GNIX_DGRAM_STATE_CONNECTING;
	else if (status == GNI_RC_ERROR_RESOURCE)
		d->state = GNIX_DGRAM_STATE_ALREADY_CONNECTING;

err:
	return ret;
}

int _gnix_dgram_hndl_alloc(const struct gnix_fid_fabric *fabric,
				struct gnix_cm_nic *cm_nic,
				struct gnix_dgram_hndl **hndl_ptr)
{
	int i, ret = FI_SUCCESS;
	int n_dgrams_tot;
	struct gnix_datagram *dgram_base = NULL, *dg_ptr;
	struct gnix_dgram_hndl *the_hndl = NULL;
	gni_return_t status;

	GNIX_TRACE(FI_LOG_EP_CTRL, "\n");

	the_hndl = calloc(1, sizeof(struct gnix_dgram_hndl));
	if (the_hndl == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	the_hndl->nic = cm_nic;

	list_head_init(&the_hndl->bnd_dgram_free_list);
	list_head_init(&the_hndl->bnd_dgram_active_list);

	list_head_init(&the_hndl->wc_dgram_free_list);
	list_head_init(&the_hndl->wc_dgram_active_list);

	/*
	 * inherit some stuff from the fabric object being
	 * used to open the domain which will use this cm nic.
	 */

	the_hndl->n_dgrams = fabric->n_bnd_dgrams;
	the_hndl->n_wc_dgrams = fabric->n_wc_dgrams;

	n_dgrams_tot = the_hndl->n_dgrams + the_hndl->n_wc_dgrams;

	/*
	 * set up the free lists for datagrams
	 */

	dgram_base = calloc(n_dgrams_tot,
			    sizeof(struct gnix_datagram));
	if (dgram_base == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	dg_ptr = dgram_base;

	/*
	 * first build up the list for connection requests
	 */

	for (i = 0; i < fabric->n_bnd_dgrams; i++, dg_ptr++) {
		dg_ptr->d_hndl = the_hndl;
		status = GNI_EpCreate(cm_nic->gni_nic_hndl,
					NULL,
					&dg_ptr->gni_ep);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err;
		}
		gnix_list_node_init(&dg_ptr->list);
		list_add(&the_hndl->bnd_dgram_free_list, &dg_ptr->list);
		dg_ptr->free_list_head = &the_hndl->bnd_dgram_free_list;
	}

	/*
	 * now the wild card (WC) dgrams
	 */

	for (i = 0; i < fabric->n_wc_dgrams; i++, dg_ptr++) {
		dg_ptr->d_hndl = the_hndl;
		status = GNI_EpCreate(cm_nic->gni_nic_hndl,
					NULL,
					&dg_ptr->gni_ep);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err;
		}
		gnix_list_node_init(&dg_ptr->list);
		list_add(&the_hndl->wc_dgram_free_list, &dg_ptr->list);
		dg_ptr->free_list_head = &the_hndl->wc_dgram_free_list;
	}

	the_hndl->dgram_base = dgram_base;

	*hndl_ptr = the_hndl;

	return ret;
err:
	dg_ptr = dgram_base;
	if (dg_ptr) {

		for (i = 0; i < n_dgrams_tot; i++, dg_ptr++) {
			if (dg_ptr->gni_ep != NULL)
				GNI_EpDestroy(dg_ptr->gni_ep);
		}
		free(dgram_base);
	}
	if (the_hndl)
		free(the_hndl);
	return ret;
}

int _gnix_dgram_hndl_free(struct gnix_dgram_hndl *the_hndl)
{
	int i;
	int n_dgrams;
	int ret = FI_SUCCESS;
	struct gnix_datagram *p, *next, *dg_ptr;
	gni_return_t status;

	GNIX_TRACE(FI_LOG_EP_CTRL, "\n");

	if (the_hndl->dgram_base == NULL) {
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * cancel any active datagrams - GNI_RC_NO_MATCH is okay.
	 */

	list_for_each_safe(&the_hndl->bnd_dgram_active_list, p, next, list) {
		dg_ptr = p;
		if (dg_ptr->state != GNIX_DGRAM_STATE_FREE) {
			status = GNI_EpPostDataCancel(dg_ptr->gni_ep);
			if ((status != GNI_RC_SUCCESS) &&
					(status != GNI_RC_NO_MATCH)) {
				ret = gnixu_to_fi_errno(status);
				goto err;
			}
		}
		gnix_list_del_init(&dg_ptr->list);
	}

	list_for_each_safe(&the_hndl->wc_dgram_active_list,
				p, next, list) {
		dg_ptr = p;
		if (dg_ptr->state == GNIX_DGRAM_STATE_FREE) {
			status = GNI_EpPostDataCancel(dg_ptr->gni_ep);
			if ((status != GNI_RC_SUCCESS) &&
					(status != GNI_RC_NO_MATCH)) {
				ret = gnixu_to_fi_errno(status);
				goto err;
			}
		}
		gnix_list_del_init(&dg_ptr->list);
	}

	/*
	 * destroy all the endpoints
	 */

	n_dgrams = the_hndl->n_dgrams + the_hndl->n_wc_dgrams;
	dg_ptr = the_hndl->dgram_base;

	for (i = 0; i < n_dgrams; i++, dg_ptr++) {
		if (dg_ptr->gni_ep != NULL)
			GNI_EpDestroy(dg_ptr->gni_ep);
	}

err:
	if (ret != FI_SUCCESS)
		GNIX_INFO(FI_LOG_EP_CTRL, "returning error %d\n", ret);
	free(the_hndl->dgram_base);
	free(the_hndl);

	return ret;
}

/*
 * this function is intended to be invoked as an argument to pthread_create,
 */
void _gnix_dgram_prog_thread_fn(void *the_arg)
{
	int ret = FI_SUCCESS;
	gni_return_t status;
	gni_post_state_t post_state = GNI_POST_PENDING;
	uint32_t responding_remote_id;
	unsigned int responding_remote_addr;
	struct gnix_datagram *dg_ptr;
	uint64_t datagram_id = 0UL;
	struct gnix_cm_nic *nic = (struct gnix_cm_nic *)the_arg;
	struct gnix_address responding_addr;

	/*
	 * block waiting for datagrams - no need for a lock here
	 */

	status = GNI_PostdataProbeWaitById(nic->gni_nic_hndl,
					   -1,
					   &datagram_id);
	if ((status != GNI_RC_SUCCESS) && (status  != GNI_RC_TIMEOUT)) {
		ret = gnixu_to_fi_errno(status);
		/* TODO: need to post something on event queue */
	}

	if (status == GNI_RC_SUCCESS) {

		dg_ptr = (struct gnix_datagram *)datagram_id;
		assert(dg_ptr != NULL);

		assert((dg_ptr->state == GNIX_DGRAM_STATE_CONNECTING) ||
			(dg_ptr->state = GNIX_DGRAM_STATE_LISTENING));

		/*
		 * do need to take lock here
		 */
		fastlock_acquire(&nic->lock);
		status = GNI_EpPostDataTestById(dg_ptr->gni_ep,
						datagram_id,
						&post_state,
						&responding_remote_addr,
						&responding_remote_id);
		fastlock_release(&nic->lock);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			/* TODO: need to post something on event queue */
		}

		switch (post_state) {
		case GNI_POST_COMPLETED:
			if (dg_ptr->callback_fn != NULL) {
				responding_addr.device_addr =
					responding_remote_addr;
				responding_addr.cdm_id =
					responding_remote_id;
				ret = dg_ptr->callback_fn((void *)datagram_id,
							responding_addr,
							post_state);
				if (ret != FI_SUCCESS) {
					ret = gnixu_to_fi_errno(status);
					/* TODO: need to post something
					 * on event queue
					 * */
				}
			}
			break;
		case GNI_POST_TIMEOUT:
		case GNI_POST_TERMINATED:
		case GNI_POST_ERROR:
			ret = -FI_EIO;
			break;
		case GNI_POST_PENDING:
		case GNI_POST_REMOTE_DATA:
			break;
		default:
			assert(0);
			break;
		}
	}
}
