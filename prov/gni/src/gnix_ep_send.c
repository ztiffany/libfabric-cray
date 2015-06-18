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

/*
 * Endpoint common code
 */
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "gnix.h"
#include "gnix_cm_nic.h"
#include "gnix_nic.h"
#include "gnix_util.h"
#include "gnix_ep.h"
#include "gnix_vc.h"
#include "gnix_hashtable.h"

/*******************************************************************************
 * Helper functions used for handling sending of messages on GNIX EPs
 ******************************************************************************/

int _gnix_ep_get_vc(struct gnix_fid_ep *ep, fi_addr_t dest_addr,
			struct gnix_vc **vc_ptr)
{
	int ret = FI_SUCCESS;
	struct gnix_vc *vc = NULL;
	struct gnix_fid_av *av;
	gnix_ht_key_t key;

	av = ep->av;
	assert(av != NULL);

	if (av->type == FI_AV_TABLE)
		return -FI_ENOSYS;

	if (av->type == FI_AV_MAP) {
		memcpy(&key, &dest_addr, sizeof(gnix_ht_key_t));
		vc = (struct gnix_vc *)_gnix_ht_lookup(ep->vc_ht,
							key);
		if (vc == NULL) {
			ret = _gnix_vc_alloc(ep,
					    dest_addr,
					    &vc);
			if (ret != FI_SUCCESS) {
				GNIX_WARN(FI_LOG_EP_DATA,
					  "_gnix_vc_alloc returned %d\n",
					  ret);
				goto err;
			}
			ret = _gnix_ht_insert(ep->vc_ht, key,
						vc);
			if (likely(ret == FI_SUCCESS)) {
				vc->modes |= GNIX_VC_MODE_IN_HT;
				fastlock_acquire(&ep->vc_list_lock);
				dlist_insert_tail(&vc->entry,
						  &ep->wc_vc_list);
				fastlock_release(&ep->vc_list_lock);
				ret = _gnix_vc_connect(vc);
				if (ret != FI_SUCCESS) {
					GNIX_WARN(FI_LOG_EP_DATA,
						"_gnix_vc_connect returned %d\n",
						   ret);
					goto err;
				}
			} else if (ret == -FI_ENOSPC) {
				vc = _gnix_ht_lookup(ep->vc_ht, key);
				assert(vc != NULL);
				assert(vc->modes & GNIX_VC_MODE_IN_HT);
			} else {
				GNIX_WARN(FI_LOG_EP_DATA,
					  "_gnix_ht_insert returned %d\n",
					   ret);
				goto err;
			}
		}
		*vc_ptr = vc;
	} else {
		/*
		 * TODO: need thread safety for vc_table
		 */
		vc = ep->vc_table[dest_addr];
		if (vc == NULL) {
			ret = _gnix_vc_alloc(ep,
					    dest_addr, /*TODO: need translate */
					    &vc);
			if (ret == FI_SUCCESS) {
				ep->vc_table[dest_addr] = vc;
				ret = _gnix_vc_connect(vc);
				if (ret != FI_SUCCESS) {
					GNIX_WARN(FI_LOG_EP_DATA,
						  "_gnix_vc_connect returned %d\n",
						   ret);
					goto err;
				}
			} else {
				GNIX_WARN(FI_LOG_EP_DATA,
					  "_gnix_vc_alloc returned %d\n",
					   ret);
				goto err;
			}
		}
		*vc_ptr = vc;
	}

	return ret;
err:
	if (vc != NULL)
		_gnix_vc_destroy(vc);
	return ret;
}

int _gnix_ep_push_vc_sendq(struct gnix_vc *vc)
{
	int ret = FI_SUCCESS;
	struct gnix_fab_req *req;
	struct gnix_nic *nic;
	struct gnix_fid_ep *ep;
	struct slist *list;
	struct slist_entry *item;
	struct gnix_tx_descriptor *tdesc;
	gni_return_t status;

	/*
	 * if vc is not in connected state can't push sends
	 */

	if (vc->conn_state != GNIX_VC_CONNECTED)
		return -FI_EAGAIN;

	/*
	 * TODO: need a lock for send queue
	 */

	list = &vc->send_queue;
	item = list->head;
	while (item != NULL) {

		req = (struct gnix_fab_req *)container_of(item,
							  struct gnix_fab_req,
							  slist);
		ep = req->gnix_ep;
		assert(ep != NULL);

		nic = ep->nic;
		assert(nic != NULL);

		if (req->len < (16384 - sizeof(struct gnix_smsg_hdr))) {

			/*
			 * pure smsg path
			 */

			ret = _gnix_nic_tx_alloc(nic, &tdesc);
			if (ret == -FI_ENOSPC)
				goto out;
			assert(ret == FI_SUCCESS);

			tdesc->desc.smsg_desc.hdr.len = req->len;
			tdesc->desc.smsg_desc.hdr.flags = 0;
			tdesc->desc.smsg_desc.buf = req->buf;
			tdesc->desc.req = req;
			tdesc->desc.ep = ep;
			tdesc->desc.completer_fn =
				gnix_ep_smsg_completers[GNIX_SMSG_T_EGR_W_DATA];
			fastlock_acquire(&nic->lock);
			status = GNI_SmsgSendWTag(vc->gni_ep,
						&tdesc->desc.smsg_desc.hdr,
						sizeof(struct gnix_smsg_hdr),
						(void *)req->buf,
						req->len,
						tdesc->desc.id,
						GNIX_SMSG_T_EGR_W_DATA);
			fastlock_release(&nic->lock);
			if (status == GNI_RC_SUCCESS)
				slist_remove_head(&vc->send_queue);
			else if (status == GNI_RC_NOT_DONE) {
				ret = gnixu_to_fi_errno(status);
				_gnix_nic_tx_free(nic, tdesc);
				goto out;
			} else {
				GNIX_WARN(FI_LOG_EP_DATA,
					 "GNI_SmsgSendWTag returned %s\n",
					  gni_err_str[status]);
				ret = gnixu_to_fi_errno(status);
				goto err;
			}
		} else {
			ret = -FI_ENOSYS;  /* only smsg path for now */
			goto out;
		}

		item = list->head;
	}
err:
out:
	/*
	 * release send_queue lock
	 */
	return ret;
}
