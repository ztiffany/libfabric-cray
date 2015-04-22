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
#include "gnix_nic.h"
#include "gnix_cm_nic.h"

static int gnix_nics_per_ptag[GNI_PTAG_USER_END];
static LIST_HEAD(gnix_nic_list);
static pthread_mutex_t gnix_nic_list_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * globals
 */

/* TODO: this will need to be adjustable - probably set in GNI_INI*/
uint32_t gnix_def_max_nics_per_ptag = 4;


/*
 * allocate a free list of tx descs for a gnix_nic struct.
 */

int _gnix_nic_tx_freelist_init(struct gnix_nic *nic, int n_descs)
{
	int i, ret = FI_SUCCESS;
	struct gnix_tx_descriptor *desc_base, *desc_ptr;

	/*
	 * set up free list of tx descriptors.
	 */

	desc_base = calloc(n_descs, sizeof(struct gnix_tx_descriptor));
	if (desc_base == NULL) {
		ret = -FI_ENOMEM;
		goto err;
	}

	list_head_init(&nic->tx_desc_free_list);
	list_head_init(&nic->tx_desc_active_list);

	for (i = 0, desc_ptr = desc_base; i < n_descs; i++) {
		desc_ptr->desc.id = i;
		gnix_list_node_init(&desc_ptr->desc.list);
		list_add_tail(&nic->tx_desc_free_list,
				&desc_ptr->desc.list);
	}

	nic->max_tx_desc_id = n_descs - 1;
	nic->tx_desc_base = desc_base;

	return ret;
err:
	return ret;

}

/*
 * free a gnix nic and associated resources if refcnt drops to 0
 */

int _gnix_nic_free(struct gnix_nic *nic)
{
	int ret = FI_SUCCESS, v;
	gni_return_t status;

	if (nic == NULL)
		return -FI_EINVAL;

	v = atomic_dec(&nic->ref_cnt);
	assert(v >= 0);

	if ((nic->gni_cdm_hndl != NULL) && (v == 0))  {
		if (nic->rx_cq_blk != NULL)
			status = GNI_CqDestroy(nic->rx_cq_blk);
		if (nic->rx_cq != NULL)
			status = GNI_CqDestroy(nic->rx_cq);
		if (nic->tx_cq_blk != NULL)
			status = GNI_CqDestroy(nic->tx_cq_blk);
		if (nic->tx_cq != NULL)
			status = GNI_CqDestroy(nic->tx_cq);
		status = GNI_CdmDestroy(nic->gni_cdm_hndl);
		if (status != GNI_RC_SUCCESS) {
			GNIX_ERR(FI_LOG_DOMAIN, "oops, cdm destroy failed\n");
			ret = gnixu_to_fi_errno(status);
			free(nic);
		}

		/*
		 * remove the nic from the linked lists
		 * for the domain and the global nic list
		 */

		pthread_mutex_lock(&gnix_nic_list_lock);

		gnix_list_del_init(&nic->gnix_nic_list);
		--gnix_nics_per_ptag[nic->ptag];
		gnix_list_del_init(&nic->list);

		pthread_mutex_unlock(&gnix_nic_list_lock);
		free(nic);
	}

	return ret;
}

/*
 * allocate a gnix_nic struct using attributes of the domain
 */

int gnix_nic_alloc(struct gnix_fid_domain *domain,
				struct gnix_nic **nic_ptr)
{
	int ret = FI_SUCCESS;
	struct gnix_nic *nic = NULL, *elem;
	uint32_t device_addr;
	gni_return_t status;
	uint32_t fake_cdm_id;

	*nic_ptr = NULL;

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

	if (gnix_nics_per_ptag[domain->ptag] ==
					gnix_def_max_nics_per_ptag) {
		list_for_each(&gnix_nic_list, elem, list) {
			if ((elem->ptag == domain->ptag) &&
				(elem->cookie == domain->cookie)) {
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

		nic = calloc(1, sizeof(struct gnix_nic));
		if (nic == NULL) {
			ret = -FI_ENOMEM;
			goto err_w_lock;
		}

		ret = gnix_get_new_cdm_id(domain, &fake_cdm_id);
		if (ret != FI_SUCCESS)
			goto err_w_lock;

		status = GNI_CdmCreate(fake_cdm_id,
					domain->ptag,
					domain->cookie,
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
					domain->gni_tx_cq_size,
					0,                  /* no delay count */
					GNI_CQ_NOBLOCK |
					domain->gni_cq_modes,
					NULL,              /* useless handler */
					NULL,               /* useless handler
								context */
					&nic->tx_cq);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain->gni_tx_cq_size,
					0,
					GNI_CQ_BLOCKING |
						domain->gni_cq_modes,
					NULL,
					NULL,
					&nic->tx_cq_blk);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		/*
		 * create RX CQs - first polling, then blocking
		 */

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain->gni_rx_cq_size,
					0,
					GNI_CQ_NOBLOCK |
						domain->gni_cq_modes,
					NULL,
					NULL,
					&nic->rx_cq);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
		goto err_w_inc;
		}

		status = GNI_CqCreate(nic->gni_nic_hndl,
					domain->gni_rx_cq_size,
					0,
					GNI_CQ_BLOCKING |
					domain->gni_cq_modes,
					NULL,
					NULL,
					&nic->rx_cq_blk);
		if (status != GNI_RC_SUCCESS) {
			ret = gnixu_to_fi_errno(status);
			goto err_w_inc;
		}

		nic->device_addr = device_addr;
		nic->ptag = domain->ptag;
		nic->cookie = domain->cookie;

		ret = _gnix_nic_tx_freelist_init(nic, domain->gni_tx_cq_size);
		if (ret != FI_SUCCESS)
			goto err_w_inc;

		/*
		 * TODO: set up work queue
		 */

		atomic_initialize(&nic->ref_cnt, 1);
		atomic_initialize(&nic->outstanding_fab_reqs_nic, 0);

		list_add_tail(&gnix_nic_list, &nic->gnix_nic_list);
		++gnix_nics_per_ptag[domain->ptag];

		list_add_tail(&domain->nic_list, &nic->list);
	}

	pthread_mutex_unlock(&gnix_nic_list_lock);

	*nic_ptr = nic;
	return FI_SUCCESS;

err_w_inc:
	atomic_dec(&gnix_id_counter);
err_w_lock:
	if (nic != NULL) {
		if (nic->rx_cq_blk != NULL)
			GNI_CqDestroy(nic->rx_cq_blk);
		if (nic->rx_cq != NULL)
			GNI_CqDestroy(nic->rx_cq);
		if (nic->tx_cq_blk != NULL)
			GNI_CqDestroy(nic->tx_cq_blk);
		if (nic->tx_cq != NULL)
			GNI_CqDestroy(nic->tx_cq);
		if (nic->gni_cdm_hndl != NULL)
			GNI_CdmDestroy(nic->gni_cdm_hndl);
		free(nic);
	}

	pthread_mutex_unlock(&gnix_nic_list_lock);
	return ret;
}
