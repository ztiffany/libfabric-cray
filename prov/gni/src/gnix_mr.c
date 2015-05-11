/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
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
// memory registration common code
//
#include <stdlib.h>
#include <string.h>

#include "gnix.h"
#include "gnix_util.h"
#include "gnix_mr.h"
//#include "gni_priv.h"

#define PAGE_SHIFT 12

static int fi_gnix_mr_close(fid_t fid);
static int fi_gnix_mr_cache_close(fid_t fid);

static struct fi_ops fi_gnix_mr_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_gnix_mr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

__attribute__((unused))
static struct fi_ops fi_gnix_mr_cache_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_gnix_mr_cache_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static inline int64_t sign_extend(uint64_t val, int len)
{
	int64_t m = 1UL << (len - 1);
	int64_t r = (val ^ m) - m;

	return r;
}

static inline gni_return_t __gnix_mr_free(gnix_mr_t *mr)
{
	gni_return_t ret;

	ret = GNI_MemDeregister(mr->nic->gni_nic_hndl, &mr->md.mem_hndl);
	if (ret == GNI_RC_SUCCESS) {
		atomic_dec(&mr->md.domain->ref_cnt);
		atomic_dec(&mr->nic->ref_cnt);
		free(mr);
	} else {
		GNIX_WARN(FI_LOG_MR, "failed to deregister memory"
				" region, mr=%p ret=%i", mr, ret);
	}

	return ret;
}

__attribute__((unused))
static inline void __gnix_mr_put(gnix_mr_t *mr)
{
	if (!atomic_dec(&mr->ref_cnt)) {
		__gnix_mr_free(mr);
	}
}

__attribute__((unused))
static inline void __gnix_mr_get(gnix_mr_t *mr)
{
	atomic_inc(&mr->ref_cnt);
}

__attribute__((unused))
static void gnix_convert_key_to_mhdl(gnix_mr_key_t *key, gni_mem_handle_t *mhdl)
{
	/*

	uint64_t va = (uint64_t) sign_extend(key->va << PAGE_SHIFT,
			GNIX_MR_KEY_BITS);

	GNI_MEMHNDL_INIT((*mhdl));
	if (key->format)
		GNI_MEMHNDL_SET_FLAGS(mdhl, GNI_MEMHNDL_FLAG_NEW_FRMT);
	GNI_MEMHNDL_SET_VA((*mhdl), va);
	GNI_MEMHNDL_SET_MDH((*mhdl), key->mdd);
	GNI_MEMHNDL_SET_NPAGES((*mhdl), GNI_MEMHNDL_NPGS_MASK);
	GNI_MEMHNDL_SET_PAGESIZE((*mhdl), PAGE_SHIFT);
	GNI_MEMHNDL_SET_CRC(*mhdl);
	*/
}

static void gnix_convert_mhdl_to_key(gni_mem_handle_t *mhdl, gnix_mr_key_t *key)
{
	//key->va = GNI_MEMHNDL_GET_VA((*mhdl));
	//key->format = 0;
	//key->mdd = GNI_MEMHNDL_GET_MDH((*mhdl));
}

int gnix_mr_reg(struct fid *fid, const void *buf, size_t len,
		uint64_t access, uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr_o, void *context)
{
	gnix_mr_t *mr;
	int fi_gnix_access = 0;
	struct gnix_fid_domain *domain;
	struct gnix_nic *nic;
	gni_cq_handle_t cq_hndl = NULL;
	gni_return_t grc = GNI_RC_INVALID_PARAM;

	if (flags)
		return -FI_EBADFLAGS;

	/* The offset parameter is reserved for future use and must be 0. */
	if (offset || !buf || !mr_o || !access ||
			(access & ~(FI_READ | FI_WRITE | FI_RECV | FI_SEND |
						FI_REMOTE_READ |
						FI_REMOTE_WRITE)) ||
			(fid->fclass != FI_CLASS_DOMAIN))
		return -FI_EINVAL;

	/* requested key is not permitted at this point */
	if (requested_key)
		return -FI_EKEYREJECTED;

	domain = container_of(fid, struct gnix_fid_domain, domain_fid.fid);

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return -FI_ENOMEM;

	/* If network would be able to write to this buffer, use read-write */
	if (access & (FI_RECV | FI_READ | FI_REMOTE_WRITE))
		fi_gnix_access |= GNI_MEM_READWRITE;
	else
		fi_gnix_access |= GNI_MEM_READ_ONLY;

	list_for_each(&domain->nic_list, nic, list)
	{

		/* TODO: when we determine the progress model,
		 *         set the cq_hndl pointer
		 */
		grc = GNI_MemRegister(nic->gni_nic_hndl, (uintptr_t) buf, len,
					cq_hndl, fi_gnix_access,
					-1, &mr->md.mem_hndl);
		if (grc == GNI_RC_SUCCESS)
			break;
	}

	if (grc != GNI_RC_SUCCESS)
		goto err;

	/* md.domain */
	mr->md.domain = domain;
	atomic_inc(&domain->ref_cnt);

	/* md.mr_fid */
	mr->md.mr_fid.fid.fclass = FI_CLASS_MR;
	mr->md.mr_fid.fid.context = context;
	mr->md.mr_fid.fid.ops = &fi_gnix_mr_ops;

	/* nic */
	mr->nic = nic;
	atomic_inc(&nic->ref_cnt);

	/* initialize ref count */
	atomic_initialize(&mr->ref_cnt, 1);

	/* setup internal key structure */
	gnix_convert_mhdl_to_key(&mr->md.mem_hndl,
			(gnix_mr_key_t *) &mr->md.mr_fid.key);

	*mr_o = &mr->md.mr_fid;

	return FI_SUCCESS;

err:
	free(mr);
	GNIX_INFO(FI_LOG_MR, "failed to register memory with uGNI, ret=%s",
			gni_err_str[grc]);
	return -gnixu_to_fi_errno(grc);
}

static int fi_gnix_mr_close(fid_t fid)
{
	gnix_mr_t *mr;
	gni_return_t ret;

	mr = container_of(fid, gnix_mr_t, md.mr_fid.fid);

	/* FI_LOCAL_MR never uses the cache, so the mr refcount should be
	 *   irrelevant
	 */
	atomic_set(&mr->ref_cnt, 0);

	ret = __gnix_mr_free(mr);

	return gnixu_to_fi_errno(ret);
}

static int fi_gnix_mr_cache_close(fid_t fid)
{
	gnix_mr_t *mr;
	gni_return_t ret = FI_SUCCESS;

	mr = container_of(fid, gnix_mr_t, md.mr_fid.fid);

	if (!atomic_dec(&mr->ref_cnt)) {
		ret = __gnix_mr_free(mr);
	}

	return gnixu_to_fi_errno(ret);
}


