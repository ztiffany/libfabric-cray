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

/*
 * Start of code pulled from gni_priv.h
 */
inline static uint8_t gni_crc_bits(uint8_t data)
{
  uint8_t lcrc = 0;

  if(data & 1)
    lcrc ^= 0x5e;
  if(data & 2)
    lcrc ^= 0xbc;
  if(data & 4)
    lcrc ^= 0x61;
  if(data & 8)
    lcrc ^= 0xc2;
  if(data & 0x10)
    lcrc ^= 0x9d;
  if(data & 0x20)
    lcrc ^= 0x23;
  if(data & 0x40)
    lcrc ^= 0x46;
  if(data & 0x80)
    lcrc ^= 0x8c;

  return lcrc;
}

inline static uint8_t gni_memhndl_calc_crc(gni_mem_handle_t *memhndl)
{
        uint64_t qw1 = memhndl->qword1;
        uint64_t qw2 = memhndl->qword2;
        uint8_t  crc = 0;
        crc  = gni_crc_bits((qw1 ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 8) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 16) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 24) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 32) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 40) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 48) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw1 >> 56) ^ crc)&0xff);
        crc  = gni_crc_bits((qw2 ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 8) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 16) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 24) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 32) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 40) ^ crc)&0xff);
        crc  = gni_crc_bits(((qw2 >> 48) ^ crc)&0xff);

        return crc;
}

typedef struct gni_mem_hndl_v1 {
        struct {
                uint64_t va: 52;
                uint64_t mdh: 12;
        };
        struct {
                uint64_t npages: 28;
                uint64_t pgsize: 6;
                uint64_t flags: 8;
                uint64_t unused: 14;
                uint64_t crc: 8;
        };
} gni_mem_hndl_v1_t;
typedef struct gni_mem_hndl_v2 {
        union {
                struct {
                        uint64_t va: 52;
                        uint64_t entropy: 12;
                };
                uint64_t id;
        };
        struct {
                uint64_t npages: 28;
                uint64_t pgsize: 6;
                uint64_t flags: 8;
                uint64_t mdh: 12;
                uint64_t unused: 2;
                uint64_t crc: 8;
        };
} gni_mem_hndl_v2_t;

/*************** Memory Handle ****************/
/* Flags (8 bits)*/
#define GNI_MEMHNDL_FLAG_READONLY       0x01UL /* Memory is not writable */
#define GNI_MEMHNDL_FLAG_VMDH           0x02UL /* Mapped via virtual MDH table */
#define GNI_MEMHNDL_FLAG_MRT            0x04UL /* MRT was used for mapping */
#define GNI_MEMHNDL_FLAG_GART           0x08UL /* GART was used for mapping */
#define GNI_MEMHNDL_FLAG_IOMMU          0x10UL /* IOMMU was used for mapping */
#define GNI_MEMHNDL_FLAG_PCI_IOMMU      0x20UL /* PCI IOMMU was used for mapping */
#define GNI_MEMHNDL_FLAG_CLONE          0x40UL /* Registration cloned from a master MDD */
#define GNI_MEMHNDL_FLAG_NEW_FRMT       0x80UL /* Used to support MDD sharing */
/* Memory Handle manipulations  */
#define GNI_MEMHNDL_INIT(memhndl) do {memhndl.qword1 = 0; memhndl.qword2 = 0;} while(0)
/* Support macros, 34 is the offset of the flags value */
#define GNI_MEMHNDL_NEW_FRMT(memhndl) ((memhndl.qword2 >> 34) & GNI_MEMHNDL_FLAG_NEW_FRMT)
#define GNI_MEMHNDL_FRMT_SET(memhndl, val, value)           \
        if (GNI_MEMHNDL_NEW_FRMT(memhndl)) {                \
                uint64_t tmp = value;                       \
                ((gni_mem_hndl_v2_t *)&memhndl)->val = tmp; \
        } else {                                            \
                uint64_t tmp = value;                       \
                ((gni_mem_hndl_v1_t *)&memhndl)->val = tmp; \
        }

#define GNI_MEMHNDL_FRMT_GET(memhndl, val) \
        ((uint64_t)(GNI_MEMHNDL_NEW_FRMT(memhndl) ? ((gni_mem_hndl_v2_t *)&memhndl)->val : ((gni_mem_hndl_v1_t *)&memhndl)->val))

/* Differing locations for V1 and V2 mem handles */
#define GNI_MEMHNDL_SET_VA(memhndl, value)  GNI_MEMHNDL_FRMT_SET(memhndl, va, (value) >> 12)
#define GNI_MEMHNDL_GET_VA(memhndl)         (GNI_MEMHNDL_FRMT_GET(memhndl, va) << 12)
#define GNI_MEMHNDL_SET_MDH(memhndl, value) GNI_MEMHNDL_FRMT_SET(memhndl, mdh, value)
#define GNI_MEMHNDL_GET_MDH(memhndl)        GNI_MEMHNDL_FRMT_GET(memhndl, mdh)


/* The MDH field size is the same, and there is no other define to
 * limit max MDHs in uGNI. */

#define GNI_MEMHNDL_MDH_MASK    0xFFFUL

/* From this point forward, there is no difference. We don't need the
 * inlined conditionals */

/* Number of Registered pages (1TB for 4kB pages): QWORD2[27:0] */
#define GNI_MEMHNDL_NPGS_MASK   0xFFFFFFFUL
#define GNI_MEMHNDL_SET_NPAGES(memhndl, value) memhndl.qword2 |= (value & GNI_MEMHNDL_NPGS_MASK)
/* Page size that was used to calculate the total number of pages : QWORD2[33:28] */
#define GNI_MEMHNDL_PSIZE_MASK  0x3FUL
#define GNI_MEMHNDL_SET_PAGESIZE(memhndl, value) memhndl.qword2 |= (((uint64_t)value & GNI_MEMHNDL_PSIZE_MASK) << 28)
/* Flags: QWORD2[41:34] */
#define GNI_MEMHNDL_FLAGS_MASK  0xFFUL
#define GNI_MEMHNDL_SET_FLAGS(memhndl, value) memhndl.qword2 |= ((value & GNI_MEMHNDL_FLAGS_MASK) << 34)
#define GNI_MEMHNDL_GET_FLAGS(memhndl) ((memhndl.qword2 >> 34) & GNI_MEMHNDL_FLAGS_MASK)
/* QWORD2[55:54] left blank */
/* CRC to verify integrity of the handle: QWORD2[63:56] ( Call this only after all other field are set!)*/
#define GNI_MEMHNDL_CRC_MASK 0xFFUL
#define GNI_MEMHNDL_SET_CRC(memhndl) (memhndl.qword2 |= ((uint64_t)gni_memhndl_calc_crc(&memhndl)<<56))

/*
 * End of code pulled from gni_priv.h
 */

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

		/* Change the fid class to prevent user from calling into
		 *   close again on a dead atomic.
		 */
		mr->md.mr_fid.fid.fclass = FI_CLASS_UNSPEC;

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
static inline void gnix_convert_key_to_mhdl(
		gnix_mr_key_t *key,
		gni_mem_handle_t *mhdl)
{
	uint64_t pfn = (uint64_t) sign_extend(key->pfn << PAGE_SHIFT,
			GNIX_MR_PFN_BITS);
	uint8_t flags = 0;

	if (key->flags & GNIX_MR_FLAG_READONLY)
		flags |= GNI_MEMHNDL_ATTR_READONLY;

	GNI_MEMHNDL_INIT((*mhdl));
	if (key->format)
		GNI_MEMHNDL_SET_FLAGS((*mhdl), GNI_MEMHNDL_FLAG_NEW_FRMT);
	GNI_MEMHNDL_SET_VA((*mhdl), pfn);
	GNI_MEMHNDL_SET_MDH((*mhdl), key->mdd);
	GNI_MEMHNDL_SET_NPAGES((*mhdl), GNI_MEMHNDL_NPGS_MASK);
	GNI_MEMHNDL_SET_FLAGS((*mhdl), flags);
	GNI_MEMHNDL_SET_PAGESIZE((*mhdl), PAGE_SHIFT);
	GNI_MEMHNDL_SET_CRC((*mhdl));
}

static inline void gnix_convert_mhdl_to_key(
		gni_mem_handle_t *mhdl,
		gnix_mr_key_t *key)
{
	key->pfn = GNI_MEMHNDL_GET_VA((*mhdl));
	key->mdd = GNI_MEMHNDL_GET_MDH((*mhdl));
	key->format = GNI_MEMHNDL_NEW_FRMT((*mhdl));
	key->flags = 0;

	if (GNI_MEMHNDL_GET_FLAGS((*mhdl)) & GNI_MEMHNDL_FLAG_READONLY)
		key->flags |= GNIX_MR_FLAG_READONLY;
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

	if (fid->fclass != FI_CLASS_MR)
		return -FI_EINVAL;

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

	if (fid->fclass != FI_CLASS_MR)
		return -FI_EINVAL;

	mr = container_of(fid, gnix_mr_t, md.mr_fid.fid);

	if (!atomic_dec(&mr->ref_cnt)) {
		ret = __gnix_mr_free(mr);
	}

	return gnixu_to_fi_errno(ret);
}


