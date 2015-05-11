/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 *
 *  Created on: May 6, 2015
 *      Author: jswaro
 */

#ifndef GNIX_MR_H_
#define GNIX_MR_H_

#include "gnix.h"
#include "gnix_nic.h"
#include "gnix_util.h"
#include "ccan/list.h"

typedef struct gnix_mr {
	struct gnix_fid_mem_desc md;
	struct gnix_nic *nic;
	atomic_t ref_cnt;
	struct list_node entry;
} gnix_mr_t;

#define GNIX_MR_PAGE_SHIFT 12
#define GNIX_MR_VA_BITS 37
#define GNIX_MR_MDD_BITS GNIX_MR_PAGE_SHIFT
#define GNIX_MR_FLAG_BITS 1
#define GNIX_MR_PFN_BITS (GNIX_MR_VA_BITS + GNIX_MR_MDD_BITS)
#define GNIX_MR_KEY_BITS (GNIX_MR_PFN_BITS + GNIX_MR_FLAG_BITS)
#define GNIX_MR_PADDING_LENGTH (64 - GNIX_MR_KEY_BITS)

enum {
	GNIX_MR_FLAG_READONLY = 1 << 0
};

typedef struct gnix_mr_key {
	union {
		struct {
			union  {
				uint64_t pfn : GNIX_MR_PFN_BITS;
				struct {
					uint64_t va: GNIX_MR_VA_BITS;
					uint64_t mdd: GNIX_MR_MDD_BITS;
				};
			};
			uint64_t flags : GNIX_MR_FLAG_BITS;
			uint64_t padding: GNIX_MR_PADDING_LENGTH;
		};
		uint64_t value;
	};
} gnix_mr_key_t;

#endif /* GNIX_MR_H_ */
