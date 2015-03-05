/*
 * Copyright (c) 2015 Cray Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos National Security, LLC. Allrights reserved.
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
// Address vector common code
//
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "gnix.h"
#include "gnix_util.h"

/*
 * TODO:
 * - Support FI_AV_MAP type. Currently treating everything as FI_AV_TABLE.
 * - Support flags.
 * - Support named AVs.
 */

/*
 * TODO: Check for named AV creation and check RX CTX bits.
 */
static int gnix_verify_av_attr(struct fi_av_attr *attr)
{
	int ret = FI_SUCCESS;

	switch (attr->type) {
	case FI_AV_TABLE:
	case FI_AV_MAP:
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}

	return ret;
}

static int gnix_check_capacity(struct gnix_fid_av *av, size_t count)
{
	struct addr_entry *addrs;
	size_t capacity = av->capacity;

	/*
	 * av->count + count is the amount of used indices after adding the
	 * count items.
	 */
	while(capacity < av->count + count) {
		/*
		 * Handle initial capacity of 0, by adding 1.
		 */
		capacity = capacity * 2 + 1;
	}

	/*
	 * Don't need to grow the table.
	 */
	if (capacity == av->capacity) {
		return FI_SUCCESS;
	}

	addrs = realloc(av->table, capacity * sizeof(*addrs));
	if (!addrs) {
		return -FI_ENOMEM;
	}

	/*
	 * Update table and capacity to reflect new values.
	 */
	av->table = addrs;
	av->capacity = capacity;

	return FI_SUCCESS;
}

static int gnix_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	struct gnix_fid_av *int_av;
	struct gnix_address *found = NULL;
	struct addr_entry *entry;

	int ret = FI_SUCCESS;
	size_t copy_size;
	size_t index;

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	if (int_av->type == FI_AV_TABLE) {
		index = (size_t) fi_addr;
		if (index > int_av->count) {
			ret = -FI_EINVAL;
			goto err;
		}

		entry = &int_av->table[index];

		if (!entry->valid) {
			ret = -FI_EINVAL;
			goto err;
		}

		found = entry->addr;
	}

	/*
	 * TODO: Mostly likely reason this would happen is that FI_AV_MAP was
	 * tried.
	 */
	if (!found) {
		ret = -FI_EINVAL;
		goto err;
	}

	copy_size = sizeof(*found);

	if (*addrlen < copy_size) {
		copy_size = *addrlen;
		*addrlen = sizeof(*found);
		ret = -FI_ETOOSMALL;
	}

	memcpy(addr, found, copy_size);

err:
	return ret;
}

static int gnix_av_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct gnix_fid_av *int_av;
	struct gnix_ep_name *temp;
	int ret = FI_SUCCESS;
	size_t index;
	size_t i;

	/*
	 * fi_addr parameter may be NULL only if the count is 0. Otherwise it
	 * must reference an array of fi_addr_t.
	 */
	if (!fi_addr && count) {
		ret = -FI_EINVAL;
		goto err;
	}

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	if (gnix_check_capacity(int_av, count)) {
		ret = -FI_ENOMEM;
		goto err;
	}

	if (int_av->type == FI_AV_TABLE) {
		for (index = int_av->count, i = 0; i < count; index++, i++) {
			temp = &((struct gnix_ep_name *) addr)[i];
			int_av->table[index].addr = &temp->gnix_addr;
			int_av->table[index].valid = true;
			fi_addr[i] = index;
		}

		int_av->count += count;
	}

err:
	return ret;
}

static int gnix_av_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	struct gnix_fid_av *int_av;
	size_t index;
	size_t i;

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	if (int_av->type == FI_AV_TABLE) {
		for (i = 0; i < count; i++) {
			index = fi_addr[i];
			if (index < int_av->count) {
				int_av->table[index].valid = false;
			}
		}
	}

	return FI_SUCCESS;
}

static const char *gnix_av_straddr(struct fid_av *av, const void *addr,
				   char *buf, size_t *len)
{
	char int_buf[64];
	int size;

	size =
	    snprintf(int_buf, sizeof(int_buf), "0x%08" PRIx32 ":0x%08" PRIx32,
		     ((struct gnix_address *) addr)->device_addr,
		     ((struct gnix_address *) addr)->cdm_id);

	snprintf(buf, *len, "%s", int_buf);
	*len = size + 1;

	return buf;
}

static struct fi_ops_av gnix_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = gnix_av_insert,
	.remove = gnix_av_remove,
	.lookup = gnix_av_lookup,
	.straddr = gnix_av_straddr
};

static int gnix_av_close(fid_t fid)
{
	struct gnix_fid_av *av;
	av = container_of(fid, struct gnix_fid_av, av_fid.fid);
	if (av->table) {
		free(av->table);
	}
	free(av);
	return 0;
}

static struct fi_ops gnix_fi_av_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_av_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

/*
 * TODO: Support shared named AVs.
 *
 */
int gnix_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
			struct fid_av **av, void *context)
{
	struct gnix_fid_domain *int_dom;
	struct gnix_fid_av *int_av;

	enum fi_av_type type = FI_AV_TABLE;
	size_t count = 128;

	int_dom = container_of(domain, struct gnix_fid_domain, domain_fid);

	int_av = calloc(1, sizeof(*int_av));
	if (!int_av) {
		return -FI_ENOMEM;
	}

	if (attr) {
		if (gnix_verify_av_attr(attr)) {
			return -FI_EINVAL;
		}

		type = attr->type;
		count = attr->count;
	}

	int_av->domain = int_dom;
	int_av->type = type;
	int_av->addrlen = sizeof(struct gnix_address);
	int_av->count = count;

	int_av->av_fid.fid.fclass = FI_CLASS_AV;
	int_av->av_fid.fid.context = context;
	int_av->av_fid.fid.ops = &gnix_fi_av_ops;
	int_av->av_fid.ops = &gnix_av_ops;

	*av = &int_av->av_fid;

	return FI_SUCCESS;
}

