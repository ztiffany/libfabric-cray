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


/*******************************************************************************
 * Forward declarations of ops structures.
 ******************************************************************************/
static struct fi_ops_av gnix_av_ops;
static struct fi_ops gnix_fi_av_ops;

/*******************************************************************************
 * Helper functions.
 ******************************************************************************/
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

/*
 * Check the capacity of the internal table used to represent FI_AV_TABLE type
 * address vectors. Initially the table starts with a capacity and count of 0
 * and the capacity increases by roughly double each time.
 */
static int gnix_check_capacity(struct gnix_fid_av *av, size_t count)
{
	struct addr_entry *addrs;
	size_t capacity = av->capacity;

	/*
	 * av->count + count is the amount of used indices after adding the
	 * count items.
	 */
	while (capacity < av->count + count) {
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

/*******************************************************************************
 * FI_AV_TABLE specific implementations.
 ******************************************************************************/
static int table_insert(struct gnix_fid_av *int_av, const void *addr,
			size_t count, fi_addr_t *fi_addr, uint64_t flags,
			void *context)
{
	struct gnix_ep_name *temp;
	int ret = count;
	size_t index;
	size_t i;

	if (gnix_check_capacity(int_av, count)) {
		ret = -FI_ENOMEM;
		goto err;
	}

	for (index = int_av->count, i = 0; i < count; index++, i++) {
		temp = &((struct gnix_ep_name *)addr)[i];
		int_av->table[index].addr = &temp->gnix_addr;
		int_av->table[index].valid = true;
		fi_addr[i] = index;
	}

	int_av->count += count;

err:
	return ret;
}

/*
 * TODO: Actually free memory.
 * Currently only marks as 'not valid'. Should actually free memory.
 */
static int table_remove(struct gnix_fid_av *int_av, fi_addr_t *fi_addr,
			size_t count, uint64_t flags)
{
	size_t index;
	size_t i;

	for (i = 0; i < count; i++) {
		index = (size_t) fi_addr[i];
		if (index < int_av->count) {
			int_av->table[index].valid = false;
		}
	}

	return FI_SUCCESS;
}

/*
 * TODO:
 * 1.) Error check return of container_of.
 */
static int table_lookup(struct gnix_fid_av *int_av, fi_addr_t fi_addr,
			void *addr, size_t *addrlen)
{
	struct gnix_ep_name *out;
	struct gnix_address *found;
	struct addr_entry *entry;
	int ret = FI_SUCCESS;
	size_t copy_size;
	size_t index;

	copy_size = sizeof(struct gnix_ep_name);

	if (*addrlen < copy_size) {
		copy_size = *addrlen;
		*addrlen = sizeof(struct gnix_ep_name);
		ret = -FI_ETOOSMALL;
	}

	if (!addr) {
		ret = -FI_ETOOSMALL;
		goto err;
	}

	index = (size_t)fi_addr;
	if (index > int_av->count) {
		ret = -FI_EINVAL;
		goto err;
	}

	entry = &int_av->table[index];

	if (entry && !entry->valid) {
		ret = -FI_EINVAL;
		goto err;
	}

	found = entry->addr;
	out = container_of(found, struct gnix_ep_name, gnix_addr);
	memcpy(addr, out, copy_size);

err:
	return ret;
}


/*******************************************************************************
 * FI_AV_MAP specific implementations.
 ******************************************************************************/
/*
 * TODO:
 * Store inserted address in some data structure.
 */
static int map_insert(struct gnix_fid_av *int_av, const void *addr,
		      size_t count, fi_addr_t *fi_addr, uint64_t flags,
		      void *context)
{
	struct gnix_ep_name *temp;
	size_t i;

	for (i = 0; i < count; i++) {
		temp = &((struct gnix_ep_name *)addr)[i];
		((struct gnix_address *)fi_addr)[i] = temp->gnix_addr;
	}

	return count;
}

/*
 * TODO: Actually implement once the address is being stored.
 */
static int map_remove(struct gnix_fid_av *int_av, fi_addr_t *fi_addr,
		      size_t count, uint64_t flags)
{
	return FI_SUCCESS;
}

/*
 * TODO:
 * 1.) Check if given item was actually inserted.
 * 2.) Do error checking on return of container_of.
 */
static int map_lookup(struct gnix_fid_av *int_av, fi_addr_t fi_addr, void *addr,
		      size_t *addrlen)
{
	struct gnix_ep_name out = {{0}};
	struct gnix_address *given;
	int ret = FI_SUCCESS;
	size_t copy_size;

	copy_size = sizeof(struct gnix_ep_name);

	if (*addrlen < copy_size) {
		copy_size = *addrlen;
		*addrlen = sizeof(struct gnix_ep_name);
		ret = -FI_ETOOSMALL;
	}

	if (!addr) {
		ret = -FI_ETOOSMALL;
		goto err;
	}

	given = (struct gnix_address *) &fi_addr;

	out.gnix_addr.device_addr = given->device_addr;
	out.gnix_addr.cdm_id = given->cdm_id;
	out.cookie = int_av->domain->cookie;

	memcpy(addr, &out, copy_size);

err:
	return ret;
}

/*******************************************************************************
 * FI_AV API implementations.
 ******************************************************************************/
static int gnix_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	struct gnix_fid_av *int_av;
	int ret = FI_SUCCESS;

	if (!av || !fi_addr) {
		ret = -FI_EINVAL;
		goto err;
	}

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	switch (int_av->type) {
	case FI_AV_TABLE:
		ret = table_lookup(int_av, fi_addr, addr, addrlen);
		break;
	case FI_AV_MAP:
		ret = map_lookup(int_av, fi_addr, addr, addrlen);
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}

err:
	return ret;
}

/*
 * TODO: Fix implementation for FI_AV_MAP so it's actually stored and looked up
 * rather than recreated each time.
 */
static int gnix_av_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct gnix_fid_av *int_av;
	int ret = FI_SUCCESS;

	if (!av || !addr) {
		ret = -FI_EINVAL;
		goto err;
	}

	/*
	 * fi_addr parameter may be NULL only if the count is 0. Otherwise it
	 * must reference an array of fi_addr_t.
	 */
	if (!fi_addr && count) {
		ret = -FI_EINVAL;
		goto err;
	}

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	switch (int_av->type) {
	case FI_AV_TABLE:
		ret =
		    table_insert(int_av, addr, count, fi_addr, flags, context);
		break;
	case FI_AV_MAP:
		ret = map_insert(int_av, addr, count, fi_addr, flags, context);
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}

err:
	return ret;
}

static int gnix_av_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	struct gnix_fid_av *int_av;
	int ret = FI_SUCCESS;

	if (!av || !fi_addr) {
		ret = -FI_EINVAL;
		goto err;
	}

	int_av = container_of(av, struct gnix_fid_av, av_fid);

	switch (int_av->type) {
	case FI_AV_TABLE:
		ret = table_remove(int_av, fi_addr, count, flags);
		break;
	case FI_AV_MAP:
		ret = map_remove(int_av, fi_addr, count, flags);
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}

err:
	return ret;
}

/*
 * Given an address pointed to by addr, stuff a string into buf representing:
 * device_addr:cdm_id
 * where device_addr and cdm_id are represented in hexadecimal.
 */
static const char *gnix_av_straddr(struct fid_av *av, const void *addr,
				   char *buf, size_t *len)
{
	char int_buf[64];
	int size;

	const struct gnix_address *gnix_addr = addr;

	size =
	    snprintf(int_buf, sizeof(int_buf), "0x%08" PRIx32 ":0x%08" PRIx32,
		     gnix_addr->device_addr, gnix_addr->cdm_id);

	snprintf(buf, *len, "%s", int_buf);
	*len = size + 1;

	return buf;
}

/*
 * TODO: Free memory for data structures when FI_AV_MAP is fully supported.
 */
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

/*
 * TODO: Support shared named AVs.
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

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static struct fi_ops_av gnix_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = gnix_av_insert,
	.remove = gnix_av_remove,
	.lookup = gnix_av_lookup,
	.straddr = gnix_av_straddr
};

static struct fi_ops gnix_fi_av_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_av_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};
