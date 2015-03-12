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

#include <assert.h>

#include "gnix.h"
#include "gnix_util.h"

/*******************************************************************************
 * Forward declaration for ops structures.
 ******************************************************************************/
static struct fi_ops_eq gnix_eq_ops;
static struct fi_ops gnix_fi_eq_ops;

/*******************************************************************************
 * Helper functions.
 ******************************************************************************/
static int gnix_verify_eq_attr(struct fi_eq_attr *attr)
{
	/*
	 * Initial implementation doesn't support any of the flags.
	 * TODO: Support FI_WRITE. This specifies that fi_eq_write can be called
	 * on the opened event queue.
	 */
	if (attr->flags)
		return -FI_ENOSYS;

	/*
	 * Initial implementation doesn't support any type of wait object.
	 */
	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
		break;
	case FI_WAIT_SET:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		return -FI_ENOSYS;
	default:
		break;
	}

	return FI_SUCCESS;
}

/*
 * TODO: Free buf?
 */
static void free_queue(struct slist *list)
{
	slist_entry *current = NULL;
	slist_entry *next = NULL;
	struct gnix_event *temp = NULL;

	if (slist_empty(list))
		return;

	for (current = list.head; current; current = next) {
		next = current->next;
		temp = container_of(current, struct gnix_event, entry);
		free(temp);
	}
}


/*******************************************************************************
 * API function implementations.
 ******************************************************************************/
/*
 * TODO:
 * - Increment fabric ref_cnt.
 * - Handle FI_WRITE flag.
 * - Handle wait objects.
 */
int gnix_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		 struct fid_eq **eq, void *context)
{
	struct gnix_fid_eq *gnix_eq = NULL;
	int ret = FI_SUCCESS;

	if (!fabric) {
		ret = -FI_EINVAL;
		goto err;
	}

	gnix_eq = calloc(1, sizeof(*gnix_eq));
	if (!gnix_eq) {
		ret = -FI_ENOMEM;
		goto err;
	}

	gnix_eq->eq_fabric = container_of(fabric, struct gnix_fid_fabric,
					  fab_fid);

	gnix_eq->eq_fid.fid.fclass = FI_CLASS_EQ;
	gnix_eq->eq_fid.fid.context = context;
	gnix_eq->eq_fid.fid.ops = &gnix_fi_eq_ops;
	gnix_eq->eq_fid.ops = &gnix_eq_ops;

	if (attr) {
		ret = gnix_verify_eq_attr(attr);
		if (ret)
			goto cleanup;
	}

	slist_init(&gnix_eq->ev_queue);
	slist_init(&gnix_eq->err_queue);

	*eq = &gnix_eq->eq;

cleanup:
	free(gnix_eq);
err:
	return ret;
}

/*
 * TOOD:
 * - Decrement fabric ref_cnt.
 */
static int gnix_eq_close(struct fid *fid)
{
	struct gnix_fid_eq *gnix_eq = NULL;

	if (!fid)
		return -FI_EINVAL;

	gnix_eq = container_of(fid, struct gnix_fid_eq, eq);

	if (!gnix_eq)
		return -FI_EINVAL;

	if (atomic_get(&gnix_eq->ref_cnt) != 0)
		return -FI_EBUSY;

	free_queue(gnix_eq->ev_queue);
	free_queue(gnix_eq->err_queue);
	free(gnix_eq);

	return FI_SUCCESS;
}

static int gnix_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
			size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static int gnix_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
			   size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static int gnix_eq_write(struct fid_eq *eq, uint32_t event,
			 const void *buf, size_t len, uint64_t flags)
{
	return -FI_ENOSYS;
}

static const char *gnix_eq_strerror(struct fid_eq *eq, int prov_errno,
				    const void *err_data, void *buf, size_t len)
{
	return -FI_ENOSYS;
}

/*******************************************************************************
 * FI_OPS_* data structures.
 ******************************************************************************/
static struct fi_ops_eq gnix_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = gnix_eq_read,
	.readerr = gnix_eq_readerr,
	.write = gnix_eq_write,
	.strerror = gnix_eq_strerror
};

static struct fi_ops gnix_fi_eq_ops = {
	.size = sizeof(struct fi_ops),
	.close = gnix_eq_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open
};

